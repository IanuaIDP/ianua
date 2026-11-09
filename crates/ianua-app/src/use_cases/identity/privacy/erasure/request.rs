//! Request erasure: ask for a person's data to be deleted for good, under
//! GDPR Article 17. The account closes at once, a grace period starts, and a
//! link to cancel goes to the person's address.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::privacy::erasure::{
    ErasureRequest, GracePeriod, RequestErasureParams,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ErasureRequestId, HttpsUrl, Text, TokenHash, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::{ErasureRequestStore, UserStore};
use crate::ports::shared::{MailRecipient, Mailer};
use crate::services::lookup::existing_user;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::account_control::{account_control, departure};
use crate::use_cases::identity::users::sessions::sign_out::StandingRemoval;
use crate::use_cases::identity::whose::Whose;

/// How erasures are asked for.
#[derive(Debug, Clone)]
pub struct ErasurePolicy {
    /// How long the person has to cancel before deletion starts.
    pub grace_period: GracePeriod,
    /// The address the cancel link is built on.
    pub base_url: HttpsUrl,
}

/// The ports [`RequestErasureUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequestErasurePorts {
    /// Keeps erasure requests.
    pub erasure_store: Arc<dyn ErasureRequestStore>,
    /// Loads and saves the account that closes.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Who the caller is and what they hold in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Ends the closing account's sessions and the delegations it granted.
    pub removal: StandingRemoval,
    /// Mails the cancel link.
    pub mailer: Arc<dyn Mailer>,
    /// Makes cancel links.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// The grace period and the address cancel links are built on.
    pub policy: ErasurePolicy,
}

/// Whose data to erase, why, and where the cancel link lands.
pub struct RequestErasureRequest {
    /// Whose data it is.
    pub whose: Whose,
    /// The reason given, if any.
    pub reason: Option<Text>,
    /// Where the cancel link lands.
    pub scope: LinkScope,
}

/// Asks for a person's data to be erased.
pub struct RequestErasureUseCase {
    ports: RequestErasurePorts,
}

impl RequestErasureUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RequestErasurePorts) -> Self {
        Self { ports }
    }

    /// A new cancel link: its raw token and the hash the request keeps.
    fn cancel_token(&self) -> Result<(Secret, TokenHash), AppError> {
        let made = self.ports.token_generator.generate().or_internal()?;
        Ok(made.into_parts())
    }

    /// The request for `whose`, made by the person or for them, with the
    /// account it closes.
    async fn submitted(
        &self,
        ctx: &CallerContext,
        whose: Whose,
        params: RequestErasureParams,
    ) -> Result<(ErasureRequest<ResolvedTenant>, User<ResolvedTenant>), AppError> {
        match whose {
            Whose::Own => self.asked_by_the_person(ctx, params).await,
            Whose::OnBehalfOf(user_id) => self.asked_for(ctx, &user_id, params).await,
        }
    }

    /// The request someone who may erase `user_id` makes for them, with the
    /// account it closes.
    async fn asked_for(
        &self,
        ctx: &CallerContext,
        user_id: &UserId,
        params: RequestErasureParams,
    ) -> Result<(ErasureRequest<ResolvedTenant>, User<ResolvedTenant>), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let records = self.ports.access_records.as_ref();
        let erasing = AccountAction::Erase;
        let control = account_control(records, &tenant, &authority, user_id, erasing).await?;
        let mut account = existing_user(self.ports.user_store.as_ref(), &tenant, user_id).await?;
        ensure_none_active(self.ports.erasure_store.as_ref(), &tenant, user_id).await?;
        let request = ErasureRequest::submit_for(params, &mut account, &control)
            .map_err(AppError::from_domain)?;
        Ok((request, account))
    }

    /// The request the signed-in person makes for their own data, with the
    /// account it closes.
    async fn asked_by_the_person(
        &self,
        ctx: &CallerContext,
        params: RequestErasureParams,
    ) -> Result<(ErasureRequest<ResolvedTenant>, User<ResolvedTenant>), AppError> {
        let tenant = ctx.tenant();
        let mut person = self.ports.tenant_authorities.signed_in(ctx).await?;
        let account = person.account.id();
        let records = self.ports.access_records.as_ref();
        let leaving = departure(records, &tenant, account).await?;
        ensure_none_active(self.ports.erasure_store.as_ref(), &tenant, account).await?;
        let request =
            ErasureRequest::submit(params, &mut person.account, &person.signed_in, &leaving)
                .map_err(AppError::from_domain)?;
        Ok((request, person.account))
    }

    /// Keeps `request` and the closed `account`, ends the account's sessions
    /// and delegations, and records it all.
    async fn keep(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: &mut ErasureRequest<ResolvedTenant>,
        account: &User<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let erasures = self.ports.erasure_store.as_ref();
        erasures.save(&tenant, request).await.or_internal()?;
        let users = self.ports.user_store.as_ref();
        users.save(&tenant, account).await.or_internal()?;
        let actor = ctx.actor();
        let removal = &self.ports.removal;
        let revoked = removal.cut_off(&tenant, account, &actor).await?;
        let mut events = request.take_events(&tenant);
        events.extend(revoked);
        auditor.dispatch_by(&actor, events).await.or_internal()
    }

    /// Mails the cancel link to the address the account has.
    async fn mail_cancel_link(
        &self,
        tenant: &ScopedTenant,
        account: &User<ResolvedTenant>,
        request: &ErasureRequest<ResolvedTenant>,
        link: CancelLink<'_>,
    ) -> Result<(), AppError> {
        let CancelLink { raw_token, scope } = link;
        let base_url = &self.ports.policy.base_url;
        let action_url = scope.action_url(base_url, "cancel-erasure", raw_token.expose());
        let variables = cancel_mail_variables(account, request, action_url);
        let to = MailRecipient {
            email: account.email(),
            locale: account.locale(),
        };
        self.ports
            .mailer
            .send_to_person(
                to,
                *tenant,
                EmailTemplateType::ErasureConfirmation,
                &variables,
            )
            .await
            .map_err(AppError::upstream)
    }
}

impl Command for RequestErasureUseCase {
    type Caller = CallerContext;
    type Input = RequestErasureRequest;
    type Output = Result<ErasureRequestId, AppError>;

    /// Asks for the data of `request.whose` to be erased once the grace
    /// period passes.
    ///
    /// The person asks from their own session, or someone who may erase
    /// them asks for them. Their account closes at once, its sessions and
    /// delegations end, and a link to cancel goes to its address: the
    /// person cannot sign in meanwhile, so the link is how they change their
    /// mind.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without erasure rights or when the person holds more rights.
    /// - `AppError::Conflict` for an existing erasure or the last administrator; `NotFound` for a missing user.
    /// - `AppError::Upstream` for refused cancel-link mail, after creating the request; `Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        input: RequestErasureRequest,
    ) -> Result<ErasureRequestId, AppError> {
        let RequestErasureRequest {
            whose,
            reason,
            scope,
        } = input;
        let tenant = ctx.tenant();
        let (raw_token, cancel_token_hash) = self.cancel_token()?;
        let params = RequestErasureParams {
            reason,
            grace_period: self.ports.policy.grace_period,
            cancel_token_hash,
        };
        let (mut request, account) = self.submitted(ctx, whose, params).await?;
        self.keep(ctx, auditor, &mut request, &account).await?;
        let link = CancelLink {
            raw_token: &raw_token,
            scope: &scope,
        };
        self.mail_cancel_link(&tenant, &account, &request, link)
            .await?;
        Ok(*request.id())
    }
}

/// The link that cancels an erasure: its raw token, and where it lands.
struct CancelLink<'a> {
    raw_token: &'a Secret,
    scope: &'a LinkScope,
}

/// Refuses a second request while one for `user_id` is under way.
async fn ensure_none_active(
    store: &dyn ErasureRequestStore,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> Result<(), AppError> {
    let existing = store
        .find_active_by_user(tenant, user_id)
        .await
        .or_internal()?;
    if existing.is_some() {
        return Err(AppError::Conflict(message!(
            "identity-active-erasure-request-already-exists",
            "active erasure request already exists"
        )));
    }
    Ok(())
}

/// What the cancel mail to `account` fills in: their name, `action_url` to
/// cancel at, and the day `request` starts deleting.
fn cancel_mail_variables(
    account: &User<ResolvedTenant>,
    request: &ErasureRequest<ResolvedTenant>,
    action_url: String,
) -> HashMap<TemplateVariable, String> {
    HashMap::from([
        (
            TemplateVariable::UserName,
            account.display_name().as_str().to_owned(),
        ),
        (TemplateVariable::ActionUrl, action_url),
        (
            TemplateVariable::ErasureDate,
            request.scheduled_at().date().to_string(),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::SessionId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::FakeDelegationStore;
    use crate::test_support::authentication::{FakeSessionStore, password_session};
    use crate::test_support::identity::{
        FakeErasureStore, FakeUserStore, access_where_holds, removal_over, stored_erasure,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeMailer, block_on, test_auditor, test_ctx, test_ctx_with,
        test_link_scope,
    };

    /// Lea, a user of the tenant signed in on her laptop, and the stores
    /// that watch her erasure.
    struct Leaving {
        lea: UserId,
        laptop: SessionId,
        users: Arc<FakeUserStore>,
        erasures: Arc<FakeErasureStore>,
        sessions: Arc<FakeSessionStore>,
        mailer: Arc<FakeMailer>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Leaving {
        fn new() -> Self {
            let lea = UserId::new();
            let laptop = password_session(lea, "leas-laptop", SecondFactor::NotOwed);
            Self {
                lea,
                laptop: *laptop.id(),
                users: Arc::new(FakeUserStore::with_user(lea, "lea@acme.com")),
                erasures: Arc::new(FakeErasureStore::empty()),
                sessions: Arc::new(FakeSessionStore::with_session(laptop)),
                mailer: Arc::new(FakeMailer::new()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> RequestErasurePorts {
            RequestErasurePorts {
                erasure_store: self.erasures.clone(),
                user_store: self.users.clone(),
                removal: removal_over(&self.sessions, &Arc::new(FakeDelegationStore::empty())),
                mailer: self.mailer.clone(),
                ..RequestErasurePorts::fakes()
            }
        }

        fn ask(
            &self,
            ports: RequestErasurePorts,
            whose: Whose,
        ) -> Result<ErasureRequestId, AppError> {
            let seeded = test_ctx();
            let as_lea = test_ctx_with(seeded.organization_id(), seeded.tenant_id(), self.lea);
            let use_case = RequestErasureUseCase::new(ports);
            block_on(use_case.execute(
                &as_lea,
                &test_auditor(self.sink.clone()),
                RequestErasureRequest {
                    whose,
                    reason: None,
                    scope: test_link_scope(),
                },
            ))
        }
    }

    /// Lea asks to be forgotten. Her account closes, she is signed out, a
    /// cancel link goes to her, and the request is recorded.
    #[test]
    fn the_person_asks_to_be_forgotten() {
        let leaving = Leaving::new();

        leaving.ask(leaving.ports(), Whose::Own).unwrap();

        assert_eq!(leaving.erasures.count(), 1);
        assert_eq!(
            leaving.users.get_status(&leaving.lea),
            Some(UserStatus::Closing)
        );
        assert_eq!(
            leaving.sessions.get_status(&leaving.laptop),
            Some(SessionStatus::Revoked)
        );
        assert_eq!(leaving.mailer.count(), 1);
        assert_eq!(
            leaving.sink.records.lock().unwrap()[0],
            "identity.erasure_requested"
        );
    }

    /// Lea cannot request her own erasure as the tenant's last administrator.
    /// The conflict saves no erasure request and leaves her account active.
    #[test]
    fn the_last_administrator_cannot_erase_themselves() {
        let leaving = Leaving::new();
        let ports = RequestErasurePorts {
            access_records: access_where_holds(leaving.lea, SystemPermission::all()),
            ..leaving.ports()
        };

        let result = leaving.ask(ports, Whose::Own);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(leaving.erasures.count(), 0);
        assert_eq!(
            leaving.users.get_status(&leaving.lea),
            Some(UserStatus::Active)
        );
    }

    /// Ann, who may delete users, asks for Lea's data to be erased. Lea's
    /// account closes and the cancel link goes to her.
    #[test]
    fn an_admin_asks_for_someone_to_be_forgotten() {
        let leaving = Leaving::new();

        leaving
            .ask(leaving.ports(), Whose::OnBehalfOf(leaving.lea))
            .unwrap();

        assert_eq!(
            leaving.users.get_status(&leaving.lea),
            Some(UserStatus::Closing)
        );
        assert_eq!(leaving.mailer.recipients(), ["lea@acme.com"]);
    }

    /// Lea already has an erasure under way. Asking again is a conflict.
    #[test]
    fn a_second_request_is_a_conflict() {
        let leaving = Leaving::new();
        let waiting = stored_erasure(leaving.lea, "lea@acme.com", (0, 14));
        block_on(leaving.erasures.save(&test_ctx().tenant(), &waiting)).unwrap();

        let result = leaving.ask(leaving.ports(), Whose::OnBehalfOf(leaving.lea));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(leaving.erasures.count(), 1);
    }

    /// User-update rights do not permit requesting erasure on Lea's behalf.
    /// Her account stays active after the refusal.
    #[test]
    fn a_caller_who_may_not_delete_users_is_refused() {
        let leaving = Leaving::new();
        let ports = RequestErasurePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Update),
            ])),
            ..leaving.ports()
        };

        let result = leaving.ask(ports, Whose::OnBehalfOf(leaving.lea));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            leaving.users.get_status(&leaving.lea),
            Some(UserStatus::Active)
        );
    }

    /// User-deletion rights do not permit erasure on behalf of an account
    /// holding broader user-management rights.
    #[test]
    fn a_person_holding_more_than_the_caller_is_not_erased() {
        let leaving = Leaving::new();
        let ports = RequestErasurePorts {
            access_records: access_where_holds(leaving.lea, &[SystemPermission::ManageUsers]),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Delete),
            ])),
            ..leaving.ports()
        };

        let result = leaving.ask(ports, Whose::OnBehalfOf(leaving.lea));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Lea cannot request her own erasure after signing out. No request is saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let leaving = Leaving::new();
        let ports = RequestErasurePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..leaving.ports()
        };

        let result = leaving.ask(ports, Whose::Own);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(leaving.erasures.count(), 0);
    }
}
