//! Request impersonation: a tenant admin asks to act as one of the tenant's
//! people for a short while, with a reason, to see what they see and put it
//! right.
//!
//! The tenant decides whether the person approves first or the admin
//! starts at once. A person asked to approve is mailed, in their language,
//! who asks and why.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::impersonation::state::{
    ImpersonationStatus, ImpersonationWindow,
};
use ianua_domain::domains::identity::impersonation::{
    CONSENT_WAIT, SupportImpersonation, SupportImpersonationTerms,
};
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, SupportImpersonationId, Text, UserId};

use crate::acting::TenantAuthorities;
use crate::acting::tenant::SignedInAccount;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::{SupportImpersonationStore, UserStore};
use crate::ports::shared::{MailRecipient, Mailer};
use crate::ports::tenant::TenantStore;
use crate::services::lookup::{existing_tenant, existing_user};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::account_control::account_control;

/// Whom to act as, why, and for how long.
pub struct RequestRequest {
    /// The person to act as.
    pub user_id: UserId,
    /// Why, kept in the audit trail.
    pub reason: Text,
    /// How long the admin may act once it starts.
    pub window: ImpersonationWindow,
}

/// The ports [`RequestUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequestPorts {
    /// Keeps the requests.
    pub impersonation_store: Arc<dyn SupportImpersonationStore>,
    /// Loads the account to act as.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant, whose setting says whether the person approves first.
    pub tenant_store: Arc<dyn TenantStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Who the caller is and what they hold in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Mails the person asked to approve.
    pub mailer: Arc<dyn Mailer>,
}

/// Asks to act as one of the tenant's people.
pub struct RequestUseCase {
    ports: RequestPorts,
}

/// A request just made, with the tenant and the people it names.
struct Asked {
    impersonation: SupportImpersonation<ResolvedTenant>,
    workspace: Tenant,
    account: User<ResolvedTenant>,
}

impl RequestUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RequestPorts) -> Self {
        Self { ports }
    }

    /// The request `admin` makes, under the tenant's rule on consent, once
    /// they may act as the account.
    async fn asked(
        &self,
        ctx: &CallerContext,
        admin: &SignedInAccount,
        request: RequestRequest,
    ) -> Result<Asked, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let records = self.ports.access_records.as_ref();
        let acting_as = AccountAction::Impersonate;
        let control =
            account_control(records, &tenant, &authority, &request.user_id, acting_as).await?;
        let users = self.ports.user_store.as_ref();
        let account = existing_user(users, &tenant, &request.user_id).await?;
        let workspace = existing_tenant(self.ports.tenant_store.as_ref(), &tenant).await?;
        let terms = SupportImpersonationTerms {
            admin: *admin.account.id(),
            reason: request.reason,
            window: request.window,
            consent: workspace.auth_config().impersonation_consent(),
        };
        let impersonation =
            SupportImpersonation::request(terms, &account, &admin.signed_in, &control)
                .map_err(AppError::from_domain)?;
        Ok(Asked {
            impersonation,
            workspace,
            account,
        })
    }

    /// Mails the person, in their language, that `admin` asks to act as
    /// them and why, when the request waits for them. Delivery is best
    /// effort: the request stands, and the person finds it among their own.
    async fn ask_person(&self, tenant: &ScopedTenant, admin: &User<ResolvedTenant>, asked: &Asked) {
        if asked.impersonation.status() != ImpersonationStatus::AwaitingConsent {
            return;
        }
        let to = MailRecipient {
            email: asked.account.email(),
            locale: asked.account.locale(),
        };
        let variables = consent_variables(admin, asked);
        let sent = self.ports.mailer.send_to_person(
            to,
            *tenant,
            EmailTemplateType::ImpersonationRequested,
            &variables,
        );
        let _ = sent.await;
    }
}

impl Command for RequestUseCase {
    type Caller = CallerContext;
    type Input = RequestRequest;
    type Output = Result<SupportImpersonationId, AppError>;

    /// Asks, as the admin signed in to `ctx`'s session, to act as
    /// `request.user_id`, and records
    /// `identity.support_impersonation_requested`. Where the tenant has the
    /// person approve, they are mailed and it waits for them; where the
    /// admin decides, it starts at once and records
    /// `identity.support_impersonation_started` too.
    ///
    /// Acting as someone is holding all they hold. Sam may update users but
    /// holds less than Ann, an admin; acting as her, he would do all she
    /// may. So the admin needs full control of users and must hold what the
    /// person holds. Nobody acts as themselves, and nobody as an account
    /// that may not sign in now.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session, or it no longer counts.
    /// - `AppError::Forbidden` when the caller may not act as the user,
    ///   holds less than them, or names themselves.
    /// - `AppError::NotFound` if the user or the tenant doesn't exist.
    /// - `AppError::Conflict` when the user may not sign in now.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: RequestRequest,
    ) -> Result<SupportImpersonationId, AppError> {
        let tenant = ctx.tenant();
        let admin = self.ports.tenant_authorities.signed_in(ctx).await?;
        let mut asked = self.asked(ctx, &admin, request).await?;
        self.ports
            .impersonation_store
            .save(&tenant, &asked.impersonation)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(
                &ActorRef::User(*admin.account.id()),
                asked.impersonation.take_events(&tenant),
            )
            .await
            .or_internal()?;
        self.ask_person(&tenant, &admin.account, &asked).await;
        Ok(*asked.impersonation.id())
    }
}

/// What the mail asking the person to approve says: who asks, why, in
/// which workspace, and how long the request waits.
fn consent_variables(
    admin: &User<ResolvedTenant>,
    asked: &Asked,
) -> HashMap<TemplateVariable, String> {
    HashMap::from([
        (
            TemplateVariable::UserName,
            asked.account.display_name().as_str().to_owned(),
        ),
        (
            TemplateVariable::TenantName,
            asked.workspace.display_name().as_str().to_owned(),
        ),
        (
            TemplateVariable::RequesterName,
            admin.display_name().as_str().to_owned(),
        ),
        (
            TemplateVariable::Reason,
            asked.impersonation.reason().as_str().to_owned(),
        ),
        (
            TemplateVariable::ExpiresAt,
            format!("{} hours", CONSENT_WAIT.whole_hours()),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::impersonation::state::ImpersonationConsent;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::types::{Locale, Preference};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::test_caller_id;
    use crate::test_support::identity::{
        FakeSupportImpersonationStore, FakeUserStore, access_where_holds, user_reading,
    };
    use crate::test_support::tenant::tenant_store_signing_in_with;
    use crate::test_support::{FakeEventDispatcher, FakeMailer, block_on, test_auditor, test_ctx};

    struct Fixture {
        bob: UserId,
        store: Arc<FakeSupportImpersonationStore>,
        mailer: Arc<FakeMailer>,
        audit: Arc<FakeEventDispatcher>,
        ports: RequestPorts,
    }

    impl Fixture {
        fn new() -> Self {
            Self::under(ImpersonationConsent::HolderApproves)
        }

        /// Bob, who reads mail in German, in a tenant whose rule on consent
        /// is `consent`.
        fn under(consent: ImpersonationConsent) -> Self {
            let bob = UserId::new();
            let store = Arc::new(FakeSupportImpersonationStore::empty());
            let mailer = Arc::new(FakeMailer::new());
            let users = FakeUserStore::empty();
            users.add(user_reading(bob, "bob@acme.test", "de-DE"));
            Self {
                ports: RequestPorts {
                    impersonation_store: store.clone(),
                    user_store: Arc::new(users),
                    tenant_store: tenant_store_signing_in_with(TenantAuthSettings {
                        impersonation_consent: consent,
                        ..TenantAuthSettings::default()
                    }),
                    mailer: mailer.clone(),
                    ..RequestPorts::fakes()
                },
                bob,
                store,
                mailer,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ask_for(self, user_id: UserId) -> (Result<SupportImpersonationId, AppError>, Self) {
            let use_case = RequestUseCase::new(self.ports);
            let request = RequestRequest {
                user_id,
                reason: Text::new("reason", "Bob cannot see the billing page").unwrap(),
                window: ImpersonationWindow::minutes(30).unwrap(),
            };
            let result =
                block_on(use_case.execute(&test_ctx(), &test_auditor(self.audit.clone()), request));
            let fixture = Self {
                ports: use_case.ports,
                ..self
            };
            (result, fixture)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann asks to act as Bob to see why his billing page is blank. The
    /// request waits for Bob to approve, and it is recorded.
    #[test]
    fn an_admin_asks_and_the_request_waits_for_the_person() {
        let fixture = Fixture::new();
        let bob = fixture.bob;

        let (result, fixture) = fixture.ask_for(bob);

        let kept = fixture.store.stored(&result.unwrap()).unwrap();
        assert_eq!(kept.status(), ImpersonationStatus::AwaitingConsent);
        assert_eq!(kept.admin(), &test_caller_id());
        assert_eq!(
            fixture.recorded(),
            ["identity.support_impersonation_requested"]
        );
    }

    /// Bob is asked to approve. He is mailed in German, the language he
    /// reads, with who asks and why.
    #[test]
    fn the_person_asked_is_mailed_in_their_language() {
        let fixture = Fixture::new();
        let bob = fixture.bob;

        let (_, fixture) = fixture.ask_for(bob);

        let sent = fixture.mailer.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, "bob@acme.test");
        assert_eq!(sent[0].template, EmailTemplateType::ImpersonationRequested);
        assert_eq!(
            sent[0].locale,
            Preference::Own(Locale::new("de-DE").unwrap())
        );
        assert_eq!(
            sent[0].variables.get(&TemplateVariable::Reason).unwrap(),
            "Bob cannot see the billing page"
        );
    }

    /// Acme lets its admins decide. Ann's request starts at once, both
    /// steps are recorded, and Bob is not asked to approve anything.
    #[test]
    fn where_the_admin_decides_it_starts_at_once() {
        let fixture = Fixture::under(ImpersonationConsent::AdminDecides);
        let bob = fixture.bob;

        let (result, fixture) = fixture.ask_for(bob);

        let kept = fixture.store.stored(&result.unwrap()).unwrap();
        assert_eq!(kept.status(), ImpersonationStatus::Active);
        assert_eq!(
            fixture.recorded(),
            [
                "identity.support_impersonation_requested",
                "identity.support_impersonation_started"
            ]
        );
        assert_eq!(fixture.mailer.count(), 0);
    }

    /// Ann cannot request impersonation of herself, and no request is saved.
    #[test]
    fn nobody_acts_as_themselves() {
        let mut fixture = Fixture::new();
        fixture.ports.user_store =
            Arc::new(FakeUserStore::with_user(test_caller_id(), "ann@acme.test"));

        let (result, fixture) = fixture.ask_for(test_caller_id());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.store.count(), 0);
    }

    /// User-update rights do not permit impersonating Bob. No request,
    /// audit event or consent mail is created.
    #[test]
    fn acting_as_someone_needs_full_control_of_users() {
        let mut fixture = Fixture::new();
        fixture.ports.tenant_authorities =
            Arc::new(FakeTenantAuthorities::holding(&[SystemPermission::Users(
                UserAction::Update,
            )]));
        let bob = fixture.bob;

        let (result, fixture) = fixture.ask_for(bob);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.store.count(), 0);
        assert!(fixture.recorded().is_empty());
        assert_eq!(fixture.mailer.count(), 0);
    }

    /// User-management rights do not permit impersonating Bob when he also
    /// holds role-management rights that the caller lacks.
    #[test]
    fn nobody_acts_as_someone_holding_more() {
        let mut fixture = Fixture::new();
        fixture.ports.access_records = access_where_holds(
            fixture.bob,
            &[SystemPermission::ManageUsers, SystemPermission::ManageRoles],
        );
        fixture.ports.tenant_authorities = Arc::new(FakeTenantAuthorities::holding(&[
            SystemPermission::ManageUsers,
        ]));
        let bob = fixture.bob;

        let (result, _) = fixture.ask_for(bob);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann names someone the tenant does not have. It is not found.
    #[test]
    fn an_unknown_user_is_not_found() {
        let (result, _) = Fixture::new().ask_for(UserId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller cannot request impersonation of Bob.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let mut fixture = Fixture::new();
        fixture.ports.tenant_authorities =
            Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut));
        let bob = fixture.bob;

        let (result, _) = fixture.ask_for(bob);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
