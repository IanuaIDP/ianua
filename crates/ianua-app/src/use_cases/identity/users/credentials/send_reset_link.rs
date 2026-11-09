//! Send reset link: an admin mails a user a link to choose a new password,
//! rather than choosing one for them. The admin never learns the password.

use std::sync::Arc;

use ianua_domain::domains::authentication::recovery::reset::ResetInitiator;
use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::UserId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::UserStore;
use crate::services::authentication::reset_mail::{
    OutgoingReset, ResetMailPorts, ResetRequestPolicy,
};
use crate::services::lookup::existing_user;
use crate::use_case::Command;
use crate::use_cases::identity::account_control::account_control;

/// Whom to send the link, and the pages it opens.
pub struct SendResetLinkRequest {
    /// The user whose password is to change.
    pub user_id: UserId,
    /// The tenant whose reset page the link opens.
    pub scope: LinkScope,
}

/// The ports [`SendResetLinkUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SendResetLinkPorts {
    /// Loads the user.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Keeps, makes and mails the link.
    pub mail: ResetMailPorts,
}

/// Mails a user a reset link on an admin's word.
pub struct SendResetLinkUseCase {
    policy: ResetRequestPolicy,
    ports: SendResetLinkPorts,
}

impl SendResetLinkUseCase {
    /// A use case making links under `policy`, working through `ports`.
    #[must_use]
    pub fn new(policy: ResetRequestPolicy, ports: SendResetLinkPorts) -> Self {
        Self { policy, ports }
    }
}

impl Command for SendResetLinkUseCase {
    type Caller = CallerContext;
    type Input = SendResetLinkRequest;
    type Output = Result<(), AppError>;

    /// Mails `request.user_id` a link to choose a new password, superseding
    /// their earlier links, and records
    /// `authentication.password_reset_requested` started by an admin.
    ///
    /// Whoever controls how an account signs in holds all it holds, so the
    /// caller must hold all the user holds, as for setting the password.
    /// The link goes only to an address the user was shown to hold.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change the user's
    ///   sign-in, the user holds more than the caller, or the deployment has
    ///   no mail server, so the caller must set the password instead.
    /// - `AppError::NotFound` if the user doesn't exist.
    /// - `AppError::Conflict` when the user may not sign in, or their
    ///   address was never confirmed, so no link may go to it.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: SendResetLinkRequest,
    ) -> Result<(), AppError> {
        let SendResetLinkRequest { user_id, scope } = request;
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let records = self.ports.access_records.as_ref();
        let signing_in = AccountAction::ChangeSignIn;
        let control = account_control(records, &tenant, &authority, &user_id, signing_in).await?;
        control
            .ensure_allowed(&user_id, signing_in)
            .map_err(AppError::from_domain)?;
        let user = existing_user(self.ports.user_store.as_ref(), &tenant, &user_id).await?;
        let mailing = self.ports.mail.mailing(&self.policy)?;
        let Some((mut reset, raw)) = mailing.fresh(&user, ResetInitiator::Admin)? else {
            return Err(no_reset_for_this_account());
        };
        mailing.replace_links(&tenant, &reset).await?;
        let outgoing = OutgoingReset {
            to: reset.email(),
            locale: user.locale(),
            raw: &raw,
            scope: &scope,
        };
        mailing.mail(&tenant, outgoing).await;
        auditor
            .dispatch_by(&ctx.actor(), reset.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// The answer when an account may not sign in, or its address was never
/// confirmed, so no reset link can be sent for it.
fn no_reset_for_this_account() -> AppError {
    AppError::Conflict(message!(
        "identity-this-account-may-not-sign-in",
        "this account may not sign in, or its address was never confirmed"
    ))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::types::{HttpsUrl, Lifetime};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakeResetRequestStore;
    use crate::test_support::identity::{FakeUserStore, access_where_holds};
    use crate::test_support::{
        FakeEventDispatcher, FakeMailSetup, FakeMailer, block_on, test_auditor, test_ctx,
        test_link_scope,
    };

    struct Fixture {
        bob: UserId,
        resets: Arc<FakeResetRequestStore>,
        mailer: Arc<FakeMailer>,
        audit: Arc<FakeEventDispatcher>,
        ports: SendResetLinkPorts,
    }

    impl Fixture {
        fn new(users: impl FnOnce(UserId) -> FakeUserStore) -> Self {
            let bob = UserId::new();
            let resets = Arc::new(FakeResetRequestStore::empty());
            let mailer = Arc::new(FakeMailer::new());
            Self {
                ports: SendResetLinkPorts {
                    user_store: Arc::new(users(bob)),
                    mail: ResetMailPorts {
                        reset_store: resets.clone(),
                        mailer: mailer.clone(),
                        ..ResetMailPorts::fakes()
                    },
                    ..SendResetLinkPorts::fakes()
                },
                bob,
                resets,
                mailer,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn send(self) -> (Result<(), AppError>, Self) {
            let policy = ResetRequestPolicy {
                lifetime: Lifetime::seconds(3600).unwrap(),
                base_url: HttpsUrl::new("https://app.acme.test").unwrap(),
            };
            let use_case = SendResetLinkUseCase::new(policy, self.ports);
            let request = SendResetLinkRequest {
                user_id: self.bob,
                scope: test_link_scope(),
            };
            let result =
                block_on(use_case.execute(&test_ctx(), &test_auditor(self.audit.clone()), request));
            let fixture = Self {
                ports: use_case.ports,
                ..self
            };
            (result, fixture)
        }
    }

    fn bob_with_address(bob: UserId) -> FakeUserStore {
        FakeUserStore::with_user(bob, "bob@acme.test")
    }

    /// Bob forgot his password and called the help desk. Ann sends him a
    /// reset link; it goes to his address, and it is recorded.
    #[test]
    fn an_admin_mails_a_reset_link() {
        let (result, fixture) = Fixture::new(bob_with_address).send();

        result.unwrap();
        assert_eq!(fixture.resets.count(), 1);
        assert_eq!(fixture.mailer.recipients(), ["bob@acme.test"]);
        assert_eq!(
            fixture.audit.records.lock().unwrap().as_slice(),
            ["authentication.password_reset_requested"]
        );
    }

    /// Without mail setup, a reset-link request is refused with a message
    /// pointing to an administrator. No reset or outgoing mail is created.
    #[test]
    fn no_link_is_sent_where_nothing_is_mailed() {
        let mut fixture = Fixture::new(bob_with_address);
        fixture.ports.mail.mail = FakeMailSetup::not_set_up();

        let (result, fixture) = fixture.send();

        assert!(
            matches!(result, Err(AppError::Forbidden(why)) if why.as_str().contains("administrator"))
        );
        assert_eq!(fixture.mailer.count(), 0);
        assert_eq!(fixture.resets.count(), 0);
    }

    /// Bob never confirmed his address. No link may go to it.
    #[test]
    fn an_unconfirmed_address_gets_no_link() {
        let (result, fixture) =
            Fixture::new(|bob| FakeUserStore::with_unverified_user(bob, "bob@acme.test")).send();

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(fixture.mailer.count(), 0);
    }

    /// A caller with user-viewing rights cannot send Bob a reset link.
    /// The refusal creates neither a reset nor outgoing mail.
    #[test]
    fn a_caller_who_may_not_change_sign_in_is_refused() {
        let mut fixture = Fixture::new(bob_with_address);
        fixture.ports.tenant_authorities =
            Arc::new(FakeTenantAuthorities::holding(&[SystemPermission::Users(
                UserAction::View,
            )]));

        let (result, fixture) = fixture.send();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.mailer.count(), 0);
        assert_eq!(fixture.resets.count(), 0);
    }

    /// A caller with user-updating rights cannot request a reset link for
    /// Bob when Bob holds broader user-management rights.
    #[test]
    fn a_user_holding_more_than_the_caller_gets_no_link() {
        let mut fixture = Fixture::new(bob_with_address);
        fixture.ports.access_records =
            access_where_holds(fixture.bob, &[SystemPermission::ManageUsers]);
        fixture.ports.tenant_authorities =
            Arc::new(FakeTenantAuthorities::holding(&[SystemPermission::Users(
                UserAction::Update,
            )]));

        let (result, _) = fixture.send();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann names someone the tenant does not have. It is not found.
    #[test]
    fn an_unknown_user_is_not_found() {
        let (result, _) = Fixture::new(|_| FakeUserStore::empty()).send();

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller cannot request Bob's reset link and is refused
    /// as unauthenticated.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let mut fixture = Fixture::new(bob_with_address);
        fixture.ports.tenant_authorities =
            Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let (result, _) = fixture.send();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
