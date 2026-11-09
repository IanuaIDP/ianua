//! Send welcome: tell a user an admin made an account for them, and where
//! to sign in.
//!
//! An account let in at once is one its owner has never heard of. This is
//! the notice. It carries a sign-in link and no secret: the password is one
//! the admin relays, or the user takes the forgotten-password way from the
//! link.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
use ianua_domain::domains::branding::email_template::EmailTemplateType;
use ianua_domain::types::UserId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::use_case::Command;
use crate::use_cases::identity::invitations::welcome::mail::{Welcome, WelcomePorts, send_welcome};

/// The ports [`SendWelcomeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SendWelcomePorts {
    /// Where the mail reads its user and tenant from, and how it goes.
    pub welcome: WelcomePorts,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Who to welcome, and the pages the sign-in link opens.
pub struct SendWelcomeRequest {
    /// The user being welcomed.
    pub user_id: UserId,
    /// Where the sign-in link lands.
    pub scope: LinkScope,
}

/// Welcomes a user an admin just made an account for.
pub struct SendWelcomeUseCase {
    ports: SendWelcomePorts,
}

impl SendWelcomeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SendWelcomePorts) -> Self {
        Self { ports }
    }
}

impl Command for SendWelcomeUseCase {
    type Caller = CallerContext;
    type Input = SendWelcomeRequest;
    type Output = Result<(), AppError>;

    /// Mails `request.user_id` that their account exists and where to sign
    /// in, for a caller who may add users. Records
    /// `identity.welcome_email_sent` once the mail is accepted.
    ///
    /// A user who is gone, or a refused send, is no error: the account was
    /// made a moment ago, and failing here would fail what succeeded.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not add users.
    /// - `AppError::Internal` if the user lookup fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: SendWelcomeRequest,
    ) -> Result<(), AppError> {
        let SendWelcomeRequest { user_id, scope } = request;
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Users(UserAction::Create))
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let welcome = Welcome {
            user_id,
            scope: &scope,
            template: EmailTemplateType::Welcome,
        };
        let welcomed = send_welcome(&self.ports.welcome, &tenant, welcome).await?;
        auditor.dispatch(&welcomed).await.or_internal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{
        FakeEventDispatcher, FakeMailer, block_on, test_auditor, test_ctx, test_link_scope,
    };

    /// Bob, whose account Ann just made, and the stores that watch his
    /// welcome.
    struct Welcomed {
        bob: UserId,
        mailer: Arc<FakeMailer>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Welcomed {
        fn new() -> Self {
            Self {
                bob: UserId::new(),
                mailer: Arc::new(FakeMailer::new()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self, users: FakeUserStore) -> SendWelcomePorts {
            SendWelcomePorts {
                welcome: WelcomePorts {
                    user_store: Arc::new(users),
                    tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                    mailer: self.mailer.clone(),
                    ..WelcomePorts::fakes()
                },
                ..SendWelcomePorts::fakes()
            }
        }

        fn with_bob(&self) -> SendWelcomePorts {
            self.ports(FakeUserStore::with_user(self.bob, "bob@acme.com"))
        }

        fn welcome(&self, ports: SendWelcomePorts) -> Result<(), AppError> {
            block_on(SendWelcomeUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                SendWelcomeRequest {
                    user_id: self.bob,
                    scope: test_link_scope(),
                },
            ))
        }
    }

    /// Ann welcomes Bob. A sign-in link goes to his address and the welcome
    /// is recorded.
    #[test]
    fn a_welcome_goes_to_the_user() {
        let welcomed = Welcomed::new();

        welcomed.welcome(welcomed.with_bob()).unwrap();

        assert_eq!(welcomed.mailer.recipients(), ["bob@acme.com"]);
        assert_eq!(
            welcomed.sink.records.lock().unwrap().as_slice(),
            ["identity.welcome_email_sent"]
        );
    }

    /// Bob is gone. Nothing is sent and nothing fails.
    #[test]
    fn a_missing_user_is_no_error() {
        let welcomed = Welcomed::new();

        welcomed
            .welcome(welcomed.ports(FakeUserStore::empty()))
            .unwrap();

        assert_eq!(welcomed.mailer.count(), 0);
        assert!(welcomed.sink.records.lock().unwrap().is_empty());
    }

    /// The mail service refuses the welcome. Nothing fails and nothing is
    /// recorded.
    #[test]
    fn a_refused_mail_is_no_error() {
        let welcomed = Welcomed::new();
        let mut ports = welcomed.with_bob();
        ports.welcome.mailer = Arc::new(FakeMailer::refusing());

        welcomed.welcome(ports).unwrap();

        assert!(welcomed.sink.records.lock().unwrap().is_empty());
    }

    /// A caller without user-creation rights cannot send Bob a welcome.
    /// No mail is sent.
    #[test]
    fn a_caller_who_may_not_add_users_is_refused() {
        let welcomed = Welcomed::new();
        let ports = SendWelcomePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..welcomed.with_bob()
        };

        let result = welcomed.welcome(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(welcomed.mailer.count(), 0);
    }

    /// A signed-out caller cannot send Bob a welcome.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let welcomed = Welcomed::new();
        let ports = SendWelcomePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..welcomed.with_bob()
        };

        let result = welcomed.welcome(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
