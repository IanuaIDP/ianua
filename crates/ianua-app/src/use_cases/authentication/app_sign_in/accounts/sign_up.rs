//! Creating an account at an app's address.

use std::sync::Arc;

use ianua_domain::types::{DisplayName, Email};

use crate::auditor::RequestAuditor;
use crate::email::LinkScope;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::authentication::app_sign_in::relay::common::AppSignInCommon;
use crate::use_cases::authentication::app_sign_in::{AppSignInContext, AppSignInOutcome};
use crate::use_cases::identity::users::{SignUp, SignUpRequest, SignUpUseCase};

/// A sign-up. Holds the password, so it has no `Debug`.
pub struct AppSignUpRequest {
    /// The address it signs in with.
    pub email: Email,
    /// The name shown for it.
    pub display_name: DisplayName,
    /// The password chosen.
    pub password: String,
}

/// Creates an account at an app's address; the dashboard's sign-up mails
/// its verification link, which leads back to the app.
pub struct AppSignUpUseCase {
    common: Arc<AppSignInCommon>,
    sign_up: Arc<SignUpUseCase>,
}

impl AppSignUpUseCase {
    /// A use case creating accounts through the dashboard's own `sign_up`.
    pub(in crate::use_cases::authentication::app_sign_in) fn new(
        common: Arc<AppSignInCommon>,
        sign_up: Arc<SignUpUseCase>,
    ) -> Self {
        Self { common, sign_up }
    }
}

impl Command for AppSignUpUseCase {
    type Caller = AppSignInContext;
    type Input = AppSignUpRequest;
    type Output = Result<AppSignInOutcome, AppError>;

    /// Creates the account through the dashboard's own sign-up, whose
    /// verification link leads back to the app. Answers `Accepted` whether
    /// or not the address was new, so it cannot be used to find accounts.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the app has no sign-in here.
    /// - `AppError::Forbidden` if the tenant has sign-up off or is at its
    ///   user limit.
    /// - `AppError::Domain` if the tenant's policy refuses the password.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &AppSignInContext,
        auditor: &RequestAuditor,
        request: AppSignUpRequest,
    ) -> Result<AppSignInOutcome, AppError> {
        let (target, auditor) = self.common.resolved(ctx, auditor).await?;
        let AppSignUpRequest {
            email,
            display_name,
            password,
        } = request;
        let sign_up = SignUpRequest {
            person: SignUp {
                email,
                display_name,
                password,
            },
            limits: target.org.limits(),
            scope: LinkScope::app(&target.sign_in, target.host.clone()),
        };
        self.sign_up.execute(&ctx.tenant, &auditor, sign_up).await?;
        Ok(AppSignInOutcome::Accepted)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::tenant::access::auth_config::{
        SelfRegistration, TenantAuthSettings,
    };
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::HttpsUrl;

    use super::*;
    use crate::test_support::authentication::{
        SHOP_HOST, app_sign_in_lifetimes, app_sign_in_services, app_sign_in_target_ports,
        cross_host_ctx, shop_with_app_sign_in,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::tenant::tenant_store_signing_in_with;
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor,
    };
    use crate::use_cases::authentication::app_sign_in::SignInPorts;
    use crate::use_cases::identity::users::SignUpPorts;

    fn sign_up_with(
        ports: SignUpPorts,
    ) -> (Result<AppSignInOutcome, AppError>, Arc<FakeUserStore>) {
        let shop = shop_with_app_sign_in();
        let shop_id = *shop.id();
        let users = Arc::new(FakeUserStore::empty());
        let app_ports = SignInPorts {
            target: app_sign_in_target_ports(app_sign_in_services([shop])),
            ..SignInPorts::fakes()
        };
        let base = HttpsUrl::new("https://ianua.example.com").unwrap();
        let common = AppSignInCommon::new(app_ports, base, app_sign_in_lifetimes());
        let sign_up = SignUpUseCase::new(SignUpPorts {
            user_store: users.clone(),
            tenant_store: tenant_store_signing_in_with(TenantAuthSettings {
                self_registration: SelfRegistration::Open,
                enabled_methods: vec![AuthMethod::Password],
                ..TenantAuthSettings::default()
            }),
            ..ports
        });
        let use_case = AppSignUpUseCase::new(Arc::new(common), Arc::new(sign_up));
        let request = AppSignUpRequest {
            email: Email::new("ann@acme.test").unwrap(),
            display_name: DisplayName::new("Ann", &DomainLimits::default().display_name).unwrap(),
            password: "Signing 1 Up 2 Today".to_owned(),
        };
        let ctx = cross_host_ctx(shop_id, SHOP_HOST);
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        (block_on(use_case.execute(&ctx, &auditor, request)), users)
    }

    /// Ann signs up on the shop of a workspace that takes sign-ups. Her
    /// account is created and she is told to check her mail.
    #[test]
    fn a_sign_up_creates_the_account() {
        let (outcome, users) = sign_up_with(SignUpPorts::fakes());

        assert!(matches!(outcome, Ok(AppSignInOutcome::Accepted)));
        assert_eq!(users.count(), 1);
    }

    /// A workspace at its user limit refuses Ann's shop sign-up and creates
    /// no account.
    #[test]
    fn a_sign_up_past_the_user_limit_is_refused() {
        let (outcome, users) = sign_up_with(SignUpPorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..SignUpPorts::fakes()
        });

        assert!(matches!(outcome, Err(AppError::Forbidden(_))));
        assert_eq!(users.count(), 0);
    }
}
