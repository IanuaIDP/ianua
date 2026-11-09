//! Confirming an address from the link an app sign-up mailed.

use std::sync::Arc;

use ianua_domain::shared::security::secret::Secret;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::authentication::app_sign_in::relay::common::AppSignInCommon;
use crate::use_cases::authentication::app_sign_in::{AppSignInContext, AppSignInOutcome};
use crate::use_cases::identity::email::VerifyUseCase;

/// Confirms an address at an app's address from the link mailed to it.
pub struct AppVerifyEmailUseCase {
    common: Arc<AppSignInCommon>,
    verify_email: Arc<VerifyUseCase>,
}

impl AppVerifyEmailUseCase {
    /// A use case confirming addresses through the dashboard's own
    /// `verify_email`.
    pub(in crate::use_cases::authentication::app_sign_in) fn new(
        common: Arc<AppSignInCommon>,
        verify_email: Arc<VerifyUseCase>,
    ) -> Self {
        Self {
            common,
            verify_email,
        }
    }
}

impl Command for AppVerifyEmailUseCase {
    type Caller = AppSignInContext;
    type Input = Secret;
    type Output = Result<AppSignInOutcome, AppError>;

    /// Confirms the address the link's `token` was mailed to, through the
    /// dashboard's own verification.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the app has no sign-in here, or the token is
    ///   unknown or already used.
    /// - `AppError::LinkExpired` if the link ran out.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        ctx: &AppSignInContext,
        auditor: &RequestAuditor,
        token: Secret,
    ) -> Result<AppSignInOutcome, AppError> {
        let (_, auditor) = self.common.resolved(ctx, auditor).await?;
        self.verify_email
            .execute(&ctx.tenant, &auditor, token.expose().to_owned())
            .await?;
        Ok(AppSignInOutcome::Accepted)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{HttpsUrl, ServiceId};

    use super::*;
    use crate::test_support::authentication::{
        SHOP_HOST, app_sign_in_lifetimes, app_sign_in_services, app_sign_in_target_ports,
        cross_host_ctx, shop_with_app_sign_in,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::authentication::app_sign_in::SignInPorts;
    use crate::use_cases::identity::email::VerifyPorts;

    fn verify(
        service_of: impl FnOnce(ServiceId) -> ServiceId,
    ) -> Result<AppSignInOutcome, AppError> {
        let shop = shop_with_app_sign_in();
        let shown_for = service_of(*shop.id());
        let ports = SignInPorts {
            target: app_sign_in_target_ports(app_sign_in_services([shop])),
            ..SignInPorts::fakes()
        };
        let base = HttpsUrl::new("https://ianua.example.com").unwrap();
        let common = AppSignInCommon::new(ports, base, app_sign_in_lifetimes());
        let verify_email = VerifyUseCase::new(VerifyPorts::fakes());
        let use_case = AppVerifyEmailUseCase::new(Arc::new(common), Arc::new(verify_email));
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        let ctx = cross_host_ctx(shown_for, SHOP_HOST);
        block_on(use_case.execute(&ctx, &auditor, Secret::new("unknown-link")))
    }

    /// A made-up confirmation link on the shop returns not found.
    #[test]
    fn an_unknown_link_confirms_nothing() {
        assert!(matches!(verify(|shop| shop), Err(AppError::NotFound(_))));
    }

    /// Following a link for an unknown service returns not found on the
    /// shop's host.
    #[test]
    fn a_service_without_sign_in_here_confirms_nothing() {
        assert!(matches!(
            verify(|_| ServiceId::new()),
            Err(AppError::NotFound(_))
        ));
    }
}
