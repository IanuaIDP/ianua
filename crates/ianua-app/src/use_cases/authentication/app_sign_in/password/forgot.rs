//! Asking for a link to set a new password at an app's address.

use std::sync::Arc;

use ianua_domain::types::Email;

use crate::auditor::RequestAuditor;
use crate::email::LinkScope;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::authentication::app_sign_in::relay::common::AppSignInCommon;
use crate::use_cases::authentication::app_sign_in::{AppSignInContext, AppSignInOutcome};
use crate::use_cases::authentication::password::{ResetMailRequest, ResetRequestUseCase};

/// Mails a reset link at an app's address; the link leads back to the app's
/// own reset address.
pub struct AppForgotPasswordUseCase {
    common: Arc<AppSignInCommon>,
    reset_request: Arc<ResetRequestUseCase>,
}

impl AppForgotPasswordUseCase {
    /// A use case mailing links through the dashboard's own
    /// `reset_request`.
    pub(in crate::use_cases::authentication::app_sign_in) fn new(
        common: Arc<AppSignInCommon>,
        reset_request: Arc<ResetRequestUseCase>,
    ) -> Self {
        Self {
            common,
            reset_request,
        }
    }
}

impl Command for AppForgotPasswordUseCase {
    type Caller = AppSignInContext;
    type Input = Email;
    type Output = Result<AppSignInOutcome, AppError>;

    /// Mails a reset link to `email` through the dashboard's own reset,
    /// when an account that may get one has it. Answers `Accepted` either
    /// way, so it tells nobody which addresses have accounts; the API holds
    /// the answer to the same time floor as the dashboard's reset request.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the app has no sign-in here.
    /// - `AppError::Forbidden` on a deployment with no mail server, for
    ///   every address alike, saying an administrator must reset it.
    /// - `AppError::Domain` if the configured link lifetime is too long.
    /// - `AppError::Internal` on persistence or token failure.
    async fn execute(
        &self,
        ctx: &AppSignInContext,
        auditor: &RequestAuditor,
        email: Email,
    ) -> Result<AppSignInOutcome, AppError> {
        let (target, auditor) = self.common.resolved(ctx, auditor).await?;
        let request = ResetMailRequest {
            email,
            scope: LinkScope::app(&target.sign_in, target.host.clone()),
        };
        self.reset_request
            .execute(&ctx.tenant, &auditor, request)
            .await?;
        Ok(AppSignInOutcome::Accepted)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{HttpsUrl, Lifetime, ServiceId, UserId};

    use super::*;
    use crate::ports::shared::MailSetup;
    use crate::services::authentication::reset_mail::{ResetMailPorts, ResetRequestPolicy};
    use crate::test_support::authentication::{
        FakeResetRequestStore, SHOP_HOST, app_sign_in_lifetimes, app_sign_in_services,
        app_sign_in_target_ports, cross_host_ctx, shop_with_app_sign_in,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{
        Fake, FakeEventDispatcher, FakeMailSetup, FakeMailer, block_on, test_auditor,
    };
    use crate::use_cases::authentication::app_sign_in::SignInPorts;
    use crate::use_cases::authentication::password::ResetRequestPorts;

    const BOB: &str = "bob@acme.test";

    /// The shop, Bob's account, and what was mailed and recorded.
    struct Fixture {
        use_case: AppForgotPasswordUseCase,
        shop: ServiceId,
        mailer: Arc<FakeMailer>,
        resets: Arc<FakeResetRequestStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    /// The shop signing people in on [`SHOP_HOST`], over a workspace where
    /// Bob has an account.
    fn fixture() -> Fixture {
        fixture_reaching(Fake::fake())
    }

    /// As [`fixture`], on a deployment whose mail is set up as `mail` says.
    fn fixture_reaching(mail: Arc<dyn MailSetup>) -> Fixture {
        let shop = shop_with_app_sign_in();
        let shop_id = *shop.id();
        let mailer = Arc::new(FakeMailer::new());
        let resets = Arc::new(FakeResetRequestStore::empty());
        let reset_request = reset_request(mail, &resets, &mailer);
        let ports = SignInPorts {
            target: app_sign_in_target_ports(app_sign_in_services([shop])),
            ..SignInPorts::fakes()
        };
        let base = HttpsUrl::new("https://ianua.example.com").unwrap();
        let common = AppSignInCommon::new(ports, base, app_sign_in_lifetimes());
        Fixture {
            use_case: AppForgotPasswordUseCase::new(Arc::new(common), Arc::new(reset_request)),
            shop: shop_id,
            mailer,
            resets,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    /// Bob can request a fifteen-minute link through the fixture's mail setup.
    fn reset_request(
        mail: Arc<dyn MailSetup>,
        resets: &Arc<FakeResetRequestStore>,
        mailer: &Arc<FakeMailer>,
    ) -> ResetRequestUseCase {
        ResetRequestUseCase::new(
            ResetRequestPolicy {
                lifetime: Lifetime::seconds(900).unwrap(),
                base_url: HttpsUrl::new("https://ianua.example.com").unwrap(),
            },
            ResetRequestPorts {
                user_store: Arc::new(FakeUserStore::with_user(UserId::new(), BOB)),
                mail: ResetMailPorts {
                    reset_store: resets.clone(),
                    mailer: mailer.clone(),
                    mail,
                    ..ResetMailPorts::fakes()
                },
                ..ResetRequestPorts::fakes()
            },
        )
    }

    /// `email` asks the shop, or `service`, for a reset link.
    fn ask(f: &Fixture, service: ServiceId, email: &str) -> Result<AppSignInOutcome, AppError> {
        block_on(f.use_case.execute(
            &cross_host_ctx(service, SHOP_HOST),
            &test_auditor(f.audit.clone()),
            Email::new(email).unwrap(),
        ))
    }

    /// Bob forgot his password on the shop. A reset link is mailed to him,
    /// leading to the shop's own reset address.
    #[test]
    fn a_known_address_gets_a_link_to_the_apps_reset_address() {
        let f = fixture();

        let outcome = ask(&f, f.shop, BOB).unwrap();

        assert!(matches!(outcome, AppSignInOutcome::Accepted));
        assert!(
            f.mailer
                .action_url()
                .starts_with("https://shop.example.com/.ianua/reset-password?token=")
        );
        assert_eq!(f.resets.count(), 1);
    }

    /// An unknown address receives an accepted response without sending
    /// mail, storing a reset, or recording an audit event.
    #[test]
    fn an_unknown_address_answers_the_same_and_mails_nothing() {
        let f = fixture();

        let outcome = ask(&f, f.shop, "nobody@acme.test").unwrap();

        assert!(matches!(outcome, AppSignInOutcome::Accepted));
        assert_eq!(f.mailer.count(), 0);
        assert_eq!(f.resets.count(), 0);
        assert!(f.audit.all_payloads().is_empty());
    }

    /// Without a mail server, Bob's reset request is refused with an
    /// administrator instruction. No reset is stored and no mail is sent.
    #[test]
    fn no_link_is_sent_where_nothing_is_mailed() {
        let f = fixture_reaching(FakeMailSetup::not_set_up());

        let outcome = ask(&f, f.shop, BOB);

        assert!(
            matches!(outcome, Err(AppError::Forbidden(why)) if why.as_str().contains("administrator"))
        );
        assert_eq!(f.mailer.count(), 0);
        assert_eq!(f.resets.count(), 0);
    }

    /// A reset-link request for an unknown service returns not found and
    /// sends no mail.
    #[test]
    fn a_service_without_app_sign_in_here_is_not_found() {
        let f = fixture();

        let outcome = ask(&f, ServiceId::new(), BOB);

        assert!(matches!(outcome, Err(AppError::NotFound(_))));
        assert_eq!(f.mailer.count(), 0);
    }
}
