//! Send activation welcome: tell a user who just finished joining, by
//! confirming their address or accepting an invitation, that it worked.

use ianua_domain::domains::branding::email_template::EmailTemplateType;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::invitations::SendWelcomeRequest;
use crate::use_cases::identity::invitations::welcome::mail::{Welcome, WelcomePorts, send_welcome};

/// Welcomes a user who has just become active.
pub struct SendActivationWelcomeUseCase {
    ports: WelcomePorts,
}

impl SendActivationWelcomeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: WelcomePorts) -> Self {
        Self { ports }
    }
}

impl Command for SendActivationWelcomeUseCase {
    type Caller = ScopedTenant;
    type Input = SendWelcomeRequest;
    type Output = Result<(), AppError>;

    /// Tells `request.user_id`, who did the last step themselves, that their
    /// account is ready. Records `identity.welcome_email_sent` once the mail
    /// is accepted.
    ///
    /// It follows the person's own step, which the composing flow has just
    /// checked, so it needs no caller of its own.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` if the user lookup fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: SendWelcomeRequest,
    ) -> Result<(), AppError> {
        let SendWelcomeRequest { user_id, scope } = request;
        let welcome = Welcome {
            user_id,
            scope: &scope,
            template: EmailTemplateType::ActivationWelcome,
        };
        let welcomed = send_welcome(&self.ports, tenant, welcome).await?;
        auditor.dispatch(&welcomed).await.or_internal()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{
        FakeEventDispatcher, FakeMailer, block_on, test_auditor, test_ctx, test_link_scope,
    };

    fn welcome(
        users: FakeUserStore,
        bob: UserId,
        mailer: &Arc<FakeMailer>,
        sink: &Arc<FakeEventDispatcher>,
    ) {
        let ports = WelcomePorts {
            user_store: Arc::new(users),
            mailer: mailer.clone(),
            ..WelcomePorts::fakes()
        };
        block_on(SendActivationWelcomeUseCase::new(ports).execute(
            &test_ctx().tenant(),
            &test_auditor(sink.clone()),
            SendWelcomeRequest {
                user_id: bob,
                scope: test_link_scope(),
            },
        ))
        .unwrap();
    }

    /// Bob just confirmed his address. A welcome message for his ready account
    /// goes to him, and it is recorded.
    #[test]
    fn a_newly_active_user_is_welcomed() {
        let bob = UserId::new();
        let mailer = Arc::new(FakeMailer::new());
        let sink = Arc::new(FakeEventDispatcher::new());

        welcome(
            FakeUserStore::with_user(bob, "bob@acme.com"),
            bob,
            &mailer,
            &sink,
        );

        assert_eq!(mailer.recipients(), ["bob@acme.com"]);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["identity.welcome_email_sent"]
        );
    }

    /// Bob is gone. Nothing is sent and nothing fails.
    #[test]
    fn a_missing_user_is_no_error() {
        let mailer = Arc::new(FakeMailer::new());
        let sink = Arc::new(FakeEventDispatcher::new());

        welcome(FakeUserStore::empty(), UserId::new(), &mailer, &sink);

        assert_eq!(mailer.count(), 0);
        assert!(sink.records.lock().unwrap().is_empty());
    }
}
