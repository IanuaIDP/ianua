//! Asking an installed integration whether an account's credential works.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::workflows::{AccountVerifier, CredentialCheck};
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
use ianua_domain::shared::security::secret::Secret;
use ianua_integration::Renewed;

use crate::http::client::LONGEST_CALL;
use crate::integrations::installed::Installed;

/// Asks the installed integrations about credentials.
///
/// Each question is held to a time limit; an integration that does not
/// answer in time, or is not installed, has vouched for nothing, so the
/// answer is [`AccountCheck::Unreachable`].
pub struct InstalledAccountVerifier {
    installed: Arc<Installed>,
    limit: Duration,
}

impl InstalledAccountVerifier {
    /// A verifier asking through `installed`, giving up after `limit`, at
    /// most [`LONGEST_CALL`].
    #[must_use]
    pub fn new(installed: Arc<Installed>, limit: Duration) -> Self {
        Self {
            installed,
            limit: limit.min(LONGEST_CALL),
        }
    }
}

#[async_trait]
impl AccountVerifier for InstalledAccountVerifier {
    async fn check(&self, integration: &IntegrationKey, credential: &Secret) -> CredentialCheck {
        let unreachable = || CredentialCheck {
            verdict: AccountCheck::Unreachable,
            replaced_by: None,
        };
        let Some(installed) = self.installed.find(integration) else {
            return unreachable();
        };
        let Ok(checked) = tokio::time::timeout(self.limit, installed.checked(credential)).await
        else {
            return unreachable();
        };
        CredentialCheck {
            verdict: checked.verdict,
            replaced_by: match checked.renewed {
                Renewed::To(replacement) => Some(replacement),
                Renewed::Unchanged => None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::execution::ActionCall;
    use ianua_domain::domains::workflows::execution::step::ActionOutcome;
    use ianua_domain::domains::workflows::integration::OperationSpec;
    use ianua_domain::domains::workflows::integration::guide::OperationGuide;
    use ianua_domain::domains::workflows::integration::profile::IntegrationProfile;
    use ianua_domain::types::UntrustedText;
    use ianua_integration::{Called, Integration};

    use super::*;
    use crate::integrations::installed::tests::profile_of;

    /// An integration answering every check with `answer` after `delay`.
    struct Answering {
        profile: IntegrationProfile,
        answer: AccountCheck,
        delay: Duration,
    }

    #[async_trait]
    impl Integration for Answering {
        fn profile(&self) -> &IntegrationProfile {
            &self.profile
        }

        fn operations(&self) -> &[OperationSpec] {
            &[]
        }

        fn guides(&self) -> &[OperationGuide] {
            &[]
        }

        async fn check_account(&self, _credential: &Secret) -> AccountCheck {
            tokio::time::sleep(self.delay).await;
            self.answer.clone()
        }

        async fn call(&self, _call: &ActionCall, _credential: Option<&Secret>) -> Called {
            ActionOutcome::Failed(UntrustedText::record("not called")).into()
        }
    }

    fn verifier(answer: AccountCheck, delay: Duration) -> InstalledAccountVerifier {
        let chat = Answering {
            profile: profile_of("chat"),
            answer,
            delay,
        };
        let installed = Installed::new(vec![Arc::new(chat)]).unwrap();
        InstalledAccountVerifier::new(Arc::new(installed), Duration::from_millis(100))
    }

    fn chat() -> IntegrationKey {
        IntegrationKey::new("chat").unwrap()
    }

    /// The integration's own answer is passed on.
    #[tokio::test]
    async fn the_integrations_answer_is_passed_on() {
        let refused = AccountCheck::Refused(UntrustedText::record("revoked"));
        let verifier = verifier(refused.clone(), Duration::ZERO);

        let answer = verifier.check(&chat(), &Secret::new("token")).await;

        assert_eq!(answer.verdict, refused);
    }

    /// An acceptance delayed beyond the check's timeout yields an unreachable
    /// verdict.
    #[tokio::test]
    async fn a_check_past_its_limit_is_unreachable() {
        let verifier = verifier(AccountCheck::Accepted, Duration::from_secs(5));

        let answer = verifier.check(&chat(), &Secret::new("token")).await;

        assert_eq!(answer.verdict, AccountCheck::Unreachable);
    }

    /// Checking a credential against an uninstalled integration yields an
    /// unreachable verdict.
    #[tokio::test]
    async fn an_integration_not_installed_is_unreachable() {
        let verifier = verifier(AccountCheck::Accepted, Duration::ZERO);

        let answer = verifier
            .check(&IntegrationKey::new("mail").unwrap(), &Secret::new("token"))
            .await;

        assert_eq!(answer.verdict, AccountCheck::Unreachable);
    }
}
