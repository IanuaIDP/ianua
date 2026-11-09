//! Asking an installed integration about the grant an account holds, and
//! exchanging it ahead of a call.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::authentication::{SealedAt, SecretEncryptor};
use ianua_app::ports::workflows::{GrantExchanger, Renewal};
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::shared::security::secret::Secret;
use ianua_integration::Renewed;
use ianua_integration::answer::{failed, turned_away};

use crate::integrations::installed::Installed;

/// Exchanges accounts' grants through the installed integrations.
pub struct InstalledGrantExchanger {
    installed: Arc<Installed>,
    encryptor: Arc<dyn SecretEncryptor>,
    limit: Duration,
}

impl InstalledGrantExchanger {
    /// An exchanger through `installed`, opening and sealing credentials
    /// with `encryptor`, giving up on an exchange after `limit`.
    #[must_use]
    pub fn new(
        installed: Arc<Installed>,
        encryptor: Arc<dyn SecretEncryptor>,
        limit: Duration,
    ) -> Self {
        Self {
            installed,
            encryptor,
            limit,
        }
    }

    /// `sealed`, opened for the account it was sealed for. The sealer's
    /// error is dropped, so nothing of the credential is passed on.
    async fn opened(&self, sealed: &SealedAt) -> Option<Secret> {
        let bytes = self
            .encryptor
            .decrypt(&sealed.secret, &sealed.place)
            .await
            .ok()?;
        String::from_utf8(bytes).ok().map(Secret::new)
    }

    /// `renewed`, sealed where `read` was.
    async fn sealed(&self, renewed: Renewed, read: &SealedAt) -> Result<Renewal, ActionOutcome> {
        let Renewed::To(replacement) = renewed else {
            return Ok(Renewal::Unchanged);
        };
        let sealing = self
            .encryptor
            .encrypt(replacement.expose().as_bytes(), &read.place)
            .await;
        match sealing {
            Ok(sealed) => Ok(Renewal::Renewed(sealed)),
            Err(error) => {
                tracing::error!(%error, "a renewed grant could not be sealed");
                Err(turned_away(
                    "the account's renewed sign-in could not be kept",
                ))
            }
        }
    }
}

#[async_trait]
impl GrantExchanger for InstalledGrantExchanger {
    async fn is_due(&self, integration: &IntegrationKey, credential: &SealedAt) -> bool {
        let Some(found) = self.installed.find(integration) else {
            return false;
        };
        let Some(opened) = self.opened(credential).await else {
            return false;
        };
        found.grant_due(&opened)
    }

    async fn exchange(
        &self,
        integration: &IntegrationKey,
        credential: &SealedAt,
    ) -> Result<Renewal, ActionOutcome> {
        let Some(found) = self.installed.find(integration) else {
            return Err(failed("the integration is not installed"));
        };
        let Some(opened) = self.opened(credential).await else {
            return Err(failed("the account's credential could not be opened"));
        };
        let Ok(renewed) = tokio::time::timeout(self.limit, found.renew_grant(&opened)).await else {
            return Err(turned_away(
                "the service's token address did not answer in time",
            ));
        };
        self.sealed(renewed?, credential).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ianua_app::ports::authentication::{SealOwner, SealedField, SealedFor};
    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::domains::workflows::execution::ActionCall;
    use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
    use ianua_domain::domains::workflows::integration::guide::OperationGuide;
    use ianua_domain::domains::workflows::integration::profile::IntegrationProfile;
    use ianua_domain::domains::workflows::integration::{AccountNeed, OperationSpec};
    use ianua_domain::types::IntegrationAccountId;
    use ianua_integration::{Called, Integration};

    use super::*;
    use crate::crypto::{AesGcmSecretEncryptor, SealingKey};
    use crate::integrations::installed::tests::{guide_of, profile_of, spec};

    /// An integration holding a rotating grant: due until it holds the new
    /// one, or refusing it.
    struct Rotating {
        profile: IntegrationProfile,
        operations: Vec<OperationSpec>,
        guides: Vec<OperationGuide>,
        answer: Result<&'static str, ActionOutcome>,
        exchanges: AtomicUsize,
    }

    #[async_trait]
    impl Integration for Rotating {
        fn profile(&self) -> &IntegrationProfile {
            &self.profile
        }

        fn operations(&self) -> &[OperationSpec] {
            &self.operations
        }

        fn guides(&self) -> &[OperationGuide] {
            &self.guides
        }

        async fn check_account(&self, _credential: &Secret) -> AccountCheck {
            AccountCheck::NotCheckable
        }

        async fn call(&self, _call: &ActionCall, _credential: Option<&Secret>) -> Called {
            failed("not called here").into()
        }

        fn grant_due(&self, credential: &Secret) -> bool {
            credential.expose() != "the new grant"
        }

        async fn renew_grant(&self, _credential: &Secret) -> Result<Renewed, ActionOutcome> {
            self.exchanges.fetch_add(1, Ordering::SeqCst);
            self.answer
                .clone()
                .map(|renewed| Renewed::To(Secret::new(renewed.to_owned())))
        }
    }

    fn rotating(answer: Result<&'static str, ActionOutcome>) -> Arc<Rotating> {
        let operations = vec![spec("jira", "get-issue", AccountNeed::Account)];
        Arc::new(Rotating {
            profile: profile_of("jira"),
            guides: operations.iter().map(guide_of).collect(),
            operations,
            answer,
            exchanges: AtomicUsize::new(0),
        })
    }

    fn sealer() -> Arc<AesGcmSecretEncryptor> {
        Arc::new(AesGcmSecretEncryptor::new(
            SealingKey::new("k1", [7; 32]).unwrap(),
            Vec::new(),
        ))
    }

    fn tenant() -> ScopedTenant {
        crate::test_support::rows::authorization::tenant()
    }

    async fn sealed(credential: &[u8]) -> SealedAt {
        let place = SealedFor::new(
            SealOwner::from(&tenant()),
            SealedField::IntegrationCredential,
            IntegrationAccountId::new(),
        );
        SealedAt {
            secret: sealer().encrypt(credential, &place).await.unwrap(),
            place,
        }
    }

    fn exchanger(integration: Arc<Rotating>) -> InstalledGrantExchanger {
        let installed = Installed::new(vec![integration as Arc<dyn Integration>]).unwrap();
        InstalledGrantExchanger::new(Arc::new(installed), sealer(), Duration::from_secs(5))
    }

    fn jira() -> IntegrationKey {
        IntegrationKey::new("jira").unwrap()
    }

    /// Jira issues a new grant. It comes back sealed for the same account,
    /// and is no longer due once opened there.
    #[tokio::test]
    async fn an_exchanged_grant_is_sealed_for_its_account() {
        let exchanger = exchanger(rotating(Ok("the new grant")));
        let held = sealed(b"the old grant").await;

        assert!(exchanger.is_due(&jira(), &held).await);
        let Renewal::Renewed(renewed) = exchanger.exchange(&jira(), &held).await.unwrap() else {
            panic!("the new grant was not kept");
        };

        let kept = SealedAt {
            secret: renewed,
            place: held.place.clone(),
        };
        assert!(!exchanger.is_due(&jira(), &kept).await);
    }

    /// A service refusing the grant is told as it was, and nothing comes
    /// back to keep.
    #[tokio::test]
    async fn a_refused_grant_stays_refused() {
        let integration = rotating(Err(failed("the grant was revoked")));
        let exchanger = exchanger(integration);
        let held = sealed(b"the old grant").await;

        let refused = exchanger.exchange(&jira(), &held).await.unwrap_err();

        assert!(matches!(refused, ActionOutcome::Failed(_)));
    }

    /// A credential that does not open is not due: the call itself says
    /// why, and no grant is sent anywhere.
    #[tokio::test]
    async fn a_credential_that_does_not_open_is_not_due() {
        let integration = rotating(Ok("the new grant"));
        let exchanger = exchanger(Arc::clone(&integration));
        let mut held = sealed(b"the old grant").await;
        held.place = SealedFor::new(
            SealOwner::from(&tenant()),
            SealedField::IntegrationCredential,
            IntegrationAccountId::new(),
        );

        assert!(!exchanger.is_due(&jira(), &held).await);
        assert_eq!(integration.exchanges.load(Ordering::SeqCst), 0);
    }
}
