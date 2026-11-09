//! The account held with a certificate authority: read back when one was
//! registered before, registered and kept when not.
//!
//! Authorities rate-limit registration, so the credentials are kept and
//! reused. A process registering afresh on every start would work until it
//! restarted often enough to be refused.

use std::sync::Arc;
use std::time::Duration;

use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::Email;
use instant_acme::{Account, AccountCredentials, NewAccount};

use crate::tls::seams::{AcmeAccountStore, AcmeDirectory};
use crate::tls::transport::AuthorityHttpClient;

/// The account kept with one authority.
pub(crate) struct AuthorityAccounts {
    /// The authority's directory.
    pub(crate) directory: AcmeDirectory,
    /// Where the authority writes about expiry and revocation, if anyone.
    pub(crate) contact: Option<Email>,
    /// Where the credentials are kept.
    pub(crate) store: Arc<dyn AcmeAccountStore>,
    /// How long each call to the authority may take.
    pub(crate) call_timeout: Duration,
}

impl AuthorityAccounts {
    /// The account, read back or registered now.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the credentials cannot be
    /// read, the authority cannot be reached or refuses, or a new account
    /// cannot be kept. Kept credentials that do not parse are reported
    /// without the parser's message, which may quote the key.
    pub(crate) async fn account(&self) -> Result<Account, DomainError> {
        let Some(kept) = self.store.load(&self.directory).await? else {
            return self.registered().await;
        };
        let credentials: AccountCredentials = serde_json::from_str(kept.expose())
            .map_err(|_| DomainError::infra_msg("the kept ACME account could not be read"))?;
        Account::builder_with_http(self.transport()?)
            .from_credentials(credentials)
            .await
            .map_err(DomainError::infra)
    }

    /// A new account, registered with the authority and kept.
    async fn registered(&self) -> Result<Account, DomainError> {
        let contact = self
            .contact
            .as_ref()
            .map(|email| format!("mailto:{}", email.as_str()));
        let contacts: Vec<&str> = contact.as_deref().into_iter().collect();
        let (account, credentials) = Account::builder_with_http(self.transport()?)
            .create(
                &NewAccount {
                    contact: &contacts,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.directory.as_str().to_owned(),
                None,
            )
            .await
            .map_err(DomainError::infra)?;
        let kept = Secret::new(serde_json::to_string(&credentials).map_err(DomainError::infra)?);
        self.store.save(&self.directory, &kept).await?;
        tracing::info!(
            directory = self.directory.as_str(),
            "registered an account with the certificate authority"
        );
        Ok(account)
    }

    /// The way out to the authority, each call held to the call timeout.
    fn transport(&self) -> Result<Box<AuthorityHttpClient>, DomainError> {
        AuthorityHttpClient::new(self.call_timeout).map(Box::new)
    }
}
