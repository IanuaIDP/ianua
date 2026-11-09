//! ACME challenges a certificate authority reads.

use async_trait::async_trait;
use ianua_domain::domains::tenant::custom_domains::acme_challenge::{
    AcmeChallenge, ChallengeToken,
};
use ianua_domain::shared::errors::DomainError;

/// Dyn-safe port for the HTTP-01 challenges a certificate authority reads.
///
/// Two processes share this. The control plane publishes a challenge while
/// talking to the authority; the proxy, the only thing answering on the
/// domain, reads it when the authority comes knocking. Neither knows about
/// the other, only about this.
#[async_trait]
pub trait AcmeChallengeStore: Send + Sync {
    /// Publishes a challenge, replacing any earlier one for the same token.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn publish(&self, challenge: &AcmeChallenge) -> Result<(), DomainError>;

    /// Finds the challenge a token names, if one is outstanding.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find(&self, token: &ChallengeToken) -> Result<Option<AcmeChallenge>, DomainError>;

    /// Withdraws a challenge once it has been answered or abandoned.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn withdraw(&self, token: &ChallengeToken) -> Result<(), DomainError>;

    /// Removes challenges past their expiry. Returns how many went.
    ///
    /// A provisioning run that dies between publishing and finalising leaves
    /// one behind, and a URL that answers forever is worth removing even
    /// though [`AcmeChallenge::answer`] would already refuse it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn purge_expired(&self) -> Result<u64, DomainError>;
}
