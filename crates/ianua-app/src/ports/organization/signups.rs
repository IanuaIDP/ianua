//! Sign-ups waiting for their founder to prove their mailbox.

use async_trait::async_trait;
use ianua_domain::domains::organization::signup::PendingSignup;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TokenHash;

/// Dyn-safe port keeping sign-ups until their link comes back.
///
/// Platform-wide: a sign-up belongs to no organization yet.
#[async_trait]
pub trait PendingSignupStore: Send + Sync {
    /// Keeps `signup` until its link comes back or runs out.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on write failure.
    async fn save(&self, signup: &PendingSignup) -> Result<(), DomainError>;

    /// Hands out the sign-up whose link carries the token hashed as `hash`,
    /// and forgets it in the same step, so a link works once.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure, or when the
    /// stored sign-up is corrupt.
    async fn take(&self, hash: &TokenHash) -> Result<Option<PendingSignup>, DomainError>;
}
