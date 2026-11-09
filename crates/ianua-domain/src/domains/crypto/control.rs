//! Who may change a tenant's signing keys.
//!
//! The signing keys decide whose tokens every relying party believes. So
//! adding, rotating or revoking one, and each step of an algorithm
//! migration, names who makes it and needs the right for it.

use crate::domains::crypto::sealed::Sealed;
use crate::shared::errors::DomainError;

/// Whether the person acting may change the tenant's signing keys.
///
/// Sam may only view the keys. Without this check, he revokes the key that
/// signs, or rolls back a migration halfway, and every relying party stops
/// believing the tenant's tokens. Authorization knows what the person holds
/// and answers with
/// [`TenantAuthority`](crate::domains::authorization::authority::TenantAuthority).
/// Crypto sits below authorization, so it names only this rule.
pub trait CryptoControlCheck: Sealed {
    /// Refuses unless the person acting may change signing keys.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they may not.
    fn ensure_may_change_keys(&self) -> Result<(), DomainError>;
}
