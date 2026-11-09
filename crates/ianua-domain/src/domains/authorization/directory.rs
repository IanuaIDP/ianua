//! The tenant's own directory, saying who belongs to which of its groups.
//!
//! Okta or an HR system keeps a tenant's teams, and SCIM carries them here.
//! Nobody in the tenant is signed in when a change arrives, so no granter
//! is asked. What may speak instead is the directory the tenant connected,
//! while it is switched on. Federation answers with its SCIM endpoint.
//! Authorization sits below federation, so it names only this rule.

use crate::domains::identity::sealed::Sealed;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;

/// The directory tenant `T` connected, speaking for it now.
///
/// Sam may only view users. Without this, any code makes "Synced" groups
/// and fills them, on the word of a directory the tenant switched off.
pub trait TenantDirectory<T: TenantScope>: Sealed {
    /// Refuses unless the directory may speak for the tenant now.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the tenant switched it off.
    fn ensure_speaks(&self) -> Result<(), DomainError>;
}
