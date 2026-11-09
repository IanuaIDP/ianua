//! Who may create and change the accounts applications bind to the
//! directory as.

use crate::domains::authentication::directory_service::scope::DirectoryAccess;
use crate::domains::identity::sealed::Sealed;
use crate::shared::errors::DomainError;

/// Whether the person acting may hand out directory access of a kind.
///
/// A service account reads the tenant's directory with no person behind
/// each bind. So making one, changing what it may reach, replacing its
/// secret or switching it off needs the right to change the tenant's
/// sign-in settings and the right to view its users. Without this check,
/// someone who may not view users makes an account and reads everyone
/// through LDAP.
///
/// Authorization knows what the person holds and answers with
/// [`TenantAuthority`](crate::domains::authorization::authority::TenantAuthority).
/// Authentication sits below authorization, so it names only this rule.
pub trait DirectoryControlCheck: Sealed {
    /// Refuses unless the person acting may hand out `access`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they may not.
    fn ensure_may_grant(&self, access: DirectoryAccess) -> Result<(), DomainError>;
}
