//! Who may open a new account in a tenant.
//!
//! A new account is a way into the tenant. So it is opened by someone the
//! tenant trusts to say who comes in: a person holding the right to add
//! users, the tenant's own directory while it is switched on, or the person
//! themselves when the tenant takes sign-ups from anyone.

use crate::domains::identity::sealed::Sealed;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;

/// How a new account is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountOpening {
    /// It waits for its holder to confirm their address, as after signing
    /// up or being added by a directory.
    Registration,
    /// Its holder is asked to claim it through an invitation, sent or sent
    /// again.
    Invitation,
    /// It is brought over from another system's records, perhaps with the
    /// password hash that system kept, and waits for its holder to confirm
    /// their address.
    Import,
}

/// Whoever may open an account of tenant `T`, in the way asked.
///
/// Sam may only view users. Without this, he registers a mailbox of his own
/// in a tenant that takes no sign-ups and lets the default roles fill it.
/// Authorization answers with what a person holds, federation with the
/// switched-on SCIM endpoint, and the tenant with its word that it takes
/// sign-ups. Identity sits below all three, so it names only this rule.
pub trait AccountCreator<T: TenantScope>: Sealed {
    /// Refuses opening an account by `opening` unless this creator may.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when this creator may not open an
    ///   account that way.
    fn ensure_may_open(&self, opening: AccountOpening) -> Result<(), DomainError>;
}
