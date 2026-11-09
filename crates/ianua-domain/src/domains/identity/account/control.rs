//! The rules an action on an account must pass first: someone else acting
//! on its sign-in, the person acting on their own account, and either one
//! changing its profile.

use crate::domains::identity::sealed::Sealed;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{PrincipalId, UserId};

/// What someone does to another person's account.
///
/// Each needs its own right. Authorization says which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountAction {
    /// Changes how the account signs in: its address, password, second
    /// factor or linked identities.
    ChangeSignIn,
    /// Lets the account in: activates or unlocks it.
    LetIn,
    /// Shuts the account out: locks or deactivates it.
    ShutOut,
    /// Erases the person's data.
    Erase,
    /// Records a decision for them that only lowers what is done with their
    /// data, such as withdrawing consent they asked support to withdraw.
    RecordForThem,
    /// Changes what their profile shows: their name, language or timezone.
    EditProfile,
    /// Changes what the company's directory records about them: its id for
    /// the account, their department, manager or employee number.
    EditRecords,
    /// Asks for a copy of all the data kept about them, on their behalf.
    Export,
    /// Acts as them for a short while, to see and fix what they see.
    Impersonate,
}

/// Whether the person acting may act on an account's sign-in: its password,
/// address or status.
///
/// Whoever controls how an account signs in holds everything it holds. So
/// the person acting needs the right for the action, and must hold all the
/// account holds. The check is made for one account and passes for no
/// other. Authorization knows what each side holds and answers with
/// [`AccountControl`](crate::domains::authorization::granter::AccountControl).
/// The tenant's directory, which nobody signs in to, answers through
/// federation's
/// [`DirectoryControl`](crate::domains::federation::scim::DirectoryControl).
/// Identity sits below both, so it names only this rule.
pub trait AccountControlCheck: Sealed {
    /// Refuses `action` on `account` unless the person acting may do it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the check was made for another
    ///   account.
    /// - [`DomainError::Forbidden`] when the person acting lacks the right
    ///   for `action`.
    /// - [`DomainError::Forbidden`] when the account holds more than the
    ///   person acting on it.
    /// - [`DomainError::Conflict`] when `action` shuts out or erases the
    ///   tenant's last administrator.
    fn ensure_allowed(&self, account: &UserId, action: AccountAction) -> Result<(), DomainError>;
}

/// Proof that the person an account of tenant `T` belongs to is the one
/// signed in now.
///
/// Only a finished sign-in to tenant `T`, or a directory client's bind with
/// the account's password and certificate, makes one, so a sign-in
/// elsewhere vouches for no account here. Consent and a person's own
/// erasure need it, so nobody else can agree or ask for them.
/// Authentication answers with its signed-in proof and its directory bind.
/// Identity sits below authentication, so it names only this rule.
pub trait SignedInPerson<T: TenantScope>: Sealed {
    /// Whether the person signed in is the holder of `account`.
    fn is_holder_of(&self, account: &UserId) -> bool;
}

/// Whether an account may leave its tenant without leaving it with nobody
/// to run it.
///
/// A person closing their own account needs no right, but the tenant must
/// keep an administrator. Ann is the tenant's only admin. Without this
/// check, someone holding her session asks to erase her account, and
/// nobody can run the tenant again. Authorization knows who administers
/// the tenant and answers with
/// [`Departure`](crate::domains::authorization::granter::Departure).
/// Identity sits below it, so it names only this rule.
pub trait DepartureCheck: Sealed {
    /// Refuses `account` leaving the tenant when nobody would be left to
    /// run it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the check was made for another
    ///   account.
    /// - [`DomainError::Conflict`] when `account` is the tenant's last
    ///   administrator.
    fn ensure_may_leave(&self, account: &UserId) -> Result<(), DomainError>;
}

/// Refuses `person` unless they are the holder of `account`.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when someone else is signed in.
pub(crate) fn ensure_holder<T: TenantScope>(
    person: &impl SignedInPerson<T>,
    account: &UserId,
) -> Result<(), DomainError> {
    if !person.is_holder_of(account) {
        return Err(DomainError::forbidden(message!(
            "identity-only-the-person-the-account-belongs",
            "only the person the account belongs to may do this"
        )));
    }
    Ok(())
}

/// Whoever may change the profile of an account of tenant `T`: its name,
/// language or timezone.
///
/// A profile is changed by the person it belongs to, from their own
/// sign-in, or by someone with the right to edit it. Sam may only view
/// users. Without this, he renames Ann to "Former employee" and her
/// colleagues stop trusting her messages. Authentication answers with its
/// signed-in proof, and authorization with
/// [`AccountControl`](crate::domains::authorization::granter::AccountControl).
/// Identity sits below both, so it names only this rule.
pub trait ProfileEditor<T: TenantScope>: Sealed {
    /// Refuses a change to the profile of `account` unless this editor may
    /// make it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when someone else is signed in.
    /// - [`DomainError::Forbidden`] when the person acting on another
    ///   account lacks the right to edit it, or the check was made for
    ///   another account.
    fn ensure_may_edit(&self, account: &UserId) -> Result<(), DomainError>;
}

/// Proof that the holder of an account proved who they are again, a moment
/// ago, as strongly as the account normally signs in.
///
/// An open session is not enough for a change that would let whoever holds
/// it keep the account after the password changes. Mallory steals Ann's
/// session and asks to move her address to Mallory's mailbox. With this,
/// she must also know Ann's password or hold her second factor.
/// Authentication decides how recent and how strong, and answers with its
/// proof. Identity sits below authentication, so it names only this rule.
pub trait RecentProof: Sealed {
    /// Whether the holder of `account` proved who they are again just now.
    fn proves_recently(&self, account: &PrincipalId) -> bool;
}
