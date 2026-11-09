//! The role an invitation gives, and the rules for who may offer it, when
//! it is sent and when it is accepted.

use crate::domains::identity::sealed::Sealed;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::types::{ActorRef, RoleId};

/// The person who sent an invitation, with what they hold now, worked out
/// when it is accepted.
///
/// Accepting gives the invited role, so it is checked against what the
/// sender holds at that moment, and only the sender. Without the second
/// part, a use case checks the role against Ann, an admin, for an
/// invitation Sam sent before he lost his rights. Authorization works it
/// out from the tenant's records. Identity sits below authorization, so it
/// names only this rule.
pub trait CurrentInviter: Sealed {
    /// Whether this was worked out for the sender `invited_by` names.
    fn is_inviter(&self, invited_by: &ActorRef) -> bool;
}

/// A role of tenant `T` that an invitation gives, checked against `G`, what
/// the inviter holds.
///
/// Whoever accepts gains all the role grants. So the inviter must be able
/// to hand out all of it. Authorization knows what a role grants and
/// answers with [`Role`](crate::domains::authorization::role::Role),
/// checked against
/// [`HeldByGranter`](crate::domains::authorization::granter::HeldByGranter)
/// when it is sent and
/// [`InviterNow`](crate::domains::authorization::inviter::InviterNow) when
/// it is accepted.
/// Identity sits below authorization, so it names only this rule.
pub trait InvitedRole<T: TenantScope, G>: Sealed {
    /// The role's id, which the invitation keeps.
    fn invited_role_id(&self) -> RoleId;

    /// Refuses `inviter` when they may not add people, or may not hand out
    /// everything the role grants.
    ///
    /// An invitation makes a new account. Sam may hand out "view users" but
    /// not add people. Without the first check, he invites anyone he likes.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `inviter` may not create users.
    /// - [`DomainError::Forbidden`] when `inviter` may not hand out one of
    ///   the role's permissions.
    fn ensure_offered_by(&self, inviter: &G) -> Result<(), DomainError>;
}
