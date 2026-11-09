//! The authority an approved action runs on, as it stands when the approval
//! is spent.

use time::OffsetDateTime;

use crate::domains::agents::authority::delegation::{ActingUnder, Delegation};
use crate::isolation::scope::TenantScope;

/// The delegation an approved action uses, with every delegation above it,
/// as the store loads them when the approval is spent.
///
/// An approval allows one action under one authority. Ann's agent asks to
/// pay an invoice and Bob approves. Ann then revokes the delegation. Without
/// this, the approval still lets the payment through.
pub enum ActionAuthority<'a, T: TenantScope> {
    /// The action uses no delegation.
    NoDelegation,
    /// The action uses `delegation`, under the chain in `above`.
    Delegation {
        /// The delegation the action uses.
        delegation: &'a Delegation<T>,
        /// The delegations its chain runs through, in any order.
        above: &'a [Delegation<T>],
    },
}

impl<T: TenantScope> ActionAuthority<'_, T> {
    /// Whether this is the authority `under` names, and it is live at
    /// `now`. A delegation given for a request that uses none, or the other
    /// way round, does not back it.
    #[must_use]
    pub fn backs(&self, under: &ActingUnder, now: OffsetDateTime) -> bool {
        match (self, under) {
            (Self::NoDelegation, ActingUnder::NoDelegation) => true,
            (Self::Delegation { delegation, above }, ActingUnder::Delegation(id)) => {
                delegation.id() == id && delegation.live_under(above, now)
            }
            (Self::NoDelegation, ActingUnder::Delegation(_))
            | (Self::Delegation { .. }, ActingUnder::NoDelegation) => false,
        }
    }
}
