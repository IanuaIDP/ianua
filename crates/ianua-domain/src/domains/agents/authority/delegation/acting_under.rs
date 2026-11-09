//! Whether something acts under a delegation, and which.

use crate::types::DelegationId;

/// Whether something acts under a delegation, and which.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActingUnder {
    /// Under no delegation.
    NoDelegation,
    /// Under this delegation.
    Delegation(DelegationId),
}

impl ActingUnder {
    /// Reads the link from a stored column. An empty column means no
    /// delegation.
    #[must_use]
    pub fn from_stored(delegation: Option<DelegationId>) -> Self {
        delegation.map_or(Self::NoDelegation, Self::Delegation)
    }

    /// The delegation, when there is one. Storage keeps the link in this
    /// form.
    #[must_use]
    pub fn delegation(&self) -> Option<&DelegationId> {
        match self {
            Self::NoDelegation => None,
            Self::Delegation(id) => Some(id),
        }
    }
}
