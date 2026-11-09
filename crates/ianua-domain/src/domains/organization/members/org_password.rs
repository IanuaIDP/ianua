//! An org user's password, or that none is set yet.

use crate::types::PasswordHash;

/// An org user's password, or that none is set yet.
///
/// One value, not an optional hash, so a password check must say what
/// happens to an account with no password. It is refused, never compared
/// against nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgPassword {
    /// No password set, as for an invited user who has not accepted yet.
    NotSet,
    /// This hash.
    Set(PasswordHash),
}

impl OrgPassword {
    /// The password a stored column records. None means not set.
    #[must_use]
    pub fn from_stored(hash: Option<PasswordHash>) -> Self {
        hash.map_or(Self::NotSet, Self::Set)
    }

    /// The hash, when one is set. This is how storage keeps it.
    #[must_use]
    pub fn hash(&self) -> Option<&PasswordHash> {
        match self {
            Self::NotSet => None,
            Self::Set(hash) => Some(hash),
        }
    }
}
