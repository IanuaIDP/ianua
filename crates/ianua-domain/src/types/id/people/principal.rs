use std::fmt;

use uuid::Uuid;

use crate::types::id::{OrgUserId, UserId};

/// The id of a person who signs in, a tenant user or an org user.
///
/// The security types that work on both identity planes use it, which are
/// `MfaEnrollment`, `RecoveryCodeSet` and `TrustedDevice`. Both [`UserId`]
/// and [`OrgUserId`] convert into it with `From`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PrincipalId(Uuid);

impl PrincipalId {
    /// Wraps a raw UUID.
    #[must_use]
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// The underlying UUID.
    #[must_use]
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl From<UserId> for PrincipalId {
    fn from(id: UserId) -> Self {
        Self(*id.as_uuid())
    }
}

impl From<OrgUserId> for PrincipalId {
    fn from(id: OrgUserId) -> Self {
        Self(*id.as_uuid())
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tenant user's id becomes a principal id with the same UUID.
    #[test]
    fn from_user_id() {
        let user_id = UserId::new();
        let principal: PrincipalId = user_id.into();
        assert_eq!(principal.as_uuid(), user_id.as_uuid());
    }

    /// An org user's id becomes a principal id with the same UUID.
    #[test]
    fn from_org_user_id() {
        let org_user_id = OrgUserId::new();
        let principal: PrincipalId = org_user_id.into();
        assert_eq!(principal.as_uuid(), org_user_id.as_uuid());
    }

    /// A new tenant user and a new org user give two different principal
    /// ids.
    #[test]
    fn different_sources_different_principals() {
        let a: PrincipalId = UserId::new().into();
        let b: PrincipalId = OrgUserId::new().into();
        assert_ne!(a, b);
    }
}
