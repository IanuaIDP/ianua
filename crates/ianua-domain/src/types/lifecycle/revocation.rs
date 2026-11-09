//! Whether a credential or grant has been revoked, said outright.

use time::OffsetDateTime;

/// Whether a credential or grant still stands, or when it was revoked.
///
/// It covers certificates, access tokens, and break-glass and impersonation
/// grants. A bare missing revocation time looks the same as one left out by
/// mistake, and either way the credential would keep working. So "in force"
/// is a value someone writes, and a revocation always carries the instant
/// it happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revocation {
    /// Not revoked.
    InForce,
    /// Revoked at this instant.
    Revoked {
        /// When it was revoked.
        at: OffsetDateTime,
    },
}

impl Revocation {
    /// The revocation a stored revocation time records. No time means in
    /// force.
    #[must_use]
    pub fn from_stored(revoked_at: Option<OffsetDateTime>) -> Self {
        revoked_at.map_or(Self::InForce, |at| Self::Revoked { at })
    }

    /// Whether it has been revoked.
    #[must_use]
    pub fn is_revoked(self) -> bool {
        matches!(self, Self::Revoked { .. })
    }

    /// When it was revoked, if it was. Storage keeps it in this form.
    #[must_use]
    pub fn revoked_at(self) -> Option<OffsetDateTime> {
        match self {
            Self::InForce => None,
            Self::Revoked { at } => Some(at),
        }
    }

    /// Revoked at `now`, or unchanged if it is already revoked. The first
    /// revocation time is the one that counts.
    #[must_use]
    pub fn revoke_at(self, now: OffsetDateTime) -> Self {
        match self {
            Self::InForce => Self::Revoked { at: now },
            Self::Revoked { .. } => self,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An admin revokes a grant, then revokes it again five minutes later.
    /// The record keeps the first time, so it shows when access really
    /// ended.
    #[test]
    fn revoking_twice_keeps_the_first_time() {
        let first = crate::shared::clock::now();
        let later = first + time::Duration::minutes(5);

        let revoked = Revocation::InForce.revoke_at(first).revoke_at(later);

        assert_eq!(revoked.revoked_at(), Some(first));
    }

    /// A stored revocation time reads back as revoked at that time. No
    /// stored time reads back as in force, which is not revoked.
    #[test]
    fn a_stored_time_reads_back_as_revoked_then() {
        let now = crate::shared::clock::now();

        assert_eq!(
            Revocation::from_stored(Some(now)),
            Revocation::Revoked { at: now }
        );
        assert_eq!(Revocation::from_stored(None), Revocation::InForce);
        assert!(!Revocation::InForce.is_revoked());
    }
}
