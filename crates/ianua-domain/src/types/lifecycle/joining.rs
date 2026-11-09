//! Whether an account has joined, said outright.

use time::OffsetDateTime;

/// Whether an account has finished joining, and when it first did.
///
/// Joining means accepting an invitation, or confirming an address, and
/// becoming active. A bare missing join time looks the same as one left out
/// by mistake, so "not yet" is a value someone writes. A join always
/// carries the instant it first happened. An account locked out and let
/// back in has not joined twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Joining {
    /// Has not become active yet.
    NotYet,
    /// First became active at this instant.
    Joined {
        /// When it first became active.
        at: OffsetDateTime,
    },
}

impl Joining {
    /// The joining a stored join time records. No time means not yet.
    #[must_use]
    pub fn from_stored(joined_at: Option<OffsetDateTime>) -> Self {
        joined_at.map_or(Self::NotYet, |at| Self::Joined { at })
    }

    /// Joined at `now`, or unchanged if it already joined. The first join is
    /// the one that counts.
    #[must_use]
    pub fn join_at(self, now: OffsetDateTime) -> Self {
        match self {
            Self::NotYet => Self::Joined { at: now },
            Self::Joined { .. } => self,
        }
    }

    /// When it first joined, if it has. Storage keeps it in this form.
    #[must_use]
    pub fn joined_at(self) -> Option<OffsetDateTime> {
        match self {
            Self::NotYet => None,
            Self::Joined { at } => Some(at),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bob joins on Monday and is let back in on Tuesday after a lockout. He
    /// still joined on Monday. No stored time reads as not joined yet.
    #[test]
    fn joining_again_keeps_the_first_time() {
        let first = crate::shared::clock::now();
        let later = first + time::Duration::days(1);

        let joined = Joining::NotYet.join_at(first).join_at(later);

        assert_eq!(joined.joined_at(), Some(first));
        assert_eq!(Joining::from_stored(None), Joining::NotYet);
    }
}
