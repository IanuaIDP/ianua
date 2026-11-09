//! Whether a trusted route that just proved an account's holder still
//! stands behind its next sign-in.
//!
//! Two routes prove the person before they ever sign in: the setup token
//! an installation shows whoever ran it, which confirms the first owner,
//! and an accepted invitation. Until the account's first sign-in after one
//! of them, that route answers what a risky sign-in would otherwise ask,
//! so the person may set up their second factor there and then. The first
//! sign-in spends it.

use crate::types::Joining;

/// Whether a trusted route vouches for the account's next sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vouching {
    /// The installation's setup token or an accepted invitation proved the
    /// person, and the account has not signed in since.
    Fresh,
    /// Nothing vouches: the account signed in since, or no trusted route
    /// made it.
    Absent,
}

impl Vouching {
    /// Whether an account whose joining is `joining` may hold this. A route
    /// vouches only for an account it let in, so a fresh one has joined.
    #[must_use]
    pub fn fits(self, joining: Joining) -> bool {
        match self {
            Self::Fresh => joining != Joining::NotYet,
            Self::Absent => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use super::*;

    /// A route vouches only for an account that joined through it. One that
    /// never joined holds nothing fresh.
    #[test]
    fn only_a_joined_account_is_vouched_for() {
        let joined = Joining::Joined {
            at: OffsetDateTime::UNIX_EPOCH,
        };

        assert!(Vouching::Fresh.fits(joined));
        assert!(!Vouching::Fresh.fits(Joining::NotYet));
        assert!(Vouching::Absent.fits(Joining::NotYet));
        assert!(Vouching::Absent.fits(joined));
    }
}
