//! What the tenant and organization email verification flows answer alike:
//! the wait after asking for another link, and what a link is worth before it
//! is spent.

use ianua_domain::types::TokenState;

/// The outcome of asking for another verification email.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationResent {
    /// How long before another may be asked for. The client counts this down
    /// rather than guessing, so the wait it shows is the one enforced.
    pub retry_after_seconds: u64,
}

/// What a verification link is worth, without spending it.
///
/// Lets the page behind the link decide what to show before it acts. Reading
/// the answer by attempting the verification would mean consuming a good token
/// just to discover it was good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationTokenStatus {
    /// Unspent and in date. Following it will confirm the address.
    Valid,
    /// Past its expiry, spent, or replaced by a newer link. Either way the
    /// address is unconfirmed and another link can be sent.
    Expired,
    /// The address behind it is already confirmed. There is nothing to do.
    Verified,
}

impl VerificationTokenStatus {
    /// What a link in `state` is worth to someone whose address is not yet
    /// confirmed.
    ///
    /// `None` when the link must be answered as if it did not exist: one
    /// issued to another account, or one for an account that is shut. Saying
    /// anything about those would tell a stranger something about an account
    /// that is not theirs.
    #[must_use]
    pub fn of(state: TokenState) -> Option<Self> {
        match state {
            TokenState::Usable => Some(Self::Valid),
            TokenState::Expired | TokenState::Consumed | TokenState::Superseded => {
                Some(Self::Expired)
            }
            TokenState::ForAnotherAccount | TokenState::AccountShut => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ann opens her verification link while it is in date and unspent. The
    /// page tells her following it will confirm her address.
    #[test]
    fn a_usable_link_is_valid() {
        assert_eq!(
            VerificationTokenStatus::of(TokenState::Usable),
            Some(VerificationTokenStatus::Valid)
        );
    }

    /// Ann opens a link that ran out, one she already used, or one a newer
    /// link replaced. Each reads as expired, so she can ask for another.
    #[test]
    fn a_link_past_its_use_is_expired() {
        for state in [
            TokenState::Expired,
            TokenState::Consumed,
            TokenState::Superseded,
        ] {
            assert_eq!(
                VerificationTokenStatus::of(state),
                Some(VerificationTokenStatus::Expired),
                "{state:?}"
            );
        }
    }

    /// Links for another account or a closed account expose no verification status.
    #[test]
    fn a_link_for_another_or_a_shut_account_says_nothing() {
        for state in [TokenState::ForAnotherAccount, TokenState::AccountShut] {
            assert_eq!(VerificationTokenStatus::of(state), None, "{state:?}");
        }
    }
}
