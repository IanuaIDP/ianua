/// What presenting a token gets you.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenState {
    /// Unspent and still in date.
    Usable,
    /// Unspent, but past its expiry. A fresh one can be issued.
    Expired,
    /// Already spent. What it allowed has happened.
    Consumed,
    /// Sent to an address that is not the account's current one. Whoever
    /// reads that mailbox now may not own the account, so the link does
    /// nothing. A fresh one can be sent to the current address.
    Superseded,
    /// Issued to another account than the one it was presented for. Nothing
    /// about it is revealed. To this account it is no token at all.
    ForAnotherAccount,
    /// A link that signs someone in, for an account that may not sign in
    /// now, such as a locked one. It does nothing until the account is let
    /// in again.
    AccountShut,
}

/// A token that could not be spent, and why.
///
/// Made only when the token is not [`TokenState::Usable`], so a refusal
/// always names a real reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the link cannot be used")]
pub struct TokenRefused(TokenState);

impl TokenRefused {
    /// The refusal for `state`, or `None` when the token is usable.
    pub(crate) fn of(state: TokenState) -> Option<Self> {
        match state {
            TokenState::Usable => None,
            TokenState::Expired
            | TokenState::Consumed
            | TokenState::Superseded
            | TokenState::ForAnotherAccount
            | TokenState::AccountShut => Some(Self(state)),
        }
    }

    /// The refusal for a token whose own record says it was already used.
    pub(crate) fn spent() -> Self {
        Self(TokenState::Consumed)
    }

    /// The refusal for a token of another kind than the one presented for,
    /// such as a sign-in's password change offered to a mailed reset. To
    /// this use it is no token at all.
    pub(crate) fn other_kind() -> Self {
        Self(TokenState::ForAnotherAccount)
    }

    /// Why the token could not be spent.
    #[must_use]
    pub fn state(self) -> TokenState {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A usable token gives no refusal, so a good link is never turned away.
    #[test]
    fn a_usable_token_is_never_a_refusal() {
        assert_eq!(TokenRefused::of(TokenState::Usable), None);
    }

    /// An expired, spent, superseded or foreign token is refused, and the
    /// refusal names that same state as its reason.
    #[test]
    fn every_other_state_is_refused_with_itself() {
        for state in [
            TokenState::Expired,
            TokenState::Consumed,
            TokenState::Superseded,
            TokenState::ForAnotherAccount,
        ] {
            assert_eq!(
                TokenRefused::of(state).map(TokenRefused::state),
                Some(state)
            );
        }
    }
}
