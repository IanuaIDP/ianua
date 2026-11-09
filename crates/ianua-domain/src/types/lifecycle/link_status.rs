//! What an emailed link is worth.
//!
//! It says whether the link can still be used. For a link that sets a
//! password, it also gives the password rules behind it.

use crate::types::{PasswordPolicy, TokenState};

/// What following an emailed link would do, answered without following it.
///
/// Password reset, invitation, email change and address verification links
/// all land on a page that must decide what to show before it acts. Trying
/// the action to find out would spend a good token. A stale one would show
/// whatever general failure the confirm step returns.
///
/// [`TokenState`] describes a token that exists. This adds the case where
/// there is no such token at all, so one answer covers everything the
/// reader can be told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TokenStatus {
    /// Unspent and in date. The action behind it is available.
    Valid,
    /// Past its expiry, or sent to an address that is not the account's
    /// current one. A fresh one can be issued.
    Expired,
    /// Already spent. What it allowed has happened, so the page says so
    /// instead of offering it again.
    AlreadyUsed,
    /// No such token. It was mistyped, cut short by a mail client, or never
    /// ours. A token issued to another account reads this way too.
    Invalid,
}

impl From<TokenState> for TokenStatus {
    /// Expired, spent and invalid stay apart, because each asks something
    /// different of the reader. Expired means request another. Spent means
    /// it already worked. Invalid means check the link itself. A sign-in
    /// link for a shut account reads as invalid, so the page does not tell
    /// a stranger the account is locked.
    fn from(state: TokenState) -> Self {
        match state {
            TokenState::Usable => Self::Valid,
            TokenState::Expired => Self::Expired,
            TokenState::Consumed => Self::AlreadyUsed,
            TokenState::Superseded => Self::Expired,
            TokenState::ForAnotherAccount | TokenState::AccountShut => Self::Invalid,
        }
    }
}

/// What a link that sets a password is worth, with the rules the new
/// password must meet when the link is still usable.
///
/// The page behind a reset or invitation link shows a password form. The
/// reader is signed out, so this is how they learn the organization's or
/// tenant's rules before they type. Only a usable link carries the rules.
/// The other answers offer no form, and an unknown token must not reveal
/// whose rules it would have been held to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordLinkStatus {
    /// Unspent and in date. The new password must meet this policy.
    Valid(PasswordPolicy),
    /// Unspent and in date, for a tenant that signs nobody in with a
    /// password. There is no password to choose, so no form to show.
    ValidWithoutPassword,
    /// Past its expiry, or sent to an old address. Another link can be
    /// issued.
    Expired,
    /// Already spent. What it allowed has happened.
    AlreadyUsed,
    /// No such token.
    Invalid,
}

impl PasswordLinkStatus {
    /// The answer for a link that offers no password form, or `None` when the
    /// link is usable and the answer still needs the policy it will be held to.
    #[must_use]
    pub fn without_form(status: TokenStatus) -> Option<Self> {
        match status {
            TokenStatus::Valid => None,
            TokenStatus::Expired => Some(Self::Expired),
            TokenStatus::AlreadyUsed => Some(Self::AlreadyUsed),
            TokenStatus::Invalid => Some(Self::Invalid),
        }
    }

    /// The token status alone, without the policy.
    #[must_use]
    pub fn token_status(&self) -> TokenStatus {
        match self {
            Self::Valid(_) | Self::ValidWithoutPassword => TokenStatus::Valid,
            Self::Expired => TokenStatus::Expired,
            Self::AlreadyUsed => TokenStatus::AlreadyUsed,
            Self::Invalid => TokenStatus::Invalid,
        }
    }

    /// The policy a new password must meet, when the link is usable.
    #[must_use]
    pub fn password_policy(&self) -> Option<&PasswordPolicy> {
        match self {
            Self::Valid(policy) => Some(policy),
            Self::ValidWithoutPassword | Self::Expired | Self::AlreadyUsed | Self::Invalid => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A usable token reads as valid, an expired one as expired, a spent one
    /// as already used, and one for another account as invalid.
    #[test]
    fn every_token_state_has_a_status() {
        assert_eq!(TokenStatus::from(TokenState::Usable), TokenStatus::Valid);
        assert_eq!(TokenStatus::from(TokenState::Expired), TokenStatus::Expired);
        assert_eq!(
            TokenStatus::from(TokenState::Consumed),
            TokenStatus::AlreadyUsed
        );
        assert_eq!(
            TokenStatus::from(TokenState::ForAnotherAccount),
            TokenStatus::Invalid
        );
    }

    /// A spent link and an expired link get different statuses. For Ann,
    /// spent means her reset already worked, and expired means she should
    /// ask for another link.
    #[test]
    fn a_spent_token_reports_apart_from_an_expired_one() {
        assert_ne!(TokenStatus::AlreadyUsed, TokenStatus::Expired);
    }

    /// A valid link gets no answer from `without_form`. The caller must look
    /// up the password policy first.
    #[test]
    fn a_usable_link_needs_its_policy_before_it_can_be_answered() {
        assert_eq!(PasswordLinkStatus::without_form(TokenStatus::Valid), None);
    }

    /// An expired, spent or unknown link is answered with its status and no
    /// policy. An unknown token does not reveal whose rules it would have
    /// used.
    #[test]
    fn a_link_offering_no_form_is_answered_without_a_policy() {
        for status in [
            TokenStatus::Expired,
            TokenStatus::AlreadyUsed,
            TokenStatus::Invalid,
        ] {
            let answer = PasswordLinkStatus::without_form(status).unwrap();

            assert_eq!(answer.token_status(), status);
            assert_eq!(answer.password_policy(), None);
        }
    }

    /// A valid reset link reads as valid and hands the page the policy the
    /// new password must meet.
    #[test]
    fn a_usable_link_carries_the_policy_it_was_given() {
        let policy = PasswordPolicy::relaxed();

        let answer = PasswordLinkStatus::Valid(policy.clone());

        assert_eq!(answer.token_status(), TokenStatus::Valid);
        assert_eq!(answer.password_policy(), Some(&policy));
    }

    /// An invitation link for a tenant that signs nobody in with a password
    /// is valid but has no policy, so the page shows no password form.
    #[test]
    fn a_usable_link_in_a_realm_without_passwords_is_valid_but_offers_no_form() {
        let answer = PasswordLinkStatus::ValidWithoutPassword;

        assert_eq!(answer.token_status(), TokenStatus::Valid);
        assert_eq!(answer.password_policy(), None);
    }
}
