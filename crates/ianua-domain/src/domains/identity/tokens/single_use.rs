//! The rules every emailed single-use token keeps, whoever it was issued to.
//!
//! A tenant user's [`SecureToken`](crate::domains::identity::tokens::secure::SecureToken) and an
//! org user's [`OrgToken`](crate::domains::organization::access::token::OrgToken)
//! differ only in who holds them. Both carry one of these.

use time::{Duration, OffsetDateTime};

use crate::domains::identity::account::verified_email::VerifiedEmail;
use crate::shared::errors::DomainError;
use crate::types::{CredentialChange, Email, Lifetime, TokenHash, TokenRefused, TokenState, Usage};

/// The account a link is presented for, as it stands now.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LinkHolder<'a> {
    /// Its address now.
    pub(crate) email: &'a Email,
    /// When it last changed how it signs in.
    pub(crate) credentials_changed_at: CredentialChange,
}

/// A hashed token that expires and can be used once.
#[derive(Debug)]
pub(crate) struct SingleUse {
    token_hash: TokenHash,
    sent_to: Email,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    usage: Usage,
}

/// A single-use token as it was stored.
pub(crate) struct StoredSingleUse {
    pub(crate) token_hash: TokenHash,
    pub(crate) sent_to: Email,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) usage: Usage,
}

impl SingleUse {
    /// A token issued now from its hash, mailed to `sent_to`, living for
    /// `lifetime`, which may be at most `longest`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `lifetime` is longer than
    ///   `longest`.
    pub(crate) fn issue(
        token_hash: TokenHash,
        sent_to: Email,
        lifetime: Lifetime,
        longest: Duration,
    ) -> Result<Self, DomainError> {
        lifetime.ensure_at_most(longest, "a link of this kind")?;
        let now = crate::shared::clock::now();
        Ok(Self {
            token_hash,
            sent_to,
            created_at: now,
            expires_at: lifetime.ends_after(now),
            usage: Usage::Unused,
        })
    }

    /// A token as it was stored.
    pub(crate) fn stored(stored: StoredSingleUse) -> Self {
        Self {
            token_hash: stored.token_hash,
            sent_to: stored.sent_to,
            created_at: stored.created_at,
            expires_at: stored.expires_at,
            usage: stored.usage,
        }
    }

    pub(crate) fn token_hash(&self) -> &TokenHash {
        &self.token_hash
    }

    pub(crate) fn sent_to(&self) -> &Email {
        &self.sent_to
    }

    pub(crate) fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    pub(crate) fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    pub(crate) fn usage(&self) -> Usage {
        self.usage
    }

    /// What the token can do at `now`, for `holder` as it stands now.
    ///
    /// A spent token stays spent whatever the time. One sent to another
    /// address does nothing. Nor does one issued before the holder last
    /// changed how they sign in: Ann asked for two reset links and used the
    /// second, so the first must not open her account again. One past its
    /// expiry can be replaced.
    pub(crate) fn state_for(&self, holder: LinkHolder<'_>, now: OffsetDateTime) -> TokenState {
        if self.usage.is_used() {
            return TokenState::Consumed;
        }
        if self.sent_to != *holder.email || holder.credentials_changed_at.since(self.created_at) {
            return TokenState::Superseded;
        }
        if now >= self.expires_at {
            return TokenState::Expired;
        }
        TokenState::Usable
    }

    /// Spends the token for `holder` as it stands now.
    ///
    /// It spends only when [`Self::state_for`] says the token is usable.
    /// Otherwise the token is left as it was. Following a link mailed to an
    /// address proves its reader holds that mailbox. So a spent token gives
    /// back the address as proven.
    pub(crate) fn redeem(
        &mut self,
        holder: LinkHolder<'_>,
        now: OffsetDateTime,
    ) -> Result<VerifiedEmail, TokenRefused> {
        if let Some(refused) = TokenRefused::of(self.state_for(holder, now)) {
            return Err(refused);
        }
        self.usage = Usage::Used { at: now };
        Ok(VerifiedEmail::proven(self.sent_to.clone()))
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;

    fn alice() -> Email {
        Email::new("alice@corp.test").unwrap()
    }

    fn issued(lifetime: Duration) -> SingleUse {
        SingleUse::issue(
            TokenHash::from_stored("hash".to_owned()),
            alice(),
            Lifetime::new(lifetime).unwrap(),
            Duration::days(1),
        )
        .unwrap()
    }

    fn held(email: &Email) -> LinkHolder<'_> {
        LinkHolder {
            email,
            credentials_changed_at: CredentialChange::Never,
        }
    }

    /// A token mailed to Alice an instant ago, good for an hour, is usable
    /// for her.
    #[test]
    fn a_fresh_token_is_usable() {
        assert_eq!(
            issued(Duration::hours(1)).state_for(held(&alice()), crate::shared::clock::now()),
            TokenState::Usable
        );
    }

    /// At its exact expiry time the token is already expired.
    #[test]
    fn a_token_is_expired_from_the_instant_it_runs_out() {
        let token = issued(Duration::hours(1));

        assert_eq!(
            token.state_for(held(&alice()), token.expires_at()),
            TokenState::Expired
        );
    }

    /// Alice uses her token, and it is checked a day after its expiry. It
    /// reads as used, not expired, since those mean different things to
    /// whoever follows the link.
    #[test]
    fn a_spent_token_stays_spent() {
        let mut token = issued(Duration::hours(1));
        token
            .redeem(held(&alice()), crate::shared::clock::now())
            .unwrap();

        assert_eq!(
            token.state_for(held(&alice()), token.expires_at() + Duration::days(1)),
            TokenState::Consumed
        );
    }

    /// Replaying Alice's redeemed link returns the consumed state and
    /// preserves its first redemption time.
    #[test]
    fn redeeming_twice_is_refused_and_keeps_the_first_time() {
        let mut token = issued(Duration::hours(1));
        let now = crate::shared::clock::now();
        token.redeem(held(&alice()), now).unwrap();

        let replay = token.redeem(held(&alice()), now + Duration::minutes(1));

        assert_eq!(
            replay.map_err(TokenRefused::state),
            Err(TokenState::Consumed)
        );
        assert_eq!(token.usage(), Usage::Used { at: now });
    }

    /// Alice's account moved to alice@newcorp.test after the link was sent.
    /// Using the link is refused as superseded and the token stays unused.
    #[test]
    fn a_link_to_a_former_address_cannot_be_redeemed() {
        let mut token = issued(Duration::hours(1));
        let moved = Email::new("alice@newcorp.test").unwrap();

        let refused = token.redeem(held(&moved), crate::shared::clock::now());

        assert_eq!(
            refused.map_err(TokenRefused::state),
            Err(TokenState::Superseded)
        );
        assert_eq!(token.usage(), Usage::Unused);
    }

    /// Alice uses her link at its expiry time. It is refused as expired and
    /// the token stays unused.
    #[test]
    fn an_expired_link_cannot_be_redeemed() {
        let mut token = issued(Duration::hours(1));

        let refused = token.redeem(held(&alice()), token.expires_at());

        assert_eq!(
            refused.map_err(TokenRefused::state),
            Err(TokenState::Expired)
        );
        assert_eq!(token.usage(), Usage::Unused);
    }

    /// Alice uses her link and gets a proof for alice@corp.test, the address
    /// it was mailed to.
    #[test]
    fn a_redeemed_link_proves_the_address_it_was_sent_to() {
        let mut token = issued(Duration::hours(1));

        let proven = token
            .redeem(held(&alice()), crate::shared::clock::now())
            .unwrap();

        assert_eq!(proven.as_email(), &alice());
    }

    /// A link sent to an address the account has left is classified as
    /// superseded rather than usable.
    #[test]
    fn a_link_sent_to_an_address_the_account_no_longer_has_does_nothing() {
        let token = issued(Duration::hours(1));
        let moved = Email::new("alice@newcorp.test").unwrap();

        assert_eq!(
            token.state_for(held(&moved), crate::shared::clock::now()),
            TokenState::Superseded
        );
    }

    /// A credential change after link issuance makes that link superseded.
    #[test]
    fn a_link_issued_before_the_sign_in_changed_is_superseded() {
        let token = issued(Duration::hours(1));
        let later = crate::shared::clock::now() + Duration::seconds(1);
        let changed = LinkHolder {
            email: &alice(),
            credentials_changed_at: CredentialChange::At { at: later },
        };

        assert_eq!(token.state_for(changed, later), TokenState::Superseded);
    }

    /// A two-day lifetime exceeds the one-day ceiling and is refused;
    /// issuance at exactly the ceiling succeeds.
    #[test]
    fn a_link_lives_only_inside_its_ceiling() {
        let issue = |lifetime: Duration| {
            SingleUse::issue(
                TokenHash::from_stored("hash".to_owned()),
                alice(),
                Lifetime::new(lifetime).unwrap(),
                Duration::days(1),
            )
        };

        assert!(matches!(
            issue(Duration::days(2)),
            Err(DomainError::Validation(_))
        ));
        assert!(issue(Duration::days(1)).is_ok());
    }

    /// A link issued for an hour ends an hour after the moment it was
    /// issued, so no expiry already past can be given to it.
    #[test]
    fn a_link_ends_its_lifetime_after_it_was_issued() {
        let token = issued(Duration::hours(1));

        assert_eq!(token.expires_at(), token.created_at() + Duration::hours(1));
    }
}
