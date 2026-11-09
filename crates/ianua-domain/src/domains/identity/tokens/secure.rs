use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::identity::account::user::User;
use crate::domains::identity::account::verified_email::VerifiedEmail;
use crate::domains::identity::tokens::purpose::{LinkEffect, TenantLinkPurpose};
use crate::domains::identity::tokens::single_use::{LinkHolder, SingleUse, StoredSingleUse};
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::types::{Email, Lifetime, TokenHash, TokenRefused, TokenState, Usage, UserId};

/// A [`SecureToken`] as storage keeps it, checked again by
/// [`SecureToken::reconstitute`].
pub struct SecureTokenRow {
    /// The token's hash.
    pub token_hash: TokenHash,
    /// The user it was issued for.
    pub user_id: UserId,
    /// The address the link was mailed to.
    pub sent_to: Email,
    /// When it was issued.
    pub created_at: OffsetDateTime,
    /// When it stops being usable.
    pub expires_at: OffsetDateTime,
    /// Whether it was used, and when.
    pub usage: Usage,
}

/// A token about to be mailed.
pub struct NewSecureToken {
    /// The one-way hash of the raw value the link carries.
    pub token_hash: TokenHash,
    /// Who it is for.
    pub user_id: UserId,
    /// The address it is mailed to, which the account must still have when
    /// the link is followed.
    pub sent_to: Email,
    /// How long it stays usable from now.
    pub lifetime: Lifetime,
}

/// A token for one user in one tenant that works once and runs out.
///
/// Only the hash is stored, never the raw value. The raw value is mailed to
/// the user and sent back when they follow the link. The presented value is
/// hashed and compared to the stored hash.
///
/// The `Purpose` type keeps token kinds apart at compile time. An email
/// verification token cannot be checked as a password reset token.
///
/// # Type safety
///
/// A token is accepted where its own purpose is expected:
///
/// ```
/// use ianua_domain::domains::identity::tokens::email_verification::EmailVerification;
/// use ianua_domain::domains::identity::tokens::secure::SecureToken;
/// use ianua_domain::isolation::scope::TenantScope;
///
/// fn verify_email<T: TenantScope>(token: &SecureToken<T, EmailVerification>) {}
///
/// fn verify<T: TenantScope>(token: &SecureToken<T, EmailVerification>) {
///     verify_email(token);
/// }
/// ```
///
/// and refused where another purpose is:
///
/// ```compile_fail
/// use ianua_domain::domains::identity::tokens::email_verification::EmailVerification;
/// use ianua_domain::domains::identity::tokens::magic_link::MagicLink;
/// use ianua_domain::domains::identity::tokens::secure::SecureToken;
/// use ianua_domain::isolation::scope::TenantScope;
///
/// fn verify_email<T: TenantScope>(token: &SecureToken<T, EmailVerification>) {}
///
/// fn misuse<T: TenantScope>(sign_in: &SecureToken<T, MagicLink>) {
///     verify_email(sign_in); // ERROR: expected EmailVerification, got MagicLink
/// }
/// ```
#[derive(Debug)]
pub struct SecureToken<T: TenantScope, Purpose: TenantLinkPurpose> {
    user_id: UserId,
    token: SingleUse,
    _scope: PhantomData<T>,
    _purpose: PhantomData<Purpose>,
}

impl<T: TenantScope, Purpose: TenantLinkPurpose> SecureToken<T, Purpose> {
    /// Creates an unused token from its hash, issued now.
    ///
    /// The infra layer makes and hashes the raw token first. The domain
    /// never sees the raw value.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the lifetime is longer than a link
    ///   of this kind may live
    ///   ([`TokenPurpose::LONGEST`](crate::domains::identity::tokens::purpose::TokenPurpose::LONGEST)).
    pub fn create(new: NewSecureToken) -> Result<Self, DomainError> {
        Ok(Self {
            user_id: new.user_id,
            token: SingleUse::issue(new.token_hash, new.sent_to, new.lifetime, Purpose::LONGEST)?,
            _scope: PhantomData,
            _purpose: PhantomData,
        })
    }

    /// Rebuilds a token from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the token was used
    ///   before it was issued, or once it had expired.
    pub fn reconstitute(row: SecureTokenRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            user_id: row.user_id,
            token: SingleUse::stored(StoredSingleUse {
                token_hash: row.token_hash,
                sent_to: row.sent_to,
                created_at: row.created_at,
                expires_at: row.expires_at,
                usage: row.usage,
            }),
            _scope: PhantomData,
            _purpose: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &SecureTokenRow) -> Result<(), DomainError> {
        RowCheck::of("secure token")
            .in_order_if(
                row.created_at,
                row.usage.used_at(),
                "used before it was issued",
            )
            .holds(
                row.usage.used_at().is_none_or(|at| at < row.expires_at),
                "used after it expired",
            )
            .finish()
    }

    /// The one-way hash of the raw token value.
    #[must_use]
    pub fn token_hash(&self) -> &TokenHash {
        self.token.token_hash()
    }

    /// The user this token was issued for.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// The address the link was mailed to.
    #[must_use]
    pub fn sent_to(&self) -> &Email {
        self.token.sent_to()
    }

    /// When this token was issued.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.token.created_at()
    }

    /// When this token stops being usable, if it was not used.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.token.expires_at()
    }

    /// When this token was used, or `None` while it is unused.
    #[must_use]
    pub fn consumed_at(&self) -> Option<OffsetDateTime> {
        self.token.usage().used_at()
    }

    /// What following this link would do for `holder`, without spending it.
    ///
    /// A link issued to another account is no token at all to this one. A
    /// link that ran out of time, or went to an address the account no
    /// longer has, can be replaced. One already spent cannot.
    ///
    /// A link that signs someone in does nothing for an account that may
    /// not sign in now. Ann's account is locked after a break-in. A magic
    /// link mailed before must not let anyone in.
    #[must_use]
    pub fn state_for(&self, holder: &User<T>, now: OffsetDateTime) -> TokenState {
        if *holder.id() != self.user_id {
            return TokenState::ForAnotherAccount;
        }
        let state = self.token.state_for(link_holder(holder), now);
        if state == TokenState::Usable
            && Purpose::EFFECT == LinkEffect::SignsIn
            && !holder.can_authenticate()
        {
            return TokenState::AccountShut;
        }
        state
    }

    /// Spends the link for `holder`. This is the only way a link is used.
    ///
    /// The link must be issued to this account and mailed to the address it
    /// has now. It must also be unspent and in date. So a replayed link, or
    /// one read from a mailbox the account has left, does nothing. It gives
    /// back the address as proven, since following the link shows its
    /// reader holds it.
    ///
    /// # Errors
    ///
    /// - [`TokenRefused`] naming why, with the token left as it was.
    pub fn redeem(
        &mut self,
        holder: &User<T>,
        now: OffsetDateTime,
    ) -> Result<VerifiedEmail, TokenRefused> {
        if let Some(refused) = TokenRefused::of(self.state_for(holder, now)) {
            return Err(refused);
        }
        self.token.redeem(link_holder(holder), now)
    }
}

/// `user` as a link sees it: its address and its last sign-in change.
fn link_holder<T: TenantScope>(user: &User<T>) -> LinkHolder<'_> {
    LinkHolder {
        email: user.email(),
        credentials_changed_at: user.credentials_changed_at(),
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::identity::account::user::tests::control_over;
    use crate::domains::identity::tokens::email_verification::EmailVerification;
    use crate::domains::identity::tokens::magic_link::MagicLink;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::builders::user;

    const ALICE: &str = "alice@corp.test";

    fn alice() -> Email {
        Email::new(ALICE).unwrap()
    }

    type TestToken = SecureToken<ResolvedTenant, EmailVerification>;

    fn future(secs: i64) -> OffsetDateTime {
        crate::shared::clock::now() + Duration::seconds(secs)
    }

    fn lasting(secs: i64) -> Lifetime {
        Lifetime::seconds(secs).unwrap()
    }

    fn token_for(holder: &User<ResolvedTenant>, lifetime: Lifetime) -> TestToken {
        SecureToken::create(NewSecureToken {
            token_hash: TokenHash::from_stored("hashed_abc123".to_owned()),
            user_id: *holder.id(),
            sent_to: holder.email().clone(),
            lifetime,
        })
        .unwrap()
    }

    fn holder() -> User<ResolvedTenant> {
        user(UserId::new(), ALICE)
    }

    fn state(token: &TestToken, holder: &User<ResolvedTenant>) -> TokenState {
        token.state_for(holder, crate::shared::clock::now())
    }

    /// A link made for Alice that lasts an hour is usable for her and not
    /// yet used.
    #[test]
    fn create_produces_a_usable_unspent_token() {
        let alice = holder();
        let token = token_for(&alice, lasting(3600));

        assert_eq!(state(&token, &alice), TokenState::Usable);
        assert!(token.consumed_at().is_none());
    }

    /// A new token keeps the hash and user it was made with, and starts
    /// unused.
    #[test]
    fn create_sets_fields_correctly() {
        let user_id = UserId::new();
        let token = TestToken::create(NewSecureToken {
            token_hash: TokenHash::from_stored("hash123".to_owned()),
            user_id,
            sent_to: alice(),
            lifetime: lasting(7200),
        })
        .unwrap();

        assert_eq!(token.token_hash().as_str(), "hash123");
        assert_eq!(*token.user_id(), user_id);
        assert!(token.consumed_at().is_none());
    }

    /// A new token is stamped with the time it was made, and expires after
    /// that.
    #[test]
    fn create_sets_timestamps() {
        let before = crate::shared::clock::now();
        let token = token_for(&holder(), lasting(3600));
        let after = crate::shared::clock::now();

        assert!(token.created_at() >= before);
        assert!(token.created_at() <= after);
        assert!(token.expires_at() > after);
    }

    /// Alice follows her link. It records the time, and following it again
    /// is refused as used.
    #[test]
    fn the_holder_redeems_a_usable_link_once() {
        let alice = holder();
        let mut token = token_for(&alice, lasting(3600));
        let now = crate::shared::clock::now();

        token.redeem(&alice, now).unwrap();

        assert_eq!(token.consumed_at(), Some(now));
        assert_eq!(
            token.redeem(&alice, now).map_err(TokenRefused::state),
            Err(TokenState::Consumed)
        );
    }

    /// Alice follows a link a second after it expired. It is refused as
    /// expired and stays unused.
    #[test]
    fn an_expired_link_is_refused() {
        let alice = holder();
        let mut token = token_for(&alice, lasting(3600));

        let refused = token.redeem(&alice, token.expires_at() + Duration::seconds(1));

        assert_eq!(
            refused.map_err(TokenRefused::state),
            Err(TokenState::Expired)
        );
        assert!(token.consumed_at().is_none());
    }

    /// After Alice changes her address, redeeming a link sent to her old
    /// mailbox is refused as superseded and leaves it unspent.
    #[test]
    fn a_link_to_an_address_the_account_has_left_is_refused() {
        let mut alice = holder();
        let mut token = token_for(&alice, lasting(3600));
        alice
            .change_email(
                Email::new("alice@newcorp.test").unwrap(),
                &control_over(&alice),
            )
            .unwrap();

        let refused = token.redeem(&alice, crate::shared::clock::now());

        assert_eq!(
            refused.map_err(TokenRefused::state),
            Err(TokenState::Superseded)
        );
        assert!(token.consumed_at().is_none());
    }

    /// Another account with Alice's email cannot redeem her link; the
    /// account mismatch is reported and the token remains unused.
    #[test]
    fn a_link_cannot_be_redeemed_for_another_account() {
        let alice = holder();
        let other = user(UserId::new(), ALICE);
        let mut token = token_for(&alice, lasting(3600));

        let refused = token.redeem(&other, crate::shared::clock::now());

        assert_eq!(
            refused.map_err(TokenRefused::state),
            Err(TokenState::ForAnotherAccount)
        );
        assert!(token.consumed_at().is_none());
    }

    /// Alice has used her link. Bob checking it sees only that it is for
    /// another account, not that it was used.
    #[test]
    fn another_account_learns_nothing_about_a_link() {
        let alice = holder();
        let other = user(UserId::new(), "bob@corp.test");
        let mut spent = token_for(&alice, lasting(3600));
        spent.redeem(&alice, crate::shared::clock::now()).unwrap();

        assert_eq!(state(&spent, &other), TokenState::ForAnotherAccount);
    }

    /// A used token loaded from storage keeps its hash, user, times and use
    /// time.
    #[test]
    fn reconstitute_preserves_all_fields() {
        let user_id = UserId::new();
        let now = crate::shared::clock::now();
        let expires = future(3600);
        let consumed = Some(now);

        let token = TestToken::reconstitute(SecureTokenRow {
            token_hash: TokenHash::from_stored("hash456".to_owned()),
            user_id,
            created_at: now,
            expires_at: expires,
            sent_to: alice(),
            usage: Usage::from_stored(consumed),
        })
        .unwrap();

        assert_eq!(token.token_hash().as_str(), "hash456");
        assert_eq!(*token.user_id(), user_id);
        assert_eq!(token.created_at(), now);
        assert_eq!(token.expires_at(), expires);
        assert_eq!(token.consumed_at(), consumed);
    }

    /// A stored token says it was used at the instant it expired. No link
    /// is let through once it expires, so loading it is refused as corrupt.
    #[test]
    fn a_stored_token_used_once_it_expired_is_refused() {
        let now = crate::shared::clock::now();
        let expires = future(3600);

        let token = TestToken::reconstitute(SecureTokenRow {
            token_hash: TokenHash::from_stored("hash456".to_owned()),
            user_id: UserId::new(),
            created_at: now,
            expires_at: expires,
            sent_to: alice(),
            usage: Usage::Used { at: expires },
        });

        assert!(refused_as_corrupt(&token));
    }

    /// Locking Alice's account prevents redemption of an issued magic
    /// link, which remains unspent after the account-shut refusal.
    #[test]
    fn a_magic_link_does_nothing_for_a_locked_account() {
        let mut alice = holder();
        alice
            .verify_email(
                &crate::domains::identity::account::verified_email::proof_of(alice.email()),
            )
            .unwrap();
        let mut link = SecureToken::<ResolvedTenant, MagicLink>::create(NewSecureToken {
            token_hash: TokenHash::from_stored("magic".to_owned()),
            user_id: *alice.id(),
            sent_to: alice.email().clone(),
            lifetime: lasting(600),
        })
        .unwrap();
        alice.lock(&control_over(&alice)).unwrap();

        let refused = link.redeem(&alice, crate::shared::clock::now());

        assert_eq!(
            refused.map_err(TokenRefused::state),
            Err(TokenState::AccountShut)
        );
        assert!(link.consumed_at().is_none());
    }

    /// A two-hour magic link is rejected because its purpose permits at
    /// most one hour.
    #[test]
    fn a_link_cannot_outlive_its_kind() {
        let alice = holder();

        let made = SecureToken::<ResolvedTenant, MagicLink>::create(NewSecureToken {
            token_hash: TokenHash::from_stored("magic".to_owned()),
            user_id: *alice.id(),
            sent_to: alice.email().clone(),
            lifetime: lasting(7200),
        });

        assert!(matches!(made, Err(DomainError::Validation(_))));
    }
}
