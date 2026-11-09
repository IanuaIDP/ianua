//! How a sign-in began, proven: the way in a person used, and for which
//! account.
//!
//! A sign-in owes less once it began strongly. A passkey alone reaches a
//! higher level than a password. So the way in is never taken on the
//! caller's word. A use case could otherwise start a "passkey" sign-in with
//! nothing behind it.

use time::OffsetDateTime;

use crate::domains::authentication::sessions::fresh_sign_in::{PasskeyAnswer, SpentPasskey};
use crate::domains::authentication::sessions::sign_in_progress::LocalMethod;
use crate::domains::identity::account::user::User;
use crate::domains::identity::tokens::magic_link::MagicLink;
use crate::domains::identity::tokens::secure::SecureToken;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{PrincipalId, TokenRefused};

/// A way into an account that ianua itself checked, just now.
///
/// Only a checked password, a passkey answer, or a spent sign-in link make
/// one. It is neither `Clone` nor `Copy`: starting a sign-in spends it, so
/// one followed link or one passkey answer opens one session.
#[derive(Debug, PartialEq, Eq)]
pub struct WayIn {
    account: PrincipalId,
    method: LocalMethod,
}

impl WayIn {
    /// A password this crate checked for `account`.
    pub(crate) fn by_password(account: PrincipalId) -> Self {
        Self {
            account,
            method: LocalMethod::Password,
        }
    }

    /// A passkey that answered a sign-in challenge moments ago.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the passkey answered a registration,
    ///   not a sign-in.
    /// - [`DomainError::Forbidden`] when the challenge was spent longer ago
    ///   than `FRESH_FOR`.
    pub fn by_passkey(spent: &SpentPasskey) -> Result<Self, DomainError> {
        if spent.answer() != PasskeyAnswer::SignIn {
            return Err(DomainError::forbidden(message!(
                "authentication-registering-a-passkey-does-not-sign",
                "registering a passkey does not sign anyone in"
            )));
        }
        if !spent.is_fresh_at(crate::shared::clock::now()) {
            return Err(DomainError::forbidden(message!(
                "authentication-the-passkey-answered-too-long-ago",
                "the passkey answered too long ago to sign anyone in now"
            )));
        }
        Ok(Self {
            account: spent.account(),
            method: LocalMethod::Passkey,
        })
    }

    /// A sign-in link followed by `holder`, spent now.
    ///
    /// # Errors
    ///
    /// - [`TokenRefused`] naming why the link does nothing, with the link
    ///   left as it was.
    pub fn by_magic_link<T: TenantScope>(
        link: &mut SecureToken<T, MagicLink>,
        holder: &User<T>,
        now: OffsetDateTime,
    ) -> Result<Self, TokenRefused> {
        link.redeem(holder, now)?;
        Ok(Self {
            account: (*holder.id()).into(),
            method: LocalMethod::MagicLink,
        })
    }

    /// A sign-in link mailed to `account`'s own address, spent just now.
    /// Only spending such a link makes this, as an organization member's
    /// link does.
    pub(crate) fn by_mailed_link(account: PrincipalId) -> Self {
        Self {
            account,
            method: LocalMethod::MagicLink,
        }
    }

    /// The account the way in was proven for.
    #[must_use]
    pub fn account(&self) -> PrincipalId {
        self.account
    }

    /// The way in.
    #[must_use]
    pub fn method(&self) -> LocalMethod {
        self.method
    }

    /// Spends this way in, handing its account and checked method to one sign-in.
    pub(crate) fn into_parts(self) -> (PrincipalId, LocalMethod) {
        (self.account, self.method)
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::authentication::mfa::owed::SecondFactor;
    use crate::domains::authentication::risk_engine::step_up::StepUpPolicy;
    use crate::domains::authentication::sessions::account_check::MaySignIn;
    use crate::domains::authentication::sessions::sign_in_progress::SignInRefused;
    use crate::domains::identity::account::user::tests::control_over;
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::domains::identity::tokens::secure::NewSecureToken;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::builders::user;
    use crate::types::{TokenHash, TokenState, UserId};

    fn active(address: &str) -> User<ResolvedTenant> {
        let mut account = user(UserId::new(), address);
        account.verify_email(&proof_of(account.email())).unwrap();
        account
    }

    fn link_for(account: &User<ResolvedTenant>) -> SecureToken<ResolvedTenant, MagicLink> {
        SecureToken::create(NewSecureToken {
            token_hash: TokenHash::from_stored("magic".to_owned()),
            user_id: *account.id(),
            sent_to: account.email().clone(),
            lifetime: crate::types::Lifetime::seconds(600).unwrap(),
        })
        .unwrap()
    }

    fn may_sign_in(
        account: &User<ResolvedTenant>,
        way_in: WayIn,
    ) -> Result<MaySignIn<ResolvedTenant>, SignInRefused> {
        MaySignIn::proven(
            account,
            way_in,
            SecondFactor::NotOwed,
            &StepUpPolicy::relaxed(),
        )
    }

    /// Bob follows his sign-in link. A session may open for Bob on it.
    #[test]
    fn a_sign_in_link_opens_a_session_for_the_account_that_followed_it() {
        let bob = active("bob@acme.test");
        let mut link = link_for(&bob);

        let way_in = WayIn::by_magic_link(&mut link, &bob, crate::shared::clock::now()).unwrap();

        assert_eq!(way_in.method(), LocalMethod::MagicLink);
        assert!(may_sign_in(&bob, way_in).is_ok());
    }

    /// Following Bob's valid sign-in link cannot establish a way into Ann's account.
    #[test]
    fn a_session_never_opens_for_another_account_on_its_way_in() {
        let ann = active("ann@acme.test");
        let bob = active("bob@acme.test");
        let mut link = link_for(&bob);

        let way_in = WayIn::by_magic_link(&mut link, &bob, crate::shared::clock::now()).unwrap();

        assert_eq!(
            may_sign_in(&ann, way_in).err(),
            Some(SignInRefused::ForAnotherAccount)
        );
    }

    /// Locking the account prevents its earlier sign-in link from being used
    /// and leaves the link unspent.
    #[test]
    fn a_sign_in_link_makes_no_way_into_a_locked_account() {
        let mut ann = active("ann@acme.test");
        let mut link = link_for(&ann);
        ann.lock(&control_over(&ann)).unwrap();

        let way_in = WayIn::by_magic_link(&mut link, &ann, crate::shared::clock::now());

        assert_eq!(
            way_in.map_err(TokenRefused::state),
            Err(TokenState::AccountShut)
        );
        assert!(link.consumed_at().is_none());
    }

    /// Ann answers a sign-in challenge with her passkey. It makes a passkey
    /// way in for her account.
    #[test]
    fn a_passkey_that_answered_a_sign_in_makes_a_passkey_way_in() {
        let ann = PrincipalId::from(UserId::new());
        let spent = SpentPasskey::new(ann, crate::shared::clock::now());

        let way_in = WayIn::by_passkey(&spent).unwrap();

        assert_eq!(way_in.account(), ann);
        assert_eq!(way_in.method(), LocalMethod::Passkey);
    }

    /// A passkey registration answer cannot establish a way into the account.
    #[test]
    fn a_registration_answer_makes_no_way_in() {
        let spent = SpentPasskey::registered(
            PrincipalId::from(UserId::new()),
            crate::shared::clock::now(),
        );

        assert!(matches!(
            WayIn::by_passkey(&spent),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A passkey answer from two days ago is rejected as a way into a new sign-in.
    #[test]
    fn a_passkey_answer_from_long_ago_makes_no_way_in() {
        let ann = PrincipalId::from(UserId::new());
        let spent = SpentPasskey::new(ann, crate::shared::clock::now() - Duration::days(2));

        assert!(matches!(
            WayIn::by_passkey(&spent),
            Err(DomainError::Forbidden(_))
        ));
    }
}
