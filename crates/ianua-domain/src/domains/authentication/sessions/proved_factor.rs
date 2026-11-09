//! A second factor proved just now, and the account it was proved for.
//!
//! A sign-in records a factor only from one of these. So no path can write
//! "proved with a code" when no code was checked, and a factor proved for
//! one account cannot finish another account's sign-in.

use time::OffsetDateTime;

use crate::domains::authentication::credentials::passkey::KeyAttestation;
use crate::domains::authentication::mfa::enrollment::{AnsweredCode, MfaMethod};
use crate::domains::authentication::sessions::fresh_sign_in::SpentPasskey;
use crate::domains::authentication::sessions::mfa_factor::MfaFactor;
use crate::domains::authentication::sessions::sign_in_progress::SignInRefused;
use crate::domains::identity::account::user::User;
use crate::domains::identity::tokens::secure::SecureToken;
use crate::domains::identity::tokens::sign_in_confirmation::SignInConfirmation;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{PrincipalId, TokenRefused};

/// A second factor someone proved just now, for one account.
///
/// It is neither `Clone` nor `Copy`, so one proof answers one sign-in.
#[derive(Debug, PartialEq, Eq)]
pub struct ProvedFactor {
    account: PrincipalId,
    factor: MfaFactor,
}

impl ProvedFactor {
    /// A right code from the account's second factor: from its
    /// authenticator app, or mailed or texted for it. The caller follows
    /// [`AnsweredCode::replay`] before it acts on this.
    #[must_use]
    pub fn by_code(answer: &AnsweredCode) -> Self {
        let factor = match answer.method() {
            MfaMethod::Totp => MfaFactor::Totp,
            MfaMethod::EmailCode => MfaFactor::EmailCode,
            MfaMethod::SmsCode => MfaFactor::SmsCode,
        };
        Self {
            account: answer.subject(),
            factor,
        }
    }

    /// A passkey the account's holder answered a challenge with just now.
    ///
    /// A key whose attestation showed hardware proves a hardware key. Any
    /// other key may be a synced copy, so it proves a passkey.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the challenge was spent longer ago
    ///   than the fresh window.
    pub fn by_passkey(spent: &SpentPasskey) -> Result<Self, DomainError> {
        if !spent.is_fresh_at(crate::shared::clock::now()) {
            return Err(DomainError::forbidden(message!(
                "authentication-the-passkey-was-used-too-long",
                "the passkey was used too long ago to count for this sign-in"
            )));
        }
        let factor = match spent.key() {
            KeyAttestation::HardwareKey => MfaFactor::HardwareKey,
            KeyAttestation::Unattested => MfaFactor::Passkey,
        };
        Ok(Self {
            account: spent.account(),
            factor,
        })
    }

    /// Consumes a sign-in confirmation link mailed to the holder's current address.
    /// It proves mailbox access, not a second factor. Verification and magic links cannot
    /// confirm a password sign-in.
    ///
    /// # Errors
    /// [`TokenRefused`] for another account, a spent or expired link, a changed address,
    /// or an account unable to sign in. Refusal leaves the link unchanged.
    pub fn by_confirmation_link<T: TenantScope>(
        link: &mut SecureToken<T, SignInConfirmation>,
        holder: &User<T>,
        now: OffsetDateTime,
    ) -> Result<Self, TokenRefused> {
        link.redeem(holder, now)?;
        Ok(Self::by_mailbox(PrincipalId::from(*holder.id())))
    }

    /// A confirmation link mailed to `account`'s own address, spent just
    /// now. Only spending such a link makes this.
    pub(crate) fn by_mailbox(account: PrincipalId) -> Self {
        Self {
            account,
            factor: MfaFactor::EmailConfirmation,
        }
    }

    /// One of the account's recovery codes, used up. Only its code set makes
    /// this, as it marks the code used.
    pub(crate) fn recovery_code(account: PrincipalId) -> Self {
        Self {
            account,
            factor: MfaFactor::RecoveryCode,
        }
    }

    /// The account the factor was proved for.
    #[must_use]
    pub fn account(&self) -> PrincipalId {
        self.account
    }

    /// The factor proved.
    #[must_use]
    pub fn factor(&self) -> MfaFactor {
        self.factor
    }

    /// Consumes this proof for its account, so it cannot answer another sign-in.
    ///
    /// # Errors
    ///
    /// [`SignInRefused::ForAnotherAccount`] when another account presents the proof.
    pub(crate) fn for_account(self, account: PrincipalId) -> Result<MfaFactor, SignInRefused> {
        if self.account != account {
            return Err(SignInRefused::ForAnotherAccount);
        }
        Ok(self.factor)
    }
}

/// `factor` proved for `account`, for tests elsewhere in the crate.
#[cfg(test)]
pub(crate) fn proved(account: PrincipalId, factor: MfaFactor) -> ProvedFactor {
    ProvedFactor { account, factor }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::authentication::sessions::account_check::tests::account_with;
    use crate::domains::identity::account::user_status::UserStatus;
    use crate::domains::identity::tokens::secure::NewSecureToken;
    use crate::isolation::scope::ResolvedTenant;
    use crate::types::{CredentialChange, Email, Lifetime, TokenHash, TokenState, UserId};

    /// An active account that may sign in.
    fn active() -> User<ResolvedTenant> {
        account_with(UserId::new(), UserStatus::Active, CredentialChange::Never)
    }

    fn confirmation_mailed_to(
        account: &User<ResolvedTenant>,
    ) -> SecureToken<ResolvedTenant, SignInConfirmation> {
        SecureToken::create(NewSecureToken {
            token_hash: TokenHash::from_stored("confirm".to_owned()),
            user_id: *account.id(),
            sent_to: account.email().clone(),
            lifetime: Lifetime::seconds(900).unwrap(),
        })
        .unwrap()
    }

    /// Ann follows the confirmation link mailed to her own address. It
    /// proves an email confirmation for her account, and is spent.
    #[test]
    fn a_confirmation_link_to_the_accounts_own_address_proves_the_mailbox() {
        let ann = active();
        let mut link = confirmation_mailed_to(&ann);

        let proof =
            ProvedFactor::by_confirmation_link(&mut link, &ann, crate::shared::clock::now())
                .unwrap();

        assert_eq!(proof.factor(), MfaFactor::EmailConfirmation);
        assert_eq!(proof.account(), PrincipalId::from(*ann.id()));
        assert!(link.consumed_at().is_some());
    }

    /// Another account's confirmation link cannot prove Ann's factor and
    /// remains unspent after the refusal.
    #[test]
    fn a_confirmation_link_for_another_account_proves_nothing() {
        let ann = active();
        let mallory = active();
        let mut mallorys = confirmation_mailed_to(&mallory);

        let refused =
            ProvedFactor::by_confirmation_link(&mut mallorys, &ann, crate::shared::clock::now())
                .map_err(TokenRefused::state);

        assert_eq!(refused, Err(TokenState::ForAnotherAccount));
        assert!(mallorys.consumed_at().is_none());
    }

    /// A confirmation link addressed to an account's former email is superseded.
    #[test]
    fn a_confirmation_link_to_a_former_address_proves_nothing() {
        let ann = active();
        let mut old = SecureToken::create(NewSecureToken {
            token_hash: TokenHash::from_stored("confirm".to_owned()),
            user_id: *ann.id(),
            sent_to: Email::new("ann@old.example.com").unwrap(),
            lifetime: Lifetime::seconds(900).unwrap(),
        })
        .unwrap();

        let refused =
            ProvedFactor::by_confirmation_link(&mut old, &ann, crate::shared::clock::now())
                .map_err(TokenRefused::state);

        assert_eq!(refused, Err(TokenState::Superseded));
    }

    /// Ann answers with a passkey nobody attested. It may be a synced copy,
    /// so it proves a passkey, not a hardware key.
    #[test]
    fn an_unattested_passkey_proves_a_passkey_not_a_hardware_key() {
        let ann = PrincipalId::from(UserId::new());
        let synced = SpentPasskey::new(ann, crate::shared::clock::now());

        let proof = ProvedFactor::by_passkey(&synced).unwrap();

        assert_eq!(proof.factor(), MfaFactor::Passkey);
        assert_eq!(proof.account(), ann);
    }

    /// A passkey answer from twenty minutes ago cannot establish a factor now.
    #[test]
    fn an_old_passkey_answer_proves_no_factor() {
        let ann = PrincipalId::from(UserId::new());
        let old = SpentPasskey::new(ann, crate::shared::clock::now() - Duration::minutes(20));

        assert!(matches!(
            ProvedFactor::by_passkey(&old),
            Err(DomainError::Forbidden(_))
        ));
    }
}
