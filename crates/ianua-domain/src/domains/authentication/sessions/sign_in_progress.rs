//! How far a sign-in has come. That is the way in, the second factor proved,
//! and what is still owed.
//!
//! A sign-in is complete only through [`SignInProgress`], and it can only
//! become complete by passing [`StepUpPolicy::admit`]. So no path can hand
//! out a finished session below the tenant's baseline.

use std::marker::PhantomData;

use crate::domains::authentication::methods::AuthMethod;
use crate::domains::authentication::mfa::owed::SecondFactor;
use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::domains::authentication::risk_engine::step_up::{BelowBaseline, StepUpPolicy};
use crate::domains::authentication::sessions::mfa_factor::{
    FactorProved, MfaFactor, assurance_level_for,
};
use crate::domains::authentication::sessions::way_in::WayIn;
use crate::domains::identity::account::control::{ProfileEditor, SignedInPerson, ensure_holder};
use crate::isolation::SecurityScope;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::types::{PrincipalId, UserId};

/// A way in that ianua checks itself, not one an identity provider vouches
/// for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalMethod {
    /// Email and password.
    Password,
    /// A link sent to the person's address.
    MagicLink,
    /// A passkey used as the first factor.
    Passkey,
}

impl From<LocalMethod> for AuthMethod {
    fn from(method: LocalMethod) -> Self {
        match method {
            LocalMethod::Password => Self::Password,
            LocalMethod::MagicLink => Self::MagicLink,
            LocalMethod::Passkey => Self::Passkey,
        }
    }
}

/// A way in an identity provider vouches for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederatedMethod {
    /// A SAML assertion.
    Saml,
    /// An `OpenID` Connect ID token.
    Oidc,
}

impl From<FederatedMethod> for AuthMethod {
    fn from(method: FederatedMethod) -> Self {
        match method {
            FederatedMethod::Saml => Self::Saml,
            FederatedMethod::Oidc => Self::Oidc,
        }
    }
}

/// A sign-in an identity provider vouched for, with the factor it proved if
/// the connection is trusted to report one.
///
/// Only the connection makes one, through
/// [`FederatedIdpConnection::vouched_sign_in`]. So a provider's factor cannot
/// be recorded by any path that skipped the connection's trust setting.
///
/// [`FederatedIdpConnection::vouched_sign_in`]: crate::domains::federation::connection::FederatedIdpConnection::vouched_sign_in
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderSignIn {
    method: AuthMethod,
    factor: FactorProved,
}

impl ProviderSignIn {
    pub(crate) fn new(method: FederatedMethod, factor: FactorProved) -> Self {
        Self {
            method: method.into(),
            factor,
        }
    }

    /// The protocol the provider signed the person in through.
    #[must_use]
    pub fn method(&self) -> AuthMethod {
        self.method
    }

    /// The factor the provider proved, if the connection is trusted to say.
    #[must_use]
    pub fn factor(&self) -> FactorProved {
        self.factor
    }
}

/// Why a sign-in could not begin or move on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignInRefused {
    /// The sign-in would finish below the tenant's baseline.
    #[error("the sign-in does not reach the required assurance")]
    BelowBaseline(BelowBaseline),
    /// The factor given does not answer what the sign-in owes.
    #[error("this factor does not answer what the sign-in owes")]
    NotAccepted {
        /// What the sign-in owed.
        owed: SecondFactor,
        /// The factor given.
        given: MfaFactor,
    },
    /// The sign-in already holds a factor at least as strong.
    #[error("the sign-in already proved a second factor")]
    AlreadyProved,
    /// The factor or way in was proved for another account than the one
    /// signing in.
    #[error("this was proved for another account")]
    ForAnotherAccount,
    /// The account is locked, switched off, still joining or waiting for
    /// erasure, so no way in opens a session for it.
    #[error("this account may not sign in")]
    AccountMayNotSignIn,
    /// The boundary signs this account in only through its identity
    /// provider, or does not allow this way in at all.
    #[error("this account signs in another way")]
    WayInNotAllowed,
}

/// How far a sign-in has come.
///
/// | owed             | accepted answers                             | then        |
/// |------------------|----------------------------------------------|-------------|
/// | Verify           | an own factor, RecoveryCode                  | complete    |
/// | Enrol            | an own factor (just set up)                  | complete    |
/// | ConfirmByEmail   | EmailConfirmation                            | complete    |
/// | ConfirmThenEnrol | EmailConfirmation                            | owes Enrol  |
/// | NotOwed          | an own factor that raises the level          | complete    |
///
/// An own factor is Totp, EmailCode, SmsCode, Passkey or HardwareKey. A
/// mailed code never answers a sign-in begun with a magic link: both prove
/// the same mailbox. A provider's factor is never an answer. It arrives with the sign-in
/// itself, through [`ProviderSignIn`]. Completing always passes
/// [`StepUpPolicy::admit`]. A recovery code stands in for a lost factor, so
/// one that falls short of the baseline leaves the person owing a new factor
/// to set up. Anything else that falls short is refused.
///
/// It is neither `Clone` nor `Copy`. A progress is made by proving each step
/// and moves into the session it was proved for. One read back from a stored
/// session can be looked at, but never handed to a new session or a
/// remembered device as if it had been proved again.
#[derive(Debug, PartialEq, Eq)]
pub struct SignInProgress {
    method: AuthMethod,
    factor: FactorProved,
    owed: SecondFactor,
}

/// Someone who finished signing in, and how far that sign-in went.
///
/// Only the session they signed in to makes one. So the account and the
/// proof of its sign-in always come together, and one account's sign-in
/// cannot be presented for another. The `S` parameter names the plane the
/// session belongs to, so a tenant sign-in cannot vouch for an organization
/// record or the other way round.
pub struct SignedIn<S: SecurityScope> {
    subject: PrincipalId,
    progress: SignInProgress,
    _scope: PhantomData<S>,
}

impl<S: SecurityScope> Clone for SignedIn<S> {
    fn clone(&self) -> Self {
        Self::of(self.subject, self.progress.carried())
    }
}

impl<S: SecurityScope> PartialEq for SignedIn<S> {
    fn eq(&self, other: &Self) -> bool {
        self.subject == other.subject && self.progress == other.progress
    }
}

impl<S: SecurityScope> Eq for SignedIn<S> {}

impl<S: SecurityScope> std::fmt::Debug for SignedIn<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedIn")
            .field("subject", &self.subject)
            .field("progress", &self.progress)
            .finish()
    }
}

impl<S: SecurityScope> SignedIn<S> {
    pub(crate) fn of(subject: PrincipalId, progress: SignInProgress) -> Self {
        Self {
            subject,
            progress,
            _scope: PhantomData,
        }
    }

    /// The account that signed in.
    #[must_use]
    pub fn subject(&self) -> PrincipalId {
        self.subject
    }

    /// How far its sign-in went.
    #[must_use]
    pub fn progress(&self) -> &SignInProgress {
        &self.progress
    }
}

impl<S: SecurityScope> crate::domains::identity::sealed::Sealed for SignedIn<S> {}

impl<T: TenantScope> SignedInPerson<T> for SignedIn<T> {
    fn is_holder_of(&self, account: &UserId) -> bool {
        self.subject == PrincipalId::from(*account)
    }
}

impl<T: TenantScope> ProfileEditor<T> for SignedIn<T> {
    fn ensure_may_edit(&self, account: &UserId) -> Result<(), DomainError> {
        ensure_holder(self, account)
    }
}

/// A sign-in's progress as stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignInProgressRow {
    /// The way in.
    pub method: AuthMethod,
    /// The strongest second factor proved so far.
    pub factor: FactorProved,
    /// What is still owed.
    pub owed: SecondFactor,
}

impl SignInProgress {
    /// Begins a sign-in through `way_in`, owing `owed`. The way in is spent
    /// on it, so one proof starts one sign-in.
    ///
    /// Only the values that bind a sign-in to its account call this. See
    /// `MaySignIn::proven` and `OrgSignInStart::new`.
    ///
    /// # Errors
    ///
    /// - [`SignInRefused::BelowBaseline`] when nothing more is owed and the
    ///   way in alone falls short of the baseline.
    pub(crate) fn start(
        way_in: WayIn,
        owed: SecondFactor,
        policy: &StepUpPolicy,
    ) -> Result<Self, SignInRefused> {
        let (_, method) = way_in.into_parts();
        Self::begin(method, owed, policy)
    }

    /// Begins a sign-in through a way in this crate already checked, owing
    /// `owed`. Everything outside starts from a [`WayIn`], which names the
    /// account it was proved for.
    ///
    /// # Errors
    ///
    /// - [`SignInRefused::BelowBaseline`] when nothing more is owed and the
    ///   way in alone falls short of the baseline.
    pub(crate) fn begin(
        method: LocalMethod,
        owed: SecondFactor,
        policy: &StepUpPolicy,
    ) -> Result<Self, SignInRefused> {
        Self {
            method: method.into(),
            factor: FactorProved::NoneYet,
            owed,
        }
        .admitted_when_complete(policy)
    }

    /// Begins a sign-in an identity provider vouched for.
    ///
    /// A factor the provider proved is the second factor, so nothing more is
    /// owed. Without one, the sign-in owes `owed`. Only the link to the
    /// provider's account calls this, through `MaySignIn::through_provider`,
    /// so the sign-in is bound to the account the link names.
    ///
    /// # Errors
    ///
    /// - [`SignInRefused::BelowBaseline`] when nothing more is owed and the
    ///   sign-in falls short of the baseline.
    pub(crate) fn begin_through_provider(
        sign_in: ProviderSignIn,
        owed: SecondFactor,
        policy: &StepUpPolicy,
    ) -> Result<Self, SignInRefused> {
        let owed = match sign_in.factor {
            FactorProved::Proved(_) => SecondFactor::NotOwed,
            FactorProved::NoneYet => owed,
        };
        Self {
            method: sign_in.method,
            factor: sign_in.factor,
            owed,
        }
        .admitted_when_complete(policy)
    }

    /// The progress once `given` was proved.
    ///
    /// Only a session calls this, with a factor it saw proved for its own
    /// account. See [`Session::answer`].
    ///
    /// [`Session::answer`]: crate::domains::authentication::sessions::session::Session::answer
    ///
    /// # Errors
    ///
    /// - [`SignInRefused::NotAccepted`] when `given` does not answer what is
    ///   owed. See the table on [`SignInProgress`].
    /// - [`SignInRefused::AlreadyProved`] when nothing is owed and `given`
    ///   would not raise the level.
    /// - [`SignInRefused::BelowBaseline`] when the answer completes the
    ///   sign-in below the baseline.
    pub(crate) fn answer(
        &self,
        given: MfaFactor,
        policy: &StepUpPolicy,
    ) -> Result<Self, SignInRefused> {
        let owed = self.owed_after(given)?;
        Self {
            method: self.method,
            factor: FactorProved::Proved(given),
            owed,
        }
        .admitted_when_complete(policy)
    }

    /// The progress once a held sign-in is proved again with `given`, a
    /// factor the person holds and proved just now.
    ///
    /// The sign-in then stands at the level `given` reaches, even when an
    /// earlier factor reached higher. Whoever holds the session now may not
    /// be the person who proved that earlier factor.
    ///
    /// # Errors
    ///
    /// - [`SignInRefused::NotAccepted`] when `given` is a recovery code, an
    ///   email link or a provider's word, or does not answer what is owed.
    /// - [`SignInRefused::BelowBaseline`] when `given` falls short of the
    ///   baseline.
    pub(crate) fn reproved(
        &self,
        given: MfaFactor,
        policy: &StepUpPolicy,
    ) -> Result<Self, SignInRefused> {
        if FactorKind::of(given) != FactorKind::Own || repeats_the_way_in(self.method, given) {
            return Err(SignInRefused::NotAccepted {
                owed: self.owed,
                given,
            });
        }
        let owed = match self.owed {
            SecondFactor::NotOwed => SecondFactor::NotOwed,
            SecondFactor::Verify
            | SecondFactor::Enrol
            | SecondFactor::ConfirmByEmail
            | SecondFactor::ConfirmThenEnrol => self.owed_after(given)?,
        };
        Self {
            method: self.method,
            factor: FactorProved::Proved(given),
            owed,
        }
        .admitted_when_complete(policy)
    }

    /// Rebuilds progress from storage, as it was saved.
    ///
    /// Only the session that stored it rebuilds it, as part of rebuilding
    /// itself. If it were public, any caller could write "signed in with a
    /// hardware key" without a factor ever being proved, and hand that to a
    /// new session or a remembered device.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row holds a provider's
    ///   factor on a sign-in ianua checked itself.
    /// - [`DomainError::Infrastructure`] when the row still owes a step that
    ///   its recorded factor settles.
    pub(crate) fn reconstitute(row: SignInProgressRow) -> Result<Self, DomainError> {
        ensure_reachable(&row)?;
        Ok(Self {
            method: row.method,
            factor: row.factor,
            owed: row.owed,
        })
    }

    /// The same progress, carried on by the session that holds it. It goes
    /// into the session that replaces it, or into proof of who signed in.
    pub(crate) fn carried(&self) -> Self {
        Self {
            method: self.method,
            factor: self.factor,
            owed: self.owed,
        }
    }

    /// The progress a finished sign-in carries into another account's
    /// session, which owes `owed` at a sign-in of its own.
    ///
    /// A second factor proved stays proved. Without one, the new session
    /// owes what the other account would owe, so a switch never lands in an
    /// account that holds a factor without that factor being asked for.
    ///
    /// # Errors
    ///
    /// - [`SignInRefused::BelowBaseline`] when nothing more is owed and the
    ///   carried sign-in falls short of the baseline.
    pub(crate) fn carried_owing(
        &self,
        owed: SecondFactor,
        policy: &StepUpPolicy,
    ) -> Result<Self, SignInRefused> {
        let carried = match self.factor {
            FactorProved::Proved(_) => self.carried(),
            FactorProved::NoneYet => Self {
                method: self.method,
                factor: FactorProved::NoneYet,
                owed,
            },
        };
        carried.admitted_when_complete(policy)
    }

    /// The way in.
    #[must_use]
    pub fn method(&self) -> AuthMethod {
        self.method
    }

    /// The strongest second factor proved so far.
    #[must_use]
    pub fn factor(&self) -> FactorProved {
        self.factor
    }

    /// What is still owed.
    #[must_use]
    pub fn owed(&self) -> SecondFactor {
        self.owed
    }

    /// Whether nothing more is owed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.owed.is_satisfied()
    }

    /// The assurance the sign-in has reached so far.
    #[must_use]
    pub fn assurance_level(&self) -> AssuranceLevel {
        assurance_level_for(self.method, self.factor)
    }

    /// What is owed after `given`, before the baseline is checked.
    fn owed_after(&self, given: MfaFactor) -> Result<SecondFactor, SignInRefused> {
        let refused = SignInRefused::NotAccepted {
            owed: self.owed,
            given,
        };
        if repeats_the_way_in(self.method, given) {
            return Err(refused);
        }
        match (self.owed, FactorKind::of(given)) {
            (SecondFactor::NotOwed, FactorKind::Own) => self.raised_by(given),
            (SecondFactor::Verify, FactorKind::Own | FactorKind::Recovery)
            | (SecondFactor::Enrol, FactorKind::Own)
            | (SecondFactor::ConfirmByEmail, FactorKind::Email) => Ok(SecondFactor::NotOwed),
            (SecondFactor::ConfirmThenEnrol, FactorKind::Email) => Ok(SecondFactor::Enrol),
            (
                SecondFactor::NotOwed | SecondFactor::Enrol,
                FactorKind::Recovery | FactorKind::Email | FactorKind::Provider,
            )
            | (SecondFactor::Verify, FactorKind::Email | FactorKind::Provider)
            | (
                SecondFactor::ConfirmByEmail | SecondFactor::ConfirmThenEnrol,
                FactorKind::Own | FactorKind::Recovery | FactorKind::Provider,
            ) => Err(refused),
        }
    }

    /// A finished sign-in accepts a further factor only when it lifts the
    /// level, as a step-up before a sensitive action does.
    /// Otherwise it refuses with [`SignInRefused::AlreadyProved`].
    fn raised_by(&self, given: MfaFactor) -> Result<SecondFactor, SignInRefused> {
        if assurance_level_for(self.method, FactorProved::Proved(given)) <= self.assurance_level() {
            return Err(SignInRefused::AlreadyProved);
        }
        Ok(SecondFactor::NotOwed)
    }

    /// `self`, checked against the baseline once nothing more is owed.
    fn admitted_when_complete(self, policy: &StepUpPolicy) -> Result<Self, SignInRefused> {
        if !self.is_complete() {
            return Ok(self);
        }
        match policy.admit(self.assurance_level()) {
            Ok(_) => Ok(self),
            Err(below) => self.short_of(below),
        }
    }

    /// What a complete sign-in below the baseline becomes. A recovery code
    /// stands in for a lost factor, so its holder sets up a new one. Anything
    /// else is refused.
    fn short_of(self, below: BelowBaseline) -> Result<Self, SignInRefused> {
        match self.factor {
            FactorProved::Proved(MfaFactor::RecoveryCode) => Ok(Self {
                owed: SecondFactor::Enrol,
                ..self
            }),
            FactorProved::Proved(
                MfaFactor::Totp
                | MfaFactor::EmailCode
                | MfaFactor::SmsCode
                | MfaFactor::Passkey
                | MfaFactor::HardwareKey
                | MfaFactor::EmailConfirmation
                | MfaFactor::ProviderMultiFactor
                | MfaFactor::ProviderHardwareKey,
            )
            | FactorProved::NoneYet => Err(SignInRefused::BelowBaseline(below)),
        }
    }
}

/// Refuses a stored progress that no sequence of [`SignInProgress::begin`],
/// [`SignInProgress::begin_through_provider`] and
/// [`SignInProgress::answer`] could have produced.
fn ensure_reachable(row: &SignInProgressRow) -> Result<(), DomainError> {
    let FactorProved::Proved(factor) = row.factor else {
        return Ok(());
    };
    if factor.is_reported_by_provider() && !row.method.is_federated() {
        return Err(DomainError::corrupt_row(
            "sign-in progress",
            "a provider's factor on a sign-in ianua checked itself",
        ));
    }
    if repeats_the_way_in(row.method, factor) {
        return Err(DomainError::corrupt_row(
            "sign-in progress",
            "a mailed code as the second factor of a magic link",
        ));
    }
    if !factor.may_leave_owed(row.owed) {
        return Err(DomainError::corrupt_row(
            "sign-in progress",
            "a step still owed after the factor that settles it",
        ));
    }
    Ok(())
}

/// Whether `given` proves only what a sign-in begun by `method` already
/// proved: a mailed code after a magic link both show the mailbox, so the
/// two together are one factor, not two.
fn repeats_the_way_in(method: AuthMethod, given: MfaFactor) -> bool {
    method == AuthMethod::MagicLink && given == MfaFactor::EmailCode
}

/// The ways a factor can answer what a sign-in owes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FactorKind {
    /// A factor the person holds and proves here. That is an authenticator
    /// code, a mailed or texted code, a passkey or a hardware key.
    Own,
    /// A recovery code, which stands in for the person's own factor.
    Recovery,
    /// A link to the person's verified address, followed.
    Email,
    /// A factor the identity provider reported.
    Provider,
}

impl FactorKind {
    fn of(factor: MfaFactor) -> Self {
        match factor {
            MfaFactor::Totp
            | MfaFactor::EmailCode
            | MfaFactor::SmsCode
            | MfaFactor::Passkey
            | MfaFactor::HardwareKey => Self::Own,
            MfaFactor::RecoveryCode => Self::Recovery,
            MfaFactor::EmailConfirmation => Self::Email,
            MfaFactor::ProviderMultiFactor | MfaFactor::ProviderHardwareKey => Self::Provider,
        }
    }
}

/// A finished password sign-in of `subject`, for tests elsewhere in the
/// crate.
#[cfg(test)]
pub(crate) fn finished_sign_in_of<S: SecurityScope>(subject: PrincipalId) -> SignedIn<S> {
    let progress = SignInProgress::begin(
        LocalMethod::Password,
        SecondFactor::NotOwed,
        &StepUpPolicy::relaxed(),
    )
    .expect("a relaxed policy admits a password");
    SignedIn::of(subject, progress)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::risk_engine::assessment::RiskLevel;
    use crate::domains::authentication::risk_engine::step_up::{MfaTrigger, StepUpPolicyParams};

    fn hardware_baseline() -> StepUpPolicy {
        StepUpPolicy::new(StepUpPolicyParams {
            baseline_aal: AssuranceLevel::Aal3,
            sensitive_aal: AssuranceLevel::Aal3,
            new_device: MfaTrigger::Ignored,
            new_country: MfaTrigger::Ignored,
            mfa_risk_threshold: RiskLevel::Critical,
            deny_risk_threshold: RiskLevel::Critical,
        })
        .expect("equal levels are valid")
    }

    fn policies() -> [StepUpPolicy; 3] {
        [
            StepUpPolicy::relaxed(),
            StepUpPolicy::strict(),
            hardware_baseline(),
        ]
    }

    const FACTORS: [MfaFactor; 9] = [
        MfaFactor::EmailCode,
        MfaFactor::SmsCode,
        MfaFactor::Totp,
        MfaFactor::RecoveryCode,
        MfaFactor::HardwareKey,
        MfaFactor::Passkey,
        MfaFactor::EmailConfirmation,
        MfaFactor::ProviderMultiFactor,
        MfaFactor::ProviderHardwareKey,
    ];

    const OWED: [SecondFactor; 5] = [
        SecondFactor::NotOwed,
        SecondFactor::Verify,
        SecondFactor::Enrol,
        SecondFactor::ConfirmByEmail,
        SecondFactor::ConfirmThenEnrol,
    ];

    fn provider(factor: FactorProved) -> ProviderSignIn {
        ProviderSignIn::new(FederatedMethod::Saml, factor)
    }

    fn password_owing(owed: SecondFactor) -> SignInProgress {
        SignInProgress::begin(LocalMethod::Password, owed, &StepUpPolicy::relaxed())
            .expect("relaxed admits a password")
    }

    /// Ann's tenant asks for a second factor and she answers with a code
    /// mailed to her after her password. The sign-in completes, still at
    /// AAL1.
    #[test]
    fn a_mailed_code_answers_a_password_sign_in_at_aal1() {
        let progress = password_owing(SecondFactor::Verify)
            .answer(MfaFactor::EmailCode, &StepUpPolicy::relaxed())
            .unwrap();

        assert!(progress.is_complete());
        assert_eq!(progress.assurance_level(), AssuranceLevel::Aal1);
    }

    /// A magic-link sign-in cannot satisfy its second-factor requirement with
    /// a code sent by email.
    #[test]
    fn a_mailed_code_does_not_answer_a_magic_link() {
        let progress = SignInProgress::begin(
            LocalMethod::MagicLink,
            SecondFactor::Verify,
            &StepUpPolicy::relaxed(),
        )
        .unwrap();

        let refused = progress.answer(MfaFactor::EmailCode, &StepUpPolicy::relaxed());

        assert_eq!(
            refused,
            Err(SignInRefused::NotAccepted {
                owed: SecondFactor::Verify,
                given: MfaFactor::EmailCode,
            })
        );
    }

    /// Under the strict baseline, mailed and texted codes fall short after a
    /// password; an authenticator-app code completes the sign-in.
    #[test]
    fn neither_a_texted_nor_a_mailed_code_meets_aal2() {
        let strict = StepUpPolicy::strict();
        let owing = || SignInProgress::begin(LocalMethod::Password, SecondFactor::Verify, &strict);

        assert!(owing().unwrap().answer(MfaFactor::Totp, &strict).is_ok());
        for weak in [MfaFactor::SmsCode, MfaFactor::EmailCode] {
            assert!(matches!(
                owing().unwrap().answer(weak, &strict),
                Err(SignInRefused::BelowBaseline(_))
            ));
        }
    }

    /// A stored magic-link sign-in whose second factor is a mailed code is
    /// refused as corrupt: no sign-in reaches it.
    #[test]
    fn a_stored_magic_link_with_a_mailed_code_is_refused() {
        let row = SignInProgressRow {
            method: AuthMethod::MagicLink,
            factor: FactorProved::Proved(MfaFactor::EmailCode),
            owed: SecondFactor::NotOwed,
        };

        assert!(matches!(
            SignInProgress::reconstitute(row),
            Err(DomainError::Infrastructure(_))
        ));
    }

    /// Under the strict AAL2 baseline, a SAML sign-in that proved no second
    /// factor and owes nothing is refused. It reached AAL1 and AAL2 is
    /// required.
    #[test]
    fn a_provider_sign_in_proving_nothing_is_refused_below_the_baseline() {
        let refused = SignInProgress::begin_through_provider(
            provider(FactorProved::NoneYet),
            SecondFactor::NotOwed,
            &StepUpPolicy::strict(),
        );

        assert_eq!(
            refused,
            Err(SignInRefused::BelowBaseline(BelowBaseline {
                reached: AssuranceLevel::Aal1,
                required: AssuranceLevel::Aal2,
            }))
        );
    }

    /// Under the strict policy, a passkey sign-in that owes nothing reaches
    /// AAL2 and is complete.
    #[test]
    fn a_sign_in_owing_nothing_at_the_baseline_is_complete() {
        let progress = SignInProgress::begin(
            LocalMethod::Passkey,
            SecondFactor::NotOwed,
            &StepUpPolicy::strict(),
        )
        .expect("a passkey reaches AAL2");

        assert!(progress.is_complete());
        assert_eq!(progress.assurance_level(), AssuranceLevel::Aal2);
    }

    /// Under an AAL3 baseline, a password sign-in that still owes a factor
    /// begins. It waits for the factor instead of being refused, because it
    /// is not complete yet.
    #[test]
    fn a_sign_in_owing_a_factor_waits_whatever_its_level() {
        let progress = SignInProgress::begin(
            LocalMethod::Password,
            SecondFactor::Verify,
            &hardware_baseline(),
        )
        .expect("nothing is complete yet");

        assert!(!progress.is_complete());
        assert_eq!(progress.owed(), SecondFactor::Verify);
    }

    /// A trusted SAML provider reports a hardware key under an AAL3
    /// baseline. The sign-in is complete at AAL3, even though it was asked to
    /// enrol.
    #[test]
    fn a_trusted_providers_hardware_key_reaches_a_hardware_baseline() {
        let progress = SignInProgress::begin_through_provider(
            provider(FactorProved::Proved(MfaFactor::ProviderHardwareKey)),
            SecondFactor::Enrol,
            &hardware_baseline(),
        )
        .expect("the provider proved a hardware key");

        assert!(progress.is_complete());
        assert_eq!(progress.method(), AuthMethod::Saml);
        assert_eq!(progress.assurance_level(), AssuranceLevel::Aal3);
    }

    /// A provider reports multi-factor, which is AAL2, under an AAL3
    /// baseline. The sign-in is refused.
    #[test]
    fn a_providers_second_factor_below_a_hardware_baseline_is_refused() {
        let refused = SignInProgress::begin_through_provider(
            provider(FactorProved::Proved(MfaFactor::ProviderMultiFactor)),
            SecondFactor::NotOwed,
            &hardware_baseline(),
        );

        assert!(matches!(refused, Err(SignInRefused::BelowBaseline(_))));
    }

    /// Ann's password sign-in owes TOTP and she types a valid code. It is
    /// complete at AAL2.
    #[test]
    fn a_verified_code_completes_the_sign_in_at_aal2() {
        let progress = password_owing(SecondFactor::Verify)
            .answer(MfaFactor::Totp, &StepUpPolicy::strict())
            .expect("a code answers Verify");

        assert!(progress.is_complete());
        assert_eq!(progress.assurance_level(), AssuranceLevel::Aal2);
    }

    /// Email confirmation is not accepted when a password sign-in owes
    /// verification of an enrolled factor.
    #[test]
    fn an_email_confirmation_does_not_stand_in_for_a_factor_the_person_holds() {
        let refused = password_owing(SecondFactor::Verify)
            .answer(MfaFactor::EmailConfirmation, &StepUpPolicy::relaxed());

        assert_eq!(
            refused,
            Err(SignInRefused::NotAccepted {
                owed: SecondFactor::Verify,
                given: MfaFactor::EmailConfirmation,
            })
        );
    }

    /// Bob has no factor and his sign-in looked risky. He confirms by email,
    /// and the sign-in is complete at AAL1.
    #[test]
    fn an_email_confirmation_answers_a_signal_for_someone_without_a_factor() {
        let progress = password_owing(SecondFactor::ConfirmByEmail)
            .answer(MfaFactor::EmailConfirmation, &StepUpPolicy::relaxed())
            .expect("the email answers the signal");

        assert!(progress.is_complete());
        assert_eq!(progress.assurance_level(), AssuranceLevel::Aal1);
    }

    /// A sign-in owing confirmation before enrollment rejects a TOTP answer
    /// offered before that confirmation.
    #[test]
    fn a_signal_is_not_answered_by_setting_a_factor_up() {
        let refused = password_owing(SecondFactor::ConfirmThenEnrol)
            .answer(MfaFactor::Totp, &StepUpPolicy::strict());

        assert!(matches!(refused, Err(SignInRefused::NotAccepted { .. })));
    }

    /// Under the strict policy, Bob confirms by email and then still owes a
    /// factor. Setting up TOTP after that completes the sign-in at AAL2.
    #[test]
    fn confirming_by_email_then_setting_a_factor_up_completes_the_sign_in() {
        let policy = StepUpPolicy::strict();

        let confirmed = password_owing(SecondFactor::ConfirmThenEnrol)
            .answer(MfaFactor::EmailConfirmation, &policy)
            .expect("the email comes first");
        assert_eq!(confirmed.owed(), SecondFactor::Enrol);

        let enrolled = confirmed
            .answer(MfaFactor::Totp, &policy)
            .expect("then the factor is set up");
        assert!(enrolled.is_complete());
        assert_eq!(enrolled.assurance_level(), AssuranceLevel::Aal2);
    }

    /// A sign-in that owes a new factor is answered with a recovery code. It
    /// is refused, because a code sets nothing up.
    #[test]
    fn a_recovery_code_does_not_set_a_factor_up() {
        let refused = password_owing(SecondFactor::Enrol)
            .answer(MfaFactor::RecoveryCode, &StepUpPolicy::relaxed());

        assert!(matches!(refused, Err(SignInRefused::NotAccepted { .. })));
    }

    /// Ann lost her phone and uses a recovery code under the strict AAL2
    /// baseline. The code stands in, but she must set up a new factor before
    /// the sign-in is complete.
    #[test]
    fn a_recovery_code_under_a_baseline_it_cannot_meet_leaves_a_factor_to_set_up() {
        let progress = password_owing(SecondFactor::Verify)
            .answer(MfaFactor::RecoveryCode, &StepUpPolicy::strict())
            .expect("a recovery code stands in for a lost factor");

        assert_eq!(progress.owed(), SecondFactor::Enrol);
        assert!(!progress.is_complete());
    }

    /// Under the relaxed AAL1 baseline, Ann's recovery code completes the
    /// sign-in.
    #[test]
    fn a_recovery_code_completes_the_sign_in_where_the_baseline_allows() {
        let progress = password_owing(SecondFactor::Verify)
            .answer(MfaFactor::RecoveryCode, &StepUpPolicy::relaxed())
            .expect("relaxed asks for no more than a password");

        assert!(progress.is_complete());
    }

    /// Under an AAL3 baseline, a TOTP code that reaches only AAL2 is refused.
    #[test]
    fn a_code_under_a_hardware_baseline_is_refused() {
        let refused =
            password_owing(SecondFactor::Verify).answer(MfaFactor::Totp, &hardware_baseline());

        assert!(matches!(refused, Err(SignInRefused::BelowBaseline(_))));
    }

    /// Neither provider MFA nor a provider hardware key can answer any step
    /// owed by a password sign-in.
    #[test]
    fn a_providers_factor_is_never_an_answer() {
        for owed in OWED {
            for factor in [
                MfaFactor::ProviderMultiFactor,
                MfaFactor::ProviderHardwareKey,
            ] {
                let refused = password_owing(owed).answer(factor, &StepUpPolicy::relaxed());

                assert!(
                    matches!(refused, Err(SignInRefused::NotAccepted { .. })),
                    "{owed:?} {factor:?}"
                );
            }
        }
    }

    /// Ann signed in with a password alone and then proves TOTP before a
    /// sensitive action. The sign-in rises to AAL2 and records TOTP.
    #[test]
    fn a_finished_sign_in_is_raised_by_a_stronger_factor() {
        let raised = password_owing(SecondFactor::NotOwed)
            .answer(MfaFactor::Totp, &StepUpPolicy::relaxed())
            .expect("a code lifts a password sign-in");

        assert_eq!(raised.assurance_level(), AssuranceLevel::Aal2);
        assert_eq!(raised.factor(), FactorProved::Proved(MfaFactor::Totp));
    }

    /// Ann's sign-in is already at AAL2 through TOTP. A passkey that would
    /// also give AAL2 is refused as already proved.
    #[test]
    fn a_finished_sign_in_refuses_a_factor_that_would_not_raise_it() {
        let policy = StepUpPolicy::relaxed();
        let raised = password_owing(SecondFactor::NotOwed)
            .answer(MfaFactor::Totp, &policy)
            .expect("the first code lifts it");

        assert_eq!(
            raised.answer(MfaFactor::Passkey, &policy),
            Err(SignInRefused::AlreadyProved)
        );
    }

    /// A stored OIDC sign-in that confirmed by email and still owes a factor
    /// loads back with the same method, factor and owed step.
    #[test]
    fn reconstitute_keeps_what_was_stored() {
        let row = SignInProgressRow {
            method: AuthMethod::Oidc,
            factor: FactorProved::Proved(MfaFactor::EmailConfirmation),
            owed: SecondFactor::Enrol,
        };

        let progress = SignInProgress::reconstitute(row).unwrap();

        assert_eq!(progress.method(), AuthMethod::Oidc);
        assert_eq!(
            progress.factor(),
            FactorProved::Proved(MfaFactor::EmailConfirmation)
        );
        assert_eq!(progress.owed(), SecondFactor::Enrol);
    }

    /// Whether restoring progress rejected the row as corrupt storage.
    fn infrastructure(result: &Result<SignInProgress, DomainError>) -> bool {
        matches!(result, Err(DomainError::Infrastructure(_)))
    }

    /// A stored password sign-in claims a provider's hardware key. No
    /// sign-in reaches that, so it is refused as corrupt.
    #[test]
    fn a_provider_factor_on_a_sign_in_ianua_checked_is_refused_as_corrupt() {
        let row = SignInProgressRow {
            method: AuthMethod::Password,
            factor: FactorProved::Proved(MfaFactor::ProviderHardwareKey),
            owed: SecondFactor::NotOwed,
        };

        assert!(infrastructure(&SignInProgress::reconstitute(row)));
    }

    /// A stored sign-in proved a hardware key yet still owes a step. Each
    /// such row is refused as corrupt.
    #[test]
    fn a_step_owed_after_the_factor_that_settles_it_is_refused_as_corrupt() {
        for owed in [
            SecondFactor::Verify,
            SecondFactor::Enrol,
            SecondFactor::ConfirmByEmail,
            SecondFactor::ConfirmThenEnrol,
        ] {
            let row = SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::Proved(MfaFactor::HardwareKey),
                owed,
            };

            assert!(
                infrastructure(&SignInProgress::reconstitute(row)),
                "{owed:?}"
            );
        }
    }

    /// Every state reached by beginning a sign-in and answering up to three
    /// factors, under three policies, reads back from storage unchanged. The
    /// corrupt-row check refuses only what no sign-in reaches.
    #[test]
    fn every_reachable_progress_reads_back() {
        for policy in policies() {
            let mut frontier = starts(&policy);
            for _ in 0..3 {
                let next: Vec<SignInProgress> = frontier
                    .iter()
                    .flat_map(|progress| {
                        FACTORS
                            .iter()
                            .filter_map(|&factor| progress.answer(factor, &policy).ok())
                    })
                    .collect();
                frontier.extend(next);
            }

            for progress in &frontier {
                let row = SignInProgressRow {
                    method: progress.method(),
                    factor: progress.factor(),
                    owed: progress.owed(),
                };

                assert_eq!(
                    SignInProgress::reconstitute(row).as_ref().ok(),
                    Some(progress)
                );
            }
        }
    }

    fn starts(policy: &StepUpPolicy) -> Vec<SignInProgress> {
        let local = [
            LocalMethod::Password,
            LocalMethod::MagicLink,
            LocalMethod::Passkey,
        ];
        let provided = [
            FactorProved::NoneYet,
            FactorProved::Proved(MfaFactor::ProviderMultiFactor),
            FactorProved::Proved(MfaFactor::ProviderHardwareKey),
        ];
        OWED.iter()
            .flat_map(|&owed| {
                let own = local
                    .iter()
                    .filter_map(move |&method| SignInProgress::begin(method, owed, policy).ok());
                let through = provided.iter().filter_map(move |&factor| {
                    SignInProgress::begin_through_provider(provider(factor), owed, policy).ok()
                });
                own.chain(through).collect::<Vec<_>>()
            })
            .collect()
    }

    /// Every way in, owing anything, is answered by up to three factors in
    /// any order. Whatever ends complete meets the baseline it was checked
    /// against.
    #[test]
    fn no_sequence_of_answers_completes_a_sign_in_below_the_baseline() {
        for policy in policies() {
            let mut frontier = starts(&policy);
            for _ in 0..3 {
                frontier = frontier
                    .iter()
                    .flat_map(|progress| {
                        FACTORS
                            .iter()
                            .filter_map(|&factor| progress.answer(factor, &policy).ok())
                    })
                    .chain(frontier.iter().map(SignInProgress::carried))
                    .collect();
                frontier.sort_by_key(|p| format!("{p:?}"));
                frontier.dedup();
            }

            for progress in frontier.iter().filter(|p| p.is_complete()) {
                assert!(
                    policy.admit(progress.assurance_level()).is_ok(),
                    "{progress:?} under {:?}",
                    policy.baseline_aal()
                );
            }
        }
    }

    /// A password sign-in owes an email confirmation because of a signal.
    /// It is not complete, and every accepted answer records a factor, so it
    /// never completes on the password alone.
    #[test]
    fn a_signal_is_never_completed_without_an_answer() {
        let policy = StepUpPolicy::relaxed();
        for owed in [SecondFactor::ConfirmByEmail, SecondFactor::ConfirmThenEnrol] {
            let progress = password_owing(owed);

            assert!(!progress.is_complete());
            assert_eq!(progress.factor(), FactorProved::NoneYet);
            assert!(
                FACTORS
                    .iter()
                    .filter_map(|&f| progress.answer(f, &policy).ok())
                    .all(|answered| answered.factor() != FactorProved::NoneYet)
            );
        }
    }
}
