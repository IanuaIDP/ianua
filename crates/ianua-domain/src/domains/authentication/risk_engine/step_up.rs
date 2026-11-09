use crate::domains::authentication::mfa::owed::{Demand, Enrolment};
use crate::domains::authentication::risk_engine::assessment::RiskLevel;
use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::two_cases::two_cases;

/// Whether something about a sign-in has been seen before for this person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Familiarity {
    /// Seen before.
    Known,
    /// Not seen before.
    New,
}

/// Whether the action being signed in for is one that needs more assurance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Sensitivity {
    /// An ordinary action.
    Ordinary,
    /// A sensitive action, such as a password change, a role assignment or a
    /// key rotation.
    Sensitive,
}

/// What the request says about where a sign-in comes from and what it is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignInSignals {
    /// Whether the device has been seen before for this person.
    pub device: Familiarity,
    /// Whether the country has been seen before for this person.
    pub country: Familiarity,
    /// Whether the action is a sensitive one.
    pub operation: Sensitivity,
}

two_cases! {
    /// Whether a signal makes a step-up policy ask for a second factor.
    /// Stored as a `require_mfa_*` flag.
    pub enum MfaTrigger {
        /// The signal asks for a second factor.
        Asks => true,
        /// The signal is not considered.
        Ignored => false,
    }
}

/// The settings a [`StepUpPolicy`] is built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepUpPolicyParams {
    /// Minimum assurance required for an ordinary sign-in.
    pub baseline_aal: AssuranceLevel,
    /// Minimum assurance required for a sensitive operation.
    pub sensitive_aal: AssuranceLevel,
    /// Whether a device the person has not trusted asks for a second factor.
    pub new_device: MfaTrigger,
    /// Whether an unfamiliar country asks for a second factor.
    pub new_country: MfaTrigger,
    /// Risk level at which a second factor is asked for, whatever else is
    /// true.
    pub mfa_risk_threshold: RiskLevel,
    /// Risk level at which the sign-in is refused.
    pub deny_risk_threshold: RiskLevel,
}

/// What a [`StepUpPolicy`] reads of a sign-in to decide whether more proof is
/// needed.
///
/// The caller fills it from the request, using the address's location, the
/// device and the person's sign-in history.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthenticationContext {
    /// The assurance level reached so far in this session.
    current_aal: AssuranceLevel,
    /// The sign-in's assessed risk.
    risk_level: RiskLevel,
    /// Whether the device has been seen before for this user.
    device: Familiarity,
    /// Whether the user has signed in from this country before.
    country: Familiarity,
    /// Whether the action is sensitive, such as a password change, a role
    /// assignment or a key rotation.
    sensitive_operation: Sensitivity,
}

impl AuthenticationContext {
    /// A context from the assurance reached, the risk and the signals.
    #[must_use]
    pub fn new(current_aal: AssuranceLevel, risk_level: RiskLevel, signals: SignInSignals) -> Self {
        Self {
            current_aal,
            risk_level,
            device: signals.device,
            country: signals.country,
            sensitive_operation: signals.operation,
        }
    }

    /// The assurance level reached so far.
    #[must_use]
    pub fn current_aal(&self) -> AssuranceLevel {
        self.current_aal
    }

    /// The sign-in's assessed risk.
    #[must_use]
    pub fn risk_level(&self) -> RiskLevel {
        self.risk_level
    }

    /// Whether the device has been seen before.
    #[must_use]
    pub fn is_known_device(&self) -> bool {
        self.device == Familiarity::Known
    }

    /// Whether the country has been seen before.
    #[must_use]
    pub fn is_known_country(&self) -> bool {
        self.country == Familiarity::Known
    }

    /// Whether the action is sensitive.
    #[must_use]
    pub fn is_sensitive_operation(&self) -> bool {
        self.sensitive_operation == Sensitivity::Sensitive
    }
}

/// What a [`StepUpPolicy`] decides for an [`AuthenticationContext`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum StepUpDecision {
    /// The assurance reached is enough. Go ahead.
    Sufficient,
    /// The user must prove a second factor to reach the level asked for.
    MfaRequired,
    /// The user must use a hardware key, for AAL3.
    HardwareKeyRequired,
    /// The risk reached the policy's deny threshold, so the request is
    /// refused.
    Denied,
}

impl StepUpDecision {
    /// Whether the user can go ahead without more proof.
    #[must_use]
    pub fn is_sufficient(&self) -> bool {
        *self == Self::Sufficient
    }

    /// Whether a second factor or a hardware key is asked for.
    #[must_use]
    pub fn requires_step_up(&self) -> bool {
        matches!(self, Self::MfaRequired | Self::HardwareKeyRequired)
    }
}

/// Proof that a sign-in met its tenant's baseline, made only by
/// [`StepUpPolicy::admit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct BaselineMet {
    level: AssuranceLevel,
}

impl BaselineMet {
    /// The level the sign-in reached, at or above the baseline.
    #[must_use]
    pub fn level(self) -> AssuranceLevel {
        self.level
    }
}

/// A sign-in that fell short of its tenant's baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BelowBaseline {
    /// The level the sign-in reached.
    pub reached: AssuranceLevel,
    /// The level the baseline asks for.
    pub required: AssuranceLevel,
}

/// A tenant's rules for when a sign-in or action must give more proof.
///
/// Each tenant sets its own thresholds. A bank may ask for a second factor
/// everywhere. A developer tools tenant may ask only for admin actions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "StepUpPolicyWire"))]
pub struct StepUpPolicy {
    /// Minimum AAL for ordinary actions.
    baseline_aal: AssuranceLevel,
    /// Minimum AAL for sensitive actions, such as a password change, role
    /// management or a key rotation.
    sensitive_aal: AssuranceLevel,
    /// Whether a device not seen before asks for a second factor.
    require_mfa_new_device: MfaTrigger,
    /// Whether a sign-in from a new country asks for a second factor.
    require_mfa_new_country: MfaTrigger,
    /// Risk level at which a second factor is asked for, whatever else is
    /// true.
    mfa_risk_threshold: RiskLevel,
    /// Risk level at which the request is refused.
    deny_risk_threshold: RiskLevel,
}

/// A step-up policy as it arrives, before [`StepUpPolicy::new`] has checked
/// it.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct StepUpPolicyWire {
    baseline_aal: AssuranceLevel,
    sensitive_aal: AssuranceLevel,
    require_mfa_new_device: MfaTrigger,
    require_mfa_new_country: MfaTrigger,
    mfa_risk_threshold: RiskLevel,
    deny_risk_threshold: RiskLevel,
}

#[cfg(feature = "serde")]
impl TryFrom<StepUpPolicyWire> for StepUpPolicy {
    type Error = DomainError;

    /// A policy read from tenant settings or an API body is held to the same
    /// rule as one built in code. A sensitive action never asks for less
    /// assurance than an ordinary one.
    fn try_from(wire: StepUpPolicyWire) -> Result<Self, Self::Error> {
        Self::new(StepUpPolicyParams {
            baseline_aal: wire.baseline_aal,
            sensitive_aal: wire.sensitive_aal,
            new_device: wire.require_mfa_new_device,
            new_country: wire.require_mfa_new_country,
            mfa_risk_threshold: wire.mfa_risk_threshold,
            deny_risk_threshold: wire.deny_risk_threshold,
        })
    }
}

impl StepUpPolicy {
    /// A step-up policy from its settings.
    ///
    /// The two risk thresholds are not checked against each other. Denial is
    /// decided first. So setting them equal, as [`Self::relaxed`] does, means
    /// risk alone never asks for a second factor. That is a valid choice.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when a sensitive action would ask for
    ///   less assurance than an ordinary one. That would make the tenant's
    ///   riskiest actions the easiest to reach.
    pub fn new(params: StepUpPolicyParams) -> Result<Self, DomainError> {
        let StepUpPolicyParams {
            baseline_aal,
            sensitive_aal,
            new_device,
            new_country,
            mfa_risk_threshold,
            deny_risk_threshold,
        } = params;
        if sensitive_aal < baseline_aal {
            return Err(DomainError::invalid(message!(
                "authentication-a-sensitive-operation-cannot-ask-for",
                "a sensitive operation cannot ask for less assurance than an ordinary one"
            )));
        }

        Ok(Self {
            baseline_aal,
            sensitive_aal,
            require_mfa_new_device: new_device,
            require_mfa_new_country: new_country,
            mfa_risk_threshold,
            deny_risk_threshold,
        })
    }

    /// Minimum assurance required for an ordinary sign-in.
    #[must_use]
    pub fn baseline_aal(&self) -> AssuranceLevel {
        self.baseline_aal
    }

    /// Minimum assurance required for a sensitive operation.
    #[must_use]
    pub fn sensitive_aal(&self) -> AssuranceLevel {
        self.sensitive_aal
    }

    /// Admits a sign-in that reached `reached`, when that meets the baseline.
    ///
    /// The returned [`BaselineMet`] can be made nowhere else. So anything
    /// that asks for one, such as completing a sign-in, cannot be reached by
    /// a path that skipped this check.
    ///
    /// # Errors
    ///
    /// - [`BelowBaseline`] when the sign-in falls short. It carries the level
    ///   reached and the level required.
    pub fn admit(&self, reached: AssuranceLevel) -> Result<BaselineMet, BelowBaseline> {
        if !reached.satisfies(self.baseline_aal) {
            return Err(BelowBaseline {
                reached,
                required: self.baseline_aal,
            });
        }
        Ok(BaselineMet { level: reached })
    }

    /// Whether a sign-in at `current` may take a sensitive action.
    ///
    /// Someone with a second factor proves it first when their sign-in is
    /// weaker than [`Self::sensitive_aal`]. Someone with none has nothing
    /// stronger to prove, so their sign-in stands. A second factor is never
    /// demanded of a person who cannot give one.
    ///
    /// # Errors
    ///
    /// - The [`AssuranceLevel`] the action needs, when someone with a second
    ///   factor has a sign-in below it.
    pub fn admits_sensitive_action(
        &self,
        current: AssuranceLevel,
        enrolment: Enrolment,
    ) -> Result<(), AssuranceLevel> {
        if enrolment == Enrolment::NotEnrolled || current.satisfies(self.sensitive_aal) {
            return Ok(());
        }
        Err(self.sensitive_aal)
    }

    /// Whether a device the user has not trusted counts as a risk signal.
    ///
    /// With it on, a device not trusted asks everyone for more proof:
    /// someone without a factor confirms through their mailbox. With it off,
    /// such a device still asks someone who set a factor up for it (see
    /// [`Self::demand`]), and asks nothing of anyone else.
    #[must_use]
    pub fn require_mfa_new_device(&self) -> bool {
        self.require_mfa_new_device == MfaTrigger::Asks
    }

    /// Whether signing in from a new country asks for a second factor.
    #[must_use]
    pub fn require_mfa_new_country(&self) -> bool {
        self.require_mfa_new_country == MfaTrigger::Asks
    }

    /// The risk level from which a second factor is asked for, whatever the
    /// other signals say.
    #[must_use]
    pub fn mfa_risk_threshold(&self) -> RiskLevel {
        self.mfa_risk_threshold
    }

    /// The risk level from which the sign-in is refused outright.
    #[must_use]
    pub fn deny_risk_threshold(&self) -> RiskLevel {
        self.deny_risk_threshold
    }

    /// A relaxed policy for low-security tenants.
    ///
    /// It asks for a second factor only for sensitive actions, and of
    /// someone who set one up on a device they did not trust (see
    /// [`Self::demand`]), and refuses critical risk.
    #[must_use]
    pub fn relaxed() -> Self {
        Self {
            baseline_aal: AssuranceLevel::Aal1,
            sensitive_aal: AssuranceLevel::Aal2,
            require_mfa_new_device: MfaTrigger::Ignored,
            require_mfa_new_country: MfaTrigger::Ignored,
            mfa_risk_threshold: RiskLevel::Critical,
            deny_risk_threshold: RiskLevel::Critical,
        }
    }

    /// [`Self::relaxed`], except that a device the person has not trusted
    /// asks for their second factor.
    ///
    /// Someone who set a factor up is asked for it everywhere except on the
    /// devices they chose to trust.
    #[must_use]
    pub fn untrusted_devices() -> Self {
        Self {
            require_mfa_new_device: MfaTrigger::Asks,
            ..Self::relaxed()
        }
    }

    /// A strict policy for high-security tenants.
    ///
    /// Every action needs AAL2 and sensitive ones AAL3. New devices, new
    /// countries and medium risk ask for a second factor. Critical risk is
    /// refused.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            baseline_aal: AssuranceLevel::Aal2,
            sensitive_aal: AssuranceLevel::Aal3,
            require_mfa_new_device: MfaTrigger::Asks,
            require_mfa_new_country: MfaTrigger::Asks,
            mfa_risk_threshold: RiskLevel::Medium,
            deny_risk_threshold: RiskLevel::Critical,
        }
    }

    /// What this policy decides for `ctx`.
    ///
    /// Risk at or above the deny threshold is refused first. Otherwise the
    /// sign-in is asked for the assurance its action and signals need.
    #[must_use]
    pub fn evaluate(&self, ctx: &AuthenticationContext) -> StepUpDecision {
        if ctx.risk_level() >= self.deny_risk_threshold {
            return StepUpDecision::Denied;
        }
        Self::decision_for_aal(self.asked_aal(ctx), ctx.current_aal())
    }

    /// Why this sign-in is asked for a second factor, if it is. That is a
    /// risk signal, the policy alone, both, or nothing.
    ///
    /// It reads the same thresholds as [`Self::evaluate`], so the two never
    /// disagree. What someone without a factor is then asked to do depends
    /// on it. See [`FactorOwed::under`]. A signal must be answered with
    /// something the password alone cannot give.
    ///
    /// Where nothing else asks, a device the person did not trust still asks
    /// for their own factor ([`Demand::OwnFactor`]): someone who set one up
    /// uses it at every sign-in except on a device they chose to remember,
    /// whatever the policy says about new devices. Someone without a factor
    /// is asked nothing more for it, so a stolen password alone never gets
    /// past a factor its owner set up.
    ///
    /// | signal | policy | device | demand          |
    /// |--------|--------|--------|-----------------|
    /// | asks   | asks   | any    | SignalAndPolicy |
    /// | asks   | -      | any    | Signal          |
    /// | -      | asks   | any    | Policy          |
    /// | -      | -      | New    | OwnFactor       |
    /// | -      | -      | Known  | NotAsked        |
    ///
    /// [`FactorOwed::under`]: crate::domains::authentication::mfa::owed::FactorOwed::under
    #[must_use]
    pub fn demand(&self, ctx: &AuthenticationContext) -> Demand {
        let current = ctx.current_aal();
        let policy_asks = !current.satisfies(self.required_aal(ctx));
        let signal_asks = self.signal_fired(ctx) && !current.satisfies(self.asked_aal(ctx));
        match (signal_asks, policy_asks, ctx.device) {
            (true, true, _) => Demand::SignalAndPolicy,
            (true, false, _) => Demand::Signal,
            (false, true, _) => Demand::Policy,
            (false, false, Familiarity::New) => Demand::OwnFactor,
            (false, false, Familiarity::Known) => Demand::NotAsked,
        }
    }

    /// What the action itself needs, before any signal.
    fn required_aal(&self, ctx: &AuthenticationContext) -> AssuranceLevel {
        if ctx.is_sensitive_operation() {
            return self.sensitive_aal;
        }
        self.baseline_aal
    }

    /// The assurance this sign-in is asked for. It is what the action needs,
    /// raised to at least AAL2 when a signal fired.
    fn asked_aal(&self, ctx: &AuthenticationContext) -> AssuranceLevel {
        let required = self.required_aal(ctx);
        if self.signal_fired(ctx) {
            return AssuranceLevel::Aal2.max(required);
        }
        required
    }

    /// Whether a risk signal asks for a second factor. That is when the risk
    /// reached the threshold, or the device or country is new and the policy
    /// asks on that.
    fn signal_fired(&self, ctx: &AuthenticationContext) -> bool {
        ctx.risk_level() >= self.mfa_risk_threshold
            || (self.require_mfa_new_device() && !ctx.is_known_device())
            || (self.require_mfa_new_country() && !ctx.is_known_country())
    }

    /// The decision for a sign-in at `current` that is asked for `required`.
    fn decision_for_aal(required: AssuranceLevel, current: AssuranceLevel) -> StepUpDecision {
        if current.satisfies(required) {
            return StepUpDecision::Sufficient;
        }

        if required >= AssuranceLevel::Aal3 {
            return StepUpDecision::HardwareKeyRequired;
        }

        StepUpDecision::MfaRequired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::methods::MfaPolicy;
    use crate::domains::authentication::mfa::owed::FactorOwed;
    use crate::domains::identity::account::address::MailReach;
    use crate::domains::identity::account::vouching::Vouching;

    /// Ann has TOTP and signed in with a password alone. A sensitive action
    /// asks her for AAL2. Once she reaches AAL2, it is allowed.
    #[test]
    fn someone_with_a_second_factor_proves_it_for_a_sensitive_action() {
        let policy = StepUpPolicy::relaxed();

        assert_eq!(
            policy.admits_sensitive_action(AssuranceLevel::Aal1, Enrolment::Enrolled),
            Err(AssuranceLevel::Aal2)
        );
        assert_eq!(
            policy.admits_sensitive_action(AssuranceLevel::Aal2, Enrolment::Enrolled),
            Ok(())
        );
    }

    /// Bob has no second factor and signed in at AAL1. A sensitive action is
    /// allowed, because he has nothing stronger to prove.
    #[test]
    fn someone_without_a_second_factor_is_not_asked_for_one() {
        let policy = StepUpPolicy::relaxed();

        assert_eq!(
            policy.admits_sensitive_action(AssuranceLevel::Aal1, Enrolment::NotEnrolled),
            Ok(())
        );
    }

    /// Under the strict policy, a sign-in at AAL1 is refused. The refusal
    /// says it reached AAL1 and AAL2 is required.
    #[test]
    fn a_sign_in_below_the_baseline_is_not_admitted() {
        let policy = StepUpPolicy::strict();

        assert_eq!(
            policy.admit(AssuranceLevel::Aal1),
            Err(BelowBaseline {
                reached: AssuranceLevel::Aal1,
                required: AssuranceLevel::Aal2,
            })
        );
    }

    /// Under the strict policy, a sign-in at AAL2 is admitted and records
    /// AAL2 as the level it reached.
    #[test]
    fn a_sign_in_at_the_baseline_is_admitted_at_the_level_it_reached() {
        let policy = StepUpPolicy::strict();

        let admitted = policy.admit(AssuranceLevel::Aal2).map(BaselineMet::level);

        assert_eq!(admitted, Ok(AssuranceLevel::Aal2));
    }

    /// Under the relaxed policy, a sign-in with a hardware key is admitted at
    /// AAL3, not cut down to the AAL1 baseline.
    #[test]
    fn a_sign_in_above_the_baseline_keeps_the_higher_level() {
        let policy = StepUpPolicy::relaxed();

        let admitted = policy.admit(AssuranceLevel::Aal3).map(BaselineMet::level);

        assert_eq!(admitted, Ok(AssuranceLevel::Aal3));
    }

    /// Under the strict policy, a sign-in at AAL2 is admitted although
    /// sensitive actions need AAL3. The sensitive level is asked when such
    /// an action is taken, not at sign-in.
    #[test]
    fn admission_does_not_ask_for_the_sensitive_level() {
        let policy = StepUpPolicy::strict();

        assert!(policy.admit(AssuranceLevel::Aal2).is_ok());
        assert!(policy.sensitive_aal() > AssuranceLevel::Aal2);
    }

    /// A context built at AAL1, low risk, a known device and country and an
    /// ordinary action reports each of those back.
    #[test]
    fn a_sign_in_context_reports_what_it_was_built_from() {
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal1,
            RiskLevel::Low,
            SignInSignals {
                device: Familiarity::Known,
                country: Familiarity::Known,
                operation: Sensitivity::Ordinary,
            },
        );
        assert_eq!(ctx.current_aal(), AssuranceLevel::Aal1);
        assert_eq!(ctx.risk_level(), RiskLevel::Low);
        assert!(ctx.is_known_device());
        assert!(ctx.is_known_country());
        assert!(!ctx.is_sensitive_operation());
    }

    /// A sufficient decision lets the user go ahead and asks for nothing
    /// more.
    #[test]
    fn sufficient_does_not_require_step_up() {
        assert!(StepUpDecision::Sufficient.is_sufficient());
        assert!(!StepUpDecision::Sufficient.requires_step_up());
    }

    /// A decision asking for MFA is not sufficient and counts as a step-up.
    #[test]
    fn mfa_required_requires_step_up() {
        assert!(!StepUpDecision::MfaRequired.is_sufficient());
        assert!(StepUpDecision::MfaRequired.requires_step_up());
    }

    /// A decision asking for a hardware key counts as a step-up.
    #[test]
    fn hardware_key_requires_step_up() {
        assert!(StepUpDecision::HardwareKeyRequired.requires_step_up());
    }

    /// A denied request is neither sufficient nor a step-up. No extra proof
    /// can turn it into a yes.
    #[test]
    fn denied_is_not_sufficient() {
        assert!(!StepUpDecision::Denied.is_sufficient());
        assert!(!StepUpDecision::Denied.requires_step_up());
    }

    /// Under the relaxed policy, Ann signs in with a password from a known
    /// device and country for an ordinary action. Nothing more is asked.
    #[test]
    fn relaxed_allows_password_only_for_normal_ops() {
        let policy = StepUpPolicy::relaxed();
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal1,
            RiskLevel::Low,
            SignInSignals {
                device: Familiarity::Known,
                country: Familiarity::Known,
                operation: Sensitivity::Ordinary,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::Sufficient);
    }

    /// Under the untrusted-devices policy, Ann's password sign-in asks for
    /// MFA on a new device and nothing on a trusted one.
    #[test]
    fn untrusted_devices_asks_only_on_a_device_not_trusted() {
        let policy = StepUpPolicy::untrusted_devices();
        let on = |device| {
            policy.evaluate(&AuthenticationContext::new(
                AssuranceLevel::Aal1,
                RiskLevel::Low,
                SignInSignals {
                    device,
                    country: Familiarity::Known,
                    operation: Sensitivity::Ordinary,
                },
            ))
        };

        assert_eq!(on(Familiarity::New), StepUpDecision::MfaRequired);
        assert_eq!(on(Familiarity::Known), StepUpDecision::Sufficient);
    }

    /// Under the relaxed policy, a password-only session that tries a
    /// sensitive action is asked for MFA.
    #[test]
    fn relaxed_requires_mfa_for_sensitive_ops() {
        let policy = StepUpPolicy::relaxed();
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal1,
            RiskLevel::Low,
            SignInSignals {
                device: Familiarity::Known,
                country: Familiarity::Known,
                operation: Sensitivity::Sensitive,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::MfaRequired);
    }

    /// Under the relaxed policy, a session at AAL2 may take a sensitive
    /// action with nothing more asked.
    #[test]
    fn relaxed_allows_mfa_user_for_sensitive_ops() {
        let policy = StepUpPolicy::relaxed();
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal2,
            RiskLevel::Low,
            SignInSignals {
                device: Familiarity::Known,
                country: Familiarity::Known,
                operation: Sensitivity::Sensitive,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::Sufficient);
    }

    /// Under the relaxed policy, a password sign-in from a new device asks
    /// for nothing more, because that policy ignores devices.
    #[test]
    fn relaxed_ignores_new_device() {
        let policy = StepUpPolicy::relaxed();
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal1,
            RiskLevel::Low,
            SignInSignals {
                device: Familiarity::New,
                country: Familiarity::Known,
                operation: Sensitivity::Ordinary,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::Sufficient);
    }

    /// Under the strict policy, a password-only sign-in for an ordinary
    /// action is asked for MFA, because the baseline is AAL2.
    #[test]
    fn strict_requires_mfa_baseline() {
        let policy = StepUpPolicy::strict();
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal1,
            RiskLevel::Low,
            SignInSignals {
                device: Familiarity::Known,
                country: Familiarity::Known,
                operation: Sensitivity::Ordinary,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::MfaRequired);
    }

    /// Under the strict policy, a session at AAL2 may take an ordinary
    /// action.
    #[test]
    fn strict_allows_aal2_for_normal_ops() {
        let policy = StepUpPolicy::strict();
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal2,
            RiskLevel::Low,
            SignInSignals {
                device: Familiarity::Known,
                country: Familiarity::Known,
                operation: Sensitivity::Ordinary,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::Sufficient);
    }

    /// Under the strict policy, a session at AAL2 that tries a sensitive
    /// action is asked for a hardware key.
    #[test]
    fn strict_requires_hardware_for_sensitive_ops() {
        let policy = StepUpPolicy::strict();
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal2,
            RiskLevel::Low,
            SignInSignals {
                device: Familiarity::Known,
                country: Familiarity::Known,
                operation: Sensitivity::Sensitive,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::HardwareKeyRequired);
    }

    /// Under the strict policy, a session at AAL3 may take a sensitive
    /// action.
    #[test]
    fn strict_allows_aal3_for_sensitive_ops() {
        let policy = StepUpPolicy::strict();
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal3,
            RiskLevel::Low,
            SignInSignals {
                device: Familiarity::Known,
                country: Familiarity::Known,
                operation: Sensitivity::Sensitive,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::Sufficient);
    }

    /// Under the strict policy, a password sign-in from a new device is
    /// asked for MFA.
    #[test]
    fn strict_requires_mfa_on_new_device() {
        let policy = StepUpPolicy::strict();
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal1,
            RiskLevel::Low,
            SignInSignals {
                device: Familiarity::New,
                country: Familiarity::Known,
                operation: Sensitivity::Ordinary,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::MfaRequired);
    }

    /// Under the strict policy, a password sign-in from a new country is
    /// asked for MFA.
    #[test]
    fn strict_requires_mfa_on_new_country() {
        let policy = StepUpPolicy::strict();
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal1,
            RiskLevel::Low,
            SignInSignals {
                device: Familiarity::Known,
                country: Familiarity::New,
                operation: Sensitivity::Ordinary,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::MfaRequired);
    }

    //
    // The strict-policy cases above reach the right answer for the wrong
    // reason: strict asks for Aal2 at baseline, so a password-only session is
    // told to step up whether or not the device rule ran. These use a policy
    // whose baseline the session already satisfies, leaving the device and
    // country rules as the only thing that can change the verdict.

    fn baseline_aal1(require_new_device: bool, require_new_country: bool) -> StepUpPolicy {
        StepUpPolicy::new(StepUpPolicyParams {
            baseline_aal: AssuranceLevel::Aal1,
            sensitive_aal: AssuranceLevel::Aal2,
            new_device: if require_new_device {
                MfaTrigger::Asks
            } else {
                MfaTrigger::Ignored
            },
            new_country: if require_new_country {
                MfaTrigger::Asks
            } else {
                MfaTrigger::Ignored
            },
            mfa_risk_threshold: RiskLevel::Critical,
            deny_risk_threshold: RiskLevel::Critical,
        })
        .expect("a sensitive level above the baseline is valid")
    }

    /// A policy built with the device rule on and the country rule off
    /// reports exactly that, and the other way round. A tenant's settings
    /// screen reads these getters, while `evaluate` reads the fields.
    #[test]
    fn the_policy_reports_the_rules_it_was_built_with() {
        let policy = baseline_aal1(true, false);
        assert!(policy.require_mfa_new_device());
        assert!(!policy.require_mfa_new_country());

        let policy = baseline_aal1(false, true);
        assert!(!policy.require_mfa_new_device());
        assert!(policy.require_mfa_new_country());
    }

    /// The baseline is AAL1 and the device rule is on. Ann's password
    /// sign-in from a new device is asked for MFA, so the device rule alone
    /// made the difference.
    #[test]
    fn a_new_device_forces_mfa_where_the_baseline_alone_would_pass() {
        let policy = baseline_aal1(true, false);
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal1,
            RiskLevel::Low,
            SignInSignals {
                device: Familiarity::New,
                country: Familiarity::Known,
                operation: Sensitivity::Ordinary,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::MfaRequired);
    }

    /// With the same policy, Ann's password sign-in from a known device asks
    /// for nothing more.
    #[test]
    fn a_known_device_passes_under_the_same_policy() {
        let policy = baseline_aal1(true, false);
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal1,
            RiskLevel::Low,
            SignInSignals {
                device: Familiarity::Known,
                country: Familiarity::Known,
                operation: Sensitivity::Ordinary,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::Sufficient);
    }

    /// With the device rule off, a password sign-in from a new device asks
    /// for nothing more.
    #[test]
    fn a_new_device_passes_when_the_device_rule_is_off() {
        let policy = baseline_aal1(false, false);
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal1,
            RiskLevel::Low,
            SignInSignals {
                device: Familiarity::New,
                country: Familiarity::Known,
                operation: Sensitivity::Ordinary,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::Sufficient);
    }

    /// The baseline is AAL1 and the country rule is on. Ann's password
    /// sign-in from a new country is asked for MFA, so the country rule alone
    /// made the difference.
    #[test]
    fn a_new_country_forces_mfa_where_the_baseline_alone_would_pass() {
        let policy = baseline_aal1(false, true);
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal1,
            RiskLevel::Low,
            SignInSignals {
                device: Familiarity::Known,
                country: Familiarity::New,
                operation: Sensitivity::Ordinary,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::MfaRequired);
    }

    /// With the same policy, Ann's password sign-in from a known country asks
    /// for nothing more.
    #[test]
    fn a_known_country_passes_under_the_same_policy() {
        let policy = baseline_aal1(false, true);
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal1,
            RiskLevel::Low,
            SignInSignals {
                device: Familiarity::Known,
                country: Familiarity::Known,
                operation: Sensitivity::Ordinary,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::Sufficient);
    }

    /// With the country rule off, a password sign-in from a new country asks
    /// for nothing more.
    #[test]
    fn a_new_country_passes_when_the_country_rule_is_off() {
        let policy = baseline_aal1(false, false);
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal1,
            RiskLevel::Low,
            SignInSignals {
                device: Familiarity::Known,
                country: Familiarity::New,
                operation: Sensitivity::Ordinary,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::Sufficient);
    }

    fn password_only(device: Familiarity) -> AuthenticationContext {
        AuthenticationContext::new(
            AssuranceLevel::Aal1,
            RiskLevel::Low,
            SignInSignals {
                device,
                country: Familiarity::Known,
                operation: Sensitivity::Ordinary,
            },
        )
    }

    /// The baseline is AAL1 and Ann signs in from a new device. The factor
    /// is asked because of the signal, and is reported that way.
    #[test]
    fn a_signal_alone_is_reported_as_a_signal() {
        let policy = baseline_aal1(true, false);

        assert_eq!(
            policy.demand(&password_only(Familiarity::New)),
            Demand::Signal
        );
    }

    /// Under the strict policy, Ann signs in with a password from a known
    /// device. The factor is asked because of the AAL2 baseline, and is
    /// reported as the policy.
    #[test]
    fn the_baseline_alone_is_reported_as_the_policy() {
        let policy = StepUpPolicy::strict();

        assert_eq!(
            policy.demand(&password_only(Familiarity::Known)),
            Demand::Policy
        );
    }

    /// Under the strict policy, Ann signs in from a new device. Both the
    /// signal and the policy are reported. Reporting only the signal would
    /// let someone with no factor confirm by email and finish below AAL2.
    #[test]
    fn a_signal_under_a_baseline_that_needs_a_factor_reports_both() {
        let policy = StepUpPolicy::strict();

        assert_eq!(
            policy.demand(&password_only(Familiarity::New)),
            Demand::SignalAndPolicy
        );
    }

    /// Under the relaxed policy, which ignores new devices as a signal, Pat
    /// signs in with a password from a device she never remembered. Her own
    /// factor is asked; from a device she remembered, nothing is.
    #[test]
    fn a_device_not_trusted_asks_for_the_persons_own_factor() {
        let policy = StepUpPolicy::relaxed();

        assert_eq!(
            policy.demand(&password_only(Familiarity::New)),
            Demand::OwnFactor
        );
        assert_eq!(
            policy.demand(&password_only(Familiarity::Known)),
            Demand::NotAsked
        );
    }

    /// Under the relaxed optional policy, an enrolled factor is required only
    /// on a new device. Unenrolled accounts owe no factor on either device,
    /// with or without mail availability.
    #[test]
    fn an_enrolled_person_owes_their_factor_except_on_a_trusted_device() {
        let policy = StepUpPolicy::relaxed();
        let cells = [
            (Familiarity::New, Enrolment::Enrolled, FactorOwed::Verify),
            (Familiarity::Known, Enrolment::Enrolled, FactorOwed::NotOwed),
            (
                Familiarity::New,
                Enrolment::NotEnrolled,
                FactorOwed::NotOwed,
            ),
            (
                Familiarity::Known,
                Enrolment::NotEnrolled,
                FactorOwed::NotOwed,
            ),
        ];

        for (device, enrolment, expected) in cells {
            for mail in [MailReach::Available, MailReach::NotSetUp] {
                let owed = FactorOwed::under(
                    MfaPolicy::Optional,
                    policy.demand(&password_only(device)),
                    enrolment,
                    mail,
                    Vouching::Absent,
                );

                assert_eq!(owed, expected, "{device:?} {enrolment:?} {mail:?}");
            }
        }
    }

    /// The baseline is AAL1 and Ann signs in from a known device. Nothing is
    /// asked.
    #[test]
    fn nothing_is_asked_of_a_session_that_already_meets_everything() {
        let policy = baseline_aal1(true, false);

        assert_eq!(
            policy.demand(&password_only(Familiarity::Known)),
            Demand::NotAsked
        );
    }

    /// Under the strict policy, a sign-in rated medium risk is asked for
    /// MFA.
    #[test]
    fn medium_risk_forces_mfa_on_strict() {
        let policy = StepUpPolicy::strict();
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal1,
            RiskLevel::Medium,
            SignInSignals {
                device: Familiarity::Known,
                country: Familiarity::Known,
                operation: Sensitivity::Ordinary,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::MfaRequired);
    }

    /// Critical risk is denied under the strict policy even with AAL3 assurance.
    #[test]
    fn critical_risk_denies_on_strict() {
        let policy = StepUpPolicy::strict();
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal3,
            RiskLevel::Critical,
            SignInSignals {
                device: Familiarity::Known,
                country: Familiarity::Known,
                operation: Sensitivity::Ordinary,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::Denied);
    }

    /// Under the relaxed policy too, a critical-risk sign-in at AAL3 is
    /// refused.
    #[test]
    fn critical_risk_denies_on_relaxed() {
        let policy = StepUpPolicy::relaxed();
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal3,
            RiskLevel::Critical,
            SignInSignals {
                device: Familiarity::Known,
                country: Familiarity::Known,
                operation: Sensitivity::Ordinary,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::Denied);
    }

    /// Under the relaxed policy, both thresholds are Critical. A high-risk
    /// sign-in at AAL2 is neither refused nor asked for more.
    #[test]
    fn high_risk_does_not_deny_on_relaxed() {
        let policy = StepUpPolicy::relaxed();
        let ctx = AuthenticationContext::new(
            AssuranceLevel::Aal2,
            RiskLevel::High,
            SignInSignals {
                device: Familiarity::Known,
                country: Familiarity::Known,
                operation: Sensitivity::Ordinary,
            },
        );
        assert_eq!(policy.evaluate(&ctx), StepUpDecision::Sufficient);
    }

    /// Each of the four decisions written to JSON reads back as itself.
    #[cfg(feature = "serde")]
    #[test]
    fn decision_roundtrips_through_json() {
        for decision in [
            StepUpDecision::Sufficient,
            StepUpDecision::MfaRequired,
            StepUpDecision::HardwareKeyRequired,
            StepUpDecision::Denied,
        ] {
            let json = serde_json::to_string(&decision).unwrap();
            let restored: StepUpDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(decision, restored);
        }
    }

    /// The strict policy written to JSON reads back equal, so stored tenant
    /// settings survive a reload.
    #[cfg(feature = "serde")]
    #[test]
    fn policy_roundtrips_through_json() {
        let policy = StepUpPolicy::strict();
        let json = serde_json::to_string(&policy).unwrap();
        let restored: StepUpPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, policy);
    }

    /// Deserialization rejects a sensitive-action assurance level below the ordinary sign-in baseline.
    #[cfg(feature = "serde")]
    #[test]
    fn a_policy_asking_less_for_sensitive_actions_is_refused_on_deserialize() {
        let mut json = serde_json::to_value(StepUpPolicy::strict()).unwrap();
        json["sensitive_aal"] = serde_json::to_value(AssuranceLevel::Aal1).unwrap();

        assert!(serde_json::from_value::<StepUpPolicy>(json).is_err());
    }
}
