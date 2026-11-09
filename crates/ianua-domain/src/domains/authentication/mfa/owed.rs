//! What a sign-in still owes in the way of a second factor.

use crate::domains::authentication::methods::MfaPolicy;
use crate::domains::identity::account::address::MailReach;
use crate::domains::identity::account::vouching::Vouching;
use crate::types::PersonProof;

/// Whether a sign-in may go straight in, must prove a second factor, or must
/// first set one up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondFactor {
    /// Nothing more is asked.
    NotOwed,
    /// The person has a second factor and must use it.
    Verify,
    /// A second factor is demanded and the person has none. They set one up
    /// before they are let in. On a deployment with no mail server, this is
    /// also what a risk signal asks of someone without a factor on the
    /// first sign-in a trusted route vouches for.
    Enrol,
    /// Something about the sign-in asked for more proof, and the person has
    /// no factor to give it with. Setting one up there and then would prove
    /// nothing, since whoever holds the password could add their own. So the
    /// person confirms through a link sent to their verified address. Only
    /// owed where a mail can reach them.
    ConfirmByEmail,
    /// As [`Self::ConfirmByEmail`], under a policy that requires a second
    /// factor. The person first confirms through their verified address, and
    /// only then sets up the factor the policy demands.
    ConfirmThenEnrol,
}

/// What a password sign-in owes in the way of a second factor, or that
/// nothing the person could give is enough.
///
/// It is [`SecondFactor`] with one more answer. A session only ever owes a
/// [`SecondFactor`], so [`Self::owed`] turns a refusal into an error before
/// any session begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactorOwed {
    /// As [`SecondFactor::NotOwed`].
    NotOwed,
    /// As [`SecondFactor::Verify`].
    Verify,
    /// As [`SecondFactor::Enrol`].
    Enrol,
    /// As [`SecondFactor::ConfirmByEmail`].
    ConfirmByEmail,
    /// As [`SecondFactor::ConfirmThenEnrol`].
    ConfirmThenEnrol,
    /// Something about the sign-in asked for more proof, the person has no
    /// factor, no mail can reach them, and no trusted route vouches for
    /// them. Setting a factor up there and then would let whoever holds the
    /// password add their own, so the sign-in is refused.
    Refused,
}

/// A sign-in refused because the person has nothing to answer its risk
/// with: no second factor, no mail that could reach them, and no trusted
/// route vouching for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the sign-in needs more proof than the account can give")]
pub struct NothingToProveWith;

/// Whether a second factor is asked of a sign-in, and why.
///
/// The reason decides what someone without a factor is asked to do, so it
/// is never reduced to a plain "asked". A factor the policy demands is set
/// up as part of joining. A factor a risk signal demands must be answered
/// with something the password alone cannot give.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Demand {
    /// The policy asks every sign-in for a second factor.
    Policy,
    /// Something about this sign-in asked, such as a new device, a new
    /// country, a raised risk or a breached password.
    Signal,
    /// A signal asked, and the policy needs a second factor anyway. Someone
    /// without one answers the signal and still sets one up.
    SignalAndPolicy,
    /// Nothing else asks, but someone who set a factor up uses it: on a
    /// device they did not trust, or wherever a sign-in can use it. Someone
    /// without one is asked nothing more for it.
    OwnFactor,
    /// Nothing more is asked.
    NotAsked,
}

impl Demand {
    /// The demand once a further signal asks too, such as a breached
    /// password. Whatever the policy needed still stands.
    #[must_use]
    pub fn with_signal(self) -> Self {
        match self {
            Self::Policy | Self::SignalAndPolicy => Self::SignalAndPolicy,
            Self::Signal | Self::OwnFactor | Self::NotAsked => Self::Signal,
        }
    }

    /// The demand once a trusted route answered its signal. Whatever the
    /// policy needed still stands. Where `mail` says no mail goes out, the
    /// signal still asks for a factor to be set up, as the policy would:
    /// nothing else could answer the next one.
    fn answered_by_route(self, mail: MailReach) -> Self {
        match (self, mail) {
            (Self::Signal, MailReach::Available) => Self::NotAsked,
            (Self::Signal, MailReach::NotSetUp)
            | (Self::SignalAndPolicy | Self::Policy, MailReach::Available | MailReach::NotSetUp) => {
                Self::Policy
            }
            (Self::OwnFactor | Self::NotAsked, MailReach::Available | MailReach::NotSetUp) => self,
        }
    }
}

/// Whether the person has a second factor set up.
///
/// Read it from [`HeldFactors::enrolment`], which counts every kind of
/// factor. A caller that counted only some would let a person who holds a
/// passkey skip the proof their passkey could give.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enrolment {
    /// They have one and can use it.
    Enrolled,
    /// They have none.
    NotEnrolled,
}

/// Whether a person holds a factor answered with a code: an authenticator
/// app, or codes mailed or texted to them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeFactorHolding {
    /// A confirmed enrollment, of any kind.
    Active,
    /// None, or one that was never confirmed.
    None,
}

/// Every second factor a person holds. It decides whether they are
/// enrolled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldFactors {
    code_factor: CodeFactorHolding,
    passkeys: usize,
}

impl HeldFactors {
    /// The factors held, as an enrollment in force or none, and a passkey
    /// count.
    #[must_use]
    pub fn new(code_factor: CodeFactorHolding, passkeys: usize) -> Self {
        Self {
            code_factor,
            passkeys,
        }
    }

    /// Enrolled when they hold any factor at all, a passkey included.
    #[must_use]
    pub fn enrolment(&self) -> Enrolment {
        if self.code_factor == CodeFactorHolding::Active || self.passkeys > 0 {
            return Enrolment::Enrolled;
        }
        Enrolment::NotEnrolled
    }
}

impl FactorOwed {
    /// Determines password sign-in requirements from policy, demand and available proof.
    /// With mail and no fresh vouching: disabled policy confirms risk by email and otherwise
    /// owes nothing. Required policy verifies enrolled factors, confirms then enrolls risky
    /// unenrolled accounts, and otherwise enrolls them. Optional policy verifies enrolled
    /// factors when asked; unenrolled accounts confirm risk by email, confirm then enroll
    /// for combined risk and policy, enroll for policy alone, and otherwise owe nothing.
    /// Without mail, email confirmation requires an existing factor or refuses sign-in.
    /// Fresh vouching for an unenrolled account answers risk but keeps policy requirements:
    /// disabled owes nothing; required enrolls; optional enrolls for policy demands or risk
    /// without mail, and otherwise owes nothing. Enrolled accounts ignore vouching.
    /// Every policy, demand and route is matched exhaustively.
    #[must_use]
    pub fn under(
        policy: MfaPolicy,
        demand: Demand,
        enrolment: Enrolment,
        mail: MailReach,
        vouching: Vouching,
    ) -> Self {
        match (enrolment, vouching) {
            (Enrolment::NotEnrolled, Vouching::Fresh) => Self::vouched(policy, demand, mail),
            (Enrolment::NotEnrolled, Vouching::Absent)
            | (Enrolment::Enrolled, Vouching::Fresh | Vouching::Absent) => {
                let owed = SecondFactor::with_mail(policy, demand, enrolment);
                Self::of(owed).reached_by(mail, enrolment)
            }
        }
    }

    /// The answer for someone without a factor whom a trusted route just
    /// vouched for: its signal answered by the route.
    fn vouched(policy: MfaPolicy, demand: Demand, mail: MailReach) -> Self {
        let answered = demand.answered_by_route(mail);
        let owed = SecondFactor::with_mail(policy, answered, Enrolment::NotEnrolled);
        Self::of(owed)
    }

    /// The same answer as `factor`.
    fn of(factor: SecondFactor) -> Self {
        match factor {
            SecondFactor::NotOwed => Self::NotOwed,
            SecondFactor::Verify => Self::Verify,
            SecondFactor::Enrol => Self::Enrol,
            SecondFactor::ConfirmByEmail => Self::ConfirmByEmail,
            SecondFactor::ConfirmThenEnrol => Self::ConfirmThenEnrol,
        }
    }

    /// This answer where `mail` says whether a confirmation link can reach
    /// the person, who holds a factor as `enrolment` says. Without mail,
    /// someone with a factor proves it, and someone without one is refused.
    fn reached_by(self, mail: MailReach, enrolment: Enrolment) -> Self {
        match (self, mail, enrolment) {
            (
                Self::ConfirmByEmail | Self::ConfirmThenEnrol,
                MailReach::NotSetUp,
                Enrolment::Enrolled,
            ) => Self::Verify,
            (
                Self::ConfirmByEmail | Self::ConfirmThenEnrol,
                MailReach::NotSetUp,
                Enrolment::NotEnrolled,
            ) => Self::Refused,
            (
                Self::ConfirmByEmail | Self::ConfirmThenEnrol,
                MailReach::Available,
                Enrolment::Enrolled | Enrolment::NotEnrolled,
            )
            | (
                Self::NotOwed | Self::Verify | Self::Enrol | Self::Refused,
                MailReach::Available | MailReach::NotSetUp,
                Enrolment::Enrolled | Enrolment::NotEnrolled,
            ) => self,
        }
    }

    /// What the sign-in's session owes.
    ///
    /// # Errors
    ///
    /// - [`NothingToProveWith`] when the answer is [`Self::Refused`]: no
    ///   session may begin.
    pub fn owed(self) -> Result<SecondFactor, NothingToProveWith> {
        match self {
            Self::NotOwed => Ok(SecondFactor::NotOwed),
            Self::Verify => Ok(SecondFactor::Verify),
            Self::Enrol => Ok(SecondFactor::Enrol),
            Self::ConfirmByEmail => Ok(SecondFactor::ConfirmByEmail),
            Self::ConfirmThenEnrol => Ok(SecondFactor::ConfirmThenEnrol),
            Self::Refused => Err(NothingToProveWith),
        }
    }

    /// What answering it shows about the person beyond their password.
    ///
    /// | answer           | shows      |
    /// |------------------|------------|
    /// | NotOwed          | Nothing    |
    /// | Enrol            | Nothing    |
    /// | ConfirmByEmail   | Mailbox    |
    /// | ConfirmThenEnrol | Mailbox    |
    /// | Verify           | OwnFactor  |
    /// | Refused          | Refused    |
    ///
    /// Setting a factor up shows nothing at the sign-in that does it, since
    /// whoever holds the password could add their own.
    #[must_use]
    pub fn proof(self) -> PersonProof {
        match self {
            Self::NotOwed | Self::Enrol => PersonProof::Nothing,
            Self::ConfirmByEmail | Self::ConfirmThenEnrol => PersonProof::Mailbox,
            Self::Verify => PersonProof::OwnFactor,
            Self::Refused => PersonProof::Refused,
        }
    }
}

impl SecondFactor {
    /// The answer of the main table on [`FactorOwed::under`], where a mail
    /// can reach the person and nothing vouches for them.
    fn with_mail(policy: MfaPolicy, demand: Demand, enrolment: Enrolment) -> Self {
        match policy {
            MfaPolicy::Disabled => Self::with_factors_off(demand),
            MfaPolicy::Optional => Self::with_factors_optional(demand, enrolment),
            MfaPolicy::Required => Self::with_factors_required(demand, enrolment),
        }
    }

    /// The disabled rows of the table. Only a signal is answered, by email.
    fn with_factors_off(demand: Demand) -> Self {
        match demand {
            Demand::Signal | Demand::SignalAndPolicy => Self::ConfirmByEmail,
            Demand::Policy | Demand::OwnFactor | Demand::NotAsked => Self::NotOwed,
        }
    }

    /// The optional rows of the table.
    fn with_factors_optional(demand: Demand, enrolment: Enrolment) -> Self {
        match (demand, enrolment) {
            (Demand::NotAsked, Enrolment::Enrolled | Enrolment::NotEnrolled)
            | (Demand::OwnFactor, Enrolment::NotEnrolled) => Self::NotOwed,
            (
                Demand::Signal | Demand::SignalAndPolicy | Demand::Policy | Demand::OwnFactor,
                Enrolment::Enrolled,
            ) => Self::Verify,
            (Demand::Signal, Enrolment::NotEnrolled) => Self::ConfirmByEmail,
            (Demand::SignalAndPolicy, Enrolment::NotEnrolled) => Self::ConfirmThenEnrol,
            (Demand::Policy, Enrolment::NotEnrolled) => Self::Enrol,
        }
    }

    /// The required rows of the table. Whoever has a factor uses it.
    fn with_factors_required(demand: Demand, enrolment: Enrolment) -> Self {
        match (demand, enrolment) {
            (
                Demand::Signal
                | Demand::SignalAndPolicy
                | Demand::Policy
                | Demand::OwnFactor
                | Demand::NotAsked,
                Enrolment::Enrolled,
            ) => Self::Verify,
            (Demand::Signal | Demand::SignalAndPolicy, Enrolment::NotEnrolled) => {
                Self::ConfirmThenEnrol
            }
            (Demand::Policy | Demand::OwnFactor | Demand::NotAsked, Enrolment::NotEnrolled) => {
                Self::Enrol
            }
        }
    }

    /// What a sign-in owes when nothing but the person's own factor asks.
    /// Someone who set one up uses it. Someone without one is asked only when
    /// the policy requires it.
    ///
    /// No risk signal asks here, so the answer never waits for a mail, and
    /// whether the deployment can send one does not change it.
    #[must_use]
    pub fn for_enrolment(policy: MfaPolicy, enrolment: Enrolment) -> Self {
        let demand = match enrolment {
            Enrolment::Enrolled => Demand::OwnFactor,
            Enrolment::NotEnrolled => Demand::NotAsked,
        };
        Self::with_mail(policy, demand, enrolment)
    }

    /// Whether the session it produces is already complete.
    #[must_use]
    pub fn is_satisfied(self) -> bool {
        self == Self::NotOwed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::methods::MfaPolicy::{Disabled, Optional, Required};
    use crate::domains::authentication::mfa::owed::Demand::{
        NotAsked, OwnFactor, Policy, Signal, SignalAndPolicy,
    };
    use crate::domains::authentication::mfa::owed::Enrolment::{Enrolled, NotEnrolled};
    use crate::domains::authentication::mfa::owed::FactorOwed::{
        ConfirmByEmail, ConfirmThenEnrol, Enrol, NotOwed, Refused, Verify,
    };
    use crate::domains::identity::account::address::MailReach::{Available, NotSetUp};
    use crate::domains::identity::account::vouching::Vouching::{Absent, Fresh};

    /// Every cell of the tables on `under`: the policy, the demand, the
    /// enrolment, whether a mail reaches the person, whether a trusted
    /// route vouches for them, and the answer.
    #[rustfmt::skip]
    const FULL_TABLE: [(MfaPolicy, Demand, Enrolment, MailReach, Vouching, FactorOwed); 120] = [
            (Disabled, Signal, Enrolled, Available, Absent, ConfirmByEmail),
            (Disabled, Signal, Enrolled, NotSetUp, Absent, Verify),
            (Disabled, Signal, Enrolled, Available, Fresh, ConfirmByEmail),
            (Disabled, Signal, Enrolled, NotSetUp, Fresh, Verify),
            (Disabled, Signal, NotEnrolled, Available, Absent, ConfirmByEmail),
            (Disabled, Signal, NotEnrolled, NotSetUp, Absent, Refused),
            (Disabled, Signal, NotEnrolled, Available, Fresh, NotOwed),
            (Disabled, Signal, NotEnrolled, NotSetUp, Fresh, NotOwed),
            (Disabled, SignalAndPolicy, Enrolled, Available, Absent, ConfirmByEmail),
            (Disabled, SignalAndPolicy, Enrolled, NotSetUp, Absent, Verify),
            (Disabled, SignalAndPolicy, Enrolled, Available, Fresh, ConfirmByEmail),
            (Disabled, SignalAndPolicy, Enrolled, NotSetUp, Fresh, Verify),
            (Disabled, SignalAndPolicy, NotEnrolled, Available, Absent, ConfirmByEmail),
            (Disabled, SignalAndPolicy, NotEnrolled, NotSetUp, Absent, Refused),
            (Disabled, SignalAndPolicy, NotEnrolled, Available, Fresh, NotOwed),
            (Disabled, SignalAndPolicy, NotEnrolled, NotSetUp, Fresh, NotOwed),
            (Disabled, Policy, Enrolled, Available, Absent, NotOwed),
            (Disabled, Policy, Enrolled, NotSetUp, Absent, NotOwed),
            (Disabled, Policy, Enrolled, Available, Fresh, NotOwed),
            (Disabled, Policy, Enrolled, NotSetUp, Fresh, NotOwed),
            (Disabled, Policy, NotEnrolled, Available, Absent, NotOwed),
            (Disabled, Policy, NotEnrolled, NotSetUp, Absent, NotOwed),
            (Disabled, Policy, NotEnrolled, Available, Fresh, NotOwed),
            (Disabled, Policy, NotEnrolled, NotSetUp, Fresh, NotOwed),
            (Disabled, OwnFactor, Enrolled, Available, Absent, NotOwed),
            (Disabled, OwnFactor, Enrolled, NotSetUp, Absent, NotOwed),
            (Disabled, OwnFactor, Enrolled, Available, Fresh, NotOwed),
            (Disabled, OwnFactor, Enrolled, NotSetUp, Fresh, NotOwed),
            (Disabled, OwnFactor, NotEnrolled, Available, Absent, NotOwed),
            (Disabled, OwnFactor, NotEnrolled, NotSetUp, Absent, NotOwed),
            (Disabled, OwnFactor, NotEnrolled, Available, Fresh, NotOwed),
            (Disabled, OwnFactor, NotEnrolled, NotSetUp, Fresh, NotOwed),
            (Disabled, NotAsked, Enrolled, Available, Absent, NotOwed),
            (Disabled, NotAsked, Enrolled, NotSetUp, Absent, NotOwed),
            (Disabled, NotAsked, Enrolled, Available, Fresh, NotOwed),
            (Disabled, NotAsked, Enrolled, NotSetUp, Fresh, NotOwed),
            (Disabled, NotAsked, NotEnrolled, Available, Absent, NotOwed),
            (Disabled, NotAsked, NotEnrolled, NotSetUp, Absent, NotOwed),
            (Disabled, NotAsked, NotEnrolled, Available, Fresh, NotOwed),
            (Disabled, NotAsked, NotEnrolled, NotSetUp, Fresh, NotOwed),
            (Optional, Signal, Enrolled, Available, Absent, Verify),
            (Optional, Signal, Enrolled, NotSetUp, Absent, Verify),
            (Optional, Signal, Enrolled, Available, Fresh, Verify),
            (Optional, Signal, Enrolled, NotSetUp, Fresh, Verify),
            (Optional, Signal, NotEnrolled, Available, Absent, ConfirmByEmail),
            (Optional, Signal, NotEnrolled, NotSetUp, Absent, Refused),
            (Optional, Signal, NotEnrolled, Available, Fresh, NotOwed),
            (Optional, Signal, NotEnrolled, NotSetUp, Fresh, Enrol),
            (Optional, SignalAndPolicy, Enrolled, Available, Absent, Verify),
            (Optional, SignalAndPolicy, Enrolled, NotSetUp, Absent, Verify),
            (Optional, SignalAndPolicy, Enrolled, Available, Fresh, Verify),
            (Optional, SignalAndPolicy, Enrolled, NotSetUp, Fresh, Verify),
            (Optional, SignalAndPolicy, NotEnrolled, Available, Absent, ConfirmThenEnrol),
            (Optional, SignalAndPolicy, NotEnrolled, NotSetUp, Absent, Refused),
            (Optional, SignalAndPolicy, NotEnrolled, Available, Fresh, Enrol),
            (Optional, SignalAndPolicy, NotEnrolled, NotSetUp, Fresh, Enrol),
            (Optional, Policy, Enrolled, Available, Absent, Verify),
            (Optional, Policy, Enrolled, NotSetUp, Absent, Verify),
            (Optional, Policy, Enrolled, Available, Fresh, Verify),
            (Optional, Policy, Enrolled, NotSetUp, Fresh, Verify),
            (Optional, Policy, NotEnrolled, Available, Absent, Enrol),
            (Optional, Policy, NotEnrolled, NotSetUp, Absent, Enrol),
            (Optional, Policy, NotEnrolled, Available, Fresh, Enrol),
            (Optional, Policy, NotEnrolled, NotSetUp, Fresh, Enrol),
            (Optional, OwnFactor, Enrolled, Available, Absent, Verify),
            (Optional, OwnFactor, Enrolled, NotSetUp, Absent, Verify),
            (Optional, OwnFactor, Enrolled, Available, Fresh, Verify),
            (Optional, OwnFactor, Enrolled, NotSetUp, Fresh, Verify),
            (Optional, OwnFactor, NotEnrolled, Available, Absent, NotOwed),
            (Optional, OwnFactor, NotEnrolled, NotSetUp, Absent, NotOwed),
            (Optional, OwnFactor, NotEnrolled, Available, Fresh, NotOwed),
            (Optional, OwnFactor, NotEnrolled, NotSetUp, Fresh, NotOwed),
            (Optional, NotAsked, Enrolled, Available, Absent, NotOwed),
            (Optional, NotAsked, Enrolled, NotSetUp, Absent, NotOwed),
            (Optional, NotAsked, Enrolled, Available, Fresh, NotOwed),
            (Optional, NotAsked, Enrolled, NotSetUp, Fresh, NotOwed),
            (Optional, NotAsked, NotEnrolled, Available, Absent, NotOwed),
            (Optional, NotAsked, NotEnrolled, NotSetUp, Absent, NotOwed),
            (Optional, NotAsked, NotEnrolled, Available, Fresh, NotOwed),
            (Optional, NotAsked, NotEnrolled, NotSetUp, Fresh, NotOwed),
            (Required, Signal, Enrolled, Available, Absent, Verify),
            (Required, Signal, Enrolled, NotSetUp, Absent, Verify),
            (Required, Signal, Enrolled, Available, Fresh, Verify),
            (Required, Signal, Enrolled, NotSetUp, Fresh, Verify),
            (Required, Signal, NotEnrolled, Available, Absent, ConfirmThenEnrol),
            (Required, Signal, NotEnrolled, NotSetUp, Absent, Refused),
            (Required, Signal, NotEnrolled, Available, Fresh, Enrol),
            (Required, Signal, NotEnrolled, NotSetUp, Fresh, Enrol),
            (Required, SignalAndPolicy, Enrolled, Available, Absent, Verify),
            (Required, SignalAndPolicy, Enrolled, NotSetUp, Absent, Verify),
            (Required, SignalAndPolicy, Enrolled, Available, Fresh, Verify),
            (Required, SignalAndPolicy, Enrolled, NotSetUp, Fresh, Verify),
            (Required, SignalAndPolicy, NotEnrolled, Available, Absent, ConfirmThenEnrol),
            (Required, SignalAndPolicy, NotEnrolled, NotSetUp, Absent, Refused),
            (Required, SignalAndPolicy, NotEnrolled, Available, Fresh, Enrol),
            (Required, SignalAndPolicy, NotEnrolled, NotSetUp, Fresh, Enrol),
            (Required, Policy, Enrolled, Available, Absent, Verify),
            (Required, Policy, Enrolled, NotSetUp, Absent, Verify),
            (Required, Policy, Enrolled, Available, Fresh, Verify),
            (Required, Policy, Enrolled, NotSetUp, Fresh, Verify),
            (Required, Policy, NotEnrolled, Available, Absent, Enrol),
            (Required, Policy, NotEnrolled, NotSetUp, Absent, Enrol),
            (Required, Policy, NotEnrolled, Available, Fresh, Enrol),
            (Required, Policy, NotEnrolled, NotSetUp, Fresh, Enrol),
            (Required, OwnFactor, Enrolled, Available, Absent, Verify),
            (Required, OwnFactor, Enrolled, NotSetUp, Absent, Verify),
            (Required, OwnFactor, Enrolled, Available, Fresh, Verify),
            (Required, OwnFactor, Enrolled, NotSetUp, Fresh, Verify),
            (Required, OwnFactor, NotEnrolled, Available, Absent, Enrol),
            (Required, OwnFactor, NotEnrolled, NotSetUp, Absent, Enrol),
            (Required, OwnFactor, NotEnrolled, Available, Fresh, Enrol),
            (Required, OwnFactor, NotEnrolled, NotSetUp, Fresh, Enrol),
            (Required, NotAsked, Enrolled, Available, Absent, Verify),
            (Required, NotAsked, Enrolled, NotSetUp, Absent, Verify),
            (Required, NotAsked, Enrolled, Available, Fresh, Verify),
            (Required, NotAsked, Enrolled, NotSetUp, Fresh, Verify),
            (Required, NotAsked, NotEnrolled, Available, Absent, Enrol),
            (Required, NotAsked, NotEnrolled, NotSetUp, Absent, Enrol),
            (Required, NotAsked, NotEnrolled, Available, Fresh, Enrol),
            (Required, NotAsked, NotEnrolled, NotSetUp, Fresh, Enrol),
    ];

    /// Every policy, demand, enrolment, mail and vouching gives the answer
    /// the tables on `under` state, all 120 cells checked one by one.
    #[test]
    fn every_input_has_its_stated_answer() {
        for (policy, demand, enrolment, mail, vouching, expected) in FULL_TABLE {
            assert_eq!(
                FactorOwed::under(policy, demand, enrolment, mail, vouching),
                expected,
                "{policy:?} {demand:?} {enrolment:?} {mail:?} {vouching:?}"
            );
        }
    }

    /// Without mail, no answer shows less about the person than the same
    /// sign-in where mail reaches them.
    #[test]
    fn no_answer_is_weaker_without_mail() {
        for (policy, demand, enrolment, _, vouching, _) in FULL_TABLE {
            let with = FactorOwed::under(policy, demand, enrolment, Available, vouching);
            let without = FactorOwed::under(policy, demand, enrolment, NotSetUp, vouching);

            assert!(
                without.proof() >= with.proof(),
                "{policy:?} {demand:?} {enrolment:?} {vouching:?}: {without:?} below {with:?}"
            );
        }
    }

    /// A risk signal with no enrolled factor, mail or vouching is refused under
    /// every MFA policy, reporting that nothing can prove the account.
    #[test]
    fn without_mail_a_risk_signal_with_nothing_to_prove_it_is_refused() {
        for policy in [Disabled, Optional, Required] {
            let answer = FactorOwed::under(policy, Signal, NotEnrolled, NotSetUp, Absent);

            assert_eq!(answer, Refused, "{policy:?}");
            assert_eq!(answer.owed(), Err(NothingToProveWith));
        }
    }

    /// Olive installed the platform with no mail server and confirmed
    /// herself with the setup token. Her first sign-in, from a new device,
    /// sets up her authenticator, unless second factors are off.
    #[test]
    fn without_mail_the_first_sign_in_a_route_vouches_for_sets_up_a_factor() {
        assert_eq!(
            FactorOwed::under(Optional, Signal, NotEnrolled, NotSetUp, Fresh),
            Enrol
        );
        assert_eq!(
            FactorOwed::under(Required, Signal, NotEnrolled, NotSetUp, Fresh),
            Enrol
        );
        assert_eq!(
            FactorOwed::under(Disabled, Signal, NotEnrolled, NotSetUp, Fresh),
            NotOwed
        );
    }

    /// When a risk signal meets an account with no factor but available mail,
    /// every MFA policy requires email confirmation before any enrollment.
    #[test]
    fn a_risk_signal_without_a_factor_never_becomes_enrolment_where_mail_reaches() {
        for policy in [Disabled, Optional, Required] {
            let answer = FactorOwed::under(policy, Signal, NotEnrolled, Available, Absent);

            assert!(
                matches!(answer, ConfirmByEmail | ConfirmThenEnrol),
                "{policy:?} answered {answer:?}"
            );
        }
    }

    /// A tenant has second factors off and a sign-in looks risky. The person
    /// still confirms through their verified address, which needs no factor.
    #[test]
    fn a_risk_signal_is_answered_while_second_factors_are_off() {
        assert_eq!(
            FactorOwed::under(Disabled, Signal, Enrolled, Available, Absent),
            ConfirmByEmail
        );
    }

    /// A breached password adds a signal to whatever was already asked. A
    /// policy demand becomes signal and policy, so the policy's factor is
    /// still owed.
    #[test]
    fn a_further_signal_keeps_what_the_policy_needed() {
        assert_eq!(Policy.with_signal(), SignalAndPolicy);
        assert_eq!(NotAsked.with_signal(), Signal);
        assert_eq!(OwnFactor.with_signal(), Signal);
        assert_eq!(Signal.with_signal(), Signal);
        assert_eq!(SignalAndPolicy.with_signal(), SignalAndPolicy);
    }

    /// Every answer but a refusal is what the session owes; a refusal
    /// begins no session.
    #[test]
    fn only_a_refusal_owes_no_session() {
        assert_eq!(NotOwed.owed(), Ok(SecondFactor::NotOwed));
        assert_eq!(Verify.owed(), Ok(SecondFactor::Verify));
        assert_eq!(Enrol.owed(), Ok(SecondFactor::Enrol));
        assert_eq!(ConfirmByEmail.owed(), Ok(SecondFactor::ConfirmByEmail));
        assert_eq!(ConfirmThenEnrol.owed(), Ok(SecondFactor::ConfirmThenEnrol));
        assert_eq!(Refused.owed(), Err(NothingToProveWith));
    }

    /// Each answer shows what it asks of the person beyond the password. A
    /// factor set up at the same sign-in shows nothing.
    #[test]
    fn each_answer_shows_what_it_asks() {
        assert_eq!(NotOwed.proof(), PersonProof::Nothing);
        assert_eq!(Enrol.proof(), PersonProof::Nothing);
        assert_eq!(ConfirmByEmail.proof(), PersonProof::Mailbox);
        assert_eq!(ConfirmThenEnrol.proof(), PersonProof::Mailbox);
        assert_eq!(Verify.proof(), PersonProof::OwnFactor);
        assert_eq!(Refused.proof(), PersonProof::Refused);
    }

    /// Ann has TOTP set up. Under an optional or a required policy she must
    /// use it. Under a disabled policy nothing more is asked.
    #[test]
    fn someone_enrolled_uses_their_factor_unless_factors_are_off() {
        assert_eq!(
            SecondFactor::for_enrolment(Optional, Enrolled),
            SecondFactor::Verify
        );
        assert_eq!(
            SecondFactor::for_enrolment(Required, Enrolled),
            SecondFactor::Verify
        );
        assert_eq!(
            SecondFactor::for_enrolment(Disabled, Enrolled),
            SecondFactor::NotOwed
        );
    }

    /// Bob has no factor. Under an optional policy he goes straight in.
    /// Under a required policy he must set one up first.
    #[test]
    fn someone_without_a_factor_sets_one_up_only_when_it_is_required() {
        assert_eq!(
            SecondFactor::for_enrolment(Optional, NotEnrolled),
            SecondFactor::NotOwed
        );
        assert_eq!(
            SecondFactor::for_enrolment(Required, NotEnrolled),
            SecondFactor::Enrol
        );
    }

    /// Ann has a confirmed TOTP, or confirmed texted codes, and no passkeys.
    /// She counts as enrolled.
    #[test]
    fn a_confirmed_totp_enrols() {
        assert_eq!(
            HeldFactors::new(CodeFactorHolding::Active, 0).enrolment(),
            Enrolled
        );
    }

    /// Holding one passkey counts as enrolled even without a code factor.
    #[test]
    fn a_passkey_alone_enrols() {
        assert_eq!(
            HeldFactors::new(CodeFactorHolding::None, 1).enrolment(),
            Enrolled
        );
    }

    /// Bob holds no TOTP and no passkeys. He counts as not enrolled.
    #[test]
    fn holding_nothing_is_not_enrolled() {
        assert_eq!(
            HeldFactors::new(CodeFactorHolding::None, 0).enrolment(),
            NotEnrolled
        );
    }
}
