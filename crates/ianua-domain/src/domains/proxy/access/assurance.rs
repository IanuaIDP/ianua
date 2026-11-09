//! How strongly a caller signed in, and what a demand for a stronger
//! sign-in comes to: met, a challenge to sign in again, or a refusal for a
//! caller that cannot.
//!
//! The tenant's policy and a route's `StepUp` stage ask the same question,
//! so both answer it here. A level nobody knows falls short of every
//! demand, `Aal1` included: a credential saying nothing of how its holder
//! signed in never passes for one that says enough. Only a person, or
//! someone not signed in yet, can sign in again; an agent or a consumer
//! that falls short is refused.

use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::domains::authorization::policy::simulator::AalDemand;
use crate::domains::proxy::access::decision::{Challenge, DenyCode, Outcome};
use crate::domains::proxy::request::context::{
    Authentication, Caller, CallerClaims, PipelineContext, Verified,
};
use crate::domains::proxy::stages::stage::StepUpConfig;
use crate::types::Fact;

/// Whether a caller can answer a demand for a stronger sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SignInAgain {
    /// A person, or someone not signed in yet: they can sign in again.
    Possible,
    /// An agent or a consumer: a machine cannot.
    Impossible,
}

/// How strongly a caller signed in, and whether they can do it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SignInStrength {
    /// The level the sign-in reached. Only a person's has one.
    pub(super) level: Fact<AssuranceLevel>,
    /// Whether they can sign in again.
    pub(super) again: SignInAgain,
}

impl SignInStrength {
    /// What the caller `authentication` proved, whose credential carries
    /// `claims`, signed in with.
    pub(super) fn of(authentication: &Authentication, claims: &CallerClaims) -> Self {
        let Authentication::Authenticated(Verified { caller, .. }) = authentication else {
            return Self::nobody();
        };
        match caller {
            Caller::User { .. } => Self::person(claims.current_aal),
            Caller::Agent { .. } | Caller::Consumer { .. } => Self::machine(),
        }
    }

    /// A person who signed in at `level`.
    pub(super) fn person(level: Fact<AssuranceLevel>) -> Self {
        Self {
            level,
            again: SignInAgain::Possible,
        }
    }

    /// Nobody signed in yet, who may.
    pub(super) fn nobody() -> Self {
        Self {
            level: Fact::Unknown,
            again: SignInAgain::Possible,
        }
    }

    /// An agent or a consumer, whose credential has no sign-in level.
    pub(super) fn machine() -> Self {
        Self {
            level: Fact::Unknown,
            again: SignInAgain::Impossible,
        }
    }
}

/// Asks for a stronger sign-in when `strength` falls short of `demand`. A
/// sign-in whose level is not known falls short.
///
/// # Errors
///
/// - [`Outcome::Challenge`] with [`Challenge::StepUp`] for someone who can
///   sign in again.
/// - [`Outcome::Deny`] with [`DenyCode::AssuranceUnattainable`] for an agent
///   or a consumer, which cannot.
pub(super) fn ensure_assurance(demand: AalDemand, strength: SignInStrength) -> Result<(), Outcome> {
    let AalDemand::AtLeast(level) = demand else {
        return Ok(());
    };
    if let Fact::Known(current) = strength.level
        && demand.is_met_by(current)
    {
        return Ok(());
    }
    match strength.again {
        SignInAgain::Possible => Err(Outcome::Challenge(Challenge::StepUp(level))),
        SignInAgain::Impossible => Err(Outcome::Deny(DenyCode::AssuranceUnattainable)),
    }
}

impl StepUpConfig {
    /// What this stage makes of the request in `ctx`: a permit when its
    /// caller signed in at least as strongly as the stage asks, a challenge
    /// to sign in again for a person or nobody, a refusal for a machine.
    #[must_use]
    pub fn verdict(&self, ctx: &PipelineContext) -> Outcome {
        let strength = SignInStrength::of(ctx.authentication(), &ctx.claims);
        match ensure_assurance(AalDemand::AtLeast(self.required_aal), strength) {
            Ok(()) => Outcome::Permit,
            Err(outcome) => outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::proxy::request::context::{ConsumerCredential, UserSignIn, Verified};
    use crate::types::{ConsumerId, CorrelationId, Expiry, PipelineId, TenantId, UserId};

    fn context(caller: Option<Caller>, current: Fact<AssuranceLevel>) -> PipelineContext {
        let mut ctx =
            PipelineContext::new(TenantId::new(), PipelineId::new(), CorrelationId::new());
        if let Some(caller) = caller {
            ctx.authenticate(Verified {
                caller,
                expiry: Expiry::Never,
            })
            .unwrap();
        }
        ctx.claims.current_aal = current;
        ctx
    }

    /// A person whose token can be assigned the assurance level under test.
    fn ann() -> Caller {
        Caller::User {
            user_id: UserId::new(),
            sign_in: UserSignIn::Token,
        }
    }

    fn asking(required_aal: AssuranceLevel) -> StepUpConfig {
        StepUpConfig { required_aal }
    }

    const STEP_UP_TO_TWO: Outcome = Outcome::Challenge(Challenge::StepUp(AssuranceLevel::Aal2));

    /// Ann signed in with two factors, and the route asks for two. She
    /// passes, as she would at AAL3.
    #[test]
    fn a_strong_enough_sign_in_passes() {
        for current in [AssuranceLevel::Aal2, AssuranceLevel::Aal3] {
            let ctx = context(Some(ann()), Fact::Known(current));

            assert_eq!(
                asking(AssuranceLevel::Aal2).verdict(&ctx),
                Outcome::Permit,
                "{current:?}"
            );
        }
    }

    /// Ann signed in with a password, and the route asks for two factors.
    /// She is asked to sign in again with a second factor.
    #[test]
    fn a_weaker_sign_in_is_challenged() {
        let ctx = context(Some(ann()), Fact::Known(AssuranceLevel::Aal1));

        assert_eq!(asking(AssuranceLevel::Aal2).verdict(&ctx), STEP_UP_TO_TWO);
    }

    /// A person's unknown assurance level cannot satisfy even an AAL1
    /// demand. The stage challenges them to reach AAL1.
    #[test]
    fn an_unknown_level_meets_no_demand() {
        let ctx = context(Some(ann()), Fact::Unknown);

        assert_eq!(
            asking(AssuranceLevel::Aal1).verdict(&ctx),
            Outcome::Challenge(Challenge::StepUp(AssuranceLevel::Aal1))
        );
    }

    /// Nobody signed in reaches a route asking for two factors. They are
    /// asked to sign in.
    #[test]
    fn nobody_is_challenged() {
        let ctx = context(None, Fact::Unknown);

        assert_eq!(asking(AssuranceLevel::Aal2).verdict(&ctx), STEP_UP_TO_TWO);
    }

    /// A consumer authenticated with an API key is denied an AAL2 demand
    /// as unattainable, even when its claims carry AAL3.
    #[test]
    fn a_machine_is_refused_whatever_its_claims_say() {
        let consumer = Some(Caller::Consumer {
            consumer_id: ConsumerId::new(),
            credential: ConsumerCredential::ApiKey,
        });
        let ctx = context(consumer, Fact::Known(AssuranceLevel::Aal3));

        assert_eq!(
            asking(AssuranceLevel::Aal2).verdict(&ctx),
            Outcome::Deny(DenyCode::AssuranceUnattainable)
        );
    }

    #[test]
    fn a_demand_for_nothing_is_met_by_anyone() {
        assert_eq!(
            ensure_assurance(AalDemand::Any, SignInStrength::machine()),
            Ok(())
        );
    }
}
