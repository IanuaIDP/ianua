//! The `StepUp` stage: a stronger sign-in asked for when the caller's
//! falls short of what the route asks.
//!
//! The level is the one the Identity stage recorded from the credential. A
//! level nobody knows falls short of every demand, `Aal1` included: a
//! credential saying nothing of how its holder signed in never passes for
//! one that says enough. Only a person, or someone not signed in yet, can
//! sign in again; an agent or a consumer that falls short is refused, as
//! the access decision refuses them.

use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
use ianua_domain::domains::proxy::request::context::{Caller, PipelineContext};
use ianua_domain::domains::proxy::stages::decision::{AnswerAt, ChallengeType, StageDecision};
use ianua_domain::domains::proxy::stages::stage::StepUpConfig;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DenialStatus, Fact};

use super::{IdentityStages, deny, pass};

impl IdentityStages {
    /// The `StepUp` stage: a pass when the caller signed in at least as
    /// strongly as `config` asks, a challenge to sign in again when a
    /// person's sign-in falls short, a deny when a machine's does.
    ///
    /// # Errors
    ///
    /// None today; the signature is the group's, so the dispatcher treats
    /// every stage alike.
    pub(crate) async fn step_up(
        &self,
        config: &StepUpConfig,
        ctx: &PipelineContext,
    ) -> Result<StageDecision, DomainError> {
        Ok(assurance_decision(config.required_aal, ctx))
    }
}

/// What a demand for `required` comes to for the caller `ctx` holds.
fn assurance_decision(required: AssuranceLevel, ctx: &PipelineContext) -> StageDecision {
    if let Fact::Known(current) = &ctx.claims.current_aal
        && current.satisfies(required)
    {
        return pass("assurance_sufficient");
    }
    match ctx.authentication().caller() {
        None | Some(Caller::User { .. }) => StageDecision::Challenge {
            challenge_type: ChallengeType::Mfa,
            answer_at: AnswerAt::Retry,
            reason: "assurance_insufficient".to_owned(),
        },
        Some(Caller::Agent { .. } | Caller::Consumer { .. }) => {
            deny(DenialStatus::FORBIDDEN, "assurance_unattainable")
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::proxy::request::context::{
        ConsumerCredential, UserSignIn, Verified,
    };
    use ianua_domain::types::{ConsumerId, CorrelationId, Expiry, PipelineId, TenantId, UserId};

    use super::*;

    /// A request whose caller signed in at `current`, by `caller` when
    /// one was proven.
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

    fn ann() -> Caller {
        Caller::User {
            user_id: UserId::new(),
            sign_in: UserSignIn::Token,
        }
    }

    fn is_mfa_challenge(decision: &StageDecision) -> bool {
        matches!(
            decision,
            StageDecision::Challenge {
                challenge_type: ChallengeType::Mfa,
                answer_at: AnswerAt::Retry,
                ..
            }
        )
    }

    /// Ann signed in with two factors, and the route asks for two. She
    /// passes, as she would at AAL3.
    #[test]
    fn a_strong_enough_sign_in_passes() {
        for current in [AssuranceLevel::Aal2, AssuranceLevel::Aal3] {
            let ctx = context(Some(ann()), Fact::Known(current));

            let decision = assurance_decision(AssuranceLevel::Aal2, &ctx);

            assert!(
                matches!(decision, StageDecision::Pass { .. }),
                "{current:?}"
            );
        }
    }

    /// Ann signed in with a password, and the route asks for two factors.
    /// She is asked to sign in again with a second factor.
    #[test]
    fn a_weaker_sign_in_is_challenged() {
        let ctx = context(Some(ann()), Fact::Known(AssuranceLevel::Aal1));

        let decision = assurance_decision(AssuranceLevel::Aal2, &ctx);

        assert!(is_mfa_challenge(&decision));
    }

    /// Ann's unknown sign-in assurance triggers an MFA challenge even when
    /// the route asks only for AAL1.
    #[test]
    fn an_unknown_level_meets_no_demand() {
        let ctx = context(Some(ann()), Fact::Unknown);

        let decision = assurance_decision(AssuranceLevel::Aal1, &ctx);

        assert!(is_mfa_challenge(&decision));
    }

    /// Nobody signed in reaches a route asking for two factors. They are
    /// asked to sign in.
    #[test]
    fn nobody_is_challenged() {
        let ctx = context(None, Fact::Unknown);

        let decision = assurance_decision(AssuranceLevel::Aal2, &ctx);

        assert!(is_mfa_challenge(&decision));
    }

    /// A consumer authenticated by API key with unknown assurance receives
    /// 403 when the route requires AAL2.
    #[test]
    fn a_machine_falling_short_is_refused() {
        let consumer = Some(Caller::Consumer {
            consumer_id: ConsumerId::new(),
            credential: ConsumerCredential::ApiKey,
        });
        let ctx = context(consumer, Fact::Unknown);

        let decision = assurance_decision(AssuranceLevel::Aal2, &ctx);

        assert!(matches!(
            decision,
            StageDecision::Deny { status, .. } if status == DenialStatus::FORBIDDEN
        ));
    }
}
