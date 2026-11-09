//! The access decision's answer, as the Policy stage enforces it.
//!
//! Only a permit lets a request on. A deny keeps its code as the reason
//! the request record reads and answers with the status the code calls
//! for; the client is told only that status. A request the decision never
//! answered is refused like one it refused.

use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
use ianua_domain::domains::proxy::access::decision::{Challenge, DenyCode, Outcome};
use ianua_domain::domains::proxy::stages::decision::{AnswerAt, ChallengeType, StageDecision};
use ianua_domain::types::DenialStatus;

/// What the Policy stage does with a request.
#[derive(Debug)]
pub(super) enum Verdict {
    /// Let it on to the next stage.
    Permit,
    /// Refuse it with this decision.
    Refuse(StageDecision),
}

/// What `outcome` comes to, or the refusal of a decision that never came.
pub(super) fn verdict_of(outcome: Option<Outcome>) -> Verdict {
    match outcome {
        Some(Outcome::Permit) => Verdict::Permit,
        Some(Outcome::Deny(code)) => Verdict::Refuse(denied(code)),
        Some(Outcome::Challenge(Challenge::StepUp(level))) => Verdict::Refuse(step_up(level)),
        Some(Outcome::Challenge(Challenge::DpopProof)) => Verdict::Refuse(proof_of_key()),
        None => Verdict::Refuse(unanswered()),
    }
}

/// The refusal of a request whose caller the Identity stage wrote one way
/// and handed over another: two readings of who is asking.
pub(super) fn callers_disagree() -> StageDecision {
    StageDecision::Deny {
        status: DenialStatus::FORBIDDEN,
        reason: "identification_disagrees".to_owned(),
    }
}

fn denied(code: DenyCode) -> StageDecision {
    StageDecision::Deny {
        status: code.status(),
        reason: code.as_str().to_owned(),
    }
}

/// A stronger sign-in, answered where the caller already signs in, then
/// retried.
fn step_up(level: AssuranceLevel) -> StageDecision {
    StageDecision::Challenge {
        challenge_type: ChallengeType::Mfa,
        answer_at: AnswerAt::Retry,
        reason: format!("step_up_{}", level.acr()),
    }
}

/// A token bound to a key, sent without a proof of it. The pipeline's
/// challenge kinds name no key proof, so it is refused as unauthenticated,
/// which a `DPoP` client answers by retrying with a proof.
fn proof_of_key() -> StageDecision {
    StageDecision::Deny {
        status: DenialStatus::UNAUTHORIZED,
        reason: "dpop_proof_required".to_owned(),
    }
}

fn unanswered() -> StageDecision {
    StageDecision::Deny {
        status: DenialStatus::SERVICE_UNAVAILABLE,
        reason: "access_decision_unanswered".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVERY_CODE: [DenyCode; 22] = [
        DenyCode::RouteUnknown,
        DenyCode::RouteClosed,
        DenyCode::RouteUnreadable,
        DenyCode::SignInRequired,
        DenyCode::CallerUnknown,
        DenyCode::CallerBarred,
        DenyCode::RecordsUnreadable,
        DenyCode::RecordsStale,
        DenyCode::DelegatorUnknown,
        DenyCode::DelegatorBarred,
        DenyCode::KeyNotProven,
        DenyCode::MethodOverridden,
        DenyCode::NothingDelegated,
        DenyCode::NothingListed,
        DenyCode::PermissionMissing,
        DenyCode::ScopeMissing,
        DenyCode::OutsideIntent,
        DenyCode::OutsideResourceScope,
        DenyCode::PostureFailed,
        DenyCode::TenantRule,
        DenyCode::TenantPolicyUnreadable,
        DenyCode::AssuranceUnattainable,
    ];

    /// Every deny code refuses, with the status the code calls for and the
    /// code itself as the reason the request record keeps.
    #[test]
    fn every_deny_code_refuses_with_its_status_and_name() {
        for code in EVERY_CODE {
            let Verdict::Refuse(StageDecision::Deny { status, reason }) =
                verdict_of(Some(Outcome::Deny(code)))
            else {
                panic!("{} did not refuse", code.as_str());
            };

            assert_eq!(status, code.status(), "{}", code.as_str());
            assert_eq!(reason, code.as_str());
        }
    }

    #[test]
    fn only_a_permit_lets_a_request_on() {
        assert!(matches!(verdict_of(Some(Outcome::Permit)), Verdict::Permit));
    }

    /// A tenant rule asking for AAL2 is a step-up challenge the caller
    /// answers and retries; the request is not let through meanwhile.
    #[test]
    fn a_step_up_is_a_challenge_naming_its_level() {
        let verdict = verdict_of(Some(Outcome::Challenge(Challenge::StepUp(
            AssuranceLevel::Aal2,
        ))));

        let Verdict::Refuse(StageDecision::Challenge {
            challenge_type: ChallengeType::Mfa,
            answer_at: AnswerAt::Retry,
            reason,
        }) = verdict
        else {
            panic!("a step-up is a challenge");
        };
        assert_eq!(reason, "step_up_aal2");
    }

    #[test]
    fn a_missing_key_proof_is_refused_as_unauthenticated() {
        let Verdict::Refuse(StageDecision::Deny { status, .. }) =
            verdict_of(Some(Outcome::Challenge(Challenge::DpopProof)))
        else {
            panic!("a key proof challenge refuses");
        };

        assert_eq!(status, DenialStatus::UNAUTHORIZED);
    }

    /// An absent access decision produces a denial rather than a permit.
    #[test]
    fn no_answer_refuses() {
        assert!(matches!(
            verdict_of(None),
            Verdict::Refuse(StageDecision::Deny { .. })
        ));
    }
}
