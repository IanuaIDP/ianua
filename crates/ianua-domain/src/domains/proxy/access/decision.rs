//! What the gateway's access decision answers: let the request through,
//! refuse it with a reason code, or ask the caller for more first.
//!
//! A reason code is for the request record and the audit trail. The client
//! is told only the status [`DenyCode::status`] gives, never the code or the
//! tenant rule behind it, so a refusal teaches an attacker nothing about the
//! policy.

use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::domains::authorization::policy::simulator::AuditMark;
use crate::domains::authorization::policy::version::PolicyVersion;
use crate::domains::proxy::observation::DecidingRule;
use crate::domains::proxy::stages::decision::{AnswerAt, ChallengeType, StageDecision};
use crate::types::{DenialStatus, Label};

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DenyCode {
    /// The route the request matched is not stored any more.
    RouteUnknown,
    /// The route is disabled.
    RouteClosed,
    /// The route could not be read.
    RouteUnreadable,
    /// The route asks for a signed-in caller and nobody signed in.
    SignInRequired,
    /// The tenant's records name no such caller, or not one the gateway
    /// serves.
    CallerUnknown,
    /// The caller may not act now.
    CallerBarred,
    /// What the caller holds could not be read.
    RecordsUnreadable,
    /// What the caller holds was read too long ago to decide on.
    RecordsStale,
    /// An agent acts for someone the tenant's records do not know, or for
    /// someone its request did not say anything about.
    DelegatorUnknown,
    /// An agent acts for someone who may not act now.
    DelegatorBarred,
    /// The credential is bound to a key, and the request proved no
    /// possession of it.
    KeyNotProven,
    /// An agent's request asks to be read as another method.
    MethodOverridden,
    /// An agent's task token names nothing it was given: no permission and
    /// nothing on an MCP server.
    NothingDelegated,
    /// The route lists the permissions or scopes it asks for, and the list
    /// is empty.
    NothingListed,
    /// The caller holds none of the permissions the route lists.
    PermissionMissing,
    /// The caller carries none of the scopes the route lists.
    ScopeMissing,
    /// An agent's request is an action outside its task's declared intent.
    OutsideIntent,
    /// An agent's request is for a path outside its token's resource scope.
    OutsideResourceScope,
    /// The device failed the route's posture check.
    PostureFailed,
    /// The tenant's policy refused the request.
    TenantRule,
    /// The tenant's policy could not be read.
    TenantPolicyUnreadable,
    /// The tenant's policy asks for a stronger sign-in than a caller of
    /// this kind can give, such as an agent or a consumer.
    AssuranceUnattainable,
}

impl DenyCode {
    /// The stable name a request record keeps.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RouteUnknown => "route_unknown",
            Self::RouteClosed => "route_closed",
            Self::RouteUnreadable => "route_unreadable",
            Self::SignInRequired => "sign_in_required",
            Self::CallerUnknown => "caller_unknown",
            Self::CallerBarred => "caller_barred",
            Self::RecordsUnreadable => "records_unreadable",
            Self::RecordsStale => "records_stale",
            Self::DelegatorUnknown => "delegator_unknown",
            Self::DelegatorBarred => "delegator_barred",
            Self::KeyNotProven => "key_not_proven",
            Self::MethodOverridden => "method_overridden",
            Self::NothingDelegated => "nothing_delegated",
            Self::NothingListed => "nothing_listed",
            Self::PermissionMissing => "permission_missing",
            Self::ScopeMissing => "scope_missing",
            Self::OutsideIntent => "outside_intent",
            Self::OutsideResourceScope => "outside_resource_scope",
            Self::PostureFailed => "posture_failed",
            Self::TenantRule => "tenant_rule",
            Self::TenantPolicyUnreadable => "tenant_policy_unreadable",
            Self::AssuranceUnattainable => "assurance_unattainable",
        }
    }

    /// The status the client is answered with.
    ///
    /// A caller who must sign in or prove its key gets 401, a request that
    /// asks to be read as another method 400, and a store that could not be
    /// read 503, so a client retries later rather than taking it as final.
    /// Everything else is 403.
    #[must_use]
    pub fn status(self) -> DenialStatus {
        match self {
            Self::SignInRequired | Self::KeyNotProven => DenialStatus::UNAUTHORIZED,
            Self::MethodOverridden => DenialStatus::BAD_REQUEST,
            Self::RouteUnreadable
            | Self::RecordsUnreadable
            | Self::RecordsStale
            | Self::TenantPolicyUnreadable => DenialStatus::SERVICE_UNAVAILABLE,
            Self::RouteUnknown
            | Self::RouteClosed
            | Self::CallerUnknown
            | Self::CallerBarred
            | Self::DelegatorUnknown
            | Self::DelegatorBarred
            | Self::NothingDelegated
            | Self::NothingListed
            | Self::PermissionMissing
            | Self::ScopeMissing
            | Self::OutsideIntent
            | Self::OutsideResourceScope
            | Self::PostureFailed
            | Self::TenantRule
            | Self::AssuranceUnattainable => DenialStatus::FORBIDDEN,
        }
    }

    /// The stage decision the refusal comes to: its status, with its code
    /// as the reason the request record keeps.
    #[must_use]
    pub fn decision(self) -> StageDecision {
        StageDecision::Deny {
            status: self.status(),
            reason: self.as_str().to_owned(),
        }
    }
}

/// What a request must show before it is let through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Challenge {
    /// A sign-in at least this strong: a second factor for AAL2, a
    /// hardware-bound one for AAL3.
    StepUp(AssuranceLevel),
    /// A `DPoP` proof of possession of the key its token is bound to.
    DpopProof,
}

impl Challenge {
    /// The stage decision the challenge comes to, answered where the caller
    /// already answers it and then retried: a stronger sign-in, or a key
    /// proof asked with `WWW-Authenticate: DPoP`.
    #[must_use]
    pub fn decision(self) -> StageDecision {
        let (challenge_type, reason) = match self {
            Self::StepUp(level) => (ChallengeType::Mfa, format!("step_up_{}", level.acr())),
            Self::DpopProof => (ChallengeType::KeyProof, "dpop_proof_required".to_owned()),
        };
        StageDecision::Challenge {
            challenge_type,
            answer_at: AnswerAt::Retry,
            reason,
        }
    }
}

/// What the decision came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Let the request through.
    Permit,
    /// Refuse it.
    Deny(DenyCode),
    /// Refuse it until the caller shows more, then let it be retried.
    Challenge(Challenge),
}

impl Outcome {
    /// The stage decision the outcome comes to. Only a permit passes; the
    /// Policy stage still records the grant itself.
    #[must_use]
    pub fn decision(self) -> StageDecision {
        match self {
            Self::Permit => StageDecision::Pass {
                reason: "access_permitted".to_owned(),
            },
            Self::Deny(code) => code.decision(),
            Self::Challenge(challenge) => challenge.decision(),
        }
    }
}

/// What in the tenant's policy settled a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettledBy {
    /// The matching named entry supplied the allow or deny decision.
    Rule(Label),
    /// No allow or deny rule matched, so the policy's default did.
    Default,
}

/// What the tenant's own policy had to do with the decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantRuling {
    /// The request was refused before the tenant's policy was read.
    NotReached,
    /// The tenant's policy could not be read.
    Unreadable,
    /// The tenant has no live policy.
    NoPolicy,
    /// The tenant's policy decided.
    Decided {
        /// The version that decided.
        version: PolicyVersion,
        /// What settled it.
        settled_by: SettledBy,
        /// Whether an audit-only rule saw the request.
        audit: AuditMark,
    },
}

/// One access decision, with what the tenant's policy had to do with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDecision {
    outcome: Outcome,
    ruling: TenantRuling,
}

impl AccessDecision {
    /// `outcome`, reached with `ruling`.
    pub(crate) fn new(outcome: Outcome, ruling: TenantRuling) -> Self {
        Self { outcome, ruling }
    }

    /// A refusal for `code`, made before the tenant's policy was read.
    pub(crate) fn refused(code: DenyCode) -> Self {
        Self::new(Outcome::Deny(code), TenantRuling::NotReached)
    }

    /// What the decision came to.
    #[must_use]
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// What the tenant's policy had to do with it, for the request record.
    #[must_use]
    pub fn ruling(&self) -> &TenantRuling {
        &self.ruling
    }

    /// Whether the request may go through now. Only a permit lets it.
    #[must_use]
    pub fn permits(&self) -> bool {
        self.outcome == Outcome::Permit
    }

    /// The tenant policy rule that refused the request, for its record:
    /// named only when a rule of the tenant's own refused it. A refusal by
    /// the route, the caller's standing, or the policy's default names no
    /// rule, and neither does a permit.
    #[must_use]
    pub fn refusing_rule(&self) -> DecidingRule {
        let (
            Outcome::Deny(DenyCode::TenantRule),
            TenantRuling::Decided {
                settled_by: SettledBy::Rule(rule),
                ..
            },
        ) = (self.outcome, &self.ruling)
        else {
            return DecidingRule::Unnamed;
        };
        DecidingRule::Named(rule.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ruled_by(settled_by: SettledBy) -> TenantRuling {
        TenantRuling::Decided {
            version: PolicyVersion::parse(3).unwrap(),
            settled_by,
            audit: AuditMark::NotAudited,
        }
    }

    fn contractors() -> Label {
        Label::new("name", "no contractors").unwrap()
    }

    /// Quinn is refused by the tenant's rule "no contractors". The record
    /// names that rule.
    #[test]
    fn a_refusal_by_a_tenant_rule_names_the_rule() {
        let decision = AccessDecision::new(
            Outcome::Deny(DenyCode::TenantRule),
            ruled_by(SettledBy::Rule(contractors())),
        );

        assert_eq!(decision.refusing_rule(), DecidingRule::Named(contractors()));
    }

    /// Pat is let through under an allow rule, then refused by the route
    /// for a permission she lacks, or refused by the policy's default. No
    /// rule refused her, so none is named.
    #[test]
    fn no_rule_is_named_where_no_rule_refused() {
        let allowed_then_refused = AccessDecision::new(
            Outcome::Deny(DenyCode::PermissionMissing),
            ruled_by(SettledBy::Rule(contractors())),
        );
        let by_default = AccessDecision::new(
            Outcome::Deny(DenyCode::TenantRule),
            ruled_by(SettledBy::Default),
        );
        let permitted =
            AccessDecision::new(Outcome::Permit, ruled_by(SettledBy::Rule(contractors())));

        for decision in [allowed_then_refused, by_default, permitted] {
            assert_eq!(decision.refusing_rule(), DecidingRule::Unnamed);
        }
    }

    /// Every code has its own stable name, so a search of the request log
    /// for one never finds another.
    #[test]
    fn every_code_has_its_own_name() {
        let codes = [
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

        let names: std::collections::HashSet<&str> =
            codes.iter().map(|code| code.as_str()).collect();

        assert_eq!(names.len(), codes.len());
    }

    /// A store that could not be read answers 503, a missing sign-in 401,
    /// and a refusal on the merits 403.
    #[test]
    fn a_code_answers_with_the_status_its_cause_calls_for() {
        assert_eq!(
            DenyCode::TenantPolicyUnreadable.status(),
            DenialStatus::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            DenyCode::SignInRequired.status(),
            DenialStatus::UNAUTHORIZED
        );
        assert_eq!(DenyCode::TenantRule.status(), DenialStatus::FORBIDDEN);
    }

    /// A refusal keeps its code as the reason and answers with its status;
    /// a step-up is a second-factor challenge naming its level; a missing
    /// key proof is a key-proof challenge; only a permit passes.
    #[test]
    fn each_outcome_comes_to_its_stage_decision() {
        let StageDecision::Deny { status, reason } =
            Outcome::Deny(DenyCode::SignInRequired).decision()
        else {
            panic!("a refusal is a deny");
        };
        assert_eq!(status, DenialStatus::UNAUTHORIZED);
        assert_eq!(reason, "sign_in_required");

        let StageDecision::Challenge {
            challenge_type: ChallengeType::Mfa,
            reason,
            ..
        } = Outcome::Challenge(Challenge::StepUp(AssuranceLevel::Aal2)).decision()
        else {
            panic!("a step-up is a second-factor challenge");
        };
        assert_eq!(reason, "step_up_aal2");

        assert!(matches!(
            Outcome::Challenge(Challenge::DpopProof).decision(),
            StageDecision::Challenge {
                challenge_type: ChallengeType::KeyProof,
                ..
            }
        ));
        assert!(!Outcome::Permit.decision().is_terminal());
    }

    /// Refused and challenged decisions report that access is not
    /// permitted; a permit reports that it is.
    #[test]
    fn only_a_permit_lets_a_request_through() {
        let refused = AccessDecision::refused(DenyCode::TenantRule);
        let challenged = AccessDecision::new(
            Outcome::Challenge(Challenge::DpopProof),
            TenantRuling::NoPolicy,
        );
        let permitted = AccessDecision::new(Outcome::Permit, TenantRuling::NoPolicy);

        assert!(!refused.permits());
        assert!(!challenged.permits());
        assert!(permitted.permits());
    }
}
