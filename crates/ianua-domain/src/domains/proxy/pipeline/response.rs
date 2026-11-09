//! What a pipeline does with the upstream's answer, and whether a request on
//! it may leave HTTP behind for a tunnel.

use crate::domains::proxy::pipeline::Pipeline;
use crate::domains::proxy::request::context::{Authentication, Caller, Metering, PipelineContext};
use crate::domains::proxy::stages::stage::StageConfig;
use crate::isolation::scope::TenantScope;

/// Whether a request may switch protocols, such as to a WebSocket, through
/// the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeRule {
    /// The connection may be upgraded and tunnelled.
    Allowed,
    /// The upgrade is refused, for this reason.
    Refused(UpgradeRefusal),
}

/// Why a request may not switch protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeRefusal {
    /// The pipeline inspects responses. Everything after the switch is the
    /// tenant's own protocol, not HTTP, so a redaction or canary scan could
    /// see none of it. The route belongs on a pipeline without response
    /// stages if it is to be tunnelled.
    InspectsResponses,
    /// The caller is an agent whose requests count against a budget. What
    /// follows the switch is not requests, so nothing could count it, and
    /// one handshake would be a way around the cap.
    MeteredCaller,
}

impl<T: TenantScope> Pipeline<T> {
    /// The enabled stages that act on the upstream's answer, in the order
    /// they run.
    ///
    /// That order is fixed by the kind of each stage, as
    /// [`ResponseSlot`](crate::domains::proxy::stages::stage::ResponseSlot)
    /// gives it, not by where the tenant placed it. Two stages of one kind
    /// run in their pipeline order.
    #[must_use]
    pub fn response_stages(&self) -> Vec<&StageConfig> {
        let mut placed: Vec<_> = self
            .active_stages()
            .into_iter()
            .filter_map(|stage| Some((stage.kind().kind_name().response_slot()?, stage)))
            .collect();
        placed.sort_by_key(|(slot, _)| *slot);
        placed.into_iter().map(|(_, stage)| stage).collect()
    }

    /// Whether the request in `ctx` may switch protocols on this pipeline.
    ///
    /// Refused when the pipeline inspects responses, then when the caller is
    /// a metered agent. Allowed otherwise.
    #[must_use]
    pub fn upgrade(&self, ctx: &PipelineContext) -> UpgradeRule {
        if !self.response_stages().is_empty() {
            return UpgradeRule::Refused(UpgradeRefusal::InspectsResponses);
        }
        if let Metering::Metered(_) = metering_of(ctx.authentication()) {
            return UpgradeRule::Refused(UpgradeRefusal::MeteredCaller);
        }
        UpgradeRule::Allowed
    }
}

/// Whether the caller's requests are counted against a budget. Only an
/// agent's task token is ever metered.
fn metering_of(authentication: &Authentication) -> Metering {
    match authentication.caller() {
        Some(Caller::Agent { limits, .. }) => limits.metering,
        Some(Caller::User { .. } | Caller::Consumer { .. }) | None => Metering::Unmetered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::authority::capability::{ActionApproval, McpGrant, RequestBudget};
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::domains::proxy::fixtures::{running, stage, switched_off};
    use crate::domains::proxy::request::context::{AgentLimits, KeyBinding, Verified};
    use crate::domains::proxy::request::transform::ResponseMutation;
    use crate::domains::proxy::stages::stage::{
        CacheConfig, CacheScope, RedactConfig, ResponseSignConfig, StageKind, StageKindName,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::restriction::Restriction;
    use crate::types::{
        AgentId, ClassificationRuleSetId, CorrelationId, DelegationId, Expiry, HeaderName,
        PipelineId, PrincipalRef, Seconds, TenantId, UserId,
    };

    fn redact() -> StageKind {
        StageKind::Redact(RedactConfig {
            rule_set_id: ClassificationRuleSetId::new(),
            min_class: DataClassLevel::Confidential,
        })
    }

    fn sign() -> StageKind {
        StageKind::ResponseSign(ResponseSignConfig {
            header_name: HeaderName::new("x-signature").unwrap(),
            ttl_seconds: Seconds::new(60),
        })
    }

    fn cache() -> StageKind {
        StageKind::Cache(CacheConfig {
            ttl_seconds: Seconds::new(60),
            vary_by_user: CacheScope::PerUser,
        })
    }

    fn transform() -> StageKind {
        StageKind::ResponseTransform(ResponseMutation::default())
    }

    fn kinds(stages: &[&StageConfig]) -> Vec<StageKindName> {
        stages
            .iter()
            .map(|stage| stage.kind().kind_name())
            .collect()
    }

    fn context() -> PipelineContext {
        PipelineContext::new(TenantId::new(), PipelineId::new(), CorrelationId::new())
    }

    fn signed_in(caller: Caller) -> PipelineContext {
        let mut ctx = context();
        ctx.authenticate(Verified {
            caller,
            expiry: Expiry::Never,
        })
        .unwrap();
        ctx
    }

    fn hundred_a_minute() -> RequestBudget {
        RequestBudget::new(100, Seconds::new(60)).unwrap()
    }

    fn agent(metering: Metering) -> Caller {
        Caller::Agent {
            agent_id: AgentId::new(),
            delegation_id: DelegationId::new(),
            acting_for: PrincipalRef::User(UserId::new()),
            limits: Box::new(AgentLimits {
                intent_envelope: Restriction::Unrestricted,
                mcp: McpGrant::default(),
                resource_scope: Restriction::Unrestricted,
                max_data_class: Restriction::Unrestricted,
                key_binding: KeyBinding::Bearer,
                approval: ActionApproval::NotRequired,
                metering,
            }),
        }
    }

    /// The tenant placed the cache first and redaction last. The answer is
    /// still redacted first, transformed, signed, then cached, so the cache
    /// never keeps a field redaction would have removed.
    #[test]
    fn response_stages_run_in_their_fixed_order() {
        let pipeline: Pipeline<ResolvedTenant> = running(vec![
            stage(cache()),
            stage(sign()),
            stage(transform()),
            stage(redact()),
        ]);

        assert_eq!(
            kinds(&pipeline.response_stages()),
            [
                StageKindName::Redact,
                StageKindName::ResponseTransform,
                StageKindName::ResponseSign,
                StageKindName::Cache,
            ]
        );
    }

    /// Request-only stages and switched-off response stages are not among
    /// the response stages.
    #[test]
    fn only_enabled_response_stages_act_on_the_answer() {
        let pipeline: Pipeline<ResolvedTenant> = running(vec![
            stage(StageKind::Mcp),
            switched_off(redact()),
            stage(sign()),
        ]);

        assert_eq!(
            kinds(&pipeline.response_stages()),
            [StageKindName::ResponseSign]
        );
    }

    /// A pipeline with no response stage lets a signed-in person open a
    /// WebSocket.
    #[test]
    fn a_pipeline_without_response_stages_allows_an_upgrade() {
        let pipeline: Pipeline<ResolvedTenant> = running(vec![stage(StageKind::Mcp)]);
        let person = signed_in(Caller::User {
            user_id: UserId::new(),
            sign_in: crate::domains::proxy::request::context::UserSignIn::Token,
        });

        assert_eq!(pipeline.upgrade(&person), UpgradeRule::Allowed);
        assert_eq!(pipeline.upgrade(&context()), UpgradeRule::Allowed);
    }

    /// A pipeline with an enabled redaction stage refuses protocol upgrades
    /// because it inspects responses.
    #[test]
    fn a_pipeline_that_inspects_responses_refuses_an_upgrade() {
        let pipeline: Pipeline<ResolvedTenant> = running(vec![stage(redact())]);

        assert_eq!(
            pipeline.upgrade(&context()),
            UpgradeRule::Refused(UpgradeRefusal::InspectsResponses)
        );
    }

    /// A switched-off redaction stage inspects nothing, so the upgrade is
    /// allowed.
    #[test]
    fn a_switched_off_response_stage_does_not_refuse_an_upgrade() {
        let pipeline: Pipeline<ResolvedTenant> = running(vec![switched_off(redact())]);

        assert_eq!(pipeline.upgrade(&context()), UpgradeRule::Allowed);
    }

    /// An agent subject to a request budget is refused a protocol upgrade.
    /// An unmetered agent is allowed on the same pipeline.
    #[test]
    fn a_metered_agent_may_not_open_a_tunnel() {
        let pipeline: Pipeline<ResolvedTenant> = running(Vec::new());

        assert_eq!(
            pipeline.upgrade(&signed_in(agent(Metering::Metered(hundred_a_minute())))),
            UpgradeRule::Refused(UpgradeRefusal::MeteredCaller)
        );
        assert_eq!(
            pipeline.upgrade(&signed_in(agent(Metering::Unmetered))),
            UpgradeRule::Allowed
        );
    }
}
