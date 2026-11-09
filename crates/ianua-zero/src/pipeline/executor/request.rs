//! The chain before forwarding: each stage kind handed to its group's
//! method, and what it finds kept for the stages after it.

use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::domains::proxy::stages::posture::PostureRule;
use ianua_domain::domains::proxy::stages::stage::{ReconDetectionConfig, StageConfig, StageKind};
use ianua_domain::domains::proxy::stages::token_budget::TokenRateLimitConfig;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::DenialStatus;

use super::carried::HeldTokens;
use super::run::{RequestRun, deny};
use crate::pipeline::stages::counters::{DecoyProbe, ReconProbe};
use crate::pipeline::stages::identity::IdentityOutcome;
use crate::pipeline::stages::response::Exchange;

impl RequestRun {
    /// What `stage` decides before forwarding, from the group its kind
    /// belongs to.
    ///
    /// One arm per kind, with no catch-all, so a new kind does not compile
    /// until it is given a group. A kind that only acts on the upstream's
    /// answer is refused here: the application never hands one to this
    /// chain, and one that arrives is a fault, not a pass.
    ///
    /// # Errors
    ///
    /// The [`DomainError`] of a group that could not run the stage, which
    /// the run turns into a refusal.
    /// The exhaustive kind dispatch keeps each stage's phase visible to the compiler.
    #[allow(clippy::too_many_lines)]
    pub(super) async fn decided(
        &self,
        stage: &StageConfig,
        ctx: &mut PipelineContext,
    ) -> Result<StageDecision, DomainError> {
        let groups = self.groups();
        let facts = self.facts();
        match stage.kind() {
            StageKind::Identity => self.identity(ctx).await,
            StageKind::Policy => self.policy(ctx).await,
            StageKind::DevicePosture(rule) => self.device_posture(rule, ctx).await,
            StageKind::StepUp(config) => groups.identity.step_up(config, ctx).await,
            StageKind::TokenExchange(config) => {
                groups
                    .identity
                    .token_exchange(&facts.tenant, config, ctx)
                    .await
            }
            StageKind::DataClassify(config) => {
                groups
                    .policy
                    .data_classify(ctx, &facts.tenant, config)
                    .await
            }
            StageKind::RateLimit(config) => {
                groups.counters.rate_limit(stage.id(), config, ctx).await
            }
            StageKind::TokenRateLimit(config) => self.token_limit(stage, config, ctx).await,
            StageKind::HoneypotRoutes(_) => self.honeypot(ctx).await,
            StageKind::ReconDetection(config) => self.recon(config, ctx).await,
            StageKind::IpReputation(config) => groups.counters.ip_reputation(config, ctx).await,
            StageKind::Waf(config) => Ok(groups.checks.waf(config, facts).await),
            StageKind::Cors(config) => Ok(groups.checks.cors(config, facts, ctx).await),
            StageKind::Fingerprint(config) => Ok(groups.checks.fingerprint(config, facts).await),
            StageKind::GeoFence(config) => Ok(groups.checks.geo_fence(config, ctx).await),
            StageKind::GraphQl(limits) => Ok(groups.checks.graphql(limits, facts).await),
            StageKind::Mcp => Ok(groups.checks.mcp(facts, ctx).await),
            StageKind::RequestTransform(mutation) => {
                Ok(groups.checks.request_transform(mutation).await)
            }
            StageKind::Custom(module) => Ok(groups.checks.custom(module, facts, ctx).await),
            StageKind::Terminate(config) => Ok(groups.checks.terminate(config, ctx).await),
            StageKind::RequestSign(config) => {
                groups.response.request_sign(config, ctx, facts).await
            }
            StageKind::SecurityHeaders(config) => groups.response.security_headers(config, ctx),
            StageKind::Cache(config) => Ok(groups
                .response
                .cache_lookup(config, ctx, Exchange::from(facts))
                .await),
            StageKind::CanaryToken(config) => {
                groups.response.canary_presented(config, ctx, facts).await
            }
            StageKind::Redact(_) | StageKind::ResponseSign(_) | StageKind::ResponseTransform(_) => {
                Ok(out_of_phase(stage, ctx))
            }
        }
    }

    /// The Identity stage: who the request comes from, kept for the Policy
    /// stage, and, for an agent whose task token is metered, its request
    /// counted against the budget at once, so every request it sends is
    /// counted whatever stops it later.
    async fn identity(&self, ctx: &mut PipelineContext) -> Result<StageDecision, DomainError> {
        let groups = self.groups();
        let IdentityOutcome {
            decision,
            identification,
        } = groups.identity.identity(self.facts(), ctx).await?;
        let Some(identification) = identification else {
            return Ok(decision);
        };
        self.carried().record_identity(identification);
        let budget = groups.counters.agent_budget(ctx).await?;
        if budget.is_terminal() {
            return Ok(budget);
        }
        Ok(decision)
    }

    /// The Policy stage, deciding on what the stages before it found. A
    /// Policy stage no Identity stage ran before proves nobody, and is
    /// refused rather than decided as if nobody were asking.
    async fn policy(&self, ctx: &mut PipelineContext) -> Result<StageDecision, DomainError> {
        let Some(earlier) = self.carried().earlier() else {
            tracing::error!(
                correlation_id = %ctx.correlation_id,
                "the Policy stage ran with no caller established before it; refusing"
            );
            return Ok(deny(DenialStatus::FORBIDDEN, "identity_not_established"));
        };
        let policy = &self.groups().policy;
        policy.policy(ctx, self.facts(), earlier).await
    }

    /// The `DevicePosture` stage, its finding kept for the Policy stage.
    async fn device_posture(
        &self,
        rule: &PostureRule,
        ctx: &mut PipelineContext,
    ) -> Result<StageDecision, DomainError> {
        let outcome = self
            .groups()
            .identity
            .device_posture(&self.facts().tenant, rule, ctx)
            .await?;
        self.carried().posture_checked(outcome.finding);
        Ok(outcome.decision)
    }

    /// The request side of a token limit, the tokens it set aside kept for
    /// the answer to settle.
    async fn token_limit(
        &self,
        stage: &StageConfig,
        config: &TokenRateLimitConfig,
        ctx: &mut PipelineContext,
    ) -> Result<StageDecision, DomainError> {
        let admission = self
            .groups()
            .counters
            .token_rate_limit(stage.id(), config, ctx)
            .await?;
        if let Some(reservation) = admission.reservation {
            self.carried().record_reservation(HeldTokens {
                stage: *stage.id(),
                config: config.clone(),
                reservation,
            });
        }
        Ok(admission.decision)
    }

    /// The `HoneypotRoutes` stage, on the decoy lifetime the handler read
    /// across the tenant's pipelines.
    async fn honeypot(&self, ctx: &PipelineContext) -> Result<StageDecision, DomainError> {
        let facts = self.facts();
        let probe = DecoyProbe {
            path: facts.admitted.path().as_str(),
            lifetime: facts.decoy,
        };
        self.groups().counters.honeypot(ctx, probe).await
    }

    /// The `ReconDetection` stage, over the tenant's recon window. A window
    /// the handler could not read leaves nothing to score in, and refuses.
    async fn recon(
        &self,
        config: &ReconDetectionConfig,
        ctx: &PipelineContext,
    ) -> Result<StageDecision, DomainError> {
        let facts = self.facts();
        let Some(window) = facts.recon_window else {
            tracing::error!(
                correlation_id = %ctx.correlation_id,
                "a recon stage ran with no recon window known; refusing"
            );
            return Ok(deny(
                DenialStatus::SERVICE_UNAVAILABLE,
                "recon_window_unknown",
            ));
        };
        let probe = ReconProbe {
            path: facts.admitted.path().as_str(),
            window,
        };
        self.groups().counters.recon(config, probe, ctx).await
    }
}

/// The refusal of a stage that only acts on the upstream's answer, handed
/// to the chain before forwarding.
fn out_of_phase(stage: &StageConfig, ctx: &PipelineContext) -> StageDecision {
    tracing::error!(
        stage = stage.kind().name(),
        correlation_id = %ctx.correlation_id,
        "a stage acting on the answer reached the chain before forwarding; refusing"
    );
    deny(DenialStatus::SERVICE_UNAVAILABLE, "stage_out_of_phase")
}
