//! The stage dispatcher: the application's stage ports filled by handing
//! each stage to the group that runs its kind.
//!
//! [`StageDispatch`] holds the five stage groups, built once at start-up.
//! The ports hand a stage only its settings and the pipeline context, so
//! for every request the handler builds the request's [`RequestFacts`] and
//! asks [`StageDispatch::for_request`] for a [`RequestRun`]: the one value
//! that answers both ports for that request, reads the facts, and carries
//! what one stage finds to the next (the proof of the caller for the
//! Policy stage, the device check, the tokens a limit set aside).
//!
//! Deny by default. A stage whose kind runs in the other chain, a stage
//! that fails, and a Policy stage with no proof before it are each a
//! refusal with a reason code, never a pass; the reason never carries a
//! credential. An agent's request refused by any stage after Policy is
//! recorded as refused.

mod carried;
mod request;
mod response;
mod run;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::RouteId;
pub(crate) use run::RequestRun;

use crate::pipeline::facts::RequestFacts;
use crate::pipeline::stages::checks::CheckStages;
use crate::pipeline::stages::counters::{CounterStages, ReconOutcome};
use crate::pipeline::stages::identity::IdentityStages;
use crate::pipeline::stages::policy::PolicyStages;
use crate::pipeline::stages::response::ResponseStages;

/// The five stage groups the dispatcher hands stages to.
pub(crate) struct StageGroups {
    /// `Identity`, `StepUp`, `DevicePosture` and `TokenExchange`.
    pub identity: IdentityStages,
    /// `Policy` and `DataClassify`.
    pub policy: PolicyStages,
    /// `RateLimit`, `TokenRateLimit` before forwarding, `HoneypotRoutes`,
    /// `ReconDetection`, `IpReputation`, and the agent request budget every
    /// proven agent is counted against.
    pub counters: CounterStages,
    /// `Waf`, `Cors`, `Fingerprint`, `GeoFence`, `GraphQl`, `Mcp`,
    /// `RequestTransform`, `Custom` and `Terminate`.
    pub checks: CheckStages,
    /// The signatures, `SecurityHeaders`, both sides of `Cache` and
    /// `CanaryToken`, and everything acting on the upstream's answer.
    pub response: ResponseStages,
}

/// Runs each stage of a pipeline in the group its kind belongs to.
pub(crate) struct StageDispatch {
    groups: StageGroups,
}

impl StageDispatch {
    /// The dispatcher over `groups`, built once at start-up.
    #[must_use]
    pub(crate) fn new(groups: StageGroups) -> Self {
        Self { groups }
    }

    /// The run of one request: the stage ports, answered for the request
    /// `facts` describe.
    ///
    /// It is shared because the application's pipeline use case holds its
    /// stage executor as one; nothing it carries outlives the request.
    #[must_use]
    pub(crate) fn for_request(self: &Arc<Self>, facts: RequestFacts) -> Arc<RequestRun> {
        Arc::new(RequestRun::new(Arc::clone(self), facts))
    }

    /// Counts a finished request toward its client's recon score, matched
    /// or not: a scanner's requests for paths no route takes are the ones
    /// the score is for. The handler calls it once every request is
    /// answered, whatever the answer.
    pub(crate) async fn record_recon(&self, outcome: ReconOutcome<'_>) {
        self.groups.counters.record_recon(outcome).await;
    }

    /// What attack mode decides of a request to `route`, before its
    /// pipeline runs.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when a refusal's headers cannot be written.
    pub(crate) async fn under_attack(
        &self,
        route: &RouteId,
        ctx: &mut PipelineContext,
    ) -> Result<StageDecision, DomainError> {
        self.groups.counters.under_attack(route, ctx).await
    }

    /// The groups, for the request and response chains.
    fn groups(&self) -> &StageGroups {
        &self.groups
    }
}
