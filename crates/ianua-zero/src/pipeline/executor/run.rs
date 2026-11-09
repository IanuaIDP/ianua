//! One request's run: both stage ports answered for it, every failure a
//! refusal, every refusal of an agent recorded.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::proxy::{
    PipelineStore, ResponseMeta, ResponseStageExecutor, ResponseStageOutcome, StageExecutor,
};
use ianua_app::use_cases::proxy::{
    ConnectionHolder, EvaluatePipelinePorts, EvaluatePipelineUseCase, RecheckConnectionRequest,
};
use ianua_domain::domains::proxy::request::body::CapturedBody;
use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::domains::proxy::stages::stage::{StageConfig, StageKind};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::DenialStatus;

use super::carried::Carried;
use super::response::{Answered, withheld};
use super::{StageDispatch, StageGroups};
use crate::pipeline::facts::RequestFacts;
use crate::pipeline::stages::identity::held_credential;
use crate::pipeline::stages::policy::{asked, held_circumstances};
use crate::pipeline::stages::response::TokenLimit;

/// The stage ports, answered for one request.
///
/// Built by [`StageDispatch::for_request`] and dropped with the request:
/// what it carries between stages is this request's alone.
pub(crate) struct RequestRun {
    dispatch: Arc<StageDispatch>,
    facts: RequestFacts,
    carried: Carried,
}

impl RequestRun {
    /// The run of the request `facts` describe, through `dispatch`.
    pub(super) fn new(dispatch: Arc<StageDispatch>, facts: RequestFacts) -> Self {
        Self {
            dispatch,
            facts,
            carried: Carried::new(),
        }
    }

    /// The request, as the stages read it: what the handler forwards from
    /// once the pipeline allowed it.
    #[must_use]
    pub(crate) fn facts(&self) -> &RequestFacts {
        &self.facts
    }

    /// The application's pipeline use case, running its stages through
    /// this run and reading pipelines from `pipelines`.
    #[must_use]
    pub(crate) fn evaluation(
        self: &Arc<Self>,
        pipelines: Arc<dyn PipelineStore>,
    ) -> EvaluatePipelineUseCase {
        EvaluatePipelineUseCase::new(EvaluatePipelinePorts {
            pipeline_store: pipelines,
            stage_executor: Arc::clone(self) as Arc<dyn StageExecutor>,
        })
    }

    /// Gives back the tokens a token limit set aside that no answer
    /// settled: the request was refused after them, answered without
    /// forwarding, or its upstream never answered. The handler calls this
    /// once the request is done, whatever became of it.
    pub(crate) async fn release_unspent(&self, ctx: &PipelineContext) {
        for held in self.carried.unspent() {
            self.groups()
                .response
                .token_release(
                    TokenLimit {
                        stage: &held.stage,
                        config: &held.config,
                    },
                    ctx,
                    held.reservation,
                )
                .await;
        }
    }

    /// What an open connection `holder` opened with this request is
    /// asked again: the credential, the route and what the handshake asked.
    /// `None` when the credential can no longer be read, so the connection
    /// is checked as failed rather than left unchecked.
    pub(crate) fn connection_recheck(
        &self,
        holder: ConnectionHolder,
        ctx: &PipelineContext,
    ) -> Option<RecheckConnectionRequest> {
        let credential = held_credential(&self.facts, &ctx.route)?;
        Some(RecheckConnectionRequest {
            credential,
            holder,
            route_id: *self.facts.route.id(),
            asked: asked(&self.facts),
            circumstances: held_circumstances(ctx, self.carried.posture()),
        })
    }

    /// The stage groups.
    pub(super) fn groups(&self) -> &StageGroups {
        self.dispatch.groups()
    }

    /// What earlier stages of this request found.
    pub(super) fn carried(&self) -> &Carried {
        &self.carried
    }

    /// Records the refusal of an agent's request by any stage but Policy,
    /// which records its own: an agent probing past its task is seen
    /// whichever stage stops it.
    async fn record_refusal(
        &self,
        stage: &StageConfig,
        ctx: &PipelineContext,
        decision: &StageDecision,
    ) {
        if !decision.is_terminal() || matches!(stage.kind(), StageKind::Policy) {
            return;
        }
        self.groups()
            .policy
            .record_agent_refusal(ctx, &self.facts, decision)
            .await;
    }
}

#[async_trait]
impl StageExecutor for RequestRun {
    /// Runs `stage` in its group. A stage that fails is a refusal, never
    /// an error the walk could take for anything else.
    ///
    /// # Errors
    ///
    /// None: every failure is answered as a refusal.
    async fn execute(
        &self,
        stage: &StageConfig,
        ctx: &mut PipelineContext,
    ) -> Result<StageDecision, DomainError> {
        let decision = match self.decided(stage, ctx).await {
            Ok(decision) => decision,
            Err(error) => failed(stage, ctx, &error),
        };
        self.record_refusal(stage, ctx, &decision).await;
        Ok(decision)
    }
}

#[async_trait]
impl ResponseStageExecutor for RequestRun {
    /// Runs `stage` on the upstream's answer in the response group. A
    /// stage that fails withholds the answer.
    ///
    /// # Errors
    ///
    /// None: every failure withholds the answer.
    async fn execute_response(
        &self,
        stage: &StageConfig,
        ctx: &PipelineContext,
        response: &ResponseMeta,
        body: CapturedBody<'_>,
    ) -> Result<ResponseStageOutcome, DomainError> {
        let answered = Answered { response, body };
        match self.answered(stage, ctx, answered).await {
            Ok(outcome) => Ok(outcome),
            Err(error) => {
                log_failure(stage, ctx, &error);
                Ok(withheld(DenialStatus::BAD_GATEWAY, "stage_failed"))
            }
        }
    }
}

/// The refusal of a request whose stage could not run.
fn failed(stage: &StageConfig, ctx: &PipelineContext, error: &DomainError) -> StageDecision {
    log_failure(stage, ctx, error);
    deny(DenialStatus::SERVICE_UNAVAILABLE, "stage_failed")
}

/// Logs a stage that could not run, by its kind and the request's
/// correlation id.
fn log_failure(stage: &StageConfig, ctx: &PipelineContext, error: &DomainError) {
    tracing::warn!(
        stage = stage.kind().name(),
        correlation_id = %ctx.correlation_id,
        %error,
        "a stage could not run; refusing"
    );
}

/// A refusal answered with `status`, recorded as `reason`.
pub(super) fn deny(status: DenialStatus, reason: &str) -> StageDecision {
    StageDecision::Deny {
        status,
        reason: reason.to_owned(),
    }
}
