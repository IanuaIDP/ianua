//! Evaluate pipeline: run the active stages of a route's pipeline against a
//! request.
//!
//! The proxy adapter calls this for every inbound request. It walks the
//! stages in order, gathering what each learns, and stops at the first that
//! refuses (Deny, Challenge). Anything short of the Policy stage granting
//! the request is a denial.

use std::sync::Arc;

use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::domains::proxy::request::context::{Authorization, PipelineContext};
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::domains::proxy::stages::stage::{MandatoryStage, StageConfig};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;

use crate::error::{AppError, OrInternal};
use crate::ports::proxy::{PipelineStore, StageExecutor};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::proxy::lookup::existing_pipeline;

/// What evaluating the whole pipeline came to.
pub struct PipelineResult {
    /// What each stage decided, in order.
    pub decisions: Vec<StageDecision>,
    /// The context as the stages left it.
    pub context: PipelineContext,
    /// Whether the request may go through.
    pub verdict: PipelineVerdict,
}

/// Whether the pipeline lets a request through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineVerdict {
    /// Every stage ran and the Policy stage granted the request.
    Allowed,
    /// A stage stopped the request, or the Policy stage never granted it.
    Denied,
}

impl PipelineVerdict {
    /// The verdict once every stage has run without stopping the request:
    /// allowed only if the Policy stage granted it.
    fn after_every_stage(ctx: &PipelineContext) -> Self {
        match ctx.authorization() {
            Authorization::Granted => Self::Allowed,
            Authorization::NotGranted => Self::Denied,
        }
    }
}

/// The ports [`EvaluatePipelineUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct EvaluatePipelinePorts {
    /// Where pipelines are kept.
    pub pipeline_store: Arc<dyn PipelineStore>,
    /// Runs one stage.
    pub stage_executor: Arc<dyn StageExecutor>,
}

/// Evaluates a pipeline for one request.
pub struct EvaluatePipelineUseCase {
    ports: EvaluatePipelinePorts,
}

impl EvaluatePipelineUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: EvaluatePipelinePorts) -> Self {
        Self { ports }
    }
}

/// How a walk through the stages ended.
enum StageWalk {
    /// A stage returned a terminal decision; the rest never ran.
    Stopped(Vec<StageDecision>),
    /// Every stage ran without a terminal decision.
    Completed(Vec<StageDecision>),
}

impl Query for EvaluatePipelineUseCase {
    type Caller = ScopedTenant;
    type Input = PipelineContext;
    type Output = Result<PipelineResult, AppError>;

    /// Runs the active stages of the pipeline `ctx` names that decide before
    /// forwarding, for the tenant the request resolved to, in position
    /// order. A stage that acts only on the upstream's answer is the
    /// response chain's and never reaches the executor here.
    ///
    /// The request is allowed only when no stage stopped it and the Policy
    /// stage granted it; anything less is a denial.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the context names a tenant other than
    ///   `tenant`, the pipeline is not active, or a mandatory stage does not
    ///   run.
    /// - `AppError::NotFound` when the tenant has no such pipeline.
    /// - `AppError::Internal` when a stage cannot run: an error, never a
    ///   pass.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        mut ctx: PipelineContext,
    ) -> Result<PipelineResult, AppError> {
        ensure_same_tenant(tenant, &ctx)?;
        let pipeline =
            existing_pipeline(self.ports.pipeline_store.as_ref(), tenant, &ctx.pipeline_id).await?;
        ensure_active(&pipeline)?;
        let request_stages = pipeline.request_stages();
        ensure_mandatory_stages(&request_stages)?;

        let walk = stage_decisions(
            self.ports.stage_executor.as_ref(),
            &request_stages,
            &mut ctx,
        )
        .await?;
        let (decisions, verdict) = match walk {
            StageWalk::Stopped(decisions) => (decisions, PipelineVerdict::Denied),
            StageWalk::Completed(decisions) => {
                (decisions, PipelineVerdict::after_every_stage(&ctx))
            }
        };
        Ok(PipelineResult {
            decisions,
            context: ctx,
            verdict,
        })
    }
}

/// Refuses a context that names a tenant other than the one the request
/// resolved to.
fn ensure_same_tenant(tenant: &ScopedTenant, ctx: &PipelineContext) -> Result<(), AppError> {
    if ctx.tenant_id != **tenant {
        return Err(AppError::Forbidden(message!(
            "proxy-the-pipeline-context-names-another-tenant",
            "the pipeline context names another tenant, so traffic is denied"
        )));
    }
    Ok(())
}

/// Refuses a pipeline that is not carrying traffic.
fn ensure_active(pipeline: &Pipeline<ResolvedTenant>) -> Result<(), AppError> {
    if !pipeline.status().is_active() {
        return Err(AppError::Forbidden(message!(
            "proxy-the-pipeline-is-not-active-so",
            "the pipeline is not active, so traffic is denied"
        )));
    }
    Ok(())
}

/// Refuses a stage list without Identity or Policy, so no request is
/// decided without knowing who sent it and what they may do.
///
/// A stored pipeline already holds both, enabled. This keeps the proxy
/// denying should that ever not hold.
fn ensure_mandatory_stages(stages: &[&StageConfig]) -> Result<(), AppError> {
    let runs = |mandatory: MandatoryStage| stages.iter().any(|stage| mandatory.is(stage.kind()));
    if !runs(MandatoryStage::Identity) || !runs(MandatoryStage::Policy) {
        return Err(AppError::Forbidden(message!(
            "proxy-the-identity-or-policy-stage-does",
            "the Identity or Policy stage does not run, so traffic is denied"
        )));
    }
    Ok(())
}

/// Runs `stages` in order against `ctx`, merging every transform into the
/// request, and stops at the first terminal decision.
async fn stage_decisions(
    executor: &dyn StageExecutor,
    stages: &[&StageConfig],
    ctx: &mut PipelineContext,
) -> Result<StageWalk, AppError> {
    let mut decisions = Vec::with_capacity(stages.len());
    for stage in stages {
        let decision = executor.execute(stage, ctx).await.or_internal()?;
        if let StageDecision::Transform { mutation, .. } = &decision {
            ctx.request_mutation.merge(mutation.clone());
        }
        let terminal = decision.is_terminal();
        decisions.push(decision);
        if terminal {
            return Ok(StageWalk::Stopped(decisions));
        }
    }
    Ok(StageWalk::Completed(decisions))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
    use ianua_domain::domains::proxy::request::transform::ResponseMutation;
    use ianua_domain::domains::proxy::stages::stage::{StageKind, StageRemoval};
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{CorrelationId, DenialStatus, TenantId};

    use super::*;
    use crate::test_support::proxy::{
        FakePipelineStore, FakeStageExecutor, test_pipeline_id, test_pipeline_in,
        test_pipeline_running,
    };
    use crate::test_support::{block_on, test_ctx};

    /// A stage that cannot reach what it needs.
    struct UnreachableExecutor;

    #[async_trait]
    impl StageExecutor for UnreachableExecutor {
        async fn execute(
            &self,
            _: &StageConfig,
            _: &mut PipelineContext,
        ) -> Result<StageDecision, DomainError> {
            Err(DomainError::infra_msg("the policy store is unreachable"))
        }
    }

    /// Passes every stage and never grants anybody: no denial, and no
    /// grant either.
    struct IndecisiveExecutor;

    #[async_trait]
    impl StageExecutor for IndecisiveExecutor {
        async fn execute(
            &self,
            _: &StageConfig,
            _: &mut PipelineContext,
        ) -> Result<StageDecision, DomainError> {
            Ok(StageDecision::Pass {
                reason: "no opinion".to_owned(),
            })
        }
    }

    /// Passes the first stage and denies the second.
    #[derive(Default)]
    struct DenyOnSecondExecutor {
        calls: Mutex<u32>,
    }

    #[async_trait]
    impl StageExecutor for DenyOnSecondExecutor {
        async fn execute(
            &self,
            _: &StageConfig,
            _: &mut PipelineContext,
        ) -> Result<StageDecision, DomainError> {
            let mut calls = self.calls.lock().unwrap();
            *calls += 1;
            if *calls < 2 {
                return Ok(StageDecision::Pass {
                    reason: "identity ok".to_owned(),
                });
            }
            Ok(StageDecision::Deny {
                status: DenialStatus::FORBIDDEN,
                reason: "policy denied".to_owned(),
            })
        }
    }

    /// Fails on a stage that acts only on the upstream's answer, as the
    /// gateway's executor refuses one handed to it before forwarding.
    struct RequestChainOnly;

    #[async_trait]
    impl StageExecutor for RequestChainOnly {
        async fn execute(
            &self,
            stage: &StageConfig,
            ctx: &mut PipelineContext,
        ) -> Result<StageDecision, DomainError> {
            if !stage.kind().phase().runs_on_request() {
                return Err(DomainError::infra_msg(
                    "a response stage reached the request chain",
                ));
            }
            FakeStageExecutor.execute(stage, ctx).await
        }
    }

    fn tenant_id() -> TenantId {
        test_ctx().tenant_id()
    }

    fn use_case(
        status: PipelineStatus,
        executor: Arc<dyn StageExecutor>,
    ) -> EvaluatePipelineUseCase {
        EvaluatePipelineUseCase::new(EvaluatePipelinePorts {
            pipeline_store: Arc::new(FakePipelineStore::holding(
                tenant_id(),
                test_pipeline_in(status),
            )),
            stage_executor: executor,
        })
    }

    fn request() -> PipelineContext {
        PipelineContext::new(tenant_id(), test_pipeline_id(), CorrelationId::new())
    }

    fn evaluate(
        use_case: &EvaluatePipelineUseCase,
        ctx: PipelineContext,
    ) -> Result<PipelineResult, AppError> {
        block_on(use_case.execute(&ScopedTenant::for_test(tenant_id()), ctx))
    }

    fn passing() -> Arc<dyn StageExecutor> {
        Arc::new(FakeStageExecutor)
    }

    /// Ann signs in to an app behind an active pipeline. Identity and
    /// Policy both run, Policy grants her, and she is let through.
    #[test]
    fn a_granted_request_is_allowed_after_every_stage() {
        let use_case = use_case(PipelineStatus::Active, passing());

        let result = evaluate(&use_case, request()).unwrap();

        assert_eq!(result.verdict, PipelineVerdict::Allowed);
        assert_eq!(result.decisions.len(), 2);
    }

    /// A context naming a different tenant from the resolved request is
    /// forbidden from pipeline evaluation.
    #[test]
    fn a_context_naming_another_tenant_is_denied() {
        let use_case = use_case(PipelineStatus::Active, passing());

        let result =
            block_on(use_case.execute(&ScopedTenant::for_test(TenantId::new()), request()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A stage unable to reach the policy store returns an internal error
    /// rather than an allowed verdict.
    #[test]
    fn a_stage_that_cannot_run_is_an_error_not_an_allow() {
        let use_case = use_case(PipelineStatus::Active, Arc::new(UnreachableExecutor));

        let result = evaluate(&use_case, request());

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// Passing every stage without an authorization grant still yields a
    /// denied verdict.
    #[test]
    fn a_request_nobody_granted_is_denied() {
        let use_case = use_case(PipelineStatus::Active, Arc::new(IndecisiveExecutor));

        let result = evaluate(&use_case, request()).unwrap();

        assert_eq!(result.verdict, PipelineVerdict::Denied);
    }

    /// A denial from the second stage ends the decision list there and denies
    /// the request.
    #[test]
    fn a_denial_stops_the_walk() {
        let use_case = use_case(
            PipelineStatus::Active,
            Arc::new(DenyOnSecondExecutor::default()),
        );

        let result = evaluate(&use_case, request()).unwrap();

        assert_eq!(result.verdict, PipelineVerdict::Denied);
        assert_eq!(result.decisions.len(), 2);
        assert!(result.decisions[1].is_terminal());
    }

    /// Ann's pipeline also rewrites the upstream's answer. That stage is
    /// the response chain's: the walk before forwarding never hands it to
    /// the executor, and she is let through on Identity and Policy.
    #[test]
    fn a_stage_acting_only_on_the_answer_is_left_to_the_response_chain() {
        let transform = StageConfig::new(
            StageKind::ResponseTransform(ResponseMutation::default()),
            300,
            StageRemoval::Allowed,
        )
        .unwrap();
        let use_case = EvaluatePipelineUseCase::new(EvaluatePipelinePorts {
            pipeline_store: Arc::new(FakePipelineStore::holding(
                tenant_id(),
                test_pipeline_running(PipelineStatus::Active, vec![transform]),
            )),
            stage_executor: Arc::new(RequestChainOnly),
        });

        let result = evaluate(&use_case, request()).unwrap();

        assert_eq!(result.verdict, PipelineVerdict::Allowed);
        assert_eq!(result.decisions.len(), 2);
    }

    /// Evaluating an unknown pipeline returns not found instead of a verdict.
    #[test]
    fn an_unknown_pipeline_is_not_found() {
        let use_case = EvaluatePipelineUseCase::new(EvaluatePipelinePorts {
            pipeline_store: Arc::new(FakePipelineStore::empty()),
            stage_executor: passing(),
        });

        let result = evaluate(&use_case, request());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A draft pipeline refuses evaluation with a forbidden error.
    #[test]
    fn a_draft_pipeline_denies_traffic() {
        let use_case = use_case(PipelineStatus::Draft, passing());

        let result = evaluate(&use_case, request());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A disabled pipeline refuses evaluation with a forbidden error.
    #[test]
    fn a_disabled_pipeline_denies_traffic() {
        let use_case = use_case(PipelineStatus::Disabled, passing());

        let result = evaluate(&use_case, request());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
