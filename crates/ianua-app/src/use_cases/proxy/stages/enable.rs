//! Enable stage: turn a stage of one of the tenant's pipelines back on.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::types::{PipelineId, StageId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::proxy::PipelineStore;
use crate::use_case::Command;
use crate::use_cases::proxy::pipeline_changes::PipelineChange;

/// Which stage to turn back on in which pipeline.
pub struct EnableRequest {
    /// The pipeline holding the stage.
    pub pipeline_id: PipelineId,
    /// The stage to enable.
    pub stage_id: StageId,
}

/// The ports [`EnableUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct EnablePorts {
    /// Where pipelines are kept.
    pub pipeline_store: Arc<dyn PipelineStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Enables a pipeline stage.
pub struct EnableUseCase {
    ports: EnablePorts,
}

impl EnableUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: EnablePorts) -> Self {
        Self { ports }
    }
}

impl Command for EnableUseCase {
    type Caller = CallerContext;
    type Input = EnableRequest;
    type Output = Result<(), AppError>;

    /// Enables the stage and records `proxy.stage_enabled`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change pipelines, or
    ///   the pipeline is active.
    /// - `AppError::NotFound` when the tenant has no such pipeline, or it no
    ///   such stage.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: EnableRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::ChangePipeline)
            .map_err(AppError::from_domain)?;
        PipelineChange::by(caller, auditor)
            .pipeline(
                self.ports.pipeline_store.as_ref(),
                &request.pipeline_id,
                |pipeline| pipeline.enable_stage(&request.stage_id, &control),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{PipelineAction, SystemPermission};
    use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
    use ianua_domain::domains::proxy::stages::stage::StageKind;
    use ianua_domain::test_support::authority::anyone_holding;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::{
        FakePipelineStore, stage_of, test_pipeline_id, test_pipeline_with_rate_limit,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A pipeline in `status` whose rate limit was switched off while it
    /// was a draft, and that stage's id.
    fn seeded(status: PipelineStatus) -> (Arc<FakePipelineStore>, StageId) {
        let mut pipeline = test_pipeline_with_rate_limit(PipelineStatus::Draft);
        let rate_limit = stage_of(&pipeline, |kind| matches!(kind, StageKind::RateLimit(_)));
        let admin = RoutingControl::new(anyone_holding(SystemPermission::all()));
        pipeline.disable_stage(&rate_limit, &admin).unwrap();
        if status == PipelineStatus::Active {
            pipeline.activate(&[], &admin).unwrap();
        }
        let store = FakePipelineStore::holding(test_ctx().tenant_id(), pipeline);
        (Arc::new(store), rate_limit)
    }

    fn enable(
        store: &Arc<FakePipelineStore>,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        stage_id: StageId,
    ) -> Result<(), AppError> {
        let use_case = EnableUseCase::new(EnablePorts {
            pipeline_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        let request = EnableRequest {
            pipeline_id: test_pipeline_id(),
            stage_id,
        };
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    fn enabled(store: &FakePipelineStore, stage_id: &StageId) -> bool {
        block_on(store.find(&test_ctx().tenant(), &test_pipeline_id()))
            .unwrap()
            .unwrap()
            .stages()
            .iter()
            .any(|stage| stage.id() == stage_id && stage.enabled())
    }

    /// Ann turns the rate limit back on. It runs again and the change is
    /// recorded.
    #[test]
    fn a_disabled_stage_is_enabled() {
        let (store, stage) = seeded(PipelineStatus::Draft);
        let audit = Arc::new(FakeEventDispatcher::new());

        enable(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            stage,
        )
        .unwrap();

        assert!(enabled(&store, &stage));
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["proxy.stage_enabled"]
        );
    }

    /// A live pipeline is not edited: turning a stage on in one is refused
    /// outright, not reported as a slip in the request.
    #[test]
    fn a_stage_of_a_live_pipeline_is_not_enabled() {
        let (store, stage) = seeded(PipelineStatus::Active);

        let result = enable(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            stage,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!enabled(&store, &stage));
    }

    /// Ann names a stage the pipeline does not have. It is not found.
    #[test]
    fn an_unknown_stage_is_not_found() {
        let (store, _) = seeded(PipelineStatus::Draft);

        let result = enable(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            StageId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann names a pipeline the tenant does not have. It is not found.
    #[test]
    fn an_unknown_pipeline_is_not_found() {
        let result = enable(
            &Arc::new(FakePipelineStore::empty()),
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            StageId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A viewer cannot enable the rate-limit stage, which remains switched off.
    #[test]
    fn a_caller_without_the_pipeline_right_is_refused() {
        let (store, stage) = seeded(PipelineStatus::Draft);

        let result = enable(
            &store,
            FakeTenantAuthorities::holding(&[SystemPermission::Pipeline(PipelineAction::View)]),
            &Arc::new(FakeEventDispatcher::new()),
            stage,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!enabled(&store, &stage));
    }

    /// Enabling a stage without change rights returns forbidden even when the
    /// named pipeline does not exist.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_pipeline() {
        let result = enable(
            &Arc::new(FakePipelineStore::empty()),
            FakeTenantAuthorities::holding(&[]),
            &Arc::new(FakeEventDispatcher::new()),
            StageId::new(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session is refused when enabling a disabled stage.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, stage) = seeded(PipelineStatus::Draft);

        let result = enable(
            &store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &Arc::new(FakeEventDispatcher::new()),
            stage,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
