//! Remove stage: take a stage the tenant chose out of one of its pipelines.

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

/// Which stage to remove from which pipeline.
pub struct RemoveRequest {
    /// The pipeline holding the stage.
    pub pipeline_id: PipelineId,
    /// The stage to remove.
    pub stage_id: StageId,
}

/// The ports [`RemoveUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemovePorts {
    /// Where pipelines are kept.
    pub pipeline_store: Arc<dyn PipelineStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Removes a stage from a pipeline.
pub struct RemoveUseCase {
    ports: RemovePorts,
}

impl RemoveUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RemovePorts) -> Self {
        Self { ports }
    }
}

impl Command for RemoveUseCase {
    type Caller = CallerContext;
    type Input = RemoveRequest;
    type Output = Result<(), AppError>;

    /// Removes the stage and records `proxy.stage_removed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change pipelines, the
    ///   stage is Identity or Policy, or the pipeline is active.
    /// - `AppError::NotFound` when the tenant has no such pipeline, or it no
    ///   such stage.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: RemoveRequest,
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
                |pipeline| pipeline.remove_stage(&request.stage_id, &control),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{PipelineAction, SystemPermission};
    use ianua_domain::domains::proxy::pipeline::Pipeline;
    use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
    use ianua_domain::domains::proxy::stages::stage::StageKind;
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::{
        FakePipelineStore, stage_of, test_pipeline_id, test_pipeline_with_rate_limit,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Seeded {
        store: Arc<FakePipelineStore>,
        identity: StageId,
        rate_limit: StageId,
    }

    fn seeded(status: PipelineStatus) -> Seeded {
        let pipeline = test_pipeline_with_rate_limit(status);
        let identity = stage_of(&pipeline, |kind| matches!(kind, StageKind::Identity));
        let rate_limit = stage_of(&pipeline, |kind| matches!(kind, StageKind::RateLimit(_)));
        Seeded {
            store: Arc::new(FakePipelineStore::holding(test_ctx().tenant_id(), pipeline)),
            identity,
            rate_limit,
        }
    }

    fn remove(
        seeded: &Seeded,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        stage_id: StageId,
    ) -> Result<(), AppError> {
        let use_case = RemoveUseCase::new(RemovePorts {
            pipeline_store: seeded.store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        let request = RemoveRequest {
            pipeline_id: test_pipeline_id(),
            stage_id,
        };
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    fn stored(seeded: &Seeded) -> Pipeline<ResolvedTenant> {
        block_on(seeded.store.find(&test_ctx().tenant(), &test_pipeline_id()))
            .unwrap()
            .unwrap()
    }

    /// Ann removes the rate limit from a draft pipeline. It is gone and the
    /// removal recorded.
    #[test]
    fn a_chosen_stage_is_removed() {
        let seeded = seeded(PipelineStatus::Draft);
        let audit = Arc::new(FakeEventDispatcher::new());

        remove(
            &seeded,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            seeded.rate_limit,
        )
        .unwrap();

        assert_eq!(stored(&seeded).stages().len(), 2);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["proxy.stage_removed"]
        );
    }

    /// Ann removes the Identity stage. It is refused: no pipeline runs
    /// without knowing who sent the request.
    #[test]
    fn a_mandatory_stage_is_not_removed() {
        let seeded = seeded(PipelineStatus::Draft);
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = remove(
            &seeded,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            seeded.identity,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(stored(&seeded).stages().len(), 3);
    }

    /// Ann names a stage the pipeline does not have. It is not found.
    #[test]
    fn an_unknown_stage_is_not_found() {
        let seeded = seeded(PipelineStatus::Draft);

        let result = remove(
            &seeded,
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            StageId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A viewer cannot remove the rate limit, leaving all three pipeline
    /// stages stored.
    #[test]
    fn a_caller_without_the_pipeline_right_is_refused() {
        let seeded = seeded(PipelineStatus::Draft);
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = remove(
            &seeded,
            FakeTenantAuthorities::holding(&[SystemPermission::Pipeline(PipelineAction::View)]),
            &audit,
            seeded.rate_limit,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(stored(&seeded).stages().len(), 3);
    }

    /// Removing a stage without change rights returns forbidden even for an
    /// unknown pipeline, withholding whether it exists.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_pipeline() {
        let nothing = Seeded {
            store: Arc::new(FakePipelineStore::empty()),
            identity: StageId::new(),
            rate_limit: StageId::new(),
        };

        let result = remove(
            &nothing,
            FakeTenantAuthorities::holding(&[]),
            &Arc::new(FakeEventDispatcher::new()),
            nothing.rate_limit,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Removing a stage with a signed-out session fails authentication.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let seeded = seeded(PipelineStatus::Draft);

        let result = remove(
            &seeded,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &Arc::new(FakeEventDispatcher::new()),
            seeded.rate_limit,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
