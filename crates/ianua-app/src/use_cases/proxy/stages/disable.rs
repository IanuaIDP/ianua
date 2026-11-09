//! Disable stage: switch off a stage the tenant chose, keeping its place in
//! the pipeline.

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

/// Which stage to switch off in which pipeline.
pub struct DisableRequest {
    /// The pipeline holding the stage.
    pub pipeline_id: PipelineId,
    /// The stage to disable.
    pub stage_id: StageId,
}

/// The ports [`DisableUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DisablePorts {
    /// Where pipelines are kept.
    pub pipeline_store: Arc<dyn PipelineStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Disables a pipeline stage.
pub struct DisableUseCase {
    ports: DisablePorts,
}

impl DisableUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DisablePorts) -> Self {
        Self { ports }
    }
}

impl Command for DisableUseCase {
    type Caller = CallerContext;
    type Input = DisableRequest;
    type Output = Result<(), AppError>;

    /// Disables the stage and records `proxy.stage_disabled`.
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
        request: DisableRequest,
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
                |pipeline| pipeline.disable_stage(&request.stage_id, &control),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{PipelineAction, SystemPermission};
    use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
    use ianua_domain::domains::proxy::stages::stage::StageKind;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::{
        FakePipelineStore, stage_of, test_pipeline_id, test_pipeline_with_rate_limit,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Seeded {
        store: Arc<FakePipelineStore>,
        policy: StageId,
        rate_limit: StageId,
    }

    fn seeded() -> Seeded {
        let pipeline = test_pipeline_with_rate_limit(PipelineStatus::Draft);
        let policy = stage_of(&pipeline, |kind| matches!(kind, StageKind::Policy));
        let rate_limit = stage_of(&pipeline, |kind| matches!(kind, StageKind::RateLimit(_)));
        Seeded {
            store: Arc::new(FakePipelineStore::holding(test_ctx().tenant_id(), pipeline)),
            policy,
            rate_limit,
        }
    }

    fn disable(
        seeded: &Seeded,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        stage_id: StageId,
    ) -> Result<(), AppError> {
        let use_case = DisableUseCase::new(DisablePorts {
            pipeline_store: seeded.store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        let request = DisableRequest {
            pipeline_id: test_pipeline_id(),
            stage_id,
        };
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    fn enabled(seeded: &Seeded, stage_id: &StageId) -> bool {
        block_on(seeded.store.find(&test_ctx().tenant(), &test_pipeline_id()))
            .unwrap()
            .unwrap()
            .stages()
            .iter()
            .any(|stage| stage.id() == stage_id && stage.enabled())
    }

    /// Ann switches off the rate limit while she tunes it. It stays in the
    /// pipeline, switched off, and the change is recorded.
    #[test]
    fn a_chosen_stage_is_disabled() {
        let seeded = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());

        disable(
            &seeded,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            seeded.rate_limit,
        )
        .unwrap();

        assert!(!enabled(&seeded, &seeded.rate_limit));
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["proxy.stage_disabled"]
        );
    }

    /// Ann switches off the Policy stage. It is refused: no request is let
    /// through without a policy deciding.
    #[test]
    fn a_mandatory_stage_is_not_disabled() {
        let seeded = seeded();

        let result = disable(
            &seeded,
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            seeded.policy,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(enabled(&seeded, &seeded.policy));
    }

    /// Ann names a stage the pipeline does not have. It is not found.
    #[test]
    fn an_unknown_stage_is_not_found() {
        let seeded = seeded();

        let result = disable(
            &seeded,
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            StageId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A viewer cannot disable the rate-limit stage, which remains enabled.
    #[test]
    fn a_caller_without_the_pipeline_right_is_refused() {
        let seeded = seeded();

        let result = disable(
            &seeded,
            FakeTenantAuthorities::holding(&[SystemPermission::Pipeline(PipelineAction::View)]),
            &Arc::new(FakeEventDispatcher::new()),
            seeded.rate_limit,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(enabled(&seeded, &seeded.rate_limit));
    }

    /// Disabling a stage without change rights returns forbidden even when
    /// the named pipeline does not exist.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_pipeline() {
        let nothing = Seeded {
            store: Arc::new(FakePipelineStore::empty()),
            policy: StageId::new(),
            rate_limit: StageId::new(),
        };

        let result = disable(
            &nothing,
            FakeTenantAuthorities::holding(&[]),
            &Arc::new(FakeEventDispatcher::new()),
            nothing.rate_limit,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session is refused when disabling a pipeline stage.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let seeded = seeded();

        let result = disable(
            &seeded,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &Arc::new(FakeEventDispatcher::new()),
            seeded.rate_limit,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
