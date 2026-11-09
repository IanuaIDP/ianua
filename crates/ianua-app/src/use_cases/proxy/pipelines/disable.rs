//! Disable pipeline: take a pipeline off live traffic, so its routes are
//! refused.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::types::PipelineId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::proxy::PipelineStore;
use crate::use_case::Command;
use crate::use_cases::proxy::pipeline_changes::PipelineChange;

/// The ports [`DisableUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DisablePorts {
    /// Where pipelines are kept.
    pub pipeline_store: Arc<dyn PipelineStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Disables a live pipeline.
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
    type Input = PipelineId;
    type Output = Result<(), AppError>;

    /// Disables the pipeline and records `proxy.pipeline_disabled`, so
    /// every proxy stops running it. Traffic on its routes is then denied.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change pipelines.
    /// - `AppError::NotFound` when the tenant has no such pipeline.
    /// - `AppError::Domain` when the pipeline is not active.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        pipeline_id: PipelineId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::ChangePipeline)
            .map_err(AppError::from_domain)?;
        PipelineChange::by(caller, auditor)
            .pipeline(
                self.ports.pipeline_store.as_ref(),
                &pipeline_id,
                |pipeline| pipeline.disable(&control),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{PipelineAction, SystemPermission};
    use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;

    use super::*;
    use crate::ports::shared::EventDispatcher;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::{FakePipelineStore, test_pipeline_id, test_pipeline_in};
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, block_on, test_auditor, test_ctx,
    };

    fn seeded(status: PipelineStatus) -> Arc<FakePipelineStore> {
        Arc::new(FakePipelineStore::holding(
            test_ctx().tenant_id(),
            test_pipeline_in(status),
        ))
    }

    fn disable(
        store: &Arc<FakePipelineStore>,
        authorities: FakeTenantAuthorities,
        audit: Arc<dyn EventDispatcher>,
    ) -> Result<(), AppError> {
        let use_case = DisableUseCase::new(DisablePorts {
            pipeline_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit), test_pipeline_id()))
    }

    fn status_of(store: &FakePipelineStore) -> PipelineStatus {
        block_on(store.find(&test_ctx().tenant(), &test_pipeline_id()))
            .unwrap()
            .unwrap()
            .status()
    }

    /// Ann takes a live pipeline off traffic. It is disabled, and that is
    /// recorded so every proxy stops running it.
    #[test]
    fn an_active_pipeline_is_disabled_and_announced() {
        let store = seeded(PipelineStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());

        disable(
            &store,
            FakeTenantAuthorities::holding_everything(),
            audit.clone(),
        )
        .unwrap();

        assert_eq!(status_of(&store), PipelineStatus::Disabled);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["proxy.pipeline_disabled"]
        );
    }

    /// The change cannot be recorded. Ann is told it failed rather than
    /// that proxies were left running a pipeline she switched off.
    #[test]
    fn a_disable_that_cannot_be_recorded_fails() {
        let store = seeded(PipelineStatus::Active);

        let result = disable(
            &store,
            FakeTenantAuthorities::holding_everything(),
            Arc::new(FailingEventDispatcher),
        );

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// Ann disables a draft pipeline. It is refused as a move the pipeline
    /// cannot make.
    #[test]
    fn a_draft_pipeline_is_not_disabled() {
        let store = seeded(PipelineStatus::Draft);

        let result = disable(
            &store,
            FakeTenantAuthorities::holding_everything(),
            Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann names a pipeline the tenant does not have. It is not found.
    #[test]
    fn an_unknown_pipeline_is_not_found() {
        let result = disable(
            &Arc::new(FakePipelineStore::empty()),
            FakeTenantAuthorities::holding_everything(),
            Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A viewer cannot disable a pipeline; its stored status remains active.
    #[test]
    fn a_caller_without_the_pipeline_right_is_refused() {
        let store = seeded(PipelineStatus::Active);

        let result = disable(
            &store,
            FakeTenantAuthorities::holding(&[SystemPermission::Pipeline(PipelineAction::View)]),
            Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status_of(&store), PipelineStatus::Active);
    }

    /// Disabling an unknown pipeline without change rights returns forbidden
    /// rather than revealing its absence.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_pipeline() {
        let result = disable(
            &Arc::new(FakePipelineStore::empty()),
            FakeTenantAuthorities::holding(&[]),
            Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot disable an active pipeline.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = seeded(PipelineStatus::Active);

        let result = disable(
            &store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
