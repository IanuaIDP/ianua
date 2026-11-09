//! Activate pipeline: put a configured pipeline on live traffic.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::types::PipelineId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::proxy::PipelineStore;
use crate::ports::routing::RouteStore;
use crate::use_case::Command;
use crate::use_cases::proxy::pipeline_changes::PipelineChange;
use crate::use_cases::routing::lookup::routes_on;

/// The ports [`ActivateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ActivatePorts {
    /// Where pipelines are kept.
    pub pipeline_store: Arc<dyn PipelineStore>,
    /// The tenant's routes, which the pipeline's stages must fit.
    pub route_store: Arc<dyn RouteStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Activates a pipeline for live traffic.
pub struct ActivateUseCase {
    ports: ActivatePorts,
}

impl ActivateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ActivatePorts) -> Self {
        Self { ports }
    }
}

impl Command for ActivateUseCase {
    type Caller = CallerContext;
    type Input = PipelineId;
    type Output = Result<(), AppError>;

    /// Activates the pipeline, held to every route that runs it, and records
    /// `proxy.pipeline_activated` so every proxy reloads it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without pipeline-change rights.
    /// - `AppError::NotFound` for a missing tenant pipeline; `Conflict` for shared response caching on a signed-in route.
    /// - `AppError::Domain` for an active pipeline; `Internal` on storage or audit failure.
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
        let tenant = caller.tenant();
        let routes = routes_on(self.ports.route_store.as_ref(), &tenant, &pipeline_id).await?;
        PipelineChange::by(caller, auditor)
            .pipeline(
                self.ports.pipeline_store.as_ref(),
                &pipeline_id,
                |pipeline| pipeline.activate(&routes, &control),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{PipelineAction, SystemPermission};
    use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
    use ianua_domain::domains::proxy::stages::stage::{
        CacheConfig, CacheScope, StageConfig, StageKind, StageRemoval,
    };
    use ianua_domain::domains::routing::policy::RoutePolicy;
    use ianua_domain::test_support::authority::anyone_holding;
    use ianua_domain::types::Seconds;

    use super::*;
    use crate::ports::shared::EventDispatcher;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::{
        FakePipelineStore, test_pipeline, test_pipeline_id, test_pipeline_in, test_route_on,
    };
    use crate::test_support::routing::FakeRouteStore;
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, block_on, test_auditor, test_ctx,
    };

    fn seeded(status: PipelineStatus) -> Arc<FakePipelineStore> {
        Arc::new(FakePipelineStore::holding(
            test_ctx().tenant_id(),
            test_pipeline_in(status),
        ))
    }

    fn use_case(
        store: &Arc<FakePipelineStore>,
        authorities: FakeTenantAuthorities,
    ) -> ActivateUseCase {
        ActivateUseCase::new(ActivatePorts {
            pipeline_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
            ..ActivatePorts::fakes()
        })
    }

    fn activate(
        use_case: &ActivateUseCase,
        audit: Arc<dyn EventDispatcher>,
    ) -> Result<(), AppError> {
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit), test_pipeline_id()))
    }

    fn status_of(store: &FakePipelineStore) -> PipelineStatus {
        block_on(store.find(&test_ctx().tenant(), &test_pipeline_id()))
            .unwrap()
            .unwrap()
            .status()
    }

    /// Ann activates a draft pipeline. It runs on live traffic, and the
    /// activation is recorded so every proxy reloads it.
    #[test]
    fn a_draft_pipeline_is_activated_and_announced() {
        let store = seeded(PipelineStatus::Draft);
        let audit = Arc::new(FakeEventDispatcher::new());

        activate(
            &use_case(&store, FakeTenantAuthorities::holding_everything()),
            audit.clone(),
        )
        .unwrap();

        assert_eq!(status_of(&store), PipelineStatus::Active);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["proxy.pipeline_activated"]
        );
    }

    /// The activation cannot be recorded. Ann is told it failed rather than
    /// that it went through unannounced.
    #[test]
    fn an_activation_that_cannot_be_recorded_fails() {
        let store = seeded(PipelineStatus::Draft);

        let result = activate(
            &use_case(&store, FakeTenantAuthorities::holding_everything()),
            Arc::new(FailingEventDispatcher),
        );

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// Ann activates a pipeline that is already active. It is refused as a
    /// move the pipeline cannot make.
    #[test]
    fn an_active_pipeline_is_not_activated_again() {
        let store = seeded(PipelineStatus::Active);

        let result = activate(
            &use_case(&store, FakeTenantAuthorities::holding_everything()),
            Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// A signed-in route runs the pipeline, and Ann added a cache shared
    /// between callers while it was a draft. Activating it is refused, or
    /// one person's page would be served to the next.
    #[test]
    fn a_shared_cache_on_a_signed_in_route_is_refused() {
        let mut pipeline = test_pipeline();
        let routes = Arc::new(FakeRouteStore::empty());
        let route = test_route_on(&pipeline, RoutePolicy::Authenticated);
        block_on(routes.save(&test_ctx().tenant(), &route)).unwrap();
        let shared_cache = StageConfig::new(
            StageKind::Cache(CacheConfig {
                ttl_seconds: Seconds::new(60),
                vary_by_user: CacheScope::Shared,
            }),
            0,
            StageRemoval::Allowed,
        )
        .unwrap();
        let admin = RoutingControl::new(anyone_holding(SystemPermission::all()));
        pipeline.add_stage(shared_cache, &admin).unwrap();
        let store = Arc::new(FakePipelineStore::holding(test_ctx().tenant_id(), pipeline));
        let use_case = ActivateUseCase::new(ActivatePorts {
            pipeline_store: store.clone(),
            route_store: routes,
            ..ActivatePorts::fakes()
        });

        let result = activate(&use_case, Arc::new(FakeEventDispatcher::new()));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(status_of(&store), PipelineStatus::Draft);
    }

    /// Ann names a pipeline the tenant does not have. It is not found.
    #[test]
    fn an_unknown_pipeline_is_not_found() {
        let store = Arc::new(FakePipelineStore::empty());

        let result = activate(
            &use_case(&store, FakeTenantAuthorities::holding_everything()),
            Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A viewer cannot activate a pipeline; the stored pipeline stays draft.
    #[test]
    fn a_caller_without_the_pipeline_right_is_refused() {
        let store = seeded(PipelineStatus::Draft);

        let result = activate(
            &use_case(
                &store,
                FakeTenantAuthorities::holding(&[SystemPermission::Pipeline(PipelineAction::View)]),
            ),
            Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status_of(&store), PipelineStatus::Draft);
    }

    /// Without pipeline-change rights, activating an unknown pipeline returns
    /// forbidden rather than revealing its absence.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_pipeline() {
        let store = Arc::new(FakePipelineStore::empty());

        let result = activate(
            &use_case(&store, FakeTenantAuthorities::holding(&[])),
            Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot activate the stored draft pipeline.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = seeded(PipelineStatus::Draft);

        let result = activate(
            &use_case(&store, FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
