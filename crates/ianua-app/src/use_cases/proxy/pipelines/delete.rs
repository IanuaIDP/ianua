//! Delete pipeline: remove one that no route runs.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::PipelineId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::proxy::PipelineStore;
use crate::ports::routing::RouteStore;
use crate::use_case::Command;
use crate::use_cases::proxy::lookup::existing_pipeline;
use crate::use_cases::proxy::pipeline_changes::pipeline_error;
use crate::use_cases::routing::lookup::routes_on;

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Where pipelines are kept.
    pub pipeline_store: Arc<dyn PipelineStore>,
    /// The tenant's routes, none of which may still run the pipeline.
    pub route_store: Arc<dyn RouteStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Deletes a pipeline no route runs.
pub struct DeleteUseCase {
    ports: DeletePorts,
}

impl DeleteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeletePorts) -> Self {
        Self { ports }
    }
}

impl Command for DeleteUseCase {
    type Caller = CallerContext;
    type Input = PipelineId;
    type Output = Result<(), AppError>;

    /// Deletes the pipeline and records `proxy.pipeline_deleted`.
    ///
    /// It is refused while any route runs it: dropping those routes, or
    /// moving them to another pipeline, would change live traffic without
    /// anyone asking.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not manage pipelines.
    /// - `AppError::NotFound` when the tenant has no such pipeline.
    /// - `AppError::Conflict` while a route still runs it.
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
            .ensure_may(RoutingRight::DeletePipeline)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let store = self.ports.pipeline_store.as_ref();
        let mut pipeline = existing_pipeline(store, &tenant, &pipeline_id).await?;
        let routes = routes_on(self.ports.route_store.as_ref(), &tenant, &pipeline_id).await?;
        pipeline
            .delete(&routes, &control)
            .map_err(|error| pipeline_error(&error))?;

        store
            .delete(&tenant, &pipeline_id)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&caller.actor(), pipeline.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{PipelineAction, SystemPermission};
    use ianua_domain::domains::routing::policy::RoutePolicy;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::{
        FakePipelineStore, test_pipeline, test_pipeline_id, test_route_on,
    };
    use crate::test_support::routing::FakeRouteStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Seeded {
        pipelines: Arc<FakePipelineStore>,
        routes: Arc<FakeRouteStore>,
    }

    fn seeded() -> Seeded {
        let routes = Arc::new(FakeRouteStore::empty());
        let pipelines = Arc::new(FakePipelineStore::holding(
            test_ctx().tenant_id(),
            test_pipeline(),
        ));
        pipelines.tracking_routes(routes.clone());
        Seeded { pipelines, routes }
    }

    fn delete(
        seeded: &Seeded,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        pipeline_id: PipelineId,
    ) -> Result<(), AppError> {
        let use_case = DeleteUseCase::new(DeletePorts {
            pipeline_store: seeded.pipelines.clone(),
            route_store: seeded.routes.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), pipeline_id))
    }

    fn still_there(seeded: &Seeded) -> bool {
        block_on(
            seeded
                .pipelines
                .find(&test_ctx().tenant(), &test_pipeline_id()),
        )
        .unwrap()
        .is_some()
    }

    /// Ann deletes a pipeline no route runs. It is gone and the deletion
    /// recorded.
    #[test]
    fn an_unused_pipeline_is_deleted() {
        let seeded = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());

        delete(
            &seeded,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            test_pipeline_id(),
        )
        .unwrap();

        assert!(!still_there(&seeded));
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["proxy.pipeline_deleted"]
        );
    }

    /// A route still runs the pipeline. Deleting it would change live
    /// traffic without anyone asking, so it is refused as a conflict.
    #[test]
    fn a_pipeline_a_route_still_runs_is_refused() {
        let seeded = seeded();
        let route = test_route_on(&test_pipeline(), RoutePolicy::Authenticated);
        block_on(seeded.routes.save(&test_ctx().tenant(), &route)).unwrap();
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = delete(
            &seeded,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            test_pipeline_id(),
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(still_there(&seeded));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Ann names a pipeline the tenant does not have. It is not found.
    #[test]
    fn an_unknown_pipeline_is_not_found() {
        let seeded = seeded();

        let result = delete(
            &seeded,
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            PipelineId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Pipeline-update rights do not permit deletion, leaving the stored
    /// pipeline in place.
    #[test]
    fn a_caller_without_the_manage_right_is_refused() {
        let seeded = seeded();

        let result = delete(
            &seeded,
            FakeTenantAuthorities::holding(&[SystemPermission::Pipeline(PipelineAction::Update)]),
            &Arc::new(FakeEventDispatcher::new()),
            test_pipeline_id(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(still_there(&seeded));
    }

    /// Deleting an unknown pipeline without manage rights returns forbidden
    /// rather than revealing its absence.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_pipeline() {
        let seeded = seeded();

        let result = delete(
            &seeded,
            FakeTenantAuthorities::holding(&[]),
            &Arc::new(FakeEventDispatcher::new()),
            PipelineId::new(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session is refused when it requests pipeline deletion.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let seeded = seeded();

        let result = delete(
            &seeded,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &Arc::new(FakeEventDispatcher::new()),
            test_pipeline_id(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
