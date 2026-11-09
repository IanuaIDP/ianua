//! List pipelines: every pipeline of the tenant, with how many routes run
//! each.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{PipelineAction, SystemPermission};
use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::proxy::PipelineStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;

/// One pipeline and how many routes run it.
pub struct WithUsage {
    /// The pipeline itself.
    pub pipeline: Pipeline<ResolvedTenant>,
    /// How many routes run it. Above zero, a delete is refused.
    pub route_count: u64,
}

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Where pipelines are kept.
    pub pipeline_store: Arc<dyn PipelineStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's pipelines.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }

    /// Enriches the listed pipelines with one shared route-count read,
    /// preserving their order and treating an omitted count as zero.
    async fn with_usage(
        &self,
        tenant: &ScopedTenant,
        pipelines: Vec<Pipeline<ResolvedTenant>>,
    ) -> Result<Vec<WithUsage>, AppError> {
        if pipelines.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<_> = pipelines.iter().map(|pipeline| *pipeline.id()).collect();
        let counts = self
            .ports
            .pipeline_store
            .route_counts(tenant, &ids)
            .await
            .or_internal()?;
        Ok(pipelines
            .into_iter()
            .map(|pipeline| WithUsage {
                route_count: counts.get(pipeline.id()).copied().unwrap_or(0),
                pipeline,
            })
            .collect())
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<WithUsage>, AppError>;

    /// Every pipeline, oldest first, each with how many routes run it.
    ///
    /// Route counts are read together for exactly the listed pipelines.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view pipelines.
    /// - `AppError::Internal` on storage failure.
    async fn execute(&self, caller: &CallerContext, (): ()) -> Result<Vec<WithUsage>, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::Pipeline(PipelineAction::View))
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let pipelines = self
            .ports
            .pipeline_store
            .list(&tenant)
            .await
            .or_internal()?;
        self.with_usage(&tenant, pipelines).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::routing::control::RoutingControl;
    use ianua_domain::domains::routing::policy::RoutePolicy;
    use ianua_domain::test_support::authority::anyone_holding;
    use ianua_domain::types::{Label, PipelineId};

    use super::*;
    use crate::ports::routing::RouteStore;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::{
        FakePipelineStore, test_pipeline, test_pipeline_id, test_route_on,
    };
    use crate::test_support::routing::FakeRouteStore;
    use crate::test_support::{block_on, test_ctx};

    fn list(
        store: Arc<FakePipelineStore>,
        authorities: FakeTenantAuthorities,
    ) -> Result<Vec<WithUsage>, AppError> {
        let use_case = ListUseCase::new(ListPorts {
            pipeline_store: store,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Pipeline(PipelineAction::View)])
    }

    /// Ann lists the tenant's two pipelines. One route runs Default, none
    /// runs Spare, and each says so with one shared route-count read.
    #[test]
    fn every_pipeline_is_listed_with_its_routes() {
        let default = test_pipeline();
        let store = Arc::new(FakePipelineStore::holding(
            test_ctx().tenant_id(),
            default.clone(),
        ));
        let admin = RoutingControl::new(anyone_holding(SystemPermission::all()));
        let spare =
            Pipeline::with_defaults(Label::new("pipeline_name", "Spare").unwrap(), &admin).unwrap();
        block_on(store.save(&test_ctx().tenant(), &spare)).unwrap();
        let routes = Arc::new(FakeRouteStore::empty());
        let route = test_route_on(&default, RoutePolicy::Authenticated);
        block_on(routes.save(&test_ctx().tenant(), &route)).unwrap();
        store.tracking_routes(routes);

        let listed = list(Arc::clone(&store), viewer()).unwrap();

        assert_eq!(listed.len(), 2);
        let count_of = |id: PipelineId| {
            listed
                .iter()
                .find(|p| *p.pipeline.id() == id)
                .unwrap()
                .route_count
        };
        assert_eq!(count_of(test_pipeline_id()), 1);
        assert_eq!(count_of(*spare.id()), 0);
        assert_eq!(store.count_reads(), 1);
    }

    /// Listing pipelines is forbidden without pipeline view rights, even
    /// when the store is empty.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let result = list(
            Arc::new(FakePipelineStore::empty()),
            FakeTenantAuthorities::holding(&[]),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Listing pipelines with a signed-out session fails authentication.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(
            Arc::new(FakePipelineStore::empty()),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
