//! List data: the stream routes a Protected data step may reach, every
//! active stream route the tenant opened to workflows, for someone who may
//! view workflows.
//!
//! Whoever builds the workflow sees which systems are open, not who may
//! use them: each connection is still asked of the stream route's access
//! for the person the run acts for.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::routing::stream::StreamRoute;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::StreamRouteStore;
use crate::use_case::Query;

/// The ports [`ListDataUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListDataPorts {
    /// Keeps the tenant's stream routes.
    pub stream_route_store: Arc<dyn StreamRouteStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the stream routes workflows may reach.
pub struct ListDataUseCase {
    ports: ListDataPorts,
}

impl ListDataUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListDataPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListDataUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<StreamRoute<ResolvedTenant>>, AppError>;

    /// Every active stream route of the tenant open to workflows, by name.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view workflows.
    /// - `AppError::Internal` when the stream routes cannot be read.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<Vec<StreamRoute<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        self.ports
            .stream_route_store
            .list_open_to_workflows(&ctx.tenant())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::routing::policy::RoutePolicy;
    use ianua_domain::domains::routing::stream::access::StreamAccess;
    use ianua_domain::domains::routing::stream::{LoginTls, LoginUser, WorkflowLogin};
    use ianua_domain::types::SealedSecret;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::routing::{
        FakeStreamRouteStore, routing_admin, routing_label, tunnel_on,
    };
    use crate::test_support::{block_on, test_ctx};

    /// The orders database, opened to workflows, and the billing database,
    /// left closed.
    fn databases() -> (Arc<FakeStreamRouteStore>, StreamRoute<ResolvedTenant>) {
        let people = || StreamAccess::People(RoutePolicy::Authenticated);
        let mut orders = tunnel_on(15432, people());
        let mut billing = tunnel_on(15433, people());
        billing
            .rename(routing_label("billing-db"), &routing_admin())
            .unwrap();
        let login = WorkflowLogin::new(
            LoginUser::new("workflows_reader").unwrap(),
            SealedSecret::new("v1.AAECAwQF").unwrap(),
            LoginTls::Off,
        );
        orders.open_to_workflows(&login, &routing_admin()).unwrap();
        let store = Arc::new(FakeStreamRouteStore::empty());
        block_on(store.save(&test_ctx().tenant(), &orders)).unwrap();
        block_on(store.save(&test_ctx().tenant(), &billing)).unwrap();
        (store, orders)
    }

    fn list(
        store: Arc<FakeStreamRouteStore>,
        authorities: FakeTenantAuthorities,
    ) -> Result<Vec<StreamRoute<ResolvedTenant>>, AppError> {
        let use_case = ListDataUseCase::new(ListDataPorts {
            stream_route_store: store,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    /// Ann builds a workflow and is offered the orders database, which Acme
    /// opened to workflows, and not billing, which it did not.
    #[test]
    fn only_the_stream_routes_open_to_workflows_are_listed() {
        let (store, orders) = databases();
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let listed = list(store, viewer).unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id(), orders.id());
    }

    /// A caller without workflow view rights cannot list open databases.
    #[test]
    fn a_caller_who_may_not_view_workflows_is_refused() {
        let (store, _) = databases();

        let result = list(store, FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
