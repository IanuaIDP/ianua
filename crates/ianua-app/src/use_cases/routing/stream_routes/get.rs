//! Get stream route: read one port of the tenant.

use std::sync::Arc;

use ianua_domain::domains::routing::stream::StreamRoute;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::StreamRouteId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::routing::StreamRouteStore;
use crate::use_case::Query;
use crate::use_cases::routing::lookup::{ensure_may_view_routing, existing_stream_route};

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Keeps the tenant's stream routes.
    pub stream_route_store: Arc<dyn StreamRouteStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one stream route.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = CallerContext;
    type Input = StreamRouteId;
    type Output = Result<StreamRoute<ResolvedTenant>, AppError>;

    /// The tenant's stream route `stream_route_id`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view routing.
    /// - `AppError::NotFound` if the route doesn't exist.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        stream_route_id: StreamRouteId,
    ) -> Result<StreamRoute<ResolvedTenant>, AppError> {
        ensure_may_view_routing(self.ports.tenant_authorities.as_ref(), caller).await?;
        existing_stream_route(
            self.ports.stream_route_store.as_ref(),
            &caller.tenant(),
            &stream_route_id,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::routing::{FakeStreamRouteStore, stream_route_on};
    use crate::test_support::{block_on, test_ctx};

    fn use_case_holding(authorities: FakeTenantAuthorities) -> (GetUseCase, StreamRouteId) {
        let route = stream_route_on(15432);
        let routes = Arc::new(FakeStreamRouteStore::empty());
        block_on(routes.save(&test_ctx().tenant(), &route)).unwrap();
        let use_case = GetUseCase::new(GetPorts {
            stream_route_store: routes,
            tenant_authorities: Arc::new(authorities),
        });
        (use_case, *route.id())
    }

    /// Ann opens the database port. She sees it.
    #[test]
    fn a_stored_stream_route_is_returned() {
        let (use_case, id) = use_case_holding(FakeTenantAuthorities::holding_everything());

        let route = block_on(use_case.execute(&test_ctx(), id)).unwrap();

        assert_eq!(route.listen_port().get(), 15432);
    }

    /// Ann opens a port that does not exist. She is told it was not found.
    #[test]
    fn an_unknown_stream_route_is_not_found() {
        let (use_case, _) = use_case_holding(FakeTenantAuthorities::holding_everything());

        let result = block_on(use_case.execute(&test_ctx(), StreamRouteId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading an existing stream route requires the routing viewing right.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let (use_case, id) = use_case_holding(FakeTenantAuthorities::holding(&[]));

        let result = block_on(use_case.execute(&test_ctx(), id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read a stream route.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (use_case, id) = use_case_holding(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = block_on(use_case.execute(&test_ctx(), id));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
