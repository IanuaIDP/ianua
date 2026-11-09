//! Delete stream route: close a port for good and release it.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::StreamRouteId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::StreamRouteStore;
use crate::use_case::Command;
use crate::use_cases::routing::lookup::existing_stream_route;

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Keeps the tenant's stream routes.
    pub stream_route_store: Arc<dyn StreamRouteStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Deletes a stream route.
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
    type Input = StreamRouteId;
    type Output = Result<(), AppError>;

    /// Deletes the stream route once the domain agrees it may go, releasing
    /// its port for any tenant to claim, and records
    /// `routing.stream_route_deleted`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not delete routing.
    /// - `AppError::NotFound` if the route doesn't exist.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        stream_route_id: StreamRouteId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::Delete)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let mut route = existing_stream_route(
            self.ports.stream_route_store.as_ref(),
            &tenant,
            &stream_route_id,
        )
        .await?;
        route.delete(&control).map_err(AppError::from_domain)?;
        self.ports
            .stream_route_store
            .delete(&tenant, &stream_route_id)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&caller.actor(), route.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::routing::{FakeStreamRouteStore, stream_route_on};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        routes: Arc<FakeStreamRouteStore>,
        audit: Arc<FakeEventDispatcher>,
        route_id: StreamRouteId,
        use_case: DeleteUseCase,
    }

    fn fixture(authorities: FakeTenantAuthorities) -> Fixture {
        let route = stream_route_on(15432);
        let routes = Arc::new(FakeStreamRouteStore::empty());
        block_on(routes.save(&test_ctx().tenant(), &route)).unwrap();
        Fixture {
            use_case: DeleteUseCase::new(DeletePorts {
                stream_route_store: routes.clone(),
                tenant_authorities: Arc::new(authorities),
            }),
            routes,
            audit: Arc::new(FakeEventDispatcher::new()),
            route_id: *route.id(),
        }
    }

    fn run(f: &Fixture, id: StreamRouteId) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), id),
        )
    }

    /// Ann deletes the database port. It is gone and the deletion recorded.
    #[test]
    fn a_stream_route_is_deleted_and_recorded() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        run(&f, f.route_id).unwrap();

        assert_eq!(f.routes.count(), 0);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.stream_route_deleted"]
        );
    }

    /// Ann deletes a port nobody holds. She is told it was not found, so a
    /// retried delete never reports a port freed that is still bound.
    #[test]
    fn an_unknown_route_is_not_found() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        let result = run(&f, StreamRouteId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The routing update right does not permit deleting a stream route.
    /// The permission refusal leaves the route stored.
    #[test]
    fn a_caller_without_the_delete_right_is_refused() {
        let f = fixture(FakeTenantAuthorities::holding(&[
            SystemPermission::Routing(RoutingAction::Update),
        ]));

        let result = run(&f, f.route_id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.routes.count(), 1);
    }

    /// A caller without the deletion right receives a permission refusal
    /// even when the requested stream route does not exist.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_route() {
        let f = fixture(FakeTenantAuthorities::holding(&[]));

        let result = run(&f, StreamRouteId::new());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot delete the stored stream route.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = run(&f, f.route_id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(f.routes.count(), 1);
    }
}
