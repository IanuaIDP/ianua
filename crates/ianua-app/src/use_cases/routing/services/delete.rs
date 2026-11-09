//! Delete service: remove a backend nothing forwards to any more.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::domains::routing::service::Service;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ServiceId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::{RouteStore, ServiceStore};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::routing::lookup::{existing_service, routes_to, services_accepting};

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Keeps the tenant's services.
    pub service_store: Arc<dyn ServiceStore>,
    /// The tenant's routes, none of which may still forward to the service.
    pub route_store: Arc<dyn RouteStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Deletes a backend.
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
    type Input = ServiceId;
    type Output = Result<(), AppError>;

    /// Deletes the service once the domain agrees it may go, and records
    /// `routing.service_deleted`.
    ///
    /// A route still forwarding to it would be left with no backend, and a
    /// service accepting its app sign-in would trust sessions nothing can
    /// issue or end. So both are moved off first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not delete routing.
    /// - `AppError::NotFound` if the service doesn't exist.
    /// - `AppError::Conflict` if a route still forwards to it, or another
    ///   service still accepts its app sign-in.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        service_id: ServiceId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::Delete)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let mut service =
            existing_service(self.ports.service_store.as_ref(), &tenant, &service_id).await?;
        delete_once_unused(&self.ports, &tenant, &mut service, &control).await?;
        self.ports
            .service_store
            .delete(&tenant, &service_id)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&caller.actor(), service.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// Deletes `service` once the domain agrees it may go, given every route
/// forwarding to it and every service accepting its sign-in.
async fn delete_once_unused(
    ports: &DeletePorts,
    tenant: &ScopedTenant,
    service: &mut Service<ResolvedTenant>,
    by: &RoutingControl<'_>,
) -> Result<(), AppError> {
    let routes = routes_to(ports.route_store.as_ref(), tenant, service.id()).await?;
    let accepting = services_accepting(ports.service_store.as_ref(), tenant, service.id()).await?;
    service
        .delete(&routes, &accepting, by)
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::domains::routing::sign_in::accepted::{AcceptedSignIn, SignInDelivery};
    use ianua_domain::types::Setting;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::test_pipeline;
    use crate::test_support::routing::{
        FakeRouteStore, FakeServiceStore, RouteShape, pinned_upstream, route_of, routing_admin,
        service_named,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        services: Arc<FakeServiceStore>,
        routes: Arc<FakeRouteStore>,
        audit: Arc<FakeEventDispatcher>,
        service: Service<ResolvedTenant>,
        use_case: DeleteUseCase,
    }

    fn fixture(authorities: FakeTenantAuthorities) -> Fixture {
        let service = service_named("portal", pinned_upstream("https://portal:8080", "portal"));
        let services = Arc::new(FakeServiceStore::empty());
        block_on(services.save(&test_ctx().tenant(), &service)).unwrap();
        let routes = Arc::new(FakeRouteStore::empty());
        Fixture {
            use_case: DeleteUseCase::new(DeletePorts {
                service_store: services.clone(),
                route_store: routes.clone(),
                tenant_authorities: Arc::new(authorities),
            }),
            services,
            routes,
            audit: Arc::new(FakeEventDispatcher::new()),
            service,
        }
    }

    fn run(f: &Fixture, service_id: ServiceId) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), service_id),
        )
    }

    /// Ann deletes a service nothing forwards to. It is gone and the deletion
    /// is recorded.
    #[test]
    fn an_unused_service_is_deleted_and_recorded() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        run(&f, *f.service.id()).unwrap();

        assert_eq!(f.services.count(), 0);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.service_deleted"]
        );
    }

    /// Ann deletes the service a route still forwards to. The route would be
    /// left with no backend, so it is refused and nothing is recorded.
    #[test]
    fn a_service_a_route_forwards_to_is_not_deleted() {
        let f = fixture(FakeTenantAuthorities::holding_everything());
        let route = route_of(
            RouteShape::public("Portal", "/portal/*"),
            &f.service,
            &test_pipeline(),
        );
        block_on(f.routes.save(&test_ctx().tenant(), &route)).unwrap();

        let result = run(&f, *f.service.id());

        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
        assert_eq!(f.services.count(), 1);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann deletes the portal, whose app sign-in the admin API accepts. The
    /// admin API would trust sessions nothing can issue or end, so it is
    /// refused.
    #[test]
    fn a_service_whose_sign_in_another_accepts_is_not_deleted() {
        let f = fixture(FakeTenantAuthorities::holding_everything());
        let mut admin_api =
            service_named("admin-api", pinned_upstream("https://admin:8080", "admin"));
        admin_api
            .accept_app_sign_in_of(
                Setting::Set(AcceptedSignIn::new(
                    *f.service.id(),
                    SignInDelivery::SameHost,
                )),
                &routing_admin(),
            )
            .unwrap();
        block_on(f.services.save(&test_ctx().tenant(), &admin_api)).unwrap();

        let result = run(&f, *f.service.id());

        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
        assert_eq!(f.services.count(), 2);
    }

    /// Ann deletes a service that does not exist. She is told it was not
    /// found.
    #[test]
    fn an_unknown_service_is_not_found() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        let result = run(&f, ServiceId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The routing update right does not permit deleting a service. The
    /// permission refusal leaves the service stored.
    #[test]
    fn a_caller_without_the_delete_right_is_refused() {
        let f = fixture(FakeTenantAuthorities::holding(&[
            SystemPermission::Routing(RoutingAction::Update),
        ]));

        let result = run(&f, *f.service.id());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.services.count(), 1);
    }

    /// A caller without the deletion right receives a permission refusal
    /// even when the requested service does not exist.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_service() {
        let f = fixture(FakeTenantAuthorities::holding(&[]));

        let result = run(&f, ServiceId::new());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot delete the stored service.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = run(&f, *f.service.id());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(f.services.count(), 1);
    }
}
