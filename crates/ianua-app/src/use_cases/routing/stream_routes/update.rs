//! Update stream route: change what a port does, or who may use it.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::domains::routing::matching::host::RouteHosts;
use ianua_domain::domains::routing::stream::access::StreamAccess;
use ianua_domain::domains::routing::stream::{
    StreamBackend, StreamPolicy, StreamRoute, StreamTimeouts,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::{Label, StreamRouteId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::StreamRouteStore;
use crate::use_case::Command;
use crate::use_cases::routing::destinations::{Destination, ensure_reachable};
use crate::use_cases::routing::lookup::existing_stream_route;
use crate::use_cases::routing::stream_routes::access::{
    StreamAccessPorts, change_admission, ensure_access_known,
};

/// What to change on a stream route. A field left `None` stays as it is.
///
/// The protocol and the port are not here: changing either is a different
/// socket on a different listener, which is a new route, not an edit.
pub struct UpdateRequest {
    /// The route to change.
    pub stream_route_id: StreamRouteId,
    /// A new name.
    pub name: Option<Label>,
    /// Which server names the handshake may ask for.
    pub sni: Option<RouteHosts>,
    /// A new policy.
    pub policy: Option<StreamPolicy>,
    /// Who by name may pass from now on.
    pub access: Option<StreamAccess>,
    /// New backends.
    pub backends: Option<Vec<StreamBackend>>,
    /// New timeouts.
    pub timeouts: Option<StreamTimeouts>,
}

impl UpdateRequest {
    /// Whether this request changes nothing.
    fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.sni.is_none()
            && self.policy.is_none()
            && self.access.is_none()
            && self.backends.is_none()
            && self.timeouts.is_none()
    }
}

/// The ports [`UpdateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdatePorts {
    /// Keeps the tenant's stream routes.
    pub stream_route_store: Arc<dyn StreamRouteStore>,
    /// The tenant's consumers and permission catalogue, which new access
    /// may name.
    pub access: StreamAccessPorts,
    /// Internal networks a backend may sit in besides public addresses.
    pub upstream_networks: UpstreamNetworks,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes a stream route.
pub struct UpdateUseCase {
    ports: UpdatePorts,
}

impl UpdateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdatePorts) -> Self {
        Self { ports }
    }
}

impl Command for UpdateUseCase {
    type Caller = CallerContext;
    type Input = UpdateRequest;
    type Output = Result<(), AppError>;

    /// Applies the changes `request` carries and records
    /// `routing.stream_route_updated`. A request changing nothing records
    /// nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update routing.
    /// - `AppError::NotFound` if the route doesn't exist, even when nothing
    ///   would change, or new access names a consumer the tenant does not
    ///   have.
    /// - `AppError::Domain` if a new backend targets an internal address the
    ///   operator does not allow, the protocol cannot carry what a new
    ///   policy, server name or access asks for, or a people policy requires
    ///   an undeclared permission.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: UpdateRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let store = self.ports.stream_route_store.as_ref();
        let mut route = existing_stream_route(store, &tenant, &request.stream_route_id).await?;
        if request.is_empty() {
            return Ok(());
        }
        ensure_reachable(
            request.backends.as_deref().map(Destination::StreamBackends),
            &self.ports.upstream_networks,
        )?;
        if let Some(access) = &request.access {
            ensure_access_known(self.ports.access.records(), &tenant, access).await?;
        }
        apply_changes(&mut route, request, &control).map_err(AppError::from_domain)?;
        store
            .save(&tenant, &route)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&caller.actor(), route.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// Applies every change `request` carries to `route`, on behalf of `by`.
fn apply_changes(
    route: &mut StreamRoute<ResolvedTenant>,
    request: UpdateRequest,
    by: &RoutingControl<'_>,
) -> Result<(), DomainError> {
    if let Some(name) = request.name {
        route.rename(name, by)?;
    }
    if let Some(sni) = request.sni {
        route.change_sni(sni, by)?;
    }
    change_admission(route, request.policy, request.access, by)?;
    if let Some(backends) = request.backends {
        route.replace_backends(backends, by)?;
    }
    let Some(timeouts) = request.timeouts else {
        return Ok(());
    };
    route.change_timeouts(timeouts, by)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::routing::policy::RoutePolicy;
    use ianua_domain::domains::routing::stream::access::StreamConsumers;
    use ianua_domain::domains::routing::stream::{
        CreateStreamRouteParams, ListenPort, StreamProtocol,
    };
    use ianua_domain::types::ConsumerId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeResourceTypeStore;
    use crate::test_support::consumers::{consumer_named, consumers_of_test_tenant};
    use crate::test_support::routing::{
        FakeStreamRouteStore, routing_admin, routing_label, stream_route_on, tunnel_on,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        routes: Arc<FakeStreamRouteStore>,
        audit: Arc<FakeEventDispatcher>,
        route_id: StreamRouteId,
        billing: ConsumerId,
        use_case: UpdateUseCase,
    }

    /// Keeps the supplied route under the caller's configured authority.
    fn fixture_over(
        route: &StreamRoute<ResolvedTenant>,
        authorities: FakeTenantAuthorities,
    ) -> Fixture {
        let routes = Arc::new(FakeStreamRouteStore::empty());
        block_on(routes.save(&test_ctx().tenant(), route)).unwrap();
        let billing = consumer_named("billing", DataClassLevel::Internal);
        Fixture {
            billing: *billing.id(),
            use_case: UpdateUseCase::new(UpdatePorts {
                stream_route_store: routes.clone(),
                access: StreamAccessPorts {
                    consumer_store: consumers_of_test_tenant(billing),
                    resource_type_store: Arc::new(FakeResourceTypeStore::seeded(
                        test_ctx().tenant_id(),
                    )),
                },
                upstream_networks: UpstreamNetworks::public_only(),
                tenant_authorities: Arc::new(authorities),
            }),
            routes,
            audit: Arc::new(FakeEventDispatcher::new()),
            route_id: *route.id(),
        }
    }

    fn fixture(authorities: FakeTenantAuthorities) -> Fixture {
        fixture_over(&stream_route_on(15432), authorities)
    }

    fn admin_fixture() -> Fixture {
        fixture(FakeTenantAuthorities::holding_everything())
    }

    /// A public port where the proxy completes the TLS handshake.
    fn terminating_port() -> StreamRoute<ResolvedTenant> {
        StreamRoute::create(
            CreateStreamRouteParams {
                name: routing_label("broker"),
                protocol: StreamProtocol::TlsTerminate,
                listen_port: ListenPort::new(15671).unwrap(),
                sni: RouteHosts::Any,
                policy: StreamPolicy::Public,
                access: StreamAccess::AnyHolder,
                backends: vec![StreamBackend::new("broker.example.com", 5671, 1).unwrap()],
                timeouts: StreamTimeouts::default(),
            },
            &routing_admin(),
        )
        .unwrap()
    }

    fn only(consumer: ConsumerId) -> StreamAccess {
        StreamAccess::Consumers(StreamConsumers::new(vec![consumer]).unwrap())
    }

    fn change(stream_route_id: StreamRouteId) -> UpdateRequest {
        UpdateRequest {
            stream_route_id,
            name: None,
            sni: None,
            policy: None,
            access: None,
            backends: None,
            timeouts: None,
        }
    }

    fn run(f: &Fixture, request: UpdateRequest) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), request),
        )
    }

    fn saved(f: &Fixture) -> StreamRoute<ResolvedTenant> {
        block_on(f.routes.find_by_id(&test_ctx().tenant(), &f.route_id))
            .unwrap()
            .unwrap()
    }

    /// Ann renames the port. It is saved and the change recorded.
    #[test]
    fn a_renamed_route_is_saved_and_recorded() {
        let f = admin_fixture();

        run(
            &f,
            UpdateRequest {
                name: Some(routing_label("renamed")),
                ..change(f.route_id)
            },
        )
        .unwrap();

        assert_eq!(saved(&f).name().as_str(), "renamed");
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.stream_route_updated"]
        );
    }

    /// Ann narrows the people tunnel to the billing consumer alone. It is
    /// saved with that access and the change recorded.
    #[test]
    fn a_tunnel_is_narrowed_to_one_consumer() {
        let f = fixture_over(
            &tunnel_on(15433, StreamAccess::People(RoutePolicy::Authenticated)),
            FakeTenantAuthorities::holding_everything(),
        );

        run(
            &f,
            UpdateRequest {
                access: Some(only(f.billing)),
                ..change(f.route_id)
            },
        )
        .unwrap();

        assert_eq!(saved(&f).access(), &only(f.billing));
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.stream_route_updated"]
        );
    }

    /// Ann moves a public broker port to client certificates and names the
    /// one consumer it lets in, in one edit. Neither change fits the route
    /// on its own, and together they are saved.
    #[test]
    fn policy_and_access_change_together() {
        let f = fixture_over(
            &terminating_port(),
            FakeTenantAuthorities::holding_everything(),
        );

        run(
            &f,
            UpdateRequest {
                policy: Some(StreamPolicy::MutualTls),
                access: Some(only(f.billing)),
                ..change(f.route_id)
            },
        )
        .unwrap();

        assert_eq!(saved(&f).policy(), StreamPolicy::MutualTls);
        assert_eq!(saved(&f).access(), &only(f.billing));
    }

    /// Replacing tunnel access with an unknown consumer returns not found.
    /// The people policy remains saved and no update event is recorded.
    #[test]
    fn access_naming_an_unknown_consumer_is_refused() {
        let f = fixture_over(
            &tunnel_on(15433, StreamAccess::People(RoutePolicy::Authenticated)),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = run(
            &f,
            UpdateRequest {
                access: Some(only(ConsumerId::new())),
                ..change(f.route_id)
            },
        );

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
        assert_eq!(
            saved(&f).access(),
            &StreamAccess::People(RoutePolicy::Authenticated)
        );
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Requiring authenticated people on a public TCP port is refused and
    /// records no update event.
    #[test]
    fn people_on_a_public_port_are_refused() {
        let f = admin_fixture();

        let result = run(
            &f,
            UpdateRequest {
                access: Some(StreamAccess::People(RoutePolicy::Authenticated)),
                ..change(f.route_id)
            },
        );

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann sends an edit that changes nothing. Nothing is recorded.
    #[test]
    fn an_empty_change_records_nothing() {
        let f = admin_fixture();

        run(&f, change(f.route_id)).unwrap();

        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann asks for a client certificate on a plain TCP port, where none can
    /// be checked. It is refused, as creating it would be, and nothing is
    /// recorded.
    #[test]
    fn tightening_to_mutual_tls_on_tcp_is_refused() {
        let f = admin_fixture();

        let result = run(
            &f,
            UpdateRequest {
                policy: Some(StreamPolicy::MutualTls),
                ..change(f.route_id)
            },
        );

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Replacing a backend with loopback is refused under public-only
    /// network rules and records no update event.
    #[test]
    fn a_private_backend_is_refused() {
        let f = admin_fixture();

        let result = run(
            &f,
            UpdateRequest {
                backends: Some(vec![StreamBackend::new("127.0.0.1", 5432, 1).unwrap()]),
                ..change(f.route_id)
            },
        );

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann renames a port that does not exist. She is told it was not found.
    #[test]
    fn an_unknown_route_is_not_found() {
        let f = admin_fixture();

        let result = run(
            &f,
            UpdateRequest {
                name: Some(routing_label("renamed")),
                ..change(StreamRouteId::new())
            },
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann sends an empty edit for a port that does not exist. She is still
    /// told it was not found, not that nothing changed.
    #[test]
    fn an_empty_change_to_an_unknown_route_is_not_found() {
        let f = admin_fixture();

        let result = run(&f, change(StreamRouteId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Changing a stream backend without the update right is forbidden and
    /// preserves its saved host.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let f = fixture(FakeTenantAuthorities::holding(&[]));

        let result = run(
            &f,
            UpdateRequest {
                backends: Some(vec![
                    StreamBackend::new("mallory.example.com", 5432, 1).unwrap(),
                ]),
                ..change(f.route_id)
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(saved(&f).backends()[0].host().as_str(), "db.example.com");
    }

    /// Changing tunnel access without the update right is forbidden. The
    /// people policy remains saved and no update event is recorded.
    #[test]
    fn a_caller_without_the_update_right_cannot_change_access() {
        let people = StreamAccess::People(RoutePolicy::Authenticated);
        let f = fixture_over(
            &tunnel_on(15433, people.clone()),
            FakeTenantAuthorities::holding(&[]),
        );

        let result = run(
            &f,
            UpdateRequest {
                access: Some(only(f.billing)),
                ..change(f.route_id)
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(saved(&f).access(), &people);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A caller without the update right receives a permission refusal even
    /// when the requested stream route does not exist.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_route() {
        let f = fixture(FakeTenantAuthorities::holding(&[]));

        let result = run(&f, change(StreamRouteId::new()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot rename a stream route.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = run(
            &f,
            UpdateRequest {
                name: Some(routing_label("mine")),
                ..change(f.route_id)
            },
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
