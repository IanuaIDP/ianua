//! Routing below HTTP: a port, and what is allowed through it.
//!
//! The rest of routing reads an HTTP request, so it routes on a method, a
//! path and headers. A database connection, a message broker, a game server
//! and a plain TLS tunnel carry none of those. Without stream routes they
//! would be reached around the proxy, and so around its policy.
//!
//! A stream route works the same way at layer 4. It has a port the proxy
//! listens on, a backend it forwards to, and a decision made before the first
//! byte moves. The wire gives much less to decide with. HTTP brings a token,
//! a path and a caller, while a TCP connection brings an address. So the
//! protocol says exactly which identity can be known. The aggregate refuses
//! to promise one the wire cannot carry.

pub mod access;
mod login_tls;
mod settings;
mod workflows;

use std::marker::PhantomData;

pub use login_tls::{CertificateName, LoginTls, TlsAuthority, TlsCheck};
pub use settings::*;
use time::OffsetDateTime;
pub use workflows::{LoginUser, StreamWorkflowUse, WorkflowLogin};

use crate::domains::routing::control::{RoutingControl, RoutingRight};
use crate::domains::routing::events::{
    StreamRouteCreated, StreamRouteDeleted, StreamRouteState, StreamRouteStatusChanged,
    StreamRouteUpdated,
};
use crate::domains::routing::matching::host::RouteHosts;
use crate::domains::routing::route_status::RouteStatus;
use crate::domains::routing::stream::access::StreamAccess;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::numeric::validate_count;
use crate::types::{Audience, Label, StreamRouteId};

/// What every stream route's tunnel audience begins with, the route's id
/// following. A token asks for one by naming it as its resource (RFC 8707).
pub(crate) const TUNNEL_AUDIENCE_PREFIX: &str = "urn:ianua:stream-route:";

/// The audience a token must name to open the signed-in tunnel of the
/// stream route `id`: `TUNNEL_AUDIENCE_PREFIX` and the id.
///
/// # Errors
///
/// - [`DomainError::Validation`] if the audience cannot be spelled, which a
///   route id never causes.
pub fn tunnel_audience_of(id: &StreamRouteId) -> Result<Audience, DomainError> {
    Audience::new(format!("{TUNNEL_AUDIENCE_PREFIX}{id}")).map_err(DomainError::from)
}

/// A port the proxy listens on, and what it does with what arrives.
///
/// Tenant-scoped: read and written only through stores opened for the
/// resolved tenant (see [`crate::isolation`]).
///
/// This is not a [`Route`](crate::domains::routing::route::Route) with a different protocol. A
/// route matches a method and a path, and rewrites that path. It runs a
/// pipeline that reads headers and bodies, and forwards to a service that
/// pins a JWT audience. None of those exist here, so most of a route's rules
/// would not apply.
///
/// Every change needs the routing right, held by a person signed in to the
/// tenant, so an agent never makes one. Without this rule, Sam makes the
/// database port public and connects to it with no certificate.
#[derive(Debug, Clone)]
pub struct StreamRoute<T: TenantScope> {
    id: StreamRouteId,
    name: Label,
    protocol: StreamProtocol,
    listen_port: ListenPort,
    sni: RouteHosts,
    policy: StreamPolicy,
    access: StreamAccess,
    backends: Vec<StreamBackend>,
    timeouts: StreamTimeouts,
    status: RouteStatus,
    workflow_use: StreamWorkflowUse,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// The settings a stream route's rules are judged on, together.
#[derive(Clone, Copy)]
struct Shape<'a> {
    protocol: StreamProtocol,
    policy: StreamPolicy,
    sni: &'a RouteHosts,
    access: &'a StreamAccess,
    backends: &'a [StreamBackend],
}

/// What a new stream route is opened with.
pub struct CreateStreamRouteParams {
    /// Name, shown in the dashboard and unique within the tenant.
    pub name: Label,
    /// How the proxy speaks on the port.
    pub protocol: StreamProtocol,
    /// The gateway port reserved for accepting this route's incoming connections.
    pub listen_port: ListenPort,
    /// Which handshakes to answer.
    pub sni: RouteHosts,
    /// What is checked on the wire.
    pub policy: StreamPolicy,
    /// Who by name may pass.
    pub access: StreamAccess,
    /// Where accepted streams go.
    pub backends: Vec<StreamBackend>,
    /// How long a stream may take to start, and stay silent.
    pub timeouts: StreamTimeouts,
}

/// A [`StreamRoute`] as storage holds it, read back through
/// [`StreamRoute::reconstitute`].
pub struct StreamRouteRow {
    /// The stream route's id.
    pub id: StreamRouteId,
    /// Name, unique within the tenant.
    pub name: Label,
    /// How the proxy speaks on the port.
    pub protocol: StreamProtocol,
    /// The port listened on.
    pub listen_port: ListenPort,
    /// Which handshakes this route answers.
    pub sni: RouteHosts,
    /// What is checked on the wire.
    pub policy: StreamPolicy,
    /// Who by name may pass.
    pub access: StreamAccess,
    /// Where accepted streams go.
    pub backends: Vec<StreamBackend>,
    /// How long a stream may take to start, and stay silent.
    pub timeouts: StreamTimeouts,
    /// Whether this route is accepting connections.
    pub status: RouteStatus,
    /// Whether workflows may reach it.
    pub workflow_use: StreamWorkflowUse,
    /// When this route was created.
    pub created_at: OffsetDateTime,
    /// When this route was last modified.
    pub updated_at: OffsetDateTime,
}

impl<T: TenantScope> StreamRoute<T> {
    /// Opens a port, active, on behalf of `by`. Raises
    /// `routing.stream_route_created` with the port and protocol to bind.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not create routing.
    /// - [`DomainError::Validation`] when no backend is given.
    /// - [`DomainError::Validation`] when it asks for a client certificate on
    ///   a protocol the proxy does not terminate.
    /// - [`DomainError::Validation`] when it restricts to a server name on a
    ///   protocol that carries none.
    /// - [`DomainError::Validation`] when its access cannot be delivered by
    ///   its protocol and policy, as [`StreamAccess`] says.
    pub fn create(
        params: CreateStreamRouteParams,
        by: &RoutingControl<'_>,
    ) -> Result<Self, DomainError> {
        by.ensure_may(RoutingRight::Create)?;
        validate(Shape {
            protocol: params.protocol,
            policy: params.policy,
            sni: &params.sni,
            access: &params.access,
            backends: &params.backends,
        })?;

        let now = crate::shared::clock::now();
        Ok(Self {
            id: StreamRouteId::new(),
            name: params.name,
            protocol: params.protocol,
            listen_port: params.listen_port,
            sni: params.sni,
            policy: params.policy,
            access: params.access,
            backends: params.backends,
            timeouts: params.timeouts,
            status: RouteStatus::Active,
            workflow_use: StreamWorkflowUse::Closed,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        }
        .created())
    }

    /// This new stream route, having raised its creation.
    fn created(mut self) -> Self {
        self.raised.raise(StreamRouteCreated {
            stream_route_id: self.id,
            name: self.name.clone(),
            listen_port: self.listen_port.get(),
            protocol: self.protocol.as_str(),
            occurred_at: self.created_at,
        });
        self
    }

    /// Rebuilds a stream route from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row has no backend.
    /// - [`DomainError::Infrastructure`] when it asks for a client
    ///   certificate on a protocol the proxy does not terminate.
    /// - [`DomainError::Infrastructure`] when it restricts to a server name
    ///   on a protocol that carries none.
    /// - [`DomainError::Infrastructure`] when its access cannot be delivered
    ///   by its protocol and policy.
    /// - [`DomainError::Infrastructure`] when it changed before it was created.
    pub fn reconstitute(row: StreamRouteRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            name: row.name,
            protocol: row.protocol,
            listen_port: row.listen_port,
            sni: row.sni,
            policy: row.policy,
            access: row.access,
            backends: row.backends,
            timeouts: row.timeouts,
            status: row.status,
            workflow_use: row.workflow_use,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &StreamRouteRow) -> Result<(), DomainError> {
        RowCheck::of("stream route")
            .holds(
                validate(Shape {
                    protocol: row.protocol,
                    policy: row.policy,
                    sni: &row.sni,
                    access: &row.access,
                    backends: &row.backends,
                })
                .is_ok(),
                "a configuration the wire cannot deliver",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was created",
            )
            .finish()
    }

    /// The route's settings as its rules judge them.
    fn shape(&self) -> Shape<'_> {
        Shape {
            protocol: self.protocol,
            policy: self.policy,
            sni: &self.sni,
            access: &self.access,
            backends: &self.backends,
        }
    }

    /// Who by name may pass, beyond what the wire checks.
    #[must_use]
    pub fn access(&self) -> &StreamAccess {
        &self.access
    }

    /// Changes what the wire checks and who by name may pass in one step,
    /// judged together. Changing only one of them passes the other as it
    /// stands.
    ///
    /// A policy and the access it must carry often change as a pair: moving
    /// a database port from mutual TLS to people signing in changes both.
    /// Judged one at a time, each half would be refused against the other
    /// as it stands; judged together, the pair the route ends up with is
    /// what counts. Raises `routing.stream_route_updated`, once for all the
    /// changes made before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::Validation`] if the route's protocol and `policy`
    ///   cannot deliver `access`.
    pub fn change_admission(
        &mut self,
        policy: StreamPolicy,
        access: StreamAccess,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        validate(Shape {
            policy,
            access: &access,
            ..self.shape()
        })?;
        self.policy = policy;
        self.access = access;
        self.record_update();
        Ok(())
    }

    /// The stream route's id.
    #[must_use]
    pub fn id(&self) -> &StreamRouteId {
        &self.id
    }

    /// Name, unique within the tenant.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// How the proxy speaks on the port.
    #[must_use]
    pub fn protocol(&self) -> StreamProtocol {
        self.protocol
    }

    /// The port listened on.
    #[must_use]
    pub fn listen_port(&self) -> ListenPort {
        self.listen_port
    }

    /// Which handshakes this route answers.
    #[must_use]
    pub fn sni(&self) -> &RouteHosts {
        &self.sni
    }

    /// Who is allowed through.
    #[must_use]
    pub fn policy(&self) -> StreamPolicy {
        self.policy
    }

    /// Where accepted streams go.
    #[must_use]
    pub fn backends(&self) -> &[StreamBackend] {
        &self.backends
    }

    /// How long a stream may take to start, and stay silent.
    #[must_use]
    pub fn timeouts(&self) -> StreamTimeouts {
        self.timeouts
    }

    /// Whether this route is accepting connections.
    #[must_use]
    pub fn status(&self) -> RouteStatus {
        self.status
    }

    /// Whether this route is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == RouteStatus::Active
    }

    /// When this route was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When this route was last modified.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Whether a handshake for `server_name` reaches this route.
    ///
    /// `None` is a connection that offered no name. That is raw TCP, UDP, or
    /// a TLS client that sent no SNI. It matches only an unrestricted route.
    /// Otherwise a client could get past a restriction by sending no name.
    #[must_use]
    pub fn accepts(&self, server_name: Option<&str>) -> bool {
        match server_name {
            Some(name) => self.sni.accepts(name),
            None => matches!(self.sni, RouteHosts::Any),
        }
    }

    /// The audience a token must name to open this route's signed-in
    /// tunnel: `urn:ianua:stream-route:` and the route's id.
    ///
    /// Each tunnel has its own, so a token minted for one route, or for an
    /// HTTP service of the tenant, never opens another. A consumer's API
    /// key names no audience and is not held to one.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if the audience cannot be spelled, which
    ///   a route id never causes.
    pub fn tunnel_audience(&self) -> Result<Audience, DomainError> {
        tunnel_audience_of(&self.id)
    }

    /// Renames the route.
    ///
    /// Raises `routing.stream_route_updated`, once for all the changes
    /// made before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    pub fn rename(&mut self, name: Label, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.name = name;
        self.record_update();
        Ok(())
    }

    /// Replaces the backends.
    ///
    /// Raises `routing.stream_route_updated`, once for all the changes
    /// made before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::Validation`] if the list is empty.
    pub fn replace_backends(
        &mut self,
        backends: Vec<StreamBackend>,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        validate(Shape {
            backends: &backends,
            ..self.shape()
        })?;
        self.backends = backends;
        self.record_update();
        Ok(())
    }

    /// Replaces the timeouts.
    ///
    /// Raises `routing.stream_route_updated`, once for all the changes
    /// made before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    pub fn change_timeouts(
        &mut self,
        timeouts: StreamTimeouts,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.timeouts = timeouts;
        self.record_update();
        Ok(())
    }

    /// Changes which handshakes are answered.
    ///
    /// Raises `routing.stream_route_updated`, once for all the changes
    /// made before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::Validation`] if the protocol carries no server name
    ///   to match on.
    pub fn change_sni(
        &mut self,
        sni: RouteHosts,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        validate(Shape {
            sni: &sni,
            ..self.shape()
        })?;
        self.sni = sni;
        self.record_update();
        Ok(())
    }

    /// Opens the port. Raises `routing.stream_route_activated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::InvalidTransition`] if already active.
    pub fn activate(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.status = self.status.try_transition(RouteStatus::Active)?;
        self.status_changed(StreamRouteState::Accepting);
        Ok(())
    }

    /// Closes the port. Streams already open stay open, and nothing new is
    /// accepted. Raises `routing.stream_route_disabled`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::InvalidTransition`] if already disabled.
    pub fn disable(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.status = self.status.try_transition(RouteStatus::Disabled)?;
        self.status_changed(StreamRouteState::Disabled);
        Ok(())
    }

    /// Deletes this stream route once `by` may delete routing. Raises
    /// `routing.stream_route_deleted`, taken once the route is removed from
    /// storage.
    ///
    /// Closing the port keeps the route, its backends and its certificate
    /// check, ready to open again. Deleting it loses them for good and frees
    /// the port. So it needs the delete right, not the update right.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not delete routing.
    pub fn delete(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Delete)?;
        self.raised.raise(StreamRouteDeleted {
            stream_route_id: self.id,
            name: self.name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Sets `updated_at` to now.
    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }

    /// Marks a change to the route's settings, raising
    /// `routing.stream_route_updated` with the route as it now is.
    fn record_update(&mut self) {
        self.touch();
        self.raised.raise_latest(StreamRouteUpdated {
            stream_route_id: self.id,
            name: self.name.clone(),
            occurred_at: self.updated_at,
        });
    }

    /// Marks the port opened or closed, raising the status it moved to.
    fn status_changed(&mut self, active: StreamRouteState) {
        self.touch();
        self.raised.raise(StreamRouteStatusChanged {
            stream_route_id: self.id,
            name: self.name.clone(),
            active,
            occurred_at: self.updated_at,
        });
    }
}

impl<T: TenantScope> Raises for StreamRoute<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for StreamRoute<T> {
    type Id = StreamRouteId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

/// The rules that hold whatever order the fields are set in.
///
/// They exist because layer 4 gives the proxy less than HTTP does:
/// - Mutual TLS needs a handshake the proxy completes. On passthrough the
///   certificate is inside the tunnel. On raw TCP and UDP there is none.
///   Without this rule, Sam's route reads as protected by a certificate, and
///   anyone who can reach the port gets in.
/// - A server name restriction needs a handshake to read the name from. On
///   TCP and UDP it would match nothing, so the route would look narrowed
///   while accepting everything.
/// - Who by name may pass must be something the protocol and policy can
///   tell, as [`StreamAccess`] says.
///
/// # Errors
///
/// - [`DomainError::Validation`] if no backend is given.
/// - [`DomainError::Validation`] if mutual TLS is asked for on a protocol the
///   proxy does not terminate.
/// - [`DomainError::Validation`] if a server name restriction is set on a
///   protocol that carries none.
/// - [`DomainError::Validation`] if the access cannot be delivered.
fn validate(shape: Shape<'_>) -> Result<(), DomainError> {
    validate_count("backends", shape.backends.len(), 1..=usize::MAX)?;
    if shape.policy == StreamPolicy::MutualTls && !shape.protocol.terminates_tls() {
        return Err(DomainError::invalid(message!(
            "routing-cannot-require-a-client-certificate-the",
            format!(
                "{} cannot require a client certificate: the proxy does not complete the \
             handshake, so there is no certificate for it to verify",
                shape.protocol.as_str()
            )
        )));
    }
    if matches!(shape.sni, RouteHosts::Only(_)) && !shape.protocol.carries_sni() {
        return Err(DomainError::invalid(message!(
            "routing-carries-no-server-name-so-restricting",
            format!(
                "{} carries no server name, so restricting this route to one would match \
             nothing while appearing to narrow it",
                shape.protocol.as_str()
            )
        )));
    }
    shape.access.ensure_fits(shape.protocol, shape.policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::routing::fixtures::{routing_admin, routing_editor, routing_viewer};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{DomainName, Seconds};

    /// A viewer cannot make a mutual-TLS route public or replace its backend.
    /// Its mutual-TLS policy and original backend remain.
    #[test]
    fn a_viewer_cannot_loosen_a_stream_route() {
        let mut route = route(StreamProtocol::TlsTerminate, StreamPolicy::MutualTls).unwrap();
        let elsewhere = StreamBackend::new("sam.example.com", 5432, 100).unwrap();

        let kept_access = route.access().clone();
        let policy = route.change_admission(StreamPolicy::Public, kept_access, &routing_viewer());
        let backends = route.replace_backends(vec![elsewhere], &routing_viewer());

        assert!(matches!(policy, Err(DomainError::Forbidden(_))));
        assert!(matches!(backends, Err(DomainError::Forbidden(_))));
        assert_eq!(route.policy(), StreamPolicy::MutualTls);
        assert_eq!(route.backends(), [backend()]);
    }

    /// A viewer cannot change SNI, timeouts or the name, or activate a disabled
    /// stream route. Its default timeouts and inactive status remain.
    #[test]
    fn a_viewer_cannot_edit_or_reopen_a_stream_route() {
        let mut route = route(StreamProtocol::TlsTerminate, StreamPolicy::Public).unwrap();
        route.disable(&routing_admin()).unwrap();
        let longer = StreamTimeouts::new(Seconds::new(7), Seconds::new(900)).unwrap();

        let sni = route.change_sni(RouteHosts::Any, &routing_viewer());
        let timeouts = route.change_timeouts(longer, &routing_viewer());
        let renamed = route.rename(Label::new("name", "mine").unwrap(), &routing_viewer());
        let opened = route.activate(&routing_viewer());

        for result in [sni, timeouts, renamed, opened] {
            assert!(matches!(result, Err(DomainError::Forbidden(_))));
        }
        assert_eq!(route.timeouts(), StreamTimeouts::default());
        assert!(!route.is_active());
    }

    /// A viewer cannot disable a stream route, which remains active.
    #[test]
    fn a_viewer_cannot_close_a_stream_route() {
        let mut route = route(StreamProtocol::Tcp, StreamPolicy::Public).unwrap();

        let closed = route.disable(&routing_viewer());

        assert!(matches!(closed, Err(DomainError::Forbidden(_))));
        assert!(route.is_active());
    }

    /// An editor cannot delete a stream route, while a routing administrator can.
    #[test]
    fn deleting_a_stream_route_needs_the_delete_right() {
        let mut route = route(StreamProtocol::Tcp, StreamPolicy::Public).unwrap();

        let by_editor = route.delete(&routing_editor());

        assert!(matches!(by_editor, Err(DomainError::Forbidden(_))));
        assert!(route.delete(&routing_admin()).is_ok());
    }

    /// Routing update permission alone cannot create a public stream route.
    #[test]
    fn opening_a_stream_route_needs_the_create_right() {
        let opened = StreamRoute::<ResolvedTenant>::create(
            params(StreamProtocol::Tcp, StreamPolicy::Public),
            &routing_editor(),
        );

        assert!(matches!(opened, Err(DomainError::Forbidden(_))));
    }

    fn backend() -> StreamBackend {
        StreamBackend::new("db.internal", 5432, 100).unwrap()
    }

    fn params(protocol: StreamProtocol, policy: StreamPolicy) -> CreateStreamRouteParams {
        CreateStreamRouteParams {
            name: Label::new("name", "postgres").unwrap(),
            protocol,
            listen_port: ListenPort::new(15432).unwrap(),
            sni: RouteHosts::Any,
            policy,
            access: StreamAccess::AnyHolder,
            backends: vec![backend()],
            timeouts: StreamTimeouts::default(),
        }
    }

    fn route(
        protocol: StreamProtocol,
        policy: StreamPolicy,
    ) -> Result<StreamRoute<ResolvedTenant>, DomainError> {
        StreamRoute::create(params(protocol, policy), &routing_admin())
    }

    /// Ann opens an SSH port through the signed-in tunnel for people who are
    /// signed in. It is kept, and the gateway holds each person to that
    /// policy before splicing.
    #[test]
    fn a_tunnel_route_ties_the_port_to_people() {
        let route = StreamRoute::<ResolvedTenant>::create(
            CreateStreamRouteParams {
                access: StreamAccess::People(
                    crate::domains::routing::policy::RoutePolicy::Authenticated,
                ),
                ..params(StreamProtocol::Tcp, StreamPolicy::Tunnel)
            },
            &routing_admin(),
        )
        .unwrap();

        assert!(matches!(
            route
                .access()
                .admits(route.policy(), access::StreamCaller::Person),
            access::StreamVerdict::CheckPolicy(_)
        ));
    }

    /// A viewer cannot broaden named-consumer access to any holder. An
    /// administrator cannot combine named consumers with a public policy.
    /// Both refusals preserve the consumer restriction.
    #[test]
    fn a_tie_to_named_consumers_is_kept_and_checked() {
        let named = StreamAccess::Consumers(
            access::StreamConsumers::new(vec![crate::types::ConsumerId::new()]).unwrap(),
        );
        let mut route = StreamRoute::<ResolvedTenant>::create(
            CreateStreamRouteParams {
                access: named,
                ..params(StreamProtocol::TlsTerminate, StreamPolicy::MutualTls)
            },
            &routing_admin(),
        )
        .unwrap();

        let kept_access = route.access().clone();
        let loosened = route.change_admission(
            StreamPolicy::MutualTls,
            StreamAccess::AnyHolder,
            &routing_viewer(),
        );
        let public = route.change_admission(StreamPolicy::Public, kept_access, &routing_admin());

        assert!(matches!(loosened, Err(DomainError::Forbidden(_))));
        assert!(matches!(public, Err(DomainError::Validation(_))));
        assert!(matches!(route.access(), StreamAccess::Consumers(_)));
    }

    /// Ann moves the public SSH port behind the signed-in tunnel for people
    /// who are signed in, policy and access in one step. The route takes
    /// both, and one update is raised.
    #[test]
    fn policy_and_access_change_together_in_one_step() {
        let mut route = route(StreamProtocol::Tcp, StreamPolicy::Public).unwrap();
        raised_names(&mut route);
        let people =
            StreamAccess::People(crate::domains::routing::policy::RoutePolicy::Authenticated);

        route
            .change_admission(StreamPolicy::Tunnel, people, &routing_admin())
            .unwrap();

        assert_eq!(route.policy(), StreamPolicy::Tunnel);
        assert!(matches!(route.access(), StreamAccess::People(_)));
        assert_eq!(raised_names(&mut route), ["routing.stream_route_updated"]);
    }

    /// Public admission restricted to a consumer is invalid for an
    /// administrator and forbidden for a viewer. The route retains its
    /// mutual-TLS policy and any-holder access.
    #[test]
    fn an_admission_the_wire_cannot_keep_is_refused_whole() {
        let mut route = route(StreamProtocol::TlsTerminate, StreamPolicy::MutualTls).unwrap();
        let named = StreamAccess::Consumers(
            access::StreamConsumers::new(vec![crate::types::ConsumerId::new()]).unwrap(),
        );

        let by_viewer =
            route.change_admission(StreamPolicy::Public, named.clone(), &routing_viewer());
        let unkeepable = route.change_admission(StreamPolicy::Public, named, &routing_admin());

        assert!(matches!(by_viewer, Err(DomainError::Forbidden(_))));
        assert!(matches!(unkeepable, Err(DomainError::Validation(_))));
        assert_eq!(route.policy(), StreamPolicy::MutualTls);
        assert!(matches!(route.access(), StreamAccess::AnyHolder));
    }

    /// A tenant opens a public TCP route on port 15432 with one backend. It
    /// starts active and keeps the port and backend.
    #[test]
    fn create_produces_an_active_route() {
        let route = route(StreamProtocol::Tcp, StreamPolicy::Public).unwrap();

        assert!(route.is_active());
        assert_eq!(route.listen_port().get(), 15432);
        assert_eq!(route.backends().len(), 1);
    }

    /// TLS passthrough cannot be configured with a mutual-TLS policy.
    #[test]
    fn passthrough_cannot_require_a_client_certificate() {
        let result = route(StreamProtocol::TlsPassthrough, StreamPolicy::MutualTls);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// Raw TCP cannot be configured with a mutual-TLS policy.
    #[test]
    fn raw_tcp_cannot_require_a_client_certificate() {
        let result = route(StreamProtocol::Tcp, StreamPolicy::MutualTls);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// UDP cannot be configured with a mutual-TLS policy.
    #[test]
    fn udp_cannot_require_a_client_certificate() {
        let result = route(StreamProtocol::Udp, StreamPolicy::MutualTls);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A route where the proxy terminates TLS requires a client certificate.
    /// It is accepted, since the proxy completes the handshake.
    #[test]
    fn terminating_tls_can_require_a_client_certificate() {
        let route = route(StreamProtocol::TlsTerminate, StreamPolicy::MutualTls).unwrap();

        assert_eq!(route.policy(), StreamPolicy::MutualTls);
    }

    /// A public passthrough route is changed to require a client
    /// certificate. It is refused, as at creation, and the route stays
    /// public.
    #[test]
    fn a_policy_change_is_checked_against_the_protocol() {
        let mut route = route(StreamProtocol::TlsPassthrough, StreamPolicy::Public).unwrap();
        let kept_access = route.access().clone();

        assert!(
            route
                .change_admission(StreamPolicy::MutualTls, kept_access, &routing_admin())
                .is_err()
        );
        assert_eq!(route.policy(), StreamPolicy::Public);
    }

    /// A TCP route is restricted to `db.acme.com`. It is refused, since TCP
    /// carries no server name and the route would look narrowed but take all.
    #[test]
    fn tcp_cannot_be_restricted_to_a_server_name() {
        let mut params = params(StreamProtocol::Tcp, StreamPolicy::Public);
        params.sni = RouteHosts::only(vec![DomainName::new("db.acme.com").unwrap()]).unwrap();

        assert!(matches!(
            StreamRoute::<ResolvedTenant>::create(params, &routing_admin()),
            Err(DomainError::Validation(_))
        ));
    }

    /// A passthrough route is restricted to `db.acme.com`. It accepts that
    /// name and refuses `other.acme.com`.
    #[test]
    fn passthrough_matches_on_the_server_name() {
        let mut params = params(StreamProtocol::TlsPassthrough, StreamPolicy::Public);
        params.sni = RouteHosts::only(vec![DomainName::new("db.acme.com").unwrap()]).unwrap();
        let route = StreamRoute::<ResolvedTenant>::create(params, &routing_admin()).unwrap();

        assert!(route.accepts(Some("db.acme.com")));
        assert!(!route.accepts(Some("other.acme.com")));
    }

    /// A route restricted to a server name does not accept a missing SNI name.
    #[test]
    fn a_missing_server_name_does_not_satisfy_a_restriction() {
        let mut params = params(StreamProtocol::TlsPassthrough, StreamPolicy::Public);
        params.sni = RouteHosts::only(vec![DomainName::new("db.acme.com").unwrap()]).unwrap();
        let route = StreamRoute::<ResolvedTenant>::create(params, &routing_admin()).unwrap();

        assert!(!route.accepts(None));
    }

    /// A TCP route with no restriction accepts a connection that offers no
    /// server name.
    #[test]
    fn an_unrestricted_route_accepts_a_connection_with_no_name() {
        let route = route(StreamProtocol::Tcp, StreamPolicy::Public).unwrap();

        assert!(route.accepts(None));
    }

    /// Two stream routes produce distinct tunnel audiences, with the staging
    /// audience containing its route ID in the expected URN.
    #[test]
    fn each_tunnel_names_its_own_audience() {
        let staging = route(StreamProtocol::Tcp, StreamPolicy::Public).unwrap();
        let production = route(StreamProtocol::Tcp, StreamPolicy::Public).unwrap();

        let audience = staging.tunnel_audience().unwrap();

        assert_eq!(
            audience.as_str(),
            format!("urn:ianua:stream-route:{}", staging.id())
        );
        assert_ne!(audience, production.tunnel_audience().unwrap());
    }

    /// A tenant opens a stream route with no backend. It is refused.
    #[test]
    fn a_route_needs_a_backend() {
        let mut params = params(StreamProtocol::Tcp, StreamPolicy::Public);
        params.backends = Vec::new();

        assert!(matches!(
            StreamRoute::<ResolvedTenant>::create(params, &routing_admin()),
            Err(DomainError::Validation(_))
        ));
    }

    /// An admin replaces a route's backends with none. It is refused and the
    /// one backend stays.
    #[test]
    fn the_backends_cannot_be_emptied_later() {
        let mut route = route(StreamProtocol::Tcp, StreamPolicy::Public).unwrap();

        assert!(
            route
                .replace_backends(Vec::new(), &routing_admin())
                .is_err()
        );
        assert_eq!(route.backends().len(), 1);
    }

    /// An admin closes a stream route and opens it again. Each change shows
    /// in whether it is active.
    #[test]
    fn disable_and_reactivate() {
        let mut route = route(StreamProtocol::Tcp, StreamPolicy::Public).unwrap();

        route.disable(&routing_admin()).unwrap();
        assert!(!route.is_active());

        route.activate(&routing_admin()).unwrap();
        assert!(route.is_active());
    }

    /// A tenant asks to listen on port 443. It is refused as a privileged
    /// port, while 1024 is accepted.
    #[test]
    fn a_privileged_port_is_refused() {
        assert!(ListenPort::new(443).is_err());
        assert!(ListenPort::new(1024).is_ok());
    }

    /// A backend at `2001:db8::1` on port 5432 is dialled as
    /// `[2001:db8::1]:5432`.
    #[test]
    fn an_ipv6_backend_is_bracketed_for_dialling() {
        let backend = StreamBackend::new("2001:db8::1", 5432, 1).unwrap();

        assert_eq!(backend.authority(), "[2001:db8::1]:5432");
    }

    /// A backend named `db.internal` on port 5432 is dialled as
    /// `db.internal:5432`.
    #[test]
    fn a_named_backend_is_dialled_as_written() {
        assert_eq!(backend().authority(), "db.internal:5432");
    }

    /// Backend hosts reject an embedded path and a newline followed by
    /// header-like text.
    #[test]
    fn a_backend_host_that_could_smuggle_a_path_is_refused() {
        assert!(StreamBackend::new("db.internal/../admin", 5432, 1).is_err());
        assert!(StreamBackend::new("db.internal\nHost: x", 5432, 1).is_err());
    }

    /// A backend with weight zero would never get traffic. It is refused.
    #[test]
    fn a_zero_weight_backend_is_refused() {
        assert!(StreamBackend::new("db.internal", 5432, 0).is_err());
    }

    /// An idle timeout one second under [`MIN_IDLE_TIMEOUT_SECS`] is refused.
    /// One at exactly that value is accepted.
    #[test]
    fn an_idle_timeout_below_the_floor_is_refused() {
        assert!(
            StreamTimeouts::new(Seconds::new(10), Seconds::new(MIN_IDLE_TIMEOUT_SECS - 1)).is_err()
        );
        assert!(StreamTimeouts::new(Seconds::new(10), Seconds::new(MIN_IDLE_TIMEOUT_SECS)).is_ok());
    }

    /// A stored route names the protocol `sctp`, which does not exist. It is
    /// an infrastructure error, not a mistake the caller can fix.
    #[test]
    fn an_unknown_stored_protocol_is_corrupted_data_not_a_validation_error() {
        assert!(matches!(
            StreamProtocol::from_stored("sctp"),
            Err(DomainError::Infrastructure(_))
        ));
    }

    /// Each of the four protocols is written in its stored form and read
    /// back as itself.
    #[test]
    fn every_protocol_round_trips_through_storage() {
        for protocol in [
            StreamProtocol::Tcp,
            StreamProtocol::TlsTerminate,
            StreamProtocol::TlsPassthrough,
            StreamProtocol::Udp,
        ] {
            assert_eq!(
                StreamProtocol::from_stored(protocol.as_str()).unwrap(),
                protocol
            );
        }
    }

    /// Mutual TLS and public are each written in their stored form and read
    /// back as themselves.
    #[test]
    fn every_policy_round_trips_through_storage() {
        for policy in [StreamPolicy::MutualTls, StreamPolicy::Public] {
            assert_eq!(StreamPolicy::from_stored(policy.as_str()).unwrap(), policy);
        }
    }

    /// A backend made as `db.internal`, port 5432, weight 70 reports each of
    /// those. The data plane dials from them, so a wrong one sends streams to
    /// the wrong machine.
    #[test]
    fn a_backend_reports_the_address_and_share_it_was_created_with() {
        let b = StreamBackend::new("db.internal", 5432, 70).unwrap();

        assert_eq!(b.host().as_str(), "db.internal");
        assert_eq!(b.port(), 5432);
        assert_eq!(b.weight(), 70);
    }

    /// Timeouts set to 7 seconds to connect and 900 idle report those two.
    /// The defaults are 10 seconds and one hour.
    #[test]
    fn timeouts_report_the_two_limits_they_were_set_with() {
        let t = StreamTimeouts::new(Seconds::new(7), Seconds::new(900)).unwrap();

        assert_eq!(t.connect_secs(), Seconds::new(7));
        assert_eq!(t.idle_secs(), Seconds::new(900));

        let default = StreamTimeouts::default();
        assert_eq!(default.connect_secs(), Seconds::new(10));
        assert_eq!(default.idle_secs(), Seconds::new(3_600));
    }

    /// A restriction to `db.acme.com` is stored as a one-name list, and no
    /// restriction as no list. So a narrowed route stays narrowed when saved.
    #[test]
    fn a_server_name_restriction_reads_back_as_the_names_it_holds() {
        let only = RouteHosts::only(vec![DomainName::new("db.acme.com").unwrap()]).unwrap();

        assert_eq!(
            only.as_stored().map(<[DomainName]>::len),
            Some(1),
            "a restriction that stored nothing would read back as unrestricted"
        );
        assert!(only.accepts("db.acme.com"));
        assert_eq!(RouteHosts::Any.as_stored(), None);
    }

    /// A stored list holding `db.acme.com` reads back as that restriction.
    /// It refuses `app.acme.com`, and does not turn into an unrestricted
    /// route.
    #[test]
    fn a_stored_restriction_survives_the_trip_back() {
        let names = vec![DomainName::new("db.acme.com").unwrap()];

        let restored = RouteHosts::from_stored(Some(names.clone())).unwrap();

        assert_eq!(restored, RouteHosts::only(names.clone()).unwrap());
        assert!(!restored.accepts("app.acme.com"));
    }

    /// A stored server name list is empty, which nothing writes. Reading it is
    /// an infrastructure error, not a mistake the caller can fix.
    #[test]
    fn an_empty_stored_sni_list_is_corrupt_data() {
        let result = RouteHosts::from_stored(Some(Vec::new()));

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A route made with 7 and 900 second timeouts and no restriction has a
    /// real id, its aggregate id is the same, and it keeps both settings.
    #[test]
    fn a_route_carries_its_id_timeouts_and_restriction() {
        let mut p = params(StreamProtocol::TlsTerminate, StreamPolicy::Public);
        p.timeouts = StreamTimeouts::new(Seconds::new(7), Seconds::new(900)).unwrap();
        let route = StreamRoute::<ResolvedTenant>::create(p, &routing_admin()).unwrap();

        assert_ne!(*route.id().as_uuid(), uuid::Uuid::nil());
        assert_eq!(Aggregate::id(&route), route.id());
        assert_eq!(
            route.timeouts(),
            StreamTimeouts::new(Seconds::new(7), Seconds::new(900)).unwrap()
        );
        assert!(route.sni().as_stored().is_none());
    }

    /// Five minutes after creation, an admin renames a route, changes its
    /// timeouts and restricts it to `db.acme.com`. Each change shows, and the
    /// update time moves to then.
    #[test]
    fn editing_a_route_takes_effect_and_moves_the_timestamp() {
        let mut route = route(StreamProtocol::TlsTerminate, StreamPolicy::Public).unwrap();
        let created = route.updated_at();
        let later = created + time::Duration::minutes(5);
        let _frozen = crate::shared::clock::freeze(later);

        route
            .rename(
                Label::new("name", "postgres-replica").unwrap(),
                &routing_admin(),
            )
            .unwrap();
        route
            .change_timeouts(
                StreamTimeouts::new(Seconds::new(7), Seconds::new(900)).unwrap(),
                &routing_admin(),
            )
            .unwrap();
        route
            .change_sni(
                RouteHosts::only(vec![DomainName::new("db.acme.com").unwrap()]).unwrap(),
                &routing_admin(),
            )
            .unwrap();

        assert_eq!(route.name().as_str(), "postgres-replica");
        assert_eq!(route.timeouts().connect_secs(), Seconds::new(7));
        assert!(route.accepts(Some("db.acme.com")));
        assert!(!route.accepts(None));
        assert_eq!(route.updated_at(), later);
        assert_eq!(route.created_at(), created);
    }

    /// A stored raw TCP route with a mutual-TLS policy is refused as corrupt.
    #[test]
    fn a_stored_route_the_wire_cannot_deliver_is_refused() {
        let route = route(StreamProtocol::TlsTerminate, StreamPolicy::MutualTls).unwrap();
        let row = StreamRouteRow {
            id: route.id,
            name: route.name.clone(),
            protocol: StreamProtocol::Tcp,
            listen_port: route.listen_port,
            sni: route.sni.clone(),
            policy: route.policy,
            access: route.access.clone(),
            backends: route.backends.clone(),
            timeouts: route.timeouts,
            status: route.status,
            workflow_use: route.workflow_use,
            created_at: route.created_at,
            updated_at: route.updated_at,
        };

        assert!(refused_as_corrupt(
            &StreamRoute::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A raw TCP route as it was saved, its creation taken out.
    fn saved_route() -> StreamRoute<ResolvedTenant> {
        let mut route = route(StreamProtocol::Tcp, StreamPolicy::Public).unwrap();
        raised_names(&mut route);
        route
    }

    fn text(event: &DomainEvent, key: &str) -> String {
        match event.payload().value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not a scalar: {other:?}"),
        }
    }

    /// Ann opens a raw TCP port. The creation is raised with the port and
    /// protocol the data plane binds from.
    #[test]
    fn opening_raises_routing_stream_route_created_with_the_port() {
        let mut route = route(StreamProtocol::Tcp, StreamPolicy::Public).unwrap();

        let events = raised(&mut route);

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "routing.stream_route_created"
        );
        assert_eq!(
            text(&events[0], "listen_port"),
            route.listen_port().get().to_string()
        );
        assert_eq!(text(&events[0], "protocol"), "tcp");
    }

    /// The route is read back from storage. Loading it is no change, so it
    /// has raised nothing.
    #[test]
    fn a_stream_route_read_back_from_storage_has_raised_nothing() {
        let route = saved_route();
        let row = StreamRouteRow {
            id: route.id,
            name: route.name.clone(),
            protocol: route.protocol,
            listen_port: route.listen_port,
            sni: route.sni.clone(),
            policy: route.policy,
            access: route.access.clone(),
            backends: route.backends.clone(),
            timeouts: route.timeouts,
            status: route.status,
            workflow_use: route.workflow_use,
            created_at: route.created_at,
            updated_at: route.updated_at,
        };

        let mut stored = StreamRoute::<ResolvedTenant>::reconstitute(row).unwrap();

        assert!(raised_names(&mut stored).is_empty());
    }

    /// Ann renames the route and stretches its timeouts in one edit. One
    /// update is raised.
    #[test]
    fn several_edits_before_a_save_raise_one_routing_stream_route_updated() {
        let mut route = saved_route();
        let longer = StreamTimeouts::new(Seconds::new(7), Seconds::new(900)).unwrap();

        route
            .rename(Label::new("name", "support-db").unwrap(), &routing_admin())
            .unwrap();
        route.change_timeouts(longer, &routing_admin()).unwrap();

        assert_eq!(raised_names(&mut route), ["routing.stream_route_updated"]);
    }

    /// Ann closes the port and opens it again. Each move is raised with the
    /// direction it went, in order.
    #[test]
    fn closing_and_opening_raise_the_direction_each_went() {
        let mut route = saved_route();

        route.disable(&routing_admin()).unwrap();
        route.activate(&routing_admin()).unwrap();

        assert_eq!(
            raised_names(&mut route),
            [
                "routing.stream_route_disabled",
                "routing.stream_route_activated"
            ]
        );
    }

    /// Fay deletes the route. The deletion is raised.
    #[test]
    fn deleting_raises_routing_stream_route_deleted() {
        let mut route = saved_route();

        route.delete(&routing_admin()).unwrap();

        assert_eq!(raised_names(&mut route), ["routing.stream_route_deleted"]);
    }

    /// An editor's deletion and a viewer's disable both fail without raising
    /// stream-route events.
    #[test]
    fn a_refused_change_raises_nothing() {
        let mut route = saved_route();

        let deleted = route.delete(&routing_editor());
        let closed = route.disable(&routing_viewer());

        assert!(deleted.is_err());
        assert!(closed.is_err());
        assert!(raised_names(&mut route).is_empty());
    }
}
