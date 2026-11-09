mod connector;

pub(crate) use connector::{ConnectorChange, ConnectorChanged};
use time::OffsetDateTime;

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::routing::egress::{EgressDestination, ServiceIdentity};
use crate::domains::routing::import::ImportMode;
use crate::domains::routing::stream::LoginUser;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::{DomainEventCore, tenant_event};
use crate::shared::events::raised::TenantEventBody;
use crate::shared::model::two_cases::two_cases;
use crate::types::{EgressPolicyId, Label, RouteId, StreamRouteId, UrlPath};

/// References the route an event acted on, labelled with its name at that time.
fn route_reference(route_id: &RouteId, name: &Label) -> Reference {
    Reference::new(RefKind::ROUTE, route_id.to_string(), name.to_string())
}

/// A new route was created within a tenant.
///
/// The proxy should reload its routing table to include this route.
#[derive(Debug)]
pub struct RouteCreated {
    /// The newly created route.
    pub(crate) route_id: RouteId,
    /// Route name shown in the routing dashboard.
    pub(crate) name: Label,
    /// The path pattern this route matches.
    pub(crate) path_pattern: UrlPath,
    /// When the route was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RouteCreated => crate::types::event_type::RoutingEvent::RouteCreated,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("route", route_reference(&self.route_id, &self.name))
            .field("path_pattern", self.path_pattern.to_string())
    }
}

/// A route's configuration was updated.
///
/// The proxy should reload this route's configuration.
#[derive(Debug)]
pub struct RouteUpdated {
    /// The route that was updated.
    pub(crate) route_id: RouteId,
    /// The route's name.
    pub(crate) name: Label,
    /// When the update occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RouteUpdated => crate::types::event_type::RoutingEvent::RouteUpdated,
    fn payload(&self) -> EventData {
        EventData::new().reference("route", route_reference(&self.route_id, &self.name))
    }
}

/// A route was deleted.
///
/// The proxy should remove this route from its routing table.
#[derive(Debug)]
pub struct RouteDeleted {
    /// The route that was deleted.
    pub(crate) route_id: RouteId,
    /// The route's name when it was deleted, kept for the audit trail.
    pub(crate) name: Label,
    /// When the deletion occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RouteDeleted => crate::types::event_type::RoutingEvent::RouteDeleted,
    fn payload(&self) -> EventData {
        EventData::new().reference("route", route_reference(&self.route_id, &self.name))
    }
}

/// A route was activated, so it takes traffic again.
#[derive(Debug)]
pub struct RouteActivated {
    /// The route that was activated.
    pub(crate) route_id: RouteId,
    /// Route name at the time of activation.
    pub(crate) name: Label,
    /// When the activation occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RouteActivated => crate::types::event_type::RoutingEvent::RouteActivated,
    fn payload(&self) -> EventData {
        EventData::new().reference("route", route_reference(&self.route_id, &self.name))
    }
}

/// A route was disabled, so it takes no traffic.
///
/// The proxy should stop forwarding requests matching this route until it is
/// activated again.
#[derive(Debug)]
pub struct RouteDisabled {
    /// The route that was disabled.
    pub(crate) route_id: RouteId,
    /// Route name at the time of disabling.
    pub(crate) name: Label,
    /// When the disable occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RouteDisabled => crate::types::event_type::RoutingEvent::RouteDisabled,
    fn payload(&self) -> EventData {
        EventData::new().reference("route", route_reference(&self.route_id, &self.name))
    }
}

/// Workflows may now call a route, each call still decided by its policy
/// as the run's person.
#[derive(Debug)]
pub struct RouteOpenedToWorkflows {
    /// The route opened.
    pub(crate) route_id: RouteId,
    /// Route name at the time.
    pub(crate) name: Label,
    /// When it was opened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RouteOpenedToWorkflows => crate::types::event_type::RoutingEvent::RouteOpenedToWorkflows,
    fn payload(&self) -> EventData {
        EventData::new().reference("route", route_reference(&self.route_id, &self.name))
    }
}

/// A route went into attack mode: until `until`, every request to it is
/// checked harder before its pipeline.
#[derive(Debug)]
pub struct RouteAttackModeStarted {
    /// The forwarding rule temporarily requiring stricter request checks.
    pub(crate) route_id: RouteId,
    /// Route name at the time.
    pub(crate) name: Label,
    /// When attack mode ends on its own.
    pub(crate) until: OffsetDateTime,
    /// When it was started.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RouteAttackModeStarted => crate::types::event_type::RoutingEvent::RouteAttackModeStarted,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("route", route_reference(&self.route_id, &self.name))
            .field("end", self.until.to_string())
    }
}

/// A route's attack mode was ended before its time.
#[derive(Debug)]
pub struct RouteAttackModeEnded {
    /// The forwarding rule returned early to its ordinary checks.
    pub(crate) route_id: RouteId,
    /// Route name at the time.
    pub(crate) name: Label,
    /// When it was ended.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RouteAttackModeEnded => crate::types::event_type::RoutingEvent::RouteAttackModeEnded,
    fn payload(&self) -> EventData {
        EventData::new().reference("route", route_reference(&self.route_id, &self.name))
    }
}

/// Workflows may call a route no more.
#[derive(Debug)]
pub struct RouteClosedToWorkflows {
    /// The route closed.
    pub(crate) route_id: RouteId,
    /// Route name at the time.
    pub(crate) name: Label,
    /// When it was closed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RouteClosedToWorkflows => crate::types::event_type::RoutingEvent::RouteClosedToWorkflows,
    fn payload(&self) -> EventData {
        EventData::new().reference("route", route_reference(&self.route_id, &self.name))
    }
}

/// References the service an event acted on, labelled with its name at that time.
fn service_reference(service_id: &crate::types::ServiceId, name: &Label) -> Reference {
    Reference::new(RefKind::SERVICE, service_id.to_string(), name.to_string())
}

/// A backend was defined for a tenant.
///
/// The proxy should reload its routing table. A service carries the address
/// and health-check settings that every route pointing at it forwards with.
#[derive(Debug)]
pub struct ServiceCreated {
    /// The newly created service.
    pub(crate) service_id: crate::types::ServiceId,
    /// Service name, shown in the dashboard.
    pub(crate) name: Label,
    /// When the service was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ServiceCreated => crate::types::event_type::RoutingEvent::ServiceCreated,
    fn payload(&self) -> EventData {
        EventData::new().reference("service", service_reference(&self.service_id, &self.name))
    }
}

/// A service's configuration changed.
///
/// Every route pointing at it forwards differently from here on. So the
/// proxy reloads on this event, not on one per route.
#[derive(Debug)]
pub struct ServiceUpdated {
    /// The service that changed.
    pub(crate) service_id: crate::types::ServiceId,
    /// The service's name.
    pub(crate) name: Label,
    /// When the update occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ServiceUpdated => crate::types::event_type::RoutingEvent::ServiceUpdated,
    fn payload(&self) -> EventData {
        EventData::new().reference("service", service_reference(&self.service_id, &self.name))
    }
}

/// A service was deleted.
#[derive(Debug)]
pub struct ServiceDeleted {
    /// The service that was deleted.
    pub(crate) service_id: crate::types::ServiceId,
    /// The service's name when it was deleted, kept for the audit trail.
    pub(crate) name: Label,
    /// When the deletion occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ServiceDeleted => crate::types::event_type::RoutingEvent::ServiceDeleted,
    fn payload(&self) -> EventData {
        EventData::new().reference("service", service_reference(&self.service_id, &self.name))
    }
}

/// Where and how people sign in on a service's hosts changed.
///
/// App sign-in was turned on, moved or turned off. Or the service started or
/// stopped accepting another service's sign-in. The proxy reloads the
/// tenant's routes, since it answers sign-in addresses and accepts app
/// sessions from the services' settings.
#[derive(Debug)]
pub struct AppSignInChanged {
    /// The service whose sign-in changed.
    pub(crate) service_id: crate::types::ServiceId,
    /// The service's name.
    pub(crate) name: Label,
    /// The hosts its sign-in addresses now answer on. Empty when sign-in is
    /// off.
    pub(crate) hosts: Vec<crate::types::DomainName>,
    /// When the change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AppSignInChanged => crate::types::event_type::RoutingEvent::AppSignInChanged,
    fn payload(&self) -> EventData {
        let hosts: Vec<&str> = self
            .hosts
            .iter()
            .map(crate::types::DomainName::as_str)
            .collect();
        EventData::new()
            .reference("service", service_reference(&self.service_id, &self.name))
            .field("hosts", hosts.join(", "))
    }
}

/// References the stream route an event acted on.
fn stream_route_reference(id: &StreamRouteId, name: &Label) -> Reference {
    Reference::new(RefKind::STREAM_ROUTE, id.to_string(), name.to_string())
}

/// A port was opened for a tenant below HTTP.
///
/// The data plane must bind it. An HTTP route is served by a listener that
/// is already running. This one asks for a socket that does not exist yet.
/// So the port travels on the event instead of being looked up.
#[derive(Debug)]
pub struct StreamRouteCreated {
    /// The newly created stream route.
    pub(crate) stream_route_id: StreamRouteId,
    /// Name, shown in the dashboard.
    pub(crate) name: Label,
    /// The port now claimed.
    pub(crate) listen_port: u16,
    /// How the proxy speaks on it.
    pub(crate) protocol: &'static str,
    /// When the route was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    StreamRouteCreated => crate::types::event_type::RoutingEvent::StreamRouteCreated,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "stream_route",
                stream_route_reference(&self.stream_route_id, &self.name),
            )
            .field("listen_port", self.listen_port.to_string())
            .field("protocol", self.protocol)
    }
}

/// A stream route's configuration changed.
#[derive(Debug)]
pub struct StreamRouteUpdated {
    /// The route that changed.
    pub(crate) stream_route_id: StreamRouteId,
    /// The display label captured when the forwarding configuration changed.
    pub(crate) name: Label,
    /// When the update occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    StreamRouteUpdated => crate::types::event_type::RoutingEvent::StreamRouteUpdated,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "stream_route",
            stream_route_reference(&self.stream_route_id, &self.name),
        )
    }
}

/// A stream route was removed and its port released.
#[derive(Debug)]
pub struct StreamRouteDeleted {
    /// The removed route.
    pub(crate) stream_route_id: StreamRouteId,
    /// The display label retained after the listening route was removed.
    pub(crate) name: Label,
    /// When the deletion occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    StreamRouteDeleted => crate::types::event_type::RoutingEvent::StreamRouteDeleted,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "stream_route",
            stream_route_reference(&self.stream_route_id, &self.name),
        )
    }
}

/// Workflows may now reach a stream route, each connection still decided
/// by its access as the run's person, with the login it keeps for them.
/// The login's user name is recorded; the password never is.
#[derive(Debug)]
pub struct StreamRouteOpenedToWorkflows {
    /// The stream route opened.
    pub(crate) stream_route_id: StreamRouteId,
    /// Its name at the time.
    pub(crate) name: Label,
    /// The user name the login signs in as.
    pub(crate) login_user: LoginUser,
    /// Whether the connection to the system is held to TLS: `required` or
    /// `off`.
    pub(crate) tls: &'static str,
    /// When it was opened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    StreamRouteOpenedToWorkflows => crate::types::event_type::RoutingEvent::StreamRouteOpenedToWorkflows,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "stream_route",
                stream_route_reference(&self.stream_route_id, &self.name),
            )
            .field("login_user", self.login_user.as_str())
            .field("tls", self.tls)
    }
}

/// Workflows may reach a stream route no more, and the login it kept for
/// them is gone.
#[derive(Debug)]
pub struct StreamRouteClosedToWorkflows {
    /// The stream route closed.
    pub(crate) stream_route_id: StreamRouteId,
    /// Its name at the time.
    pub(crate) name: Label,
    /// When it was closed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    StreamRouteClosedToWorkflows => crate::types::event_type::RoutingEvent::StreamRouteClosedToWorkflows,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "stream_route",
            stream_route_reference(&self.stream_route_id, &self.name),
        )
    }
}

two_cases! {
    /// Whether a stream route is accepting connections.
    pub enum StreamRouteState {
        /// Accepting.
        Accepting => true,
        /// Disabled.
        Disabled => false,
    }
}

/// A stream route started or stopped accepting connections.
///
/// One event carries the new status for both directions. The data plane does
/// the same thing either way. It reads the route again and binds or unbinds
/// the port.
#[derive(Debug)]
pub(crate) struct StreamRouteStatusChanged {
    /// The route whose status changed.
    pub(crate) stream_route_id: StreamRouteId,
    /// The display label captured when the listening port changed availability.
    pub(crate) name: Label,
    /// Whether it is now accepting.
    pub(crate) active: StreamRouteState,
    /// When the change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

impl DomainEventCore for StreamRouteStatusChanged {
    fn event_type(&self) -> crate::types::EventType {
        if self.active == StreamRouteState::Accepting {
            return crate::types::event_type::RoutingEvent::StreamRouteActivated.into();
        }
        crate::types::event_type::RoutingEvent::StreamRouteDisabled.into()
    }

    fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }

    fn payload(&self) -> EventData {
        EventData::new().reference(
            "stream_route",
            stream_route_reference(&self.stream_route_id, &self.name),
        )
    }
}

impl TenantEventBody for StreamRouteStatusChanged {}

/// What happened to an egress policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EgressPolicyChange {
    /// It was made.
    Created,
    /// Its destinations or its most sensitive data class changed.
    Updated,
    /// It was removed.
    Deleted,
}

/// An egress policy was made, changed or removed.
#[derive(Debug)]
pub(crate) struct EgressPolicyChanged {
    /// The outbound-access declaration whose permitted destinations changed.
    pub(crate) policy_id: EgressPolicyId,
    /// The declaration's display label captured with its current destinations.
    pub(crate) name: Label,
    /// The workload identity whose outbound reach is governed by this declaration.
    pub(crate) service: ServiceIdentity,
    /// Where the service may now go, as `host:port`. Empty once deleted.
    pub(crate) destinations: Vec<EgressDestination>,
    /// The most sensitive data an agent may now send through it.
    pub(crate) max_data_class: DataClassLevel,
    /// What happened.
    pub(crate) change: EgressPolicyChange,
    /// When.
    pub(crate) occurred_at: OffsetDateTime,
}

impl DomainEventCore for EgressPolicyChanged {
    fn event_type(&self) -> crate::types::EventType {
        match self.change {
            EgressPolicyChange::Created => {
                crate::types::event_type::RoutingEvent::EgressPolicyCreated
            }
            EgressPolicyChange::Updated => {
                crate::types::event_type::RoutingEvent::EgressPolicyUpdated
            }
            EgressPolicyChange::Deleted => {
                crate::types::event_type::RoutingEvent::EgressPolicyDeleted
            }
        }
        .into()
    }

    fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }

    fn payload(&self) -> EventData {
        EventData::new()
            .field("egress_policy_id", self.policy_id.to_string())
            .field("name", self.name.as_str())
            .field("service", self.service.as_str())
            .field(
                "destinations",
                self.destinations
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .field("max_data_class", self.max_data_class.as_str())
    }
}

impl TenantEventBody for EgressPolicyChanged {}

/// A configuration document was applied to the tenant's gateway.
///
/// One record covers the whole apply, not one per resource. The document is
/// the change the person made, and the counts say how far it reached.
#[derive(Debug)]
pub struct GatewayConfigImported {
    /// How the document was applied.
    pub(crate) mode: ImportMode,
    /// How many services, pipelines and routes it created.
    pub(crate) created: usize,
    /// How many it changed.
    pub(crate) updated: usize,
    /// How many it removed.
    pub(crate) deleted: usize,
    /// When the apply finished.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    GatewayConfigImported => crate::types::event_type::RoutingEvent::GatewayConfigImported,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("mode", self.mode.as_str())
            .field("created", self.created.to_string())
            .field("updated", self.updated.to_string())
            .field("deleted", self.deleted.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::test_support::builders::label;
    use crate::types::ServiceId;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn entity(payload: &EventData, key: &str) -> (RefKind, String, String) {
        match payload.value(key) {
            Some(FieldValue::Reference(reference)) => (
                reference.kind(),
                reference.id().to_owned(),
                reference.label().to_owned(),
            ),
            other => panic!("{key} is not an entity reference: {other:?}"),
        }
    }

    fn text(payload: &EventData, key: &str) -> String {
        match payload.value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not a scalar: {other:?}"),
        }
    }

    /// An egress-policy update payload records its restricted data ceiling.
    #[test]
    fn an_egress_change_records_the_data_ceiling() {
        let event = EgressPolicyChanged {
            policy_id: EgressPolicyId::new(),
            name: label("fetcher"),
            service: ServiceIdentity::new("spiffe://ianua.test/ns/svc/sa/fetcher").unwrap(),
            destinations: vec![
                EgressDestination::new(
                    crate::types::DomainName::new("api.partner.com").unwrap(),
                    443,
                )
                .unwrap(),
            ],
            max_data_class: DataClassLevel::Restricted,
            change: EgressPolicyChange::Updated,
            occurred_at: now(),
        };

        assert_eq!(
            text(&event.payload(), "max_data_class"),
            DataClassLevel::Restricted.as_str()
        );
    }

    /// The "Public API" route is created, updated, activated, disabled and
    /// deleted. Each event names the route, so the data plane
    /// knows what to reload.
    #[test]
    fn every_route_event_names_the_route() {
        let route = RouteId::new();

        let events: Vec<Box<dyn TenantEventBody>> = vec![
            Box::new(RouteCreated {
                route_id: route,
                name: label("Public API"),
                path_pattern: UrlPath::new("/api/*").unwrap(),
                occurred_at: now(),
            }),
            Box::new(RouteUpdated {
                route_id: route,
                name: label("Public API"),
                occurred_at: now(),
            }),
            Box::new(RouteActivated {
                route_id: route,
                name: label("Public API"),
                occurred_at: now(),
            }),
            Box::new(RouteDisabled {
                route_id: route,
                name: label("Public API"),
                occurred_at: now(),
            }),
            Box::new(RouteDeleted {
                route_id: route,
                name: label("Public API"),
                occurred_at: now(),
            }),
        ];

        for event in events {
            let kind = event.event_type();
            assert_eq!(
                entity(&event.payload(), "route"),
                (RefKind::ROUTE, route.to_string(), "Public API".to_owned()),
                "{kind}"
            );
        }
    }

    /// A route is created for `/api/*`. The event records that pattern, since
    /// it decides which requests the route answers.
    #[test]
    fn creating_a_route_records_the_path_it_claims() {
        let event = RouteCreated {
            route_id: RouteId::new(),
            name: label("Public API"),
            path_pattern: UrlPath::new("/api/*").unwrap(),
            occurred_at: now(),
        };

        assert_eq!(text(&event.payload(), "path_pattern"), "/api/*");
    }

    /// App sign-in for "orders-api" now answers on two hosts. The event lists
    /// them as `app.example.com, www.example.com`.
    #[test]
    fn an_app_sign_in_change_records_the_hosts_it_now_answers_on() {
        let event = AppSignInChanged {
            service_id: ServiceId::new(),
            name: label("orders-api"),
            hosts: vec![
                crate::types::DomainName::new("app.example.com").unwrap(),
                crate::types::DomainName::new("www.example.com").unwrap(),
            ],
            occurred_at: now(),
        };

        assert_eq!(
            text(&event.payload(), "hosts"),
            "app.example.com, www.example.com"
        );
    }

    /// "orders-api" is created, updated and deleted, and its sign-in
    /// changes. Each event names the service, so the record
    /// shows which backend changed.
    #[test]
    fn every_service_event_names_the_service() {
        let service = ServiceId::new();

        for event in service_events(service) {
            let kind = event.event_type();
            assert_eq!(
                entity(&event.payload(), "service"),
                (
                    RefKind::SERVICE,
                    service.to_string(),
                    "orders-api".to_owned()
                ),
                "{kind}"
            );
        }
    }

    /// The changes that keep a reference to the same backend service.
    fn service_events(service: ServiceId) -> Vec<Box<dyn TenantEventBody>> {
        vec![
            Box::new(ServiceCreated {
                service_id: service,
                name: label("orders-api"),
                occurred_at: now(),
            }),
            Box::new(ServiceUpdated {
                service_id: service,
                name: label("orders-api"),
                occurred_at: now(),
            }),
            Box::new(ServiceDeleted {
                service_id: service,
                name: label("orders-api"),
                occurred_at: now(),
            }),
            Box::new(AppSignInChanged {
                service_id: service,
                name: label("orders-api"),
                hosts: vec![],
                occurred_at: now(),
            }),
        ]
    }

    /// A "postgres" stream route opens TCP port 5432. The event names the
    /// route and carries the port and protocol, which the data plane binds
    /// from.
    #[test]
    fn creating_a_stream_route_records_the_port_and_protocol_to_bind() {
        let id = StreamRouteId::new();

        let event = StreamRouteCreated {
            stream_route_id: id,
            name: label("postgres"),
            listen_port: 5432,
            protocol: "tcp",
            occurred_at: now(),
        };

        let payload = event.payload();
        assert_eq!(
            entity(&payload, "stream_route"),
            (RefKind::STREAM_ROUTE, id.to_string(), "postgres".to_owned())
        );
        assert_eq!(text(&payload, "listen_port"), "5432");
        assert_eq!(text(&payload, "protocol"), "tcp");
    }

    /// The "postgres" stream route is updated and then deleted. Both events
    /// name the route.
    #[test]
    fn changing_or_removing_a_stream_route_names_it() {
        let id = StreamRouteId::new();

        let events: Vec<Box<dyn TenantEventBody>> = vec![
            Box::new(StreamRouteUpdated {
                stream_route_id: id,
                name: label("postgres"),
                occurred_at: now(),
            }),
            Box::new(StreamRouteDeleted {
                stream_route_id: id,
                name: label("postgres"),
                occurred_at: now(),
            }),
        ];

        for event in events {
            let kind = event.event_type();
            assert_eq!(
                entity(&event.payload(), "stream_route"),
                (RefKind::STREAM_ROUTE, id.to_string(), "postgres".to_owned()),
                "{kind}"
            );
        }
    }

    /// The "postgres" stream route is opened and then closed. The events are
    /// typed activated and disabled, so a subscriber filtering on "disabled"
    /// never sees the port being opened.
    #[test]
    fn a_stream_route_status_change_reports_the_direction_it_went() {
        let id = StreamRouteId::new();

        let opened = StreamRouteStatusChanged {
            stream_route_id: id,
            name: label("postgres"),
            active: StreamRouteState::Accepting,
            occurred_at: now(),
        };
        let closed = StreamRouteStatusChanged {
            stream_route_id: id,
            name: label("postgres"),
            active: StreamRouteState::Disabled,
            occurred_at: now(),
        };

        assert_eq!(
            opened.event_type().as_str(),
            "routing.stream_route_activated"
        );
        assert_eq!(
            closed.event_type().as_str(),
            "routing.stream_route_disabled"
        );
        assert_eq!(
            entity(&closed.payload(), "stream_route"),
            (RefKind::STREAM_ROUTE, id.to_string(), "postgres".to_owned())
        );
    }
}
