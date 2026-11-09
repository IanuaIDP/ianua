//! Rows of the routing context.

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::routing::backend::health_check::HealthCheckPolicy;
use ianua_domain::domains::routing::backend::upstream::{HostHeader, Upstream, UpstreamTimeout};
use ianua_domain::domains::routing::connector::scope::ConnectorScope;
use ianua_domain::domains::routing::connector::{
    ConnectorEnrollment, ConnectorStatus, LastSeen, PrivateConnectorRow,
};
use ianua_domain::domains::routing::egress::{EgressDestination, EgressPolicyRow, ServiceIdentity};
use ianua_domain::domains::routing::matching::host::RouteHosts;
use ianua_domain::domains::routing::matching::parameter::RouteReach;
use ianua_domain::domains::routing::matching::path_rewrite::PathRewrite;
use ianua_domain::domains::routing::matching::request_match::RouteConditions;
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::route::{AttackMode, RouteRow, WorkflowUse};
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::domains::routing::service::ServiceRow;
use ianua_domain::domains::routing::stream::access::StreamAccess;
use ianua_domain::domains::routing::stream::{
    ListenPort, StreamBackend, StreamPolicy, StreamProtocol, StreamRouteRow, StreamTimeouts,
    StreamWorkflowUse,
};
use ianua_domain::types::{
    Audience, ConnectorId, DeclaredAction, DomainName, EgressPolicyId, HttpUrl, Label, PipelineId,
    PrincipalRef, RouteId, ServiceId, Setting, StreamRouteId, TokenHash, UrlPath, UserId,
};

use crate::test_support::rows::at;

/// An active service named `name`, forwarding to one backend over HTTPS
/// and pinning the audience `name`, so routes needing sign-in may use it.
///
/// # Panics
///
/// When `name` is not a valid label or audience, which is a mistake in the
/// test.
#[must_use]
pub fn service_row(name: &str) -> ServiceRow {
    let upstream = Upstream::new(
        HttpUrl::new("https://backend.example.com").expect("a valid URL"),
        UpstreamTimeout::DEFAULT,
        HostHeader::Rewrite,
    )
    .with_audience(Audience::new(name).expect("a valid audience"));
    ServiceRow {
        id: ServiceId::new(),
        name: Label::new("name", name).expect("a valid name"),
        upstream,
        health_check: HealthCheckPolicy::default(),
        app_sign_in: Setting::Unset,
        accepted_sign_in: Setting::Unset,
        status: RouteStatus::Active,
        created_at: at(0),
        updated_at: at(0),
    }
}

/// An active route named `name` on `/api/<name>` to `service`, for
/// signed-in callers on every host, on a pipeline of its own.
///
/// # Panics
///
/// When `name` is not a valid label or path segment, which is a mistake in
/// the test.
#[must_use]
pub fn route_row(service: ServiceId, name: &str) -> RouteRow {
    RouteRow {
        id: RouteId::new(),
        name: Label::new("name", name).expect("a valid name"),
        path_pattern: UrlPath::new(format!("/api/{name}")).expect("a valid path"),
        methods: Vec::new(),
        service_id: service,
        policy: RoutePolicy::Authenticated,
        hosts: RouteHosts::Any,
        conditions: RouteConditions::default(),
        pipeline_id: PipelineId::new(),
        path_rewrite: PathRewrite::Keep,
        status: RouteStatus::Active,
        priority: 100,
        data_class: DataClassLevel::Internal,
        action_class: DeclaredAction::Undeclared,
        reach: RouteReach::Fixed,
        parameter_rules: Vec::new(),
        workflow_use: WorkflowUse::Closed,
        attack_mode: AttackMode::Off,
        created_at: at(0),
        updated_at: at(0),
    }
}

/// An active, open TCP stream route named `name` on `port`, to one
/// database.
///
/// # Panics
///
/// When `name` is not a valid label or `port` not one a stream route may
/// listen on, which is a mistake in the test.
#[must_use]
pub fn stream_route_row(name: &str, port: u16) -> StreamRouteRow {
    StreamRouteRow {
        id: StreamRouteId::new(),
        name: Label::new("name", name).expect("a valid name"),
        protocol: StreamProtocol::Tcp,
        listen_port: ListenPort::new(port).expect("a valid port"),
        sni: RouteHosts::Any,
        policy: StreamPolicy::Public,
        access: StreamAccess::AnyHolder,
        backends: vec![StreamBackend::new("db.example.com", 5432, 1).expect("a valid backend")],
        timeouts: StreamTimeouts::default(),
        status: RouteStatus::Active,
        workflow_use: StreamWorkflowUse::Closed,
        created_at: at(0),
        updated_at: at(0),
    }
}

/// The hash a connector row keeps for the enrollment code `code`.
#[must_use]
pub fn connector_code_hash(code: &str) -> TokenHash {
    TokenHash::from_stored(format!("hash:{code}"))
}

/// An active connector named `name`, awaiting enrollment with the code
/// `code` for the hour after it was made, allowed to dial one domain.
///
/// # Panics
///
/// When `name` is not a valid label, which is a mistake in the test.
#[must_use]
pub fn connector_row(name: &str, code: &str) -> PrivateConnectorRow {
    let domain = DomainName::new("intranet.example.com").expect("a valid domain");
    PrivateConnectorRow {
        id: ConnectorId::new(),
        name: Label::new("name", name).expect("a valid name"),
        scope: ConnectorScope::new(Vec::new(), vec![domain]).expect("a valid scope"),
        enrollment: ConnectorEnrollment::Awaiting {
            code_hash: connector_code_hash(code),
            expires_at: at(3600),
        },
        status: ConnectorStatus::Active,
        last_seen: LastSeen::Never,
        created_at: at(0),
        updated_at: at(0),
    }
}

/// A policy named `name` letting the service `service` reach
/// `api.github.com` on 443 with internal data, made by a tenant user.
///
/// # Panics
///
/// When `name` is not a valid label or `service` not a service identity,
/// which is a mistake in the test.
#[must_use]
pub fn egress_policy_row(name: &str, service: &str) -> EgressPolicyRow {
    let github = DomainName::new("api.github.com").expect("a valid domain");
    EgressPolicyRow {
        id: EgressPolicyId::new(),
        name: Label::new("name", name).expect("a valid name"),
        service: ServiceIdentity::new(service).expect("a valid service identity"),
        destinations: vec![EgressDestination::new(github, 443).expect("a public destination")],
        max_data_class: DataClassLevel::Internal,
        created_by: PrincipalRef::User(UserId::new()),
        created_at: at(0),
        updated_at: at(0),
    }
}
