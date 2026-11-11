//! A tenant's routing as the API takes it: services and where they forward
//! to, pipelines and their stages, routes, and the tenant's names.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Which tokens a service takes as the caller's identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenAudience {
    /// None: a token never identifies anyone on its routes.
    NoTokenAccepted,
    /// Only tokens issued for this audience.
    Pinned(String),
}

/// Where a service forwards, as the API writes an upstream.
#[derive(Debug, Clone, Serialize)]
pub struct Upstream {
    /// The backend's address, such as `http://127.0.0.1:4000`.
    pub url: String,
    /// The longest the backend may take to answer, in seconds.
    pub timeout_secs: u32,
    /// Whether the backend gets the host the client asked for.
    pub preserve_host: bool,
    /// Which tokens identify a caller.
    pub expected_audience: TokenAudience,
    /// What identity the routes take: `token` or `client_certificate`.
    pub identity: String,
}

impl Upstream {
    /// The backend at `url`, given `timeout_secs` to answer, taking tokens
    /// for `audience`.
    #[must_use]
    pub fn at(url: &str, timeout_secs: u32, audience: TokenAudience) -> Self {
        Self {
            url: url.to_owned(),
            timeout_secs,
            preserve_host: false,
            expected_audience: audience,
            identity: "token".to_owned(),
        }
    }
}

/// `POST …/services`.
#[derive(Debug, Clone, Serialize)]
pub struct NewService {
    /// Label used when selecting the backend service for a route.
    pub name: String,
    /// Where it forwards.
    pub upstream: Upstream,
}

/// What a create answers: the id of what it made.
#[derive(Debug, Clone, Deserialize)]
pub struct Made {
    /// Handle used to address the newly created routing resource.
    pub id: String,
}

/// `POST …/pipelines`.
#[derive(Debug, Clone, Serialize)]
pub struct NewPipeline {
    /// Label used when choosing the processing stages for a route.
    pub name: String,
}

/// `POST …/pipelines/{id}/stages`: one stage, its kind and settings as the
/// API writes a stage kind, such as `{"RateLimit": {...}}`.
#[derive(Debug, Clone, Serialize)]
pub struct NewStage {
    /// The stage's kind and settings.
    pub kind: Value,
}

/// What a route asks of a caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum RoutePolicy {
    /// Nothing: anyone reaches it.
    Public,
    /// A caller signed in, holding nothing in particular.
    Authenticated,
    /// A caller holding one of these permissions of the tenant's own.
    RequireCustomPermission(Vec<CustomPermission>),
}

/// A permission of the tenant's own, such as `orders` and `read`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CustomPermission {
    /// What it is about, such as `orders`.
    pub resource: String,
    /// What it allows, such as `read`.
    pub action: String,
}

/// `PATCH …/routes/{id}`: what changes on a route.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RouteChange {
    /// The service it forwards to instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_id: Option<String>,
    /// The paths it answers instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_pattern: Option<String>,
}

/// `PATCH …/routes/{id}` declaring what kind of action the route takes,
/// such as `Financial`, which an agent's held call there is judged by.
#[derive(Debug, Clone, Serialize)]
pub struct DeclaredAction {
    /// `Read`, `Write`, `Delete`, `Configure`, `Communicate`, `Financial`
    /// or `Admin`.
    pub action_class: String,
}

/// `PATCH …/routes/{id}` asking something else of a route's callers.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyChange {
    /// What the route asks of a caller from now on.
    pub policy: RoutePolicy,
}

/// `POST …/routes`.
#[derive(Debug, Clone, Serialize)]
pub struct NewRoute {
    /// Label identifying this path and host mapping in route lists.
    pub name: String,
    /// The paths it answers, such as `/orders/*`.
    pub path_pattern: String,
    /// The methods it answers, such as `Get`; none answers every method.
    pub methods: Vec<String>,
    /// The service it forwards to.
    pub service_id: String,
    /// What it asks of a caller.
    pub policy: RoutePolicy,
    /// The pipeline its requests run through.
    pub pipeline_id: String,
    /// The hosts it answers on; none answers on every host of the tenant.
    pub hosts: Vec<String>,
}

/// The names a tenant is reached on.
#[derive(Debug, Clone, Deserialize)]
pub struct Hostnames {
    /// The permanent random root, under the historical API field name.
    pub uuid_subdomain: String,
    /// The permanent random label, independent of the tenant id.
    pub platform_label: String,
    /// Whether readable addresses are enabled by the tenant.
    pub readable_address: bool,
    /// `{tenant slug}.{org slug}.{apps domain}`, only when opted in.
    #[serde(default)]
    pub slug_subdomain: Option<String>,
}

/// One app on a person's start page, from `GET …/me/apps`.
#[derive(Debug, Clone, Deserialize)]
pub struct OpenableApp {
    /// The route the app is served through.
    pub route_id: String,
    /// The app's name, as its route is named.
    pub name: String,
    /// The path it opens at, such as `/wiki`.
    pub path: String,
    /// The addresses it answers on; empty for every one of the tenant's.
    pub hosts: Vec<String>,
    /// `now`, `step_up` or `key_proof`.
    pub opens: String,
}

/// `POST …/stream-routes`: a port below HTTP, and where it forwards.
#[derive(Debug, Clone, Serialize)]
pub struct NewStreamRoute {
    /// Label identifying this listener in stream-route administration.
    pub name: String,
    /// How the gateway speaks on the port, such as `tcp`.
    pub protocol: String,
    /// Gateway socket number accepting client connections.
    pub listen_port: u16,
    /// What the wire checks, such as `tunnel` for people signing in.
    pub policy: String,
    /// Who by name may pass, such as `{"people": "Authenticated"}`.
    pub access: Value,
    /// Where accepted streams go.
    pub backends: Vec<StreamBackend>,
}

/// One place a stream route forwards to.
#[derive(Debug, Clone, Serialize)]
pub struct StreamBackend {
    /// Backend address reached after the gateway accepts a stream.
    pub host: String,
    /// Backend socket number receiving forwarded connections.
    pub port: u16,
    /// Its share of the streams.
    pub weight: u32,
}

/// `POST …/stream-routes/{id}/open-to-workflows`: the login Protected
/// data steps sign in with.
#[derive(Debug, Clone, Serialize)]
pub struct WorkflowLogin {
    /// The user name.
    pub login_user: String,
    /// Secret used by protected-data steps to authenticate to the backend.
    pub login_password: String,
    /// `required` or `off`; the platform requires TLS when left out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<String>,
    /// The PEM of the authority the system's certificate is from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_authority: Option<String>,
    /// The name the system's certificate is for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_server_name: Option<String>,
}
