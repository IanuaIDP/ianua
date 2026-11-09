//! A route in front of an app, as a tenant's administrator makes one: a
//! service forwarding to the app, a pipeline, its stages, and the route,
//! each through the API; then awaited until the gateway serves it, by
//! asking for it through the gateway, never by sleeping. [`domain`] brings
//! a domain of the tenant's own for routes to answer on.

pub mod domain;

use serde_json::Value;

use crate::api::{Request, TenantPath, routing};
use crate::expect::eventually;
use crate::net::{Call, Client};
use crate::upstreams::Arrival;
use crate::wire::Status;
use crate::wire::routing::{
    NewPipeline, NewRoute, NewService, NewStage, RoutePolicy, TokenAudience, Upstream,
};

/// How long a backend may take to answer when the route names nothing else.
const DEFAULT_TIMEOUT_SECS: u32 = 30;

/// The status the gateway answers for a host or path it serves no route on.
const NOT_SERVED: Status = Status::NOT_FOUND;

/// The status while a route's required configuration is not ready to serve.
const NOT_READY: Status = Status::SERVICE_UNAVAILABLE;

/// A route and what it needs, in any configuration.
#[derive(Debug, Clone)]
pub struct RouteSpec {
    name: String,
    path_pattern: String,
    methods: Vec<String>,
    policy: RoutePolicy,
    audience: TokenAudience,
    timeout_secs: u32,
    hosts: Vec<String>,
    stages: Vec<Value>,
}

/// Where a route is made: the tenant, the app it forwards to, and the host
/// it is asked for on.
#[derive(Debug, Clone, Copy)]
pub struct Placement<'a> {
    /// API scope owning the service, pipeline and route being created.
    pub tenant: &'a TenantPath,
    /// The app's address, such as `http://127.0.0.1:4000`.
    pub upstream: &'a str,
    /// A host of the tenant the route answers on.
    pub host: &'a str,
}

/// The ids of what a [`RouteSpec`] made.
#[derive(Debug, Clone)]
pub struct AppliedRoute {
    /// Handle for the backend destination created with the route.
    pub service_id: String,
    /// Handle for the processing stages activated for this route.
    pub pipeline_id: String,
    /// Handle for the host and path mapping served by the gateway.
    pub route_id: String,
}

impl RouteSpec {
    /// A route named `name` for every method at `path_pattern`, such as
    /// `/orders/*`, open to anyone, its service taking no token.
    #[must_use]
    pub fn public(name: &str, path_pattern: &str) -> Self {
        Self {
            name: name.to_owned(),
            path_pattern: path_pattern.to_owned(),
            methods: Vec::new(),
            policy: RoutePolicy::Public,
            audience: TokenAudience::NoTokenAccepted,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            hosts: Vec::new(),
            stages: Vec::new(),
        }
    }

    /// The same route asking `policy` of a caller.
    #[must_use]
    pub fn asking(mut self, policy: RoutePolicy) -> Self {
        self.policy = policy;
        self
    }

    /// The same route, its service taking tokens issued for `audience`.
    #[must_use]
    pub fn pinned(mut self, audience: &str) -> Self {
        self.audience = TokenAudience::Pinned(audience.to_owned());
        self
    }

    /// The same route, its backend given `seconds` to answer.
    #[must_use]
    pub fn timing_out_after(mut self, seconds: u32) -> Self {
        self.timeout_secs = seconds;
        self
    }

    /// The same route answering only on `hosts`.
    #[must_use]
    pub fn on_hosts(mut self, hosts: &[String]) -> Self {
        self.hosts = hosts.to_vec();
        self
    }

    /// The same route with a stage of `kind`, as the API writes one, such
    /// as `{"RateLimit": {...}}`, added after the mandatory ones.
    #[must_use]
    pub fn with_stage(mut self, kind: Value) -> Self {
        self.stages.push(kind);
        self
    }

    /// A path the route answers, for asking after it: its pattern with any
    /// final `*` filled in.
    #[must_use]
    pub fn a_path(&self) -> String {
        self.path_pattern.replace('*', "probe")
    }

    /// Makes the route where `placement` says, as `admin`, then waits until
    /// the gateway serves it, asked by `probe`, a client with no
    /// credential.
    ///
    /// # Panics
    ///
    /// When any part is refused, or the gateway does not serve the route
    /// within [`eventually`]'s patience.
    pub async fn applied(
        &self,
        admin: &Client,
        probe: &Client,
        placement: Placement<'_>,
    ) -> AppliedRoute {
        let applied = self.made(admin, placement.tenant, placement.upstream).await;
        wait_until_serving(probe, placement.host, &self.a_path()).await;
        applied
    }

    /// Makes the service, the pipeline with its stages and the route, then
    /// activates the pipeline.
    async fn made(&self, admin: &Client, tenant: &TenantPath, upstream: &str) -> AppliedRoute {
        let service_id = self.make_service(admin, tenant, upstream).await;
        let pipeline_id = self.make_pipeline(admin, tenant).await;
        let route = NewRoute {
            name: self.name.clone(),
            path_pattern: self.path_pattern.clone(),
            methods: self.methods.clone(),
            service_id: service_id.clone(),
            policy: self.policy.clone(),
            pipeline_id: pipeline_id.clone(),
            hosts: self.hosts.clone(),
        };
        let route_id = routing::create_route(tenant, &route)
            .send(admin)
            .await
            .ok()
            .id;
        routing::activate_pipeline(tenant, &pipeline_id)
            .send(admin)
            .await
            .ok();
        AppliedRoute {
            service_id,
            pipeline_id,
            route_id,
        }
    }

    /// Creates the service destination with this route's timeout and token policy.
    async fn make_service(&self, admin: &Client, tenant: &TenantPath, upstream: &str) -> String {
        let service = NewService {
            name: format!("{}-service", self.name),
            upstream: Upstream::at(upstream, self.timeout_secs, self.audience.clone()),
        };
        routing::create_service(tenant, &service)
            .send(admin)
            .await
            .ok()
            .id
    }

    /// Creates the pipeline and appends the configured stages in their original order.
    async fn make_pipeline(&self, admin: &Client, tenant: &TenantPath) -> String {
        let pipeline = NewPipeline {
            name: format!("{}-pipeline", self.name),
        };
        let pipeline_id = routing::create_pipeline(tenant, &pipeline)
            .send(admin)
            .await
            .ok()
            .id;
        for kind in &self.stages {
            let stage = NewStage { kind: kind.clone() };
            routing::add_stage(tenant, &pipeline_id, &stage)
                .send(admin)
                .await
                .ok();
        }
        pipeline_id
    }
}

/// A visit to `path` on `host` through the gateway, its answer read as
/// what the echo app behind the route saw arrive.
#[must_use]
pub fn visit(host: &str, path: &str) -> Request<Arrival> {
    Request::of(Call::get(format!("https://{host}{path}")))
}

/// Waits until the gateway serves `path` on `host`: it answers anything
/// but that it serves nothing there or is not ready. A temporary `Status::SERVICE_UNAVAILABLE` is
/// still convergence, not proof that the route is ready for assertions.
/// A handshake refused counts as not yet: the gateway serves no name it
/// holds no certificate for.
///
/// # Panics
///
/// When it does not within [`eventually`]'s patience.
pub(crate) async fn wait_until_serving(client: &Client, host: &str, path: &str) {
    let url = format!("https://{host}{path}");
    let what = format!("the gateway to serve {url}");
    eventually(&what, || async {
        let answer = client
            .attempt::<serde::de::IgnoredAny>(Call::get(url.as_str()))
            .await
            .ok()?;
        (!matches!(answer.status(), NOT_SERVED | NOT_READY)).then_some(())
    })
    .await;
}
