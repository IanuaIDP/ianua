//! The steps before a route's pipeline: admitting the request, holding its
//! host to its connection, resolving the tenant, answering what the
//! gateway answers itself on a tenant's hosts, and finding the route.
//!
//! Each step answers a refusal the gateway made itself, recorded under the
//! check that made it.

use std::sync::Arc;

use http::request::Parts;
use hyper::body::Incoming;
use ianua_app::ports::authentication::{AppSignInBroker, PassReach, RunPassToken, TokenReading};
use ianua_app::ports::pages::ErrorPageKind;
use ianua_app::ports::runtime::FleetCounters;
use ianua_app::tenancy::ScopedTenant;
use ianua_app::use_case::Query as _;
use ianua_app::use_cases::proxy::credentials::Presented;
use ianua_domain::domains::proxy::observation::GatewayCheck;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DenialStatus, RouteId};
use tokio::time::error::Elapsed;

use super::{GatewayBody, GatewayParts, Refused, whole};
use crate::app_sign_in::{self, Addressed, Arrived, Gate, HopArrived, Inbound};
use crate::listen::{ConnectionFacts, HostCheck};
use crate::request::{self, Admitted, RequestHeaders, RequestRefusal};
use crate::resolve::{
    HostResolution, MatchedRoute, RouteLookup, RouteQuery, RouteRefusal, Routing, TenantTable,
};
use crate::respond::key_set::{KEY_SET_PATH, key_set};

/// What a request on a tenant's host is, past the gateway's own answers.
pub(super) enum OnHost {
    /// The gateway answered it itself.
    Answered(hyper::Response<GatewayBody>),
    /// It is for the tenant's app; its body is handed back untouched.
    App(Incoming),
}

/// The tenant a request was sent to, with its table.
pub(super) struct Resolved {
    /// The tenant, scoped to the request's host, or named by a run pass
    /// that checked out under its keys.
    pub(super) tenant: ScopedTenant,
    /// Its table, as this request's version of the routing holds it.
    pub(super) table: Arc<TenantTable>,
    /// How the request's route is found.
    pub(super) reach: Reach,
}

/// How a request's route is found.
#[derive(Debug, Clone, Copy)]
pub(super) enum Reach {
    /// By its host, method, conditions and path, on the public and runner
    /// listeners.
    ByHost,
    /// The route a checked run pass names, on the workflow listener.
    Named(RouteId),
}

/// The request admitted, its host held to the connection it came on.
///
/// # Errors
///
/// A `400` for a request whose host, method or path cannot be read one way
/// only, and a `421` for a host the connection was not opened for.
pub(super) fn admitted(
    parts: &mut Parts,
    connection: &ConnectionFacts,
) -> Result<Admitted, Refused> {
    let admitted = request::admit(parts).map_err(unreadable)?;
    match connection.host_check(admitted.host().as_str()) {
        HostCheck::Matches => Ok(admitted),
        HostCheck::Misdirected => Err(Refused::at_gateway(
            ErrorPageKind::Misdirected,
            GatewayCheck::Tenant,
            "misdirected_host",
        )),
    }
}

/// The tenant `admitted`'s host belongs to, in `routing`.
///
/// # Errors
///
/// A `404` for a host no tenant answers on, or one two tenants claim.
pub(super) fn tenant(routing: &Routing, admitted: &Admitted) -> Result<Resolved, Refused> {
    let tenant = match routing.tenant_for(admitted.host()) {
        HostResolution::Tenant(tenant) => tenant,
        HostResolution::Unknown => return Err(unknown_host("unknown_host")),
        HostResolution::Ambiguous => return Err(unknown_host("contested_host")),
    };
    let Some(table) = routing.shared_tenant(&tenant) else {
        return Err(unknown_host("tenant_not_served"));
    };
    Ok(Resolved {
        tenant,
        table,
        reach: Reach::ByHost,
    })
}

/// The tenant and route the run pass in `parts` names, once it checks out
/// under that tenant's keys and issuer, so nothing of a tenant runs for a
/// pass it did not sign.
///
/// # Errors
///
/// A `401` for a request with no readable pass, one naming a tenant not
/// served, one that does not check out, or one that cannot be checked in
/// time.
pub(super) async fn by_pass(
    gateway: &GatewayParts,
    routing: &Routing,
    parts: &Parts,
) -> Result<Resolved, Refused> {
    let Ok(Presented::RunPass(pass)) = request::run_pass(&parts.headers) else {
        return Err(no_pass("no_run_pass"));
    };
    let Some(claimed) = gateway.passes.claimed_pass(&pass) else {
        return Err(no_pass("unreadable_run_pass"));
    };
    let tenant = ScopedTenant::from_verified_credential(claimed.tenant_id);
    let Some(table) = routing.shared_tenant(&tenant) else {
        tracing::info!(tenant = %claimed.tenant_id, "a run pass names a tenant not served");
        return Err(no_pass("run_pass_tenant_not_served"));
    };
    let reading = gateway.passes.read_run_pass(&tenant, &pass, table.issuer());
    let checked = pass_checked(tokio::time::timeout(gateway.bounds.call, reading).await)?;
    let PassReach::Route(route_id) = checked.reaches else {
        return Err(no_pass("run_pass_for_a_stream_route"));
    };
    Ok(Resolved {
        tenant,
        table,
        reach: Reach::Named(route_id),
    })
}

/// The route the run pass named, when it takes `admitted`'s method and
/// path, in `table`.
///
/// # Errors
///
/// A `404` when the named route is not served or does not take the
/// request, and the refusal of one that cannot run safely.
pub(super) fn named_route(
    table: &TenantTable,
    route_id: &RouteId,
    admitted: &Admitted,
    parts: &Parts,
) -> Result<MatchedRoute, Refused> {
    let values = RequestHeaders::new(&parts.headers);
    let query = RouteQuery {
        host: admitted.host(),
        method: admitted.method(),
        path: admitted.path(),
        values: &values,
    };
    looked_up(table, table.routes().find_named(route_id, &query))
}

/// The refusal of a request on the workflow listener whose pass does not
/// open anything, recorded under `reason`.
/// What reading a run pass came to: the pass, a `401` for one that was
/// read and refused, or a `503` for one that could not be checked, as when
/// the tenant's keys did not answer in time. Nothing gets through
/// unchecked; the `503` tells the run to try again rather than fail as if
/// its pass were bad.
///
/// # Errors
///
/// The refusal of a pass refused or not checked.
pub(super) fn pass_checked(
    read: Result<Result<TokenReading<RunPassToken>, DomainError>, Elapsed>,
) -> Result<RunPassToken, Refused> {
    match read {
        Ok(Ok(TokenReading::Read(checked))) => Ok(checked),
        Ok(Ok(TokenReading::Refused(fault))) => {
            tracing::info!(?fault, "a run pass was refused");
            Err(no_pass("run_pass_refused"))
        }
        Ok(Err(error)) => {
            tracing::warn!(%error, "a run pass could not be checked");
            Err(pass_unchecked())
        }
        Err(_) => {
            tracing::warn!("a run pass was not checked in time");
            Err(pass_unchecked())
        }
    }
}

/// The refusal of a run pass that could not be checked.
fn pass_unchecked() -> Refused {
    Refused::at_gateway(
        ErrorPageKind::Unavailable,
        GatewayCheck::Tenant,
        "run_pass_unchecked",
    )
}

fn no_pass(reason: &'static str) -> Refused {
    Refused::at_gateway(ErrorPageKind::NotSignedIn, GatewayCheck::Tenant, reason)
}

/// Answers what the gateway answers itself on a tenant's host: its
/// published assertion keys, its app sign-in addresses and the hops of its
/// services' own cookies. Anything else is the app's, its body handed back.
///
/// # Errors
///
/// The refusal of a sign-in address that refused the request, or of a
/// sign-in the gateway has no API to relay to.
pub(super) async fn on_host(
    gateway: &GatewayParts,
    resolved: &Resolved,
    here: &Here<'_>,
    body: Incoming,
) -> Result<OnHost, Refused> {
    let branding = resolved.table.branding();
    if here.parts.uri.path() == KEY_SET_PATH {
        return published_keys(gateway, &resolved.tenant)
            .await
            .map(OnHost::Answered)
            .map_err(|refused| refused.wearing(branding));
    }
    let request = HostRequest {
        gateway,
        resolved,
        here,
    };
    let sign_in = resolved.table.sign_in();
    if let Some(host) = sign_in.on_host(here.admitted.host()) {
        return request
            .sign_in_address(host, body)
            .await
            .map_err(|refused| refused.wearing(branding));
    }
    request.cookie_hop(body).await
}

/// The gateway and resolved host needed to answer a sign-in or cookie hop.
struct HostRequest<'a, 'b> {
    gateway: &'a GatewayParts,
    resolved: &'a Resolved,
    here: &'a Here<'b>,
}

impl HostRequest<'_, '_> {
    /// Answers only a configured cookie-hop path, leaving other bodies untouched.
    async fn cookie_hop(&self, body: Incoming) -> Result<OnHost, Refused> {
        let Self {
            gateway,
            resolved,
            here,
        } = self;
        let branding = resolved.table.branding();
        let sign_in = resolved.table.sign_in();
        let Some(cookie) = sign_in.cookie_host(here.admitted.host()) else {
            return Ok(OnHost::App(body));
        };
        if here.parts.uri.path() != cookie.hop_path().as_str() {
            return Ok(OnHost::App(body));
        }
        let gate = gate(gateway.sign_in.as_deref(), gateway.counters.as_ref())
            .map_err(|refused| refused.wearing(branding))?;
        let arrived = HopArrived {
            inbound: here.inbound(resolved, *cookie.service()),
            onward_origins: cookie.onward_origins(),
            owner_origins: cookie.owner_origins(),
        };
        Ok(OnHost::Answered(whole(
            app_sign_in::hop(&gate, &arrived).await,
        )))
    }
}

/// The route `admitted` takes in `table`.
///
/// # Errors
///
/// A `404` when no route takes it, and the refusal of a route that takes
/// it but cannot run safely.
pub(super) fn route(
    table: &TenantTable,
    admitted: &Admitted,
    parts: &Parts,
) -> Result<MatchedRoute, Refused> {
    let values = RequestHeaders::new(&parts.headers);
    let query = RouteQuery {
        host: admitted.host(),
        method: admitted.method(),
        path: admitted.path(),
        values: &values,
    };
    looked_up(table, table.routes().find(&query))
}

/// The route `lookup` found in `table`, or its refusal, wearing the
/// tenant's look.
fn looked_up(table: &TenantTable, lookup: RouteLookup) -> Result<MatchedRoute, Refused> {
    let refused = match lookup {
        RouteLookup::Found(matched) => return Ok(matched),
        RouteLookup::NotFound => {
            Refused::at_gateway(ErrorPageKind::NotFound, GatewayCheck::Route, "no_route")
        }
        RouteLookup::Refused { why, .. } => refused_route(why),
    };
    Err(refused.wearing(table.branding()))
}

/// Where a request on a tenant's host was sent and who sent it.
pub(super) struct Here<'a> {
    /// The request's head.
    pub(super) parts: &'a Parts,
    /// Its host, method and path.
    pub(super) admitted: &'a Admitted,
    /// The client, as the gateway established it.
    pub(super) client: std::net::IpAddr,
}

impl Here<'_> {
    /// The request, as the sign-in answers take it, for `service`.
    fn inbound(&self, resolved: &Resolved, service: ianua_domain::types::ServiceId) -> Inbound<'_> {
        Inbound {
            tenant: *resolved.tenant,
            service,
            host: self.admitted.host().name(),
            parts: self.parts,
            client_ip: self.client,
        }
    }
}

impl HostRequest<'_, '_> {
    /// Answers configured sign-in addresses and leaves app requests untouched.
    async fn sign_in_address(
        &self,
        host: &crate::resolve::SignInHost,
        body: Incoming,
    ) -> Result<OnHost, Refused> {
        let Self {
            gateway,
            resolved,
            here,
        } = self;
        let sign_in = host.sign_in();
        let asked = match app_sign_in::addressed(sign_in, &here.parts.method, here.parts.uri.path())
        {
            Addressed::App => return Ok(OnHost::App(body)),
            Addressed::Refused(status) => return Err(sign_in_refused(status)),
            Addressed::SignIn(asked) => asked,
        };
        let gate = gate(gateway.sign_in.as_deref(), gateway.counters.as_ref())?;
        let arrived = Arrived {
            inbound: here.inbound(resolved, *host.owner()),
            sign_in,
            asked,
        };
        Ok(OnHost::Answered(whole(
            app_sign_in::answer(&gate, &arrived, body).await,
        )))
    }
}

/// What app sign-in is answered through: the `broker` relaying it to the
/// API and the `counters` holding its limits, or a `503` when the gateway
/// was given no address of the API to relay it to.
pub(super) fn gate<'a>(
    broker: Option<&'a dyn AppSignInBroker>,
    counters: &'a dyn FleetCounters,
) -> Result<Gate<'a>, Refused> {
    let Some(broker) = broker else {
        return Err(Refused::at_gateway(
            ErrorPageKind::Unavailable,
            GatewayCheck::AppSignIn,
            "sign_in_not_relayed",
        ));
    };
    Ok(Gate { broker, counters })
}

/// The tenant's published assertion keys.
///
/// # Errors
///
/// A `404` when the tenant has no assertion keys yet, and a `503` when
/// they cannot be read in time.
async fn published_keys(
    gateway: &GatewayParts,
    tenant: &ScopedTenant,
) -> Result<hyper::Response<GatewayBody>, Refused> {
    let listed = tokio::time::timeout(
        gateway.bounds.call,
        gateway.published_keys.execute(tenant, ()),
    )
    .await;
    match listed {
        Ok(Ok(keys)) => Ok(whole(key_set(keys))),
        Ok(Err(ianua_app::error::AppError::NotFound(_))) => Err(Refused::at_gateway(
            ErrorPageKind::NotFound,
            GatewayCheck::Route,
            "no_assertion_keys",
        )),
        Ok(Err(_)) | Err(_) => Err(Refused::at_gateway(
            ErrorPageKind::Unavailable,
            GatewayCheck::Upstream,
            "assertion_keys_unread",
        )),
    }
}

/// The refusal of a request that cannot be read one way only.
fn unreadable(why: RequestRefusal) -> Refused {
    let reason = match why {
        RequestRefusal::Host(_) => "host_unreadable",
        RequestRefusal::Method => "method_unknown",
        RequestRefusal::Path => "path_unreadable",
    };
    Refused::at_gateway(ErrorPageKind::BadRequest, GatewayCheck::Tenant, reason)
}

/// The refusal of a host no single tenant answers on.
fn unknown_host(reason: &'static str) -> Refused {
    Refused::at_gateway(ErrorPageKind::NotFound, GatewayCheck::Tenant, reason)
}

/// The refusal of a route that takes the request but cannot run safely.
fn refused_route(why: RouteRefusal) -> Refused {
    match why {
        RouteRefusal::PipelineMissing => Refused::at_gateway(
            ErrorPageKind::Unavailable,
            GatewayCheck::PipelineOff,
            "pipeline_missing",
        ),
        RouteRefusal::PipelineInactive => Refused::at_gateway(
            ErrorPageKind::Unavailable,
            GatewayCheck::PipelineOff,
            "pipeline_inactive",
        ),
        RouteRefusal::CertificatesUnverifiable => Refused::at_gateway(
            ErrorPageKind::Forbidden,
            GatewayCheck::Route,
            "client_certificates_unverifiable",
        ),
        RouteRefusal::Unforwardable => Refused::at_gateway(
            ErrorPageKind::NotFound,
            GatewayCheck::Route,
            "path_unforwardable",
        ),
    }
}

/// The refusal of a sign-in address that takes no request like this one.
fn sign_in_refused(status: http::StatusCode) -> Refused {
    let refused = Refused::at_gateway(
        ErrorPageKind::NotFound,
        GatewayCheck::AppSignIn,
        "sign_in_address_refused",
    );
    match DenialStatus::new(status.as_u16()) {
        Ok(status) => refused.answered_with(status),
        Err(_) => refused,
    }
}
