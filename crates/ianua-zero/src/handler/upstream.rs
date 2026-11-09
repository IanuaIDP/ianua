//! What an upstream is sent once the pipeline let a request through: its
//! headers without the caller's credentials, changed as the stages said,
//! with what the gateway vouches for (the client, the trace, the signed
//! identity), and where it goes.
//!
//! Identity reaches an upstream signed or not at all: a request whose
//! caller is known is forwarded only with its assertion, and an assertion
//! that cannot be signed refuses the request.

use std::sync::Arc;

use http::header::{HOST, HeaderName, HeaderValue};
use http::request::Parts;
use http::{HeaderMap, Request, Uri};
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use ianua_app::error::AppError;
use ianua_app::ports::pages::ErrorPageKind;
use ianua_app::tenancy::ScopedTenant;
use ianua_app::use_case::Query as _;
use ianua_app::use_cases::agents::enforcement::AgentAuthorityRequest;
use ianua_app::use_cases::proxy::ConnectionHolder;
use ianua_domain::domains::proxy::assertion::UpstreamAssertion;
use ianua_domain::domains::proxy::observation::GatewayCheck;
use ianua_domain::domains::proxy::request::context::{Authentication, Caller, PipelineContext};
use ianua_domain::domains::proxy::request::forwarded::{ClientScheme, forwarded_headers};
use ianua_domain::domains::proxy::request::transform::RequestMutation;
use ianua_domain::domains::proxy::stages::decision::HeaderEntry;
use ianua_domain::domains::routing::backend::upstream::StickySession;
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::Expiry;

use super::arrival::{Arrival, TRACEPARENT};
use super::{GatewayParts, Refused};
use crate::forward::{
    AffinityKey, AgentTunnelAuthority, BoxError, ForwardTarget, HolderTunnelAuthority, RequestBody,
    ResponseInspection, ResponseSpan, ServicePool, TunnelAuthority, UncheckableTunnel,
    UpgradeTerms, asks_to_switch,
};
use crate::observability::TunnelCloseRecord;
use crate::pipeline::executor::RequestRun;
use crate::request::{self, PrefixThenBody, Scheme};
use crate::resolve::MatchedRoute;

/// The header the signed identity travels in.
pub(crate) const ASSERTION_HEADER: &str = "x-ianua-assertion";

/// The header the request's reference travels in, for the upstream's logs.
const CORRELATION_HEADER: &str = "x-ianua-correlation-id";

/// What forwarding one request starts from.
pub(super) struct Outbound<'a> {
    /// The gateway's parts.
    pub(super) gateway: &'a GatewayParts,
    /// How the request arrived.
    pub(super) arrival: &'a Arrival,
    /// The tenant it resolved to.
    pub(super) tenant: ScopedTenant,
    /// The host the client addressed, without a port.
    pub(super) host: &'a str,
    /// The route it matched.
    pub(super) matched: &'a MatchedRoute,
    /// The context the pipeline left.
    pub(super) ctx: &'a PipelineContext,
    /// The request's run, holding what a person's open connection is
    /// asked again.
    pub(super) run: &'a RequestRun,
    /// Where a tunnel this request opens records a close for access.
    pub(super) closing: TunnelCloseRecord,
}

/// The request as its upstream is sent it, and where it goes.
pub(super) struct Prepared {
    /// The outbound HTTP message after route and pipeline transformations.
    pub(super) request: Request<RequestBody>,
    /// Where it goes and what holds it.
    pub(super) target: ForwardTarget,
}

impl Outbound<'_> {
    /// The request made of `parts` and `body`, signed and changed as the
    /// stages said, and its target.
    ///
    /// # Errors
    ///
    /// A `503` when the caller's identity cannot be signed or the service
    /// has no pool, and a `400` when the changed query is no URI.
    pub(super) async fn prepared(
        &self,
        mut parts: Parts,
        body: PrefixThenBody<Incoming>,
        response_stages: ResponseInspection,
    ) -> Result<Prepared, Refused> {
        let client_host = parts.headers.get(HOST).cloned();
        let assertion = self.assertion().await?;
        request::strip_credentials(&mut parts.headers);
        apply(&self.ctx.request_mutation, &mut parts)?;
        self.vouch(&mut parts.headers, assertion)?;
        let target = self.target(&parts.headers, client_host, response_stages)?;
        let body = body
            .map_err(|error| -> BoxError { Box::new(error) })
            .boxed();
        Ok(Prepared {
            request: Request::from_parts(parts, body),
            target,
        })
    }

    /// The caller's identity signed for the service, or `None` for a
    /// request nobody was proven to send.
    ///
    /// # Errors
    ///
    /// A `503` when it cannot be made or signed in time.
    async fn assertion(&self) -> Result<Option<HeaderValue>, Refused> {
        let service = *self.matched.service_id();
        let made = UpstreamAssertion::for_request(self.ctx, service, clock::now())
            .map_err(|_| unsigned("assertion_unmade"))?;
        let Some(assertion) = made else {
            return Ok(None);
        };
        let signing = self.gateway.sign_assertion.execute(&self.tenant, assertion);
        let signed = tokio::time::timeout(self.gateway.bounds.call, signing).await;
        assertion_header(signed).map(Some)
    }

    /// Sets what the gateway vouches for: the client it saw, the trace it
    /// joined, the request's reference and the signed identity.
    ///
    /// # Errors
    ///
    /// A `400` when the host the client sent cannot be written in a
    /// forwarding header.
    fn vouch(
        &self,
        headers: &mut HeaderMap,
        assertion: Option<HeaderValue>,
    ) -> Result<(), Refused> {
        let scheme = match self.gateway.scheme {
            Scheme::Https => ClientScheme::Https,
            Scheme::Http => ClientScheme::Http,
        };
        let forwarded = forwarded_headers(self.arrival.client, scheme, self.host)
            .map_err(|_| unforwardable("host_unwritable"))?;
        set_all(headers, &forwarded);
        insert(headers, TRACEPARENT, &self.arrival.trace.to_header());
        insert(
            headers,
            CORRELATION_HEADER,
            &self.arrival.correlation_id.to_string(),
        );
        if let Some(assertion) = assertion {
            headers.insert(HeaderName::from_static(ASSERTION_HEADER), assertion);
        }
        Ok(())
    }

    /// Where the request goes: the service's pool, the route's path, and
    /// what holds the answer and any tunnel it opens.
    ///
    /// # Errors
    ///
    /// The refusal of a service that has no pool.
    fn target(
        &self,
        headers: &HeaderMap,
        client_host: Option<HeaderValue>,
        inspection: ResponseInspection,
    ) -> Result<ForwardTarget, Refused> {
        let pipeline = self.matched.pipeline();
        let pool = self
            .gateway
            .pools
            .pool(*self.tenant, self.matched.service_id())
            .map_err(|error| {
                tracing::warn!(%error, "a request's service has no pool; refusing");
                Refused::at_gateway(
                    ErrorPageKind::Unavailable,
                    GatewayCheck::Upstream,
                    "no_pool",
                )
            })?;
        Ok(ForwardTarget {
            affinity: affinity(self, headers, &pool),
            pool,
            path: self.matched.forwarding_path().as_str().to_owned(),
            body_limit: pipeline.body_limit(self.gateway.bounds.bodies.default_limit),
            client_host,
            inspection,
            span: ResponseSpan::Bounded,
            upgrade: UpgradeTerms {
                rule: pipeline.upgrade(self.ctx),
                expiry: expiry_of(self.ctx.authentication()),
                authority: self.tunnel_authority(headers),
                correlation_id: self.arrival.correlation_id,
                closing: self.closing.clone(),
            },
        })
    }

    /// What a tunnel this request opens is held to, if it asks to open
    /// one: an agent's authority, or a person's or consumer's standing,
    /// asked again while it stays open.
    fn tunnel_authority(&self, headers: &HeaderMap) -> Option<Arc<dyn TunnelAuthority>> {
        if !asks_to_switch(headers) {
            return None;
        }
        match self.ctx.authentication().caller()? {
            Caller::Agent {
                agent_id,
                delegation_id,
                ..
            } => Some(Arc::new(AgentTunnelAuthority::new(
                Arc::clone(&self.gateway.agent_authority),
                self.tenant,
                AgentAuthorityRequest {
                    agent_id: *agent_id,
                    delegation_id: *delegation_id,
                },
            ))),
            Caller::User { user_id, .. } => {
                Some(self.holder_authority(ConnectionHolder::Person(*user_id)))
            }
            Caller::Consumer { consumer_id, .. } => {
                Some(self.holder_authority(ConnectionHolder::Consumer(*consumer_id)))
            }
        }
    }

    /// What a person's or consumer's tunnel is held to: their standing asked
    /// again, or, when the handshake's credential cannot be read twice, a
    /// check that fails at once.
    fn holder_authority(&self, holder: ConnectionHolder) -> Arc<dyn TunnelAuthority> {
        let Some(request) = self.run.connection_recheck(holder, self.ctx) else {
            return Arc::new(UncheckableTunnel);
        };
        Arc::new(HolderTunnelAuthority::new(
            Arc::clone(&self.gateway.recheck_connection),
            self.tenant,
            request,
        ))
    }
}

/// The changes the stages asked for: headers removed and set, the query
/// rewritten.
///
/// # Errors
///
/// A `400` when the rewritten query makes no URI.
fn apply(mutation: &RequestMutation, parts: &mut Parts) -> Result<(), Refused> {
    for name in mutation.remove_headers() {
        parts.headers.remove(name.as_str());
    }
    set_all(&mut parts.headers, mutation.headers_to_set());
    let query = mutation.apply_to_query(parts.uri.query());
    let target = match query {
        Some(query) => format!("{}?{query}", parts.uri.path()),
        None => parts.uri.path().to_owned(),
    };
    parts.uri = target
        .parse::<Uri>()
        .map_err(|_| unforwardable("query_unwritable"))?;
    Ok(())
}

/// Sets every one of `entries`, replacing what was there.
fn set_all(headers: &mut HeaderMap, entries: &[HeaderEntry]) {
    for entry in entries {
        insert(headers, entry.name().as_str(), entry.value().as_str());
    }
}

/// Sets `name` to `value`, dropping a pair that is no header.
fn insert(headers: &mut HeaderMap, name: &str, value: &str) {
    let (Ok(name), Ok(value)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) else {
        return;
    };
    headers.insert(name, value);
}

/// When the caller's credential stops being valid: a tunnel closes then at
/// the latest. A tunnel on a public route has no credential to outlive and
/// is held to the tunnels' lifetime and idle limits alone.
fn expiry_of(authentication: &Authentication) -> Expiry {
    match authentication {
        Authentication::Authenticated(verified) => verified.expiry,
        Authentication::Anonymous => Expiry::Never,
    }
}

/// What pins the request to one backend, as the service's sticky sessions
/// say.
fn affinity(
    outbound: &Outbound<'_>,
    headers: &HeaderMap,
    pool: &ServicePool,
) -> Option<AffinityKey> {
    let caller = outbound.ctx.authentication().caller();
    match pool.sticky_session()? {
        StickySession::UserId => match caller? {
            Caller::User { user_id, .. } => Some(AffinityKey::new(user_id.to_string())),
            Caller::Agent { agent_id, .. } => Some(AffinityKey::new(agent_id.to_string())),
            Caller::Consumer { .. } => None,
        },
        StickySession::ConsumerId => match caller? {
            Caller::Consumer { consumer_id, .. } => Some(AffinityKey::new(consumer_id.to_string())),
            Caller::User { .. } | Caller::Agent { .. } => None,
        },
        StickySession::Cookie(name) => match request::read_cookie(headers, name.as_str()) {
            request::CookieRead::One(value) => Some(AffinityKey::new(value)),
            request::CookieRead::Absent | request::CookieRead::Ambiguous => None,
        },
        StickySession::Header(name) => headers
            .get(name.as_str())
            .and_then(|value| value.to_str().ok())
            .map(AffinityKey::new),
        StickySession::SourceIp => Some(AffinityKey::new(outbound.arrival.client.to_string())),
    }
}

/// The refusal of a request whose identity could not be signed.
/// The header the signed assertion travels in, marked sensitive, or a
/// `503` when the tenant has no key to sign with, the signing failed or
/// it ran out of time: identity never reaches an upstream unsigned.
pub(super) fn assertion_header(
    signed: Result<Result<Secret, AppError>, tokio::time::error::Elapsed>,
) -> Result<HeaderValue, Refused> {
    let signed = signed
        .map_err(|_| unsigned("assertion_timed_out"))?
        .map_err(|_| unsigned("assertion_unsigned"))?;
    let mut value =
        HeaderValue::from_str(signed.expose()).map_err(|_| unsigned("assertion_unsigned"))?;
    value.set_sensitive(true);
    Ok(value)
}

fn unsigned(reason: &'static str) -> Refused {
    tracing::warn!(
        reason,
        "the caller's identity could not be signed; refusing"
    );
    Refused::at_gateway(ErrorPageKind::Unavailable, GatewayCheck::Upstream, reason)
}

/// The refusal of a request that cannot be written for its upstream.
fn unforwardable(reason: &'static str) -> Refused {
    Refused::at_gateway(ErrorPageKind::BadRequest, GatewayCheck::Route, reason)
}

#[cfg(test)]
mod tests {
    use http::Request as HttpRequest;

    use super::*;

    /// A header a stage sets replaces what the client sent under its name,
    /// and the client's path and query are kept.
    #[test]
    fn a_header_a_stage_sets_replaces_the_clients() {
        let (mut parts, ()) = HttpRequest::get("/orders?page=2")
            .header("x-signature", "forged")
            .body(())
            .unwrap()
            .into_parts();
        let mutation = RequestMutation::asserting(vec![HeaderEntry::new(
            ianua_domain::types::HeaderName::new("x-signature").unwrap(),
            ianua_domain::types::HeaderValue::new("signed").unwrap(),
        )]);

        apply(&mutation, &mut parts).unwrap();

        assert_eq!(parts.uri.to_string(), "/orders?page=2");
        assert_eq!(parts.headers["x-signature"], "signed");
    }

    /// A tunnel on a public route has no credential to outlive.
    #[test]
    fn a_public_routes_tunnel_has_no_credential_to_outlive() {
        assert_eq!(expiry_of(&Authentication::Anonymous), Expiry::Never);
    }
}
