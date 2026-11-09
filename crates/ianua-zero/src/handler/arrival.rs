//! What the gateway knows of a request before it reads anything else: its
//! reference, the client it came from and the trace it is part of.
//!
//! All three are read before the request is admitted, since admitting it
//! strips the forwarding headers a trusted proxy in front of the gateway
//! wrote; the client is believed from them only for such a proxy.

use std::net::IpAddr;

use http::request::Parts;
use ianua_domain::domains::proxy::request::forwarded::{TrustedProxies, client_address};
use ianua_domain::domains::proxy::request::trace::{Sampling, SpanId, TraceContext, TraceId};
use ianua_domain::types::CorrelationId;

use crate::listen::ConnectionFacts;
use crate::observability;

/// The header a trace context arrives and leaves in.
pub(crate) const TRACEPARENT: &str = "traceparent";

/// The header that names the client to the proxy in front.
const FORWARDED_FOR: &str = "x-forwarded-for";

/// A request as it arrived.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Arrival {
    /// The reference its logs, records and error pages share.
    pub(crate) correlation_id: CorrelationId,
    /// The client, as the connection and a trusted proxy name it.
    pub(crate) client: IpAddr,
    /// The gateway's own span, in the caller's trace or a fresh one.
    pub(crate) trace: TraceContext,
}

impl Arrival {
    /// What `parts`, which came on `connection`, say of the request, the
    /// client's address believed from `trusted` proxies only.
    pub(crate) fn read(
        parts: &Parts,
        connection: &ConnectionFacts,
        trusted: &TrustedProxies,
    ) -> Self {
        let forwarded_for = forwarded_for(parts);
        Self {
            correlation_id: CorrelationId::new(),
            client: client_address(connection.client().ip(), forwarded_for.as_deref(), trusted),
            trace: trace_of(parts),
        }
    }

    /// The request as its record starts.
    pub(crate) fn recorded<'a>(&self, parts: &'a Parts) -> observability::Arrival<'a> {
        observability::Arrival {
            correlation_id: self.correlation_id,
            client: self.client,
            method: parts.method.as_str(),
            target: parts
                .uri
                .path_and_query()
                .map_or("/", http::uri::PathAndQuery::as_str),
        }
    }
}

/// Every `X-Forwarded-For` the request carries, joined in order, or `None`
/// when it carries none or one that is not text.
fn forwarded_for(parts: &Parts) -> Option<String> {
    let values: Option<Vec<&str>> = parts
        .headers
        .get_all(FORWARDED_FOR)
        .iter()
        .map(|value| value.to_str().ok())
        .collect();
    let values = values?;
    if values.is_empty() {
        return None;
    }
    Some(values.join(","))
}

/// The gateway's span: a child of the caller's trace when it sent one
/// that reads, else the root of a fresh, sampled trace.
fn trace_of(parts: &Parts) -> TraceContext {
    let sent = parts
        .headers
        .get(TRACEPARENT)
        .and_then(|value| value.to_str().ok())
        .and_then(TraceContext::parse);
    match sent {
        Some(caller) => caller.child(fresh_span()),
        None => TraceContext::new(fresh_trace(), fresh_span(), Sampling::Sampled),
    }
}

/// A random span id; all zeroes, which no span may be, is drawn again.
fn fresh_span() -> SpanId {
    loop {
        if let Some(span) = SpanId::new(rand::random()) {
            return span;
        }
    }
}

/// A random trace id; all zeroes, which no trace may be, is drawn again.
fn fresh_trace() -> TraceId {
    loop {
        if let Some(trace) = TraceId::new(rand::random()) {
            return trace;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use http::Request;
    use ianua_domain::domains::proxy::request::forwarded::ClientScheme;
    use ianua_domain::types::Fact;

    use super::*;
    use crate::listen::{ClientCertificate, ConnectionParts};

    fn connection(peer: &str) -> ConnectionFacts {
        let peer: SocketAddr = peer.parse().unwrap();
        ConnectionFacts::new(ConnectionParts {
            client: peer,
            peer,
            scheme: ClientScheme::Https,
            server_name: Fact::Unknown,
            client_certificate: ClientCertificate::NotAsked,
            ja4: Fact::Unknown,
        })
    }

    fn parts(build: http::request::Builder) -> Parts {
        build.body(()).unwrap().into_parts().0
    }

    /// An untrusted peer's forwarded address is ignored and its socket
    /// address remains the recorded client.
    #[test]
    fn a_forwarded_address_from_an_untrusted_peer_is_not_believed() {
        let sent = parts(Request::get("/").header("x-forwarded-for", "10.0.0.1"));

        let arrival = Arrival::read(
            &sent,
            &connection("203.0.113.9:4000"),
            &TrustedProxies::none(),
        );

        assert_eq!(arrival.client.to_string(), "203.0.113.9");
    }

    /// The client a trusted proxy names is the client.
    #[test]
    fn a_trusted_proxy_names_the_client() {
        let sent = parts(Request::get("/").header("x-forwarded-for", "198.51.100.4"));
        let trusted = TrustedProxies::parse("10.0.0.0/8");

        let arrival = Arrival::read(&sent, &connection("10.1.2.3:4000"), &trusted);

        assert_eq!(arrival.client.to_string(), "198.51.100.4");
    }

    /// A caller's trace is continued in a span of the gateway's own.
    #[test]
    fn a_callers_trace_is_continued_in_a_span_of_its_own() {
        let caller = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let sent = parts(Request::get("/").header(TRACEPARENT, caller));

        let arrival = Arrival::read(
            &sent,
            &connection("203.0.113.9:4000"),
            &TrustedProxies::none(),
        );

        let parent = TraceContext::parse(caller).unwrap();
        assert_eq!(arrival.trace.trace_id(), parent.trace_id());
        assert_ne!(arrival.trace.span_id(), parent.span_id());
    }
}
