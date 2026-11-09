//! The headers that describe one connection rather than the message, and
//! the `Host` a backend is sent.
//!
//! RFC 9110 has a proxy drop connection headers in both directions. On a
//! request only the fixed list is dropped, not the names a client lists in
//! its `Connection` header: by the time a request gets here the gateway has
//! set headers of its own for the upstream, and a client naming one in
//! `Connection` must not be able to strip it. The ingress step drops the
//! listed names before anything is set. On a response the listed names go
//! too, since the backend only describes its own answer.
//!
//! `Trailer` is not on the list. It says which fields follow the body,
//! which is about the message; dropping it lost every trailer, and
//! `grpc-status` is one.

use http::Uri;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use ianua_domain::domains::routing::backend::upstream::HostHeader;

/// Whether a request is an ordinary message or a switch the gateway will
/// tunnel.
///
/// The two differ in what `Connection` and `Upgrade` are: on a message
/// they describe this hop and stop here, on a switch they are the request,
/// and the backend cannot answer `101` without them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Hop {
    /// An ordinary request.
    Message,
    /// A protocol switch the pipeline allows.
    Upgrade,
}

/// The headers that describe one connection.
const HOP_BY_HOP: [HeaderName; 8] = [
    header::CONNECTION,
    HeaderName::from_static("keep-alive"),
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    HeaderName::from_static("proxy-connection"),
    header::TE,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
];

/// Readies a request's headers for the backend.
///
/// The connection headers go. `TE: trailers` is said again on the
/// gateway's own behalf, which is true, since it passes trailers on; a gRPC
/// server sends no `grpc-status` without it. On a switch, `Upgrade` and a
/// `Connection: upgrade` naming it are sent, so the backend can agree.
pub(super) fn prepare_request(headers: &mut HeaderMap, hop: Hop) {
    let trailers = declares_trailers(headers);
    let protocol = protocol_to_forward(headers, hop);
    remove_hop_by_hop(headers);
    if trailers {
        headers.insert(header::TE, HeaderValue::from_static("trailers"));
    }
    let Some(protocol) = protocol else {
        return;
    };
    headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    headers.insert(header::UPGRADE, protocol);
}

/// Drops a response's connection headers, and the ones its `Connection`
/// names.
///
/// `hyper` hands the body over decoded, so a backend's
/// `Transfer-Encoding: chunked` would describe framing that no longer
/// exists, and an HTTP/2 client may not receive it at all.
pub(super) fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named = connection_options(headers);
    remove_hop_by_hop(headers);
    for name in named {
        headers.remove(name);
    }
}

/// Sets the `Host` the service asks for: the one the client addressed when
/// the service preserves it, the backend's own otherwise. Whatever the
/// request carried before is replaced.
pub(super) fn set_host(
    headers: &mut HeaderMap,
    rule: HostHeader,
    client_host: Option<&HeaderValue>,
    uri: &Uri,
) {
    headers.remove(header::HOST);
    let host = match (rule, client_host) {
        (HostHeader::Preserve, Some(host)) => Some(host.clone()),
        (HostHeader::Preserve, None) | (HostHeader::Rewrite, _) => authority_of(uri),
    };
    let Some(host) = host else {
        return;
    };
    headers.insert(header::HOST, host);
}

/// Whether `Connection` and `Upgrade` together ask to switch protocols.
///
/// Both halves are needed: `Upgrade` names the protocol and `Connection`
/// says it applies to this hop. A stray `Upgrade` alone is not a request
/// to switch, and must not open a tunnel.
pub(crate) fn asks_to_switch(headers: &HeaderMap) -> bool {
    let offered = connection_options(headers).contains(&header::UPGRADE);
    let named = headers
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|protocol| !protocol.trim().is_empty());
    offered && named
}

/// The `Upgrade` header to send on, on a switch.
fn protocol_to_forward(headers: &HeaderMap, hop: Hop) -> Option<HeaderValue> {
    match hop {
        Hop::Message => None,
        Hop::Upgrade => headers.get(header::UPGRADE).cloned(),
    }
}

/// Whether the request says `TE: trailers`, exactly. Any other `TE` asks
/// for a transfer coding on a connection the gateway ends.
fn declares_trailers(headers: &HeaderMap) -> bool {
    headers.get_all(header::TE).iter().any(|value| {
        value
            .to_str()
            .is_ok_and(|value| value.trim().eq_ignore_ascii_case("trailers"))
    })
}

/// The header names a `Connection` header lists.
fn connection_options(headers: &HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|option| HeaderName::from_bytes(option.trim().as_bytes()).ok())
        .collect()
}

/// Removes every header on the fixed list.
fn remove_hop_by_hop(headers: &mut HeaderMap) {
    for name in &HOP_BY_HOP {
        headers.remove(name);
    }
}

/// The URI's authority as a header value.
fn authority_of(uri: &Uri) -> Option<HeaderValue> {
    uri.authority()
        .and_then(|authority| HeaderValue::from_str(authority.as_str()).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn connection_headers_do_not_reach_the_backend() {
        let mut sent = headers(&[
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("proxy-authorization", "Basic abc"),
            ("content-type", "text/plain"),
        ]);

        prepare_request(&mut sent, Hop::Message);

        assert_eq!(sent.len(), 1);
        assert_eq!(sent.get(header::CONTENT_TYPE).unwrap(), "text/plain");
    }

    /// A client naming a header in `Connection` must not strip one the
    /// gateway set for the upstream.
    #[test]
    fn a_header_a_client_names_in_connection_still_reaches_the_backend() {
        let mut sent = headers(&[
            ("connection", "x-ianua-assertion"),
            ("x-ianua-assertion", "signed"),
        ]);

        prepare_request(&mut sent, Hop::Message);

        assert_eq!(sent.get("x-ianua-assertion").unwrap(), "signed");
    }

    #[test]
    fn a_repeated_header_reaches_the_backend_in_full() {
        let mut sent = headers(&[("cookie", "a=1"), ("cookie", "b=2")]);

        prepare_request(&mut sent, Hop::Message);

        assert_eq!(sent.get_all(header::COOKIE).iter().count(), 2);
    }

    /// gRPC puts `grpc-status` in trailers, and a server sends none unless
    /// it sees this.
    #[test]
    fn te_trailers_reaches_the_backend_however_it_is_written() {
        for value in ["trailers", "Trailers", " TRAILERS "] {
            let mut sent = headers(&[("te", value)]);

            prepare_request(&mut sent, Hop::Message);

            assert_eq!(sent.get(header::TE).unwrap(), "trailers", "{value}");
        }
    }

    #[test]
    fn any_other_te_is_dropped() {
        for value in ["gzip", "deflate, trailers", "chunked"] {
            let mut sent = headers(&[("te", value)]);

            prepare_request(&mut sent, Hop::Message);

            assert!(sent.get(header::TE).is_none(), "{value} was sent");
        }
    }

    #[test]
    fn a_switch_carries_its_handshake_to_the_backend() {
        let mut sent = headers(&[
            ("connection", "keep-alive, Upgrade"),
            ("upgrade", "websocket"),
        ]);

        prepare_request(&mut sent, Hop::Upgrade);

        assert_eq!(sent.get(header::CONNECTION).unwrap(), "upgrade");
        assert_eq!(sent.get(header::UPGRADE).unwrap(), "websocket");
    }

    #[test]
    fn a_message_never_carries_a_handshake() {
        let mut sent = headers(&[("connection", "upgrade"), ("upgrade", "websocket")]);

        prepare_request(&mut sent, Hop::Message);

        assert!(sent.get(header::UPGRADE).is_none());
        assert!(sent.get(header::CONNECTION).is_none());
    }

    #[test]
    fn a_response_loses_its_connection_headers_and_the_ones_it_names() {
        let mut answered = headers(&[
            ("connection", "close, x-hop"),
            ("x-hop", "1"),
            ("transfer-encoding", "chunked"),
            ("trailer", "grpc-status"),
            ("content-type", "text/plain"),
        ]);

        strip_hop_by_hop(&mut answered);

        assert!(answered.get("x-hop").is_none());
        assert!(answered.get(header::TRANSFER_ENCODING).is_none());
        assert_eq!(answered.get(header::TRAILER).unwrap(), "grpc-status");
        assert_eq!(answered.get(header::CONTENT_TYPE).unwrap(), "text/plain");
    }

    #[test]
    fn a_switch_needs_both_halves_of_the_handshake() {
        assert!(asks_to_switch(&headers(&[
            ("connection", "keep-alive, UPGRADE"),
            ("upgrade", "WebSocket"),
        ])));
        assert!(!asks_to_switch(&headers(&[("upgrade", "websocket")])));
        assert!(!asks_to_switch(&headers(&[("connection", "upgrade")])));
        assert!(!asks_to_switch(&headers(&[
            ("connection", "upgrade"),
            ("upgrade", " "),
        ])));
    }

    #[test]
    fn the_host_follows_the_service_rule() {
        let uri: Uri = "http://10.0.0.5:8080/orders".parse().unwrap();
        let client = HeaderValue::from_static("shop.example");
        let mut preserved = headers(&[("host", "spoofed.example")]);
        let mut rewritten = headers(&[("host", "spoofed.example")]);

        set_host(&mut preserved, HostHeader::Preserve, Some(&client), &uri);
        set_host(&mut rewritten, HostHeader::Rewrite, Some(&client), &uri);

        assert_eq!(preserved.get(header::HOST).unwrap(), "shop.example");
        assert_eq!(rewritten.get(header::HOST).unwrap(), "10.0.0.5:8080");
    }
}
