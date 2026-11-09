//! The signed-in tunnel: TLS ended on the route's port, then one HTTP/1.1
//! `CONNECT` carrying the caller's token in `Proxy-Authorization`.
//!
//! The application names the token's holder and the route says whether
//! they may pass. Only then is the backend dialled and the `200` sent, so
//! a refused caller never learns whether the backend is up. Where the
//! `CONNECT` asks to go is not read: the port is the route, and the route
//! names its backends.
//!
//! The token is checked again on an interval for as long as the tunnel
//! lasts, and the route asked again with what it names. Revoking the token,
//! deactivating its person, disabling its consumer, or narrowing the route
//! closes the tunnel within one interval, and so does a check that cannot
//! be made in time. The tunnel closes when the token expires at the latest.
//! The token is held in memory for those checks, never logged or recorded.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use http::header::{PROXY_AUTHENTICATE, PROXY_AUTHORIZATION};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::Empty;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::{OnUpgrade, Upgraded};
use hyper_util::rt::{TokioIo, TokioTimer};
use ianua_app::use_cases::routing::stream_routes::{
    IdentifiedStreamCaller, StreamCallerRefusal, StreamConnectionCaller, StreamCredential,
    StreamRefusal,
};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::DomainName;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

use super::admission::{Gate, Shut};
use super::backend::DialFailure;
use super::route::{ConnectionRecord, Dialled, ServedRoute};
use super::splice::{SpliceOutcome, expiring, splice};
use crate::listen::{StreamHandshake, TerminatedStream};

/// The longest the `CONNECT` may take to arrive, be decided and be
/// answered, and the client's side to switch after the `200`.
const OPEN_TIMEOUT: Duration = Duration::from_secs(15);

/// The longest the `CONNECT`'s headers may take to arrive.
const HEADER_READ: Duration = Duration::from_secs(10);

/// The most headers a `CONNECT` may carry.
const MAX_HEADERS: usize = 32;

/// The shortest interval the token is checked again on. A period of zero
/// would spin, and the runtime refuses one.
const SHORTEST_CHECK: Duration = Duration::from_millis(10);

/// Why a tunnel was not opened.
enum NotOpened {
    /// It was refused, for this reason.
    Shut(Shut),
    /// It was admitted and its backend could not be reached.
    Unreachable(DialFailure),
}

impl From<Shut> for NotOpened {
    fn from(shut: Shut) -> Self {
        Self::Shut(shut)
    }
}

/// A `CONNECT` the route admitted: its backend, the token it was opened
/// with and whom that names, and the client's side once it switches.
struct Admitted {
    backend: Dialled,
    token: Secret,
    named: IdentifiedStreamCaller,
    upgrade: OnUpgrade,
}

/// An open tunnel: both sides, and what it is held to.
struct Tunnel {
    client: TokioIo<Upgraded>,
    backend: Dialled,
    server_name: DomainName,
    token: Secret,
    named: IdentifiedStreamCaller,
}

/// Opens one tunnel, then splices it to a backend for as long as its token
/// and the route still let its caller through.
pub(super) async fn carry(route: &ServedRoute, client: TcpStream, peer: SocketAddr) {
    let mut record = route.record(peer);
    let tunnel = match open(route, &mut record, client).await {
        Ok(tunnel) => tunnel,
        Err(NotOpened::Shut(shut)) => {
            record.report_refusal(shut);
            return;
        }
        Err(NotOpened::Unreachable(failure)) => {
            record.unreachable(&failure);
            return;
        }
    };
    let Tunnel {
        mut client,
        mut backend,
        server_name,
        token,
        named,
    } = tunnel;
    let held = held(route, &server_name, &token, &named);
    let idle = route.idle_limit();
    let (outcome, counts) = splice(&mut client, &mut backend.stream, idle, held).await;
    record.report_close(&backend.authority, outcome, counts);
}

/// Ends TLS, takes the `CONNECT`, and waits for the client to switch.
///
/// # Errors
///
/// - [`NotOpened::Shut`] when the handshake, the `CONNECT` or its caller is
///   refused, or any step takes too long.
/// - [`NotOpened::Unreachable`] when the backend could not be reached.
async fn open(
    route: &ServedRoute,
    record: &mut ConnectionRecord<'_>,
    client: TcpStream,
) -> Result<Tunnel, NotOpened> {
    let TerminatedStream {
        stream,
        server_name,
        ..
    } = route.terminate(client, StreamHandshake::Tunnel).await?;
    record.record_server_name(Some(server_name.clone()));
    let admitted = tokio::time::timeout(OPEN_TIMEOUT, answered(route, &server_name, stream))
        .await
        .map_err(|_| Shut::Late)??;
    record.record_caller(admitted.named.caller.clone());
    let switched = tokio::time::timeout(OPEN_TIMEOUT, admitted.upgrade)
        .await
        .map_err(|_| Shut::Late)?
        .map_err(|_| Shut::NoTunnelRequest)?;
    Ok(Tunnel {
        client: TokioIo::new(switched),
        backend: admitted.backend,
        server_name,
        token: admitted.token,
        named: admitted.named,
    })
}

/// Serves the one request the tunnel opens with, and what was decided on
/// it. The connection serves nothing after it.
async fn answered(
    route: &ServedRoute,
    server_name: &DomainName,
    stream: TlsStream<TcpStream>,
) -> Result<Admitted, NotOpened> {
    let decided: Mutex<Option<Result<Admitted, NotOpened>>> = Mutex::new(None);
    let service = service_fn(|request| answer(route, server_name, &decided, request));
    let served = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ)
        .max_headers(MAX_HEADERS)
        .keep_alive(false)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await;
    if let Err(error) = served {
        tracing::debug!(%error, "a tunnel's CONNECT ended with an error");
    }
    decided
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner)
        .unwrap_or(Err(NotOpened::Shut(Shut::NoTunnelRequest)))
}

/// Decides `request`, keeps the decision in `decided`, and answers with
/// the status it comes to.
async fn answer(
    route: &ServedRoute,
    server_name: &DomainName,
    decided: &Mutex<Option<Result<Admitted, NotOpened>>>,
    mut request: Request<Incoming>,
) -> Result<Response<Empty<Bytes>>, Infallible> {
    let decision = decide(route, server_name, &mut request).await;
    let response = response_to(&decision);
    *decided.lock().unwrap_or_else(PoisonError::into_inner) = Some(decision);
    Ok(response)
}

/// Whether `request` opens the tunnel: a `CONNECT` whose token names a
/// caller the route lets in, to a backend that answers.
async fn decide(
    route: &ServedRoute,
    server_name: &DomainName,
    request: &mut Request<Incoming>,
) -> Result<Admitted, NotOpened> {
    if request.method() != Method::CONNECT {
        return Err(Shut::NoTunnelRequest.into());
    }
    let token = bearer_of(request.headers()).ok_or(Shut::NoToken)?;
    let credential = StreamCredential::TunnelToken(token.clone());
    let named = route.identify(server_name.clone(), credential).await?;
    if let Gate::Closed(shut) = route
        .gate(Some(server_name.clone()), named.caller.clone())
        .await
    {
        return Err(shut.into());
    }
    let backend = route.dial().await.map_err(NotOpened::Unreachable)?;
    Ok(Admitted {
        backend,
        token,
        named,
        upgrade: hyper::upgrade::on(request),
    })
}

/// The token a `CONNECT` carries in its one `Proxy-Authorization: Bearer`
/// header. Two headers, another scheme or an empty token carry none.
pub(super) fn bearer_of(headers: &HeaderMap) -> Option<Secret> {
    let mut values = headers.get_all(PROXY_AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.to_str().ok()?.split_once(' ')?;
    let token = token.trim();
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return None;
    }
    Some(Secret::new(token))
}

/// The answer to a `CONNECT` decided as `decision`.
///
/// The status says no more than whether to try again: why a token was
/// refused is in the record, never told to the client.
fn response_to(decision: &Result<Admitted, NotOpened>) -> Response<Empty<Bytes>> {
    let mut response = Response::new(Empty::new());
    *response.status_mut() = status_of(decision);
    if response.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        response
            .headers_mut()
            .insert(PROXY_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    response
}

/// The status a decision is answered with.
fn status_of(decision: &Result<Admitted, NotOpened>) -> StatusCode {
    let shut = match decision {
        Ok(_) => return StatusCode::OK,
        Err(NotOpened::Unreachable(_)) => return StatusCode::BAD_GATEWAY,
        Err(NotOpened::Shut(shut)) => *shut,
    };
    match shut {
        Shut::NoTunnelRequest => StatusCode::METHOD_NOT_ALLOWED,
        Shut::NoToken => StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        Shut::NotNamed(StreamCallerRefusal::Unavailable)
        | Shut::Refused(StreamRefusal::NoDecision)
        | Shut::Undecided
        | Shut::Late => StatusCode::SERVICE_UNAVAILABLE,
        Shut::NotNamed(_) | Shut::Refused(_) | Shut::RouteUnknown | Shut::Handshake(_) => {
            StatusCode::FORBIDDEN
        }
    }
}

/// What holds an open tunnel: it ends when the token expires, or when a
/// check finds its caller no longer let through.
async fn held(
    route: &ServedRoute,
    server_name: &DomainName,
    token: &Secret,
    named: &IdentifiedStreamCaller,
) -> SpliceOutcome {
    tokio::select! {
        ended = expiring(named.expiry) => ended,
        () = wait_for_caller_loss(route, server_name, token, &named.caller) => SpliceOutcome::CallerLost,
    }
}

/// Resolves once a check of the tunnel's caller does not clearly hold.
async fn wait_for_caller_loss(
    route: &ServedRoute,
    server_name: &DomainName,
    token: &Secret,
    caller: &StreamConnectionCaller,
) {
    let checks = route.tunnel_checks();
    let mut ticks = tokio::time::interval(checks.every.max(SHORTEST_CHECK));
    ticks.tick().await;
    loop {
        ticks.tick().await;
        let checked = tokio::time::timeout(
            checks.timeout,
            still_holds(route, server_name, token, caller),
        )
        .await;
        if !matches!(checked, Ok(true)) {
            return;
        }
    }
}

/// Whether `token` still names `caller`, and the route still lets them
/// through. It is checked as the token an open tunnel holds, so a
/// consumer's quota, counted when the tunnel opened, is not counted again
/// on every check.
async fn still_holds(
    route: &ServedRoute,
    server_name: &DomainName,
    token: &Secret,
    caller: &StreamConnectionCaller,
) -> bool {
    let credential = StreamCredential::HeldTunnelToken(token.clone());
    let Ok(named) = route.identify(server_name.clone(), credential).await else {
        return false;
    };
    if named.caller != *caller {
        return false;
    }
    route.gate(Some(server_name.clone()), named.caller).await == Gate::Open
}

#[cfg(test)]
mod tests {
    use ianua_app::use_cases::proxy::credentials::Refusal;

    use super::*;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(PROXY_AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    fn refused(shut: Shut) -> Result<Admitted, NotOpened> {
        Err(NotOpened::Shut(shut))
    }

    #[test]
    fn a_bearer_token_is_taken() {
        let token = bearer_of(&headers(&["Bearer a.signed.token"])).unwrap();

        assert_eq!(token.expose(), "a.signed.token");
    }

    /// Two proxy-authorization bearer headers yield no tunnel credential.
    #[test]
    fn two_tokens_carry_none() {
        let two = headers(&["Bearer first.token", "Bearer second.token"]);

        assert!(bearer_of(&two).is_none());
    }

    #[test]
    fn another_scheme_or_an_empty_token_carries_none() {
        assert!(bearer_of(&headers(&["Basic YTpi"])).is_none());
        assert!(bearer_of(&headers(&["Bearer  "])).is_none());
        assert!(bearer_of(&HeaderMap::new()).is_none());
    }

    /// A tunnel opened without a token is asked for one; a token that is
    /// refused is turned away without saying why.
    #[test]
    fn a_missing_token_is_asked_for_and_a_refused_one_turned_away() {
        let expired = Shut::NotNamed(StreamCallerRefusal::Credential(Refusal::Expired));

        let asked = response_to(&refused(Shut::NoToken));

        assert_eq!(asked.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert_eq!(asked.headers()[PROXY_AUTHENTICATE], "Bearer");
        assert_eq!(status_of(&refused(expired)), StatusCode::FORBIDDEN);
    }

    /// A check that could not be made says to try again later, never that
    /// the caller is let in.
    #[test]
    fn an_undecided_tunnel_is_unavailable() {
        assert_eq!(
            status_of(&refused(Shut::Late)),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status_of(&refused(Shut::NotNamed(StreamCallerRefusal::Unavailable))),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn a_request_that_is_no_connect_is_refused() {
        assert_eq!(
            status_of(&refused(Shut::NoTunnelRequest)),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
}
