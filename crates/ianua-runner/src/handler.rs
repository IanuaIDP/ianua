//! One request from the agent: asked what it carries, sent on with that and
//! nothing the agent added, and its answer streamed back without what the
//! agent may not hold.
//!
//! Deny by default: a method the platform does not know, a relay path that
//! names no topic, no key or token to be had, an unreachable destination or
//! one past its time, each is answered with a refusal of the runner's own
//! words, and nothing of the agent's request leaves. No refusal names a
//! key, a token or what the platform said.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{AUTHORIZATION, CONNECTION, HOST};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use ianua_app::error::AppError;
use ianua_app::use_case::Query as _;
use ianua_app::use_cases::agents::runner::{
    Credential, CredentialRequest, CredentialUseCase, ForgetUseCase,
};
use ianua_domain::domains::agents::authority::capability::TokenBinding;
use ianua_domain::domains::agents::runner::{GatewayAddress, crosses, is_withheld};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::HttpMethod;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, Sleep};
use url::Url;

use crate::outbound::{Outbound, Outbounds};

/// An error a body may end with.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// What the runner answers the agent with, and sends on.
pub(crate) type RunnerBody = UnsyncBoxBody<Bytes, BoxError>;

/// The header a proof of possession travels in.
const DPOP: &str = "dpop";

/// Headers that concern one hop only (RFC 9110 section 7.6.1), never
/// passed on from an answer.
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
];

/// Where the agent's requests are sent.
#[derive(Debug, Clone)]
pub struct Destinations {
    /// Where the gateway is reached.
    pub gateway_url: Url,
    /// The gateway as the agent's requests name it.
    pub gateway: GatewayAddress,
    /// The tenant's agents collection on the API, whose `messages/{topic}`
    /// is the relay.
    pub agents_url: Url,
}

/// What one request and the runner as a whole may take on.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RequestLimits {
    /// The longest one request may take, its answer streamed to the end
    /// included.
    pub timeout: Duration,
    /// The most requests in flight at once.
    pub in_flight: usize,
}

/// The use cases the runner asks.
pub(crate) struct RunnerUseCases {
    /// What a request carries.
    pub credential: CredentialUseCase,
    /// Dropping a token a destination refused.
    pub forget: ForgetUseCase,
}

/// The runner: what it asks, where it sends, and how much it takes on.
pub struct Runner {
    use_cases: RunnerUseCases,
    outbounds: Outbounds,
    destinations: Destinations,
    permits: Arc<Semaphore>,
    timeout: Duration,
}

/// Why a request was not sent on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// Every slot for a request in flight is taken.
    Busy,
    /// The method is not one the platform knows.
    Method,
    /// The relay path names no topic.
    Topic,
    /// No key or token could be had, or the platform refused them.
    Credential,
    /// The destination could not be reached.
    Unreachable,
    /// The destination did not answer in time.
    TimedOut,
}

impl Refusal {
    /// The status and the words the agent is answered with.
    fn answer(self) -> (StatusCode, &'static str) {
        match self {
            Self::Busy => (StatusCode::SERVICE_UNAVAILABLE, "the runner is busy"),
            Self::Method => (StatusCode::METHOD_NOT_ALLOWED, "the method is not allowed"),
            Self::Topic => (StatusCode::BAD_REQUEST, "the path names no topic"),
            Self::Credential | Self::Unreachable => (
                StatusCode::BAD_GATEWAY,
                "the runner could not complete the request",
            ),
            Self::TimedOut => (StatusCode::GATEWAY_TIMEOUT, "the request timed out"),
        }
    }
}

impl Runner {
    /// A runner asking `use_cases`, sending through `outbounds` to
    /// `destinations`, within `limits`.
    #[must_use]
    pub(crate) fn new(
        use_cases: RunnerUseCases,
        outbounds: Outbounds,
        destinations: Destinations,
        limits: RequestLimits,
    ) -> Self {
        Self {
            use_cases,
            outbounds,
            destinations,
            permits: Arc::new(Semaphore::new(limits.in_flight)),
            timeout: limits.timeout,
        }
    }

    /// Answers one request from the agent. Never fails: every refusal is
    /// an answer.
    pub(crate) async fn handle<B>(&self, request: Request<B>) -> Response<RunnerBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            return refused(Refusal::Busy);
        };
        let deadline = Instant::now() + self.timeout;
        match tokio::time::timeout_at(deadline, self.sent(request)).await {
            Ok(Ok(answer)) => held_until(answer, deadline, permit),
            Ok(Err(refusal)) => refused(refusal),
            Err(_) => refused(Refusal::TimedOut),
        }
    }

    /// Sends `request` on with its credential, and takes the answer's
    /// head.
    async fn sent<B>(&self, request: Request<B>) -> Result<Response<Incoming>, Refusal>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let (parts, body) = request.into_parts();
        let method = HttpMethod::parse(parts.method.as_str())
            .filter(|method| *method != HttpMethod::Any)
            .ok_or(Refusal::Method)?;
        let path_and_query = parts
            .uri
            .path_and_query()
            .map_or("/", |path| path.as_str())
            .to_owned();
        let credential = self.credential_for(method, &path_and_query).await?;
        let binding = binding_of(&credential);
        let client = self.client_for(&credential);
        let outbound = self.outbound_request(
            Request::from_parts(parts, body),
            &path_and_query,
            credential,
        )?;
        let answer = client.request(outbound).await.map_err(|error| {
            tracing::warn!(%error, "the agent's request could not be sent on");
            Refusal::Unreachable
        })?;
        if answer.status() == StatusCode::UNAUTHORIZED {
            self.use_cases.forget.execute(&(), binding).await;
        }
        Ok(answer)
    }

    /// Asks for the credential bound to this method and complete request path.
    async fn credential_for(
        &self,
        method: HttpMethod,
        path_and_query: &str,
    ) -> Result<Credential, Refusal> {
        self.use_cases
            .credential
            .execute(
                &(),
                CredentialRequest {
                    method,
                    path_and_query: path_and_query.to_owned(),
                },
            )
            .await
            .map_err(|error| refusal_of(&error))
    }

    /// The client `credential`'s destination is reached through.
    fn client_for(&self, credential: &Credential) -> &Outbound {
        match credential {
            Credential::Gateway { .. } => &self.outbounds.gateway,
            Credential::Relay { .. } => &self.outbounds.platform,
        }
    }

    /// The request that leaves for `credential`'s destination: the agent's
    /// method and body, the headers that cross, and the credential.
    fn outbound_request<B>(
        &self,
        request: Request<B>,
        path_and_query: &str,
        credential: Credential,
    ) -> Result<Request<RunnerBody>, Refusal>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let (parts, body) = request.into_parts();
        let mut headers = crossing(&parts.headers);
        let uri = match credential {
            Credential::Gateway { token, proof } => {
                bearing(&mut headers, token.reveal())?;
                headers.insert(HOST, value_of(self.destinations.gateway.host().as_str())?);
                headers.insert(HeaderName::from_static(DPOP), secret_value(&proof)?);
                joined(&self.destinations.gateway_url, path_and_query)?
            }
            Credential::Relay { topic, token } => {
                bearing(&mut headers, token.reveal())?;
                let query = path_and_query
                    .split_once('?')
                    .map_or("", |(_, query)| query);
                relay_uri(&self.destinations.agents_url, topic.as_str(), query)?
            }
        };
        let mut outbound = Request::new(body.map_err(Into::into).boxed_unsync());
        *outbound.method_mut() = parts.method;
        *outbound.uri_mut() = uri;
        *outbound.headers_mut() = headers;
        Ok(outbound)
    }
}

/// The binding of the token `credential` carries.
fn binding_of(credential: &Credential) -> TokenBinding {
    match credential {
        Credential::Gateway { .. } => TokenBinding::ProofOfPossession,
        Credential::Relay { .. } => TokenBinding::Bearer,
    }
}

/// The refusal for the use case's `error`, logged without its detail
/// reaching the agent.
fn refusal_of(error: &AppError) -> Refusal {
    if matches!(error, AppError::Domain(_)) {
        return Refusal::Topic;
    }
    tracing::warn!(%error, "no credential for the agent's request");
    Refusal::Credential
}

/// The agent's headers that cross: descriptive ones only.
fn crossing(inbound: &HeaderMap) -> HeaderMap {
    let mut outbound = HeaderMap::new();
    for (name, value) in inbound.iter().filter(|(name, _)| crosses(name.as_str())) {
        outbound.append(name.clone(), value.clone());
    }
    outbound
}

/// Sets `Authorization` to `token` as a bearer credential, marked
/// sensitive so no log of the headers shows it.
fn bearing(headers: &mut HeaderMap, token: &str) -> Result<(), Refusal> {
    let mut value = value_of(&format!("Bearer {token}"))?;
    value.set_sensitive(true);
    headers.insert(AUTHORIZATION, value);
    Ok(())
}

/// `secret` as a header value marked sensitive.
fn secret_value(secret: &Secret) -> Result<HeaderValue, Refusal> {
    let mut value = value_of(secret.expose())?;
    value.set_sensitive(true);
    Ok(value)
}

/// `text` as a header value. A credential that is no header value is no
/// credential the runner can send.
fn value_of(text: &str) -> Result<HeaderValue, Refusal> {
    HeaderValue::from_str(text).map_err(|_| Refusal::Credential)
}

/// `path_and_query` on the gateway at `base`.
fn joined(base: &Url, path_and_query: &str) -> Result<Uri, Refusal> {
    let origin = base.as_str().trim_end_matches('/');
    format!("{origin}{path_and_query}")
        .parse()
        .map_err(|_| Refusal::Unreachable)
}

/// The relay's address for `topic`, with `query` when there is one.
fn relay_uri(agents_url: &Url, topic: &str, query: &str) -> Result<Uri, Refusal> {
    let base = agents_url.as_str().trim_end_matches('/');
    let address = match query {
        "" => format!("{base}/messages/{topic}"),
        query => format!("{base}/messages/{topic}?{query}"),
    };
    address.parse().map_err(|_| Refusal::Unreachable)
}

/// The answer the agent is given: the destination's, without what it may
/// not hold, its body held to `deadline` and to the slot it takes.
fn held_until(
    answer: Response<Incoming>,
    deadline: Instant,
    permit: OwnedSemaphorePermit,
) -> Response<RunnerBody> {
    let (mut parts, body) = answer.into_parts();
    withhold(&mut parts.headers);
    let body = Deadline {
        inner: body.map_err(Into::into).boxed_unsync(),
        until: Box::pin(tokio::time::sleep_until(deadline)),
        _permit: permit,
    };
    Response::from_parts(parts, body.boxed_unsync())
}

/// Removes from an answer what the agent may not hold, and what concerns
/// one hop only.
fn withhold(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    let withheld: Vec<HeaderName> = headers
        .keys()
        .filter(|name| is_withheld(name.as_str()))
        .cloned()
        .collect();
    for name in withheld {
        headers.remove(name);
    }
}

/// The answer for `refusal`, in the runner's own words.
fn refused(refusal: Refusal) -> Response<RunnerBody> {
    let (status, words) = refusal.answer();
    let mut response = Response::new(
        Full::new(Bytes::from_static(words.as_bytes()))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = status;
    response
}

/// An answer's body, ended with an error once its deadline passes, and
/// holding its request's slot until it ends.
struct Deadline {
    inner: RunnerBody,
    until: Pin<Box<Sleep>>,
    _permit: OwnedSemaphorePermit,
}

impl Body for Deadline {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.until.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err("the answer outlasted its time".into())));
        }
        Pin::new(&mut this.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests;
