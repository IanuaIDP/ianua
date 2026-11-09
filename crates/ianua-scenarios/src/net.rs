//! The HTTP client every actor uses: HTTPS to the stack's ingress, the
//! stack's authority the only one trusted, a cookie jar of its own, an
//! address of its own the ingress tells the platform it came from, a
//! fresh correlation id on every request, and a redacted log of each
//! request for a failure's message.

mod addresses;
mod call;
mod names;
pub(crate) mod redaction;
mod socket;
pub mod streams;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

pub use call::Call;
use call::CallBody;
use names::{Front, Fronts, StackNames};
use reqwest::cookie::{CookieStore as _, Jar};
use reqwest::header::HeaderMap;
use reqwest::redirect::Policy;
use serde::Serialize;
use serde::de::DeserializeOwned;
pub use socket::{Frame, Opened, Socket};
use url::Url;

use crate::stack::Stack;
use crate::stack::ingress::CLIENT_ADDRESS;
use crate::wire::{Answer, Arrived, Exchange, Received, Sent};

/// The header the correlation id goes in.
pub const CORRELATION_HEADER: &str = "x-request-id";

/// The longest a request and its answer may take.
const REQUEST_WAIT: Duration = Duration::from_secs(60);

/// Why a client could not be made.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// The stack's authority is not a certificate.
    #[error("the stack's authority is not a certificate")]
    Authority(#[source] reqwest::Error),
    /// The client could not be built.
    #[error("the client could not be built")]
    Client(#[source] reqwest::Error),
}

/// One actor's way to the platform. Each holds its own cookies, its own
/// bearer token and its own address, so actors never share a session or
/// a per-address limit.
pub struct Client {
    actor: String,
    http: reqwest::Client,
    jar: Arc<Jar>,
    base: Url,
    bearer: Option<String>,
    address: IpAddr,
    names: StackNames,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("actor", &self.actor)
            .field("address", &self.address)
            .field("signed_in", &self.bearer.is_some())
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client for `actor`, named in every log line, reaching `stack`
    /// through its ingress and trusting its authority alone, from an
    /// address in the documentation ranges no other client of the test
    /// stands for.
    ///
    /// # Errors
    ///
    /// [`NetError`] when the client cannot be built.
    pub fn new(stack: &Stack, actor: &str) -> Result<Self, NetError> {
        Self::at(stack, actor, addresses::fresh())
    }

    /// A client for `actor` as [`new`](Self::new) makes one, arriving from
    /// `address`, such as one a geo rule places in a country.
    ///
    /// # Errors
    ///
    /// [`NetError`] when the client cannot be built.
    pub fn at(stack: &Stack, actor: &str, address: IpAddr) -> Result<Self, NetError> {
        let jar = Arc::new(Jar::default());
        let names = stack_names(stack);
        let http = trusting(stack, &names)?
            .cookie_provider(Arc::clone(&jar))
            .user_agent(format!("ianua-scenarios ({actor})"))
            .build()
            .map_err(NetError::Client)?;
        Ok(Self {
            actor: actor.to_owned(),
            http,
            jar,
            base: stack.app_url(),
            bearer: None,
            address,
            names,
        })
    }

    /// A client for `actor` arriving from `address` with the bearer token
    /// `holder` sends, as whoever copied that token would.
    ///
    /// # Errors
    ///
    /// [`NetError`] when the client cannot be built.
    pub fn same_bearer_at(
        holder: &Self,
        stack: &Stack,
        actor: &str,
        address: IpAddr,
    ) -> Result<Self, NetError> {
        let mut copy = Self::at(stack, actor, address)?;
        copy.bearer.clone_from(&holder.bearer);
        Ok(copy)
    }

    /// Who this client acts as.
    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }

    /// The address the platform sees this client's requests come from.
    #[must_use]
    pub fn address(&self) -> IpAddr {
        self.address
    }

    /// Sends `token` as `Authorization: Bearer` to the API from now on.
    pub fn authorize(&mut self, token: &str) {
        self.bearer = Some(token.to_owned());
    }

    /// Sends no bearer token from now on.
    pub fn forget_authorization(&mut self) {
        self.bearer = None;
    }

    /// The cookies this client would send to `url`, as one header value.
    #[must_use]
    pub fn cookies_for(&self, url: &Url) -> Option<String> {
        self.jar
            .cookies(url)
            .and_then(|value| value.to_str().ok().map(str::to_owned))
    }

    /// `GET path`, its answer read as `T`.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Answer<T> {
        self.send(Call::get(path)).await
    }

    /// `POST path` with `body` as JSON, its answer read as `T`.
    pub async fn post<T: DeserializeOwned>(&self, path: &str, body: &impl Serialize) -> Answer<T> {
        self.send(Call::post(path).json(body)).await
    }

    /// Sends `call` and reads its answer as `T`.
    ///
    /// # Panics
    ///
    /// When the request cannot be made or no answer comes, which means the
    /// stack is down, naming the request redacted.
    pub async fn send<T: DeserializeOwned>(&self, call: Call) -> Answer<T> {
        match self.attempt(call).await {
            Ok(answer) => answer,
            Err(why) => panic!("{why}"),
        }
    }

    /// Sends `call` and reads its answer as `T`, or says why no answer
    /// came, such as a handshake refused for a name the gateway does not
    /// serve yet.
    ///
    /// # Errors
    ///
    /// The request, redacted, and why no whole answer came.
    pub async fn attempt<T: DeserializeOwned>(&self, call: Call) -> Result<Answer<T>, String> {
        self.exchanged(call).await.map(Answer::read)
    }

    /// Sends `call` and reads a successful answer's body as text, such as
    /// an XML document; a refusal still reads as the API's problem.
    ///
    /// # Panics
    ///
    /// When the request cannot be made or no answer comes, which means the
    /// stack is down, naming the request redacted.
    pub async fn send_text(&self, call: Call) -> Answer<String> {
        match self.exchanged(call).await {
            Ok(arrived) => Answer::read_text(arrived),
            Err(why) => panic!("{why}"),
        }
    }

    /// Sends `call` and takes in its whole answer, or says why no answer
    /// came.
    async fn exchanged(&self, call: Call) -> Result<Arrived, String> {
        let url = self.url_of(&call.path);
        let correlation_id = uuid::Uuid::now_v7().to_string();
        let request = self.request(&call, &url, &correlation_id);
        let sent = self.sent(&call, &url, correlation_id);
        let response = request.send().await.map_err(|error| {
            format!(
                "{} {} as {} got no answer: {error}",
                sent.method, sent.url, sent.actor
            )
        })?;
        receive(response, sent).await
    }

    /// Builds the actor's request with credentials restricted to the ingress.
    fn request(&self, call: &Call, url: &Url, correlation_id: &str) -> reqwest::RequestBuilder {
        let mut request = self
            .http
            .request(call.method.clone(), url.clone())
            .header(CORRELATION_HEADER, correlation_id)
            .header(reqwest::header::ACCEPT, "application/json");
        if self.through_ingress(url) {
            request = request.header(CLIENT_ADDRESS, self.address.to_string());
        }
        for (name, value) in &call.headers {
            request = request.header(name.as_str(), value.as_str());
        }
        if let Some(token) = self.bearer_for(url) {
            request = request.bearer_auth(token);
        }
        match &call.body {
            Some(CallBody::Json(value)) => request.json(value),
            Some(CallBody::Raw(raw)) => request
                .header(reqwest::header::CONTENT_TYPE, raw.content_type.as_str())
                .body(raw.text.clone()),
            Some(CallBody::Bytes(sent)) => request
                .header(reqwest::header::CONTENT_TYPE, sent.content_type.as_str())
                .body(sent.bytes.clone()),
            None => request,
        }
    }

    /// The bearer token to send to `url`: the platform's own, sent to the
    /// API alone, as a dashboard sends it; an app behind the gateway gets
    /// only what the call itself carries.
    fn bearer_for(&self, url: &Url) -> Option<&str> {
        self.bearer.as_deref().filter(|_| self.through_ingress(url))
    }

    /// Whether `url` is served behind the stack's ingress, which reads the
    /// address this client stands for. The gateway is reached directly,
    /// from the connection's own address, as a load balancer passing TCP
    /// through would leave it.
    fn through_ingress(&self, url: &Url) -> bool {
        url.host_str()
            .and_then(|host| self.names.front_of(host))
            .is_some_and(|front| front == Front::Ingress)
    }

    /// `path` under the dashboard's address, or `path` itself when it is a
    /// whole URL, such as a mailed link.
    fn url_of(&self, path: &str) -> Url {
        Url::parse(path)
            .ok()
            .filter(Url::has_host)
            .or_else(|| self.base.join(path).ok())
            .unwrap_or_else(|| self.base.clone())
    }

    /// The request half of the log of `call` to `url`, redacted.
    fn sent(&self, call: &Call, url: &Url, correlation_id: String) -> Sent {
        let mut headers: Vec<(String, String)> = call
            .headers
            .iter()
            .map(|(name, value)| (name.clone(), redaction::header(name, value)))
            .collect();
        if self.through_ingress(url) {
            headers.push((CLIENT_ADDRESS.to_owned(), self.address.to_string()));
        }
        if self.bearer_for(url).is_some() {
            headers.push((
                "authorization".to_owned(),
                redaction::header("authorization", ""),
            ));
        }
        Sent {
            actor: self.actor.clone(),
            method: call.method.to_string(),
            url: redaction::path(url.as_str()),
            correlation_id,
            headers,
            body: call.body.as_ref().map(CallBody::redacted),
        }
    }
}

/// Reads the response and records a redacted exchange, preserving body failures.
async fn receive(response: reqwest::Response, sent: Sent) -> Result<Arrived, String> {
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.bytes().await.map_err(|error| {
        format!(
            "{} {} as {}: the answer's body was cut off: {error}",
            sent.method, sent.url, sent.actor
        )
    })?;
    let received = Received {
        status,
        headers: redacted_headers(&headers),
        body: redaction::body(&bytes),
    };
    Ok(Arrived {
        status,
        headers,
        bytes: bytes.to_vec(),
        exchange: Exchange::of(sent, received),
    })
}

/// A plain client of `stack` for a part of the scenarios rather than an
/// actor, such as an app behind the gateway fetching its tenant's keys:
/// it trusts the stack's authority alone and reaches only the stack's
/// names, with no cookies.
///
/// # Errors
///
/// [`NetError`] when the client cannot be built.
pub(crate) fn plain(stack: &Stack) -> Result<reqwest::Client, NetError> {
    trusting(stack, &stack_names(stack))?
        .user_agent("ianua-scenarios")
        .build()
        .map_err(NetError::Client)
}

/// Where each of `stack`'s names is served.
fn stack_names(stack: &Stack) -> StackNames {
    let gateway_domains = [stack.apps_domain(), stack.customer_domain()];
    StackNames::new(&Fronts {
        base_domain: stack.base_domain(),
        ingress: stack.ingress(),
        gateway_domains: &gateway_domains,
        gateway: stack.gateway(),
    })
}

/// A client builder over HTTPS alone, trusting `stack`'s authority and no
/// other, resolving `names`, following no redirect, within
/// [`REQUEST_WAIT`].
fn trusting(stack: &Stack, names: &StackNames) -> Result<reqwest::ClientBuilder, NetError> {
    let authority = reqwest::Certificate::from_pem(stack.root_certificate_pem().as_bytes())
        .map_err(NetError::Authority)?;
    Ok(reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(authority)
        .https_only(true)
        .dns_resolver(Arc::new(names.clone()))
        .redirect(Policy::none())
        .no_proxy()
        .timeout(REQUEST_WAIT))
}

/// `headers` as printed, credentials taken out.
fn redacted_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let text = value.to_str().unwrap_or("[not text]");
            (
                name.as_str().to_owned(),
                redaction::header(name.as_str(), text),
            )
        })
        .collect()
}
