//! Answering a request at a host's sign-in addresses: checked for where it
//! came from, counted against its address's limit, read, relayed to the
//! API, and its outcome rendered.
//!
//! Every step that cannot be taken refuses: a page elsewhere sent it, the
//! limit was reached or could not be counted, the body could not be read in
//! time, the API could not be asked in time, or it answered something that
//! does not fit. Nothing here decides who may sign in; the API does.

use std::error::Error;
use std::net::IpAddr;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::request::Parts;
use http::{Method, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Limited};
use hyper::body::{Body, Bytes};
use ianua_app::ports::authentication::{
    AppSignInBroker, WIRE_VERSION, WireCommand, WireContext, WireOutcome, WireRequest,
};
use ianua_app::ports::runtime::FleetCounters;
use ianua_domain::domains::routing::sign_in::app::{AppSignIn, SignInAction};
use ianua_domain::shared::clock;
use ianua_domain::types::{DomainName, HostOrigin, Nonce, Seconds, ServiceId, TenantId};
use sha2::{Digest, Sha256};

use super::address::Asked;
use super::commands::{self, Carried};
use super::fields::{Client, Fields, header};
use super::origin::{from_same_origin, leads_to};
use super::respond::{self, Answering, PageScript, Step, UNAVAILABLE};
use super::{Response, cookies};

/// How many sign-in requests one address may make on one host per window.
const PER_ADDRESS_PER_WINDOW: u32 = 20;

/// The window the per-address limit counts in.
const LIMIT_WINDOW: Seconds = Seconds::new(60);

/// The largest sign-in request body read. A form or a passkey answer is a
/// few kilobytes; a SAML response posted back can be larger.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// How long a client may take to send its body.
const BODY_TIMEOUT: Duration = Duration::from_secs(10);

/// How long counting a request against the limit may take.
const COUNT_TIMEOUT: Duration = Duration::from_secs(2);

/// How long the API may take to answer one sign-in, beyond which the
/// person's connection is freed and the request refused. Longer than the
/// broker's own timeout, so this bound only catches a broker that never
/// answers.
const RELAY_TIMEOUT: Duration = Duration::from_secs(15);

/// A body read up to [`MAX_BODY_BYTES`].
type SentBody = UnsyncBoxBody<Bytes, Box<dyn Error + Send + Sync>>;

/// What answering a sign-in request needs from the gateway.
pub struct Gate<'a> {
    /// Where requests are relayed: the API, over the sealed internal
    /// channel.
    pub broker: &'a dyn AppSignInBroker,
    /// The counters every gateway shares, holding the per-address limit.
    pub counters: &'a dyn FleetCounters,
}

/// A request at a sign-in address: where it was sent and who sent it.
pub struct Inbound<'a> {
    /// The tenant the host belongs to.
    pub tenant: TenantId,
    /// The service whose sign-in the host answers for.
    pub service: ServiceId,
    /// The host, without its port.
    pub host: &'a DomainName,
    /// The request's head.
    pub parts: &'a Parts,
    /// The client's address, as the gateway established it.
    pub client_ip: IpAddr,
}

/// A request at one of the sign-in addresses of the service owning them.
pub struct Arrived<'a> {
    /// Where it was sent and who sent it.
    pub inbound: Inbound<'a>,
    /// The host's app sign-in.
    pub sign_in: &'a AppSignIn,
    /// What was asked, from [`super::addressed`].
    pub asked: Asked,
}

/// A hop arriving on the host of a service accepting the sign-in with a
/// cookie of its own.
pub(crate) struct HopArrived<'a> {
    /// Where it was sent and who sent it; the service is the one accepting
    /// the sign-in.
    pub inbound: Inbound<'a>,
    /// The origins a browser passing through may be sent on to.
    pub onward_origins: &'a [HostOrigin],
    /// The origins of the owner's hosts, the only ones a hop's code is
    /// fetched from.
    pub owner_origins: &'a [HostOrigin],
}

/// Who may send an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Senders {
    /// Only a page on the host itself.
    OwnPages,
    /// Anyone: a link opened from a mailbox, or a provider sending the
    /// browser back. What it carries is checked against the browser's
    /// cookies by the API.
    Anyone,
}

/// Why a request was refused before the API answered it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Refusal {
    status: StatusCode,
    code: &'static str,
}

const CROSS_SITE: Refusal = Refusal {
    status: StatusCode::FORBIDDEN,
    code: "cross_site",
};

const TOO_MANY: Refusal = Refusal {
    status: StatusCode::TOO_MANY_REQUESTS,
    code: "too_many_requests",
};

const MALFORMED: Refusal = Refusal {
    status: StatusCode::BAD_REQUEST,
    code: "malformed",
};

const NO_ANSWER: Refusal = Refusal {
    status: StatusCode::SERVICE_UNAVAILABLE,
    code: UNAVAILABLE,
};

impl Refusal {
    fn answer(self, answering: &Answering<'_>) -> Response {
        respond::refused(answering, self.status.as_u16(), self.code)
    }
}

/// Answers a request at one of a host's sign-in addresses.
pub async fn answer<B>(gate: &Gate<'_>, arrived: &Arrived<'_>, body: B) -> Response
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let body = Limited::new(body, MAX_BODY_BYTES).boxed_unsync();
    match arrived.asked {
        Asked::Submit(action) => submit(gate, arrived, action, body).await,
        Asked::Page(action) => show_page(gate, arrived, action).await,
        Asked::Token => issue_token(gate, arrived, body).await,
        Asked::HopCode => issue_hop_code(gate, arrived).await,
        Asked::PasskeyScript => respond::passkey_script(),
    }
}

/// Carries out `action`. The way back from a single sign-on ends it,
/// whatever the answer: what the browser kept is good for one return.
async fn submit(
    gate: &Gate<'_>,
    arrived: &Arrived<'_>,
    action: SignInAction,
    body: SentBody,
) -> Response {
    let answer = carry_out(gate, arrived, action, body).await;
    if action == SignInAction::SsoCallback {
        return respond::ending_single_sign_on(answer);
    }
    answer
}

async fn carry_out(
    gate: &Gate<'_>,
    arrived: &Arrived<'_>,
    action: SignInAction,
    body: SentBody,
) -> Response {
    let early = answering(arrived, action);
    if let Err(refusal) = admit(gate.counters, &arrived.inbound, senders(action)).await {
        return refusal.answer(&early);
    }
    let Some(fields) = sent_fields(arrived.inbound.parts, body).await else {
        return MALFORMED.answer(&early);
    };
    let return_to = fields.value("return_to").map(str::to_owned);
    let step = step_of(action, fields.value("token"));
    let command = match commands::command(action, fields, carried(arrived.inbound.parts)) {
        Ok(command) => command,
        Err(unread) => {
            let answering = Answering {
                step,
                return_to,
                ..early
            };
            return respond::refused(&answering, StatusCode::BAD_REQUEST.as_u16(), &unread.code());
        }
    };
    let answering = Answering {
        step,
        return_to,
        ..early
    };
    answered(gate, &arrived.inbound, command, &answering).await
}

/// Answers a page asking for a token. Only a page on the owner's own host
/// may ask: the token is a credential, and the answer is readable.
async fn issue_token(gate: &Gate<'_>, arrived: &Arrived<'_>, body: SentBody) -> Response {
    let answering = Answering {
        client: Client::Script,
        host: arrived.inbound.host,
        sign_in: arrived.sign_in,
        step: Step::Token,
        return_to: None,
    };
    if let Err(refusal) = admit(gate.counters, &arrived.inbound, Senders::OwnPages).await {
        return refusal.answer(&answering);
    }
    let parts = arrived.inbound.parts;
    let Some(fields) = sent_fields(parts, body).await else {
        return MALFORMED.answer(&answering);
    };
    let session = cookies::session_of(&parts.headers);
    match commands::token_command(fields, session) {
        Ok(command) => answered(gate, &arrived.inbound, command, &answering).await,
        Err(unread) => respond::refused(&answering, MALFORMED.status.as_u16(), &unread.code()),
    }
}

/// Shows the page of `action`, drawn by the API. Nothing here redirects: a
/// page that cannot be shown answers its status. The login page alone may
/// run the gateway's passkey script.
async fn show_page(gate: &Gate<'_>, arrived: &Arrived<'_>, action: SignInAction) -> Response {
    if let Err(refusal) = within_limit(gate.counters, &arrived.inbound).await {
        return respond::page_refused(refusal.status);
    }
    let query = Fields::from_query(arrived.inbound.parts.uri.query());
    let Some(command) = commands::page_command(action, query) else {
        return respond::page_refused(StatusCode::NOT_FOUND);
    };
    let script_src = format!(
        "https://{}{}",
        arrived.inbound.host,
        arrived.sign_in.script_path()
    );
    let script = match action {
        SignInAction::LogIn => PageScript::Passkey(&script_src),
        _ => PageScript::None,
    };
    match relayed(gate.broker, &arrived.inbound, command).await {
        Ok(WireOutcome::Page { html }) => respond::page(StatusCode::OK, html, script),
        Ok(WireOutcome::Rejected { status, .. }) => respond::page_refused(status_of(status.code())),
        Ok(_) => respond::page_refused(StatusCode::BAD_GATEWAY),
        Err(refusal) => respond::page_refused(refusal.status),
    }
}

/// Answers a browser on its way through a host of a service accepting the
/// sign-in with a cookie of its own, asking this owner's host for the hop's
/// code: relayed with this host's session cookie, the code comes back bound
/// to the digest the other host sent, and the browser goes back there with
/// it.
///
/// It arrives from the other host's redirect, another origin, so it is not
/// held to this host's pages; the code is bound to a value only the browser
/// that asked holds, and goes nowhere but the host the API named. A browser
/// that gets no code goes back to this host, signed in here either way.
async fn issue_hop_code(gate: &Gate<'_>, arrived: &Arrived<'_>) -> Response {
    let inbound = &arrived.inbound;
    let fields = Fields::from_query(inbound.parts.uri.query());
    let own_origin: Vec<HostOrigin> = HostOrigin::of(inbound.host).into_iter().collect();
    let next = fields.value("next");
    let fallback = format!(
        "https://{}{}",
        inbound.host,
        arrived.sign_in.after_sign_in()
    );
    let back_here = next
        .filter(|next| leads_to(next, &own_origin))
        .unwrap_or(&fallback);
    if within_limit(gate.counters, inbound).await.is_err() {
        return respond::see_other(back_here, []);
    }
    let session = cookies::session_of(&inbound.parts.headers);
    let Ok(command) = commands::hop_code_command(&fields, session) else {
        return respond::see_other(back_here, []);
    };
    match relayed(gate.broker, inbound, command).await {
        Ok(WireOutcome::HopIssued { host, code }) => {
            let land_at = hop_landing(&host, arrived.sign_in, &code, next);
            respond::hop_code_issued(&land_at)
        }
        Ok(_) | Err(_) => respond::see_other(back_here, []),
    }
}

/// The other host's hop address, carrying the code and where to go on.
fn hop_landing(host: &DomainName, sign_in: &AppSignIn, code: &str, next: Option<&str>) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("code", code);
    if let Some(next) = next {
        query.append_pair("next", next);
    }
    format!("https://{host}{}?{}", sign_in.hop_path(), query.finish())
}

/// Answers a hop on the host of a service accepting the sign-in with a
/// cookie of its own.
///
/// A hop arrives twice. Without a code, it is starting: the browser is
/// given a fresh value in this host's hop cookie and sent to the owner's
/// host it came from, which hands it a code bound to the value's digest.
/// With a code, it is landing: the code is relayed with the digest of the
/// value this browser holds, and sets the session only if they match. A
/// hop link sent to someone else carries a code bound to the sender's
/// browser, so it sets nothing in theirs.
///
/// The browser is sent on only to an origin of the same sign-in, and back
/// for a code only to one of the owner's, so the hop address is not a
/// redirect anyone can point anywhere. A hop that sets nothing still sends
/// the browser on: the person is signed in on the owner's host either way.
pub(crate) async fn hop(gate: &Gate<'_>, arrived: &HopArrived<'_>) -> Response {
    let parts = arrived.inbound.parts;
    let fields = Fields::from_query(parts.uri.query());
    let onward = fields
        .value("next")
        .filter(|next| leads_to(next, arrived.onward_origins));
    if parts.method != Method::GET {
        return respond::hop_failed(StatusCode::METHOD_NOT_ALLOWED, None);
    }
    if let Err(refusal) = within_limit(gate.counters, &arrived.inbound).await {
        return respond::hop_failed(refusal.status, onward);
    }
    match fields.value("code") {
        Some(code) => land_hop(gate, arrived, code, onward).await,
        None => start_hop(arrived, &fields, onward),
    }
}

/// The first leg of a hop: a fresh value kept in this host's hop cookie, and
/// the browser sent to the owner's host it came from for a code bound to it.
fn start_hop(arrived: &HopArrived<'_>, fields: &Fields, onward: Option<&str>) -> Response {
    let parts = arrived.inbound.parts;
    let Some(from) = fields.value("from").filter(|from| {
        arrived
            .owner_origins
            .iter()
            .any(|own| own.as_str() == *from)
    }) else {
        return respond::hop_failed(StatusCode::BAD_REQUEST, onward);
    };
    let value = fresh_value();
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("host", arrived.inbound.host.as_str())
        .append_pair("browser", &browser_digest(&value));
    if let Some(onward) = onward {
        query.append_pair("next", onward);
    }
    let fetch_code = format!("{from}{}?{}", parts.uri.path(), query.finish());
    respond::hop_started(&value, &fetch_code)
}

/// The last leg of a hop: the code relayed with the digest of the value
/// this browser keeps here. A browser keeping none never asked for a code.
async fn land_hop(
    gate: &Gate<'_>,
    arrived: &HopArrived<'_>,
    code: &str,
    onward: Option<&str>,
) -> Response {
    let Some(value) = cookies::hop_value_of(&arrived.inbound.parts.headers) else {
        return respond::hop_failed(StatusCode::FORBIDDEN, onward);
    };
    let command = WireCommand::Hop {
        code: code.to_owned(),
        browser: browser_digest(&value),
    };
    match relayed(gate.broker, &arrived.inbound, command).await {
        Ok(WireOutcome::HandedOver { token, expires_at }) => {
            respond::handed_over(&token, expires_at, onward)
        }
        Ok(WireOutcome::Rejected { status, .. }) => {
            respond::hop_failed(status_of(status.code()), onward)
        }
        Ok(_) => respond::hop_failed(StatusCode::BAD_GATEWAY, onward),
        Err(refusal) => respond::hop_failed(refusal.status, onward),
    }
}

/// The digest of a hop value, URL-safe: what leaves the browser's own host,
/// so the value itself is never written into an address.
fn browser_digest(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

/// 32 random bytes, URL-safe, for a browser to keep while a hop is under
/// way.
fn fresh_value() -> String {
    let bytes: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The answer to `command`, relayed.
async fn answered(
    gate: &Gate<'_>,
    inbound: &Inbound<'_>,
    command: WireCommand,
    answering: &Answering<'_>,
) -> Response {
    match relayed(gate.broker, inbound, command).await {
        Ok(outcome) => respond::outcome(answering, outcome),
        Err(refusal) => refusal.answer(answering),
    }
}

/// What the API answered `command` with. An API that cannot be asked, or
/// does not answer in time, is a refusal.
async fn relayed(
    broker: &dyn AppSignInBroker,
    inbound: &Inbound<'_>,
    command: WireCommand,
) -> Result<WireOutcome, Refusal> {
    let request = WireRequest {
        v: WIRE_VERSION,
        ctx: context(inbound).ok_or(NO_ANSWER)?,
        command,
    };
    match tokio::time::timeout(RELAY_TIMEOUT, broker.submit(request)).await {
        Ok(Ok(outcome)) => Ok(outcome),
        Ok(Err(error)) => {
            tracing::warn!(%error, "an app sign-in could not be relayed");
            Err(NO_ANSWER)
        }
        Err(_) => {
            tracing::warn!("an app sign-in relay did not answer in time");
            Err(NO_ANSWER)
        }
    }
}

/// Whether the request may go on: sent by whom `senders` allows, and within
/// its address's limit.
async fn admit(
    counters: &dyn FleetCounters,
    inbound: &Inbound<'_>,
    senders: Senders,
) -> Result<(), Refusal> {
    let own_page = from_same_origin(&inbound.parts.headers, inbound.host.as_str());
    if senders == Senders::OwnPages && !own_page {
        return Err(CROSS_SITE);
    }
    within_limit(counters, inbound).await
}

/// Counts the request against its address's limit on this host, across
/// every gateway. A count that cannot be made refuses.
async fn within_limit(counters: &dyn FleetCounters, inbound: &Inbound<'_>) -> Result<(), Refusal> {
    let key = format!(
        "app-sign-in:{}:{}:{}",
        inbound.tenant.as_uuid().simple(),
        inbound.host,
        inbound.client_ip
    );
    match tokio::time::timeout(COUNT_TIMEOUT, counters.count(&key, LIMIT_WINDOW)).await {
        Ok(Some(count)) if count <= PER_ADDRESS_PER_WINDOW => Ok(()),
        Ok(Some(_)) => Err(TOO_MANY),
        Ok(None) | Err(_) => Err(NO_ANSWER),
    }
}

/// Who may send `action`: a link from a mailbox is opened from anywhere,
/// and a provider sends the browser back from its own site.
fn senders(action: SignInAction) -> Senders {
    match action {
        SignInAction::Verify | SignInAction::ConfirmSignIn | SignInAction::SsoCallback => {
            Senders::Anyone
        }
        SignInAction::LogIn
        | SignInAction::SignUp
        | SignInAction::Mfa
        | SignInAction::LogOut
        | SignInAction::Sso
        | SignInAction::Passkey
        | SignInAction::ForgotPassword
        | SignInAction::ResetPassword
        | SignInAction::ChangePassword => Senders::OwnPages,
    }
}

/// How to answer `action` before anything was read. A passkey is answered
/// as JSON: only a script can hand its challenge to the authenticator.
fn answering<'a>(arrived: &'a Arrived<'_>, action: SignInAction) -> Answering<'a> {
    let client = match action {
        SignInAction::Passkey => Client::Script,
        _ => Client::of(&arrived.inbound.parts.headers),
    };
    Answering {
        client,
        host: arrived.inbound.host,
        sign_in: arrived.sign_in,
        step: Step::Action(action),
        return_to: None,
    }
}

/// What was asked, as answering it needs: a reset or a change carries the
/// mailed link's `token` it was sent with, so a refused browser can try
/// again from the same link.
fn step_of(action: SignInAction, token: Option<&str>) -> Step {
    match (action, token) {
        (SignInAction::ResetPassword, Some(token)) => Step::Reset {
            token: token.to_owned(),
        },
        (SignInAction::ChangePassword, token) => Step::ChangePassword {
            token: token.map(str::to_owned),
        },
        (action, _) => Step::Action(action),
    }
}

/// The fields sent: the query of a `GET`, the body of anything else.
/// `None` when the body could not be read whole and in time.
async fn sent_fields(parts: &Parts, body: SentBody) -> Option<Fields> {
    if parts.method == Method::GET {
        return Some(Fields::from_query(parts.uri.query()));
    }
    let collected = tokio::time::timeout(BODY_TIMEOUT, body.collect())
        .await
        .ok()?
        .ok()?;
    let content_type = header(&parts.headers, http::header::CONTENT_TYPE.as_str());
    Some(Fields::read(content_type, &collected.to_bytes()))
}

fn carried(parts: &Parts) -> Carried {
    Carried {
        challenge: cookies::challenge_of(&parts.headers),
        session: cookies::session_of(&parts.headers),
        single_sign_on: cookies::kept_sign_on(&parts.headers),
        device: cookies::device_of(&parts.headers),
        fresh_device: cookies::fresh_device_secret(),
    }
}

/// Where the request came from, as the API is told, with a fresh nonce.
fn context(inbound: &Inbound<'_>) -> Option<WireContext> {
    Some(WireContext {
        tenant_id: inbound.tenant,
        service_id: inbound.service,
        host: inbound.host.clone(),
        client_ip: Some(inbound.client_ip.to_string()),
        user_agent: header(&inbound.parts.headers, "user-agent").map(str::to_owned),
        accept_language: header(&inbound.parts.headers, "accept-language").map(str::to_owned),
        ts: clock::now().unix_timestamp(),
        nonce: fresh_nonce()?,
    })
}

/// 32 random bytes, URL-safe: used once, so a captured request cannot be
/// sent again.
fn fresh_nonce() -> Option<Nonce> {
    let bytes: [u8; 32] = rand::random();
    Nonce::new(URL_SAFE_NO_PAD.encode(bytes)).ok()
}

/// The status the API refused with, which is always an error status.
fn status_of(code: u16) -> StatusCode {
    StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use http::header::{CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
    use http_body_util::Full;
    use ianua_app::ports::authentication::{WirePage, WireSsoAnswer};
    use ianua_domain::domains::routing::sign_in::app::{AppSignInParams, SignedOutBrowsers};
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{CeremonyId, DenialStatus, Setting};

    use super::*;
    use crate::app_sign_in::{Addressed, addressed};

    const SAME_ORIGIN: (&str, &str) = ("sec-fetch-site", "same-origin");
    const CROSS_SITE_PAGE: (&str, &str) = ("sec-fetch-site", "cross-site");
    const FORM: (&str, &str) = ("content-type", "application/x-www-form-urlencoded");
    const JSON: (&str, &str) = ("content-type", "application/json");
    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    type Answered = fn() -> Result<WireOutcome, DomainError>;

    /// The API, as the gateway reaches it: answers with `answer` and keeps
    /// every request it was sent.
    struct Api {
        answer: Answered,
        sent: Mutex<Vec<WireRequest>>,
    }

    impl Api {
        fn answering(answer: Answered) -> Self {
            Self {
                answer,
                sent: Mutex::new(Vec::new()),
            }
        }

        fn unreachable() -> Self {
            Self::answering(|| Err(DomainError::infra_msg("connection refused")))
        }

        fn was_asked(&self) -> bool {
            !self.sent.lock().unwrap().is_empty()
        }

        fn last(&self) -> WireRequest {
            self.sent
                .lock()
                .unwrap()
                .pop()
                .expect("the API was not asked")
        }
    }

    #[async_trait]
    impl AppSignInBroker for Api {
        async fn submit(&self, request: WireRequest) -> Result<WireOutcome, DomainError> {
            self.sent.lock().unwrap().push(request);
            (self.answer)()
        }
    }

    /// The shared counters, answering every count with the same number, or
    /// with nothing when the cache cannot be reached.
    struct Counted(Option<u32>);

    #[async_trait]
    impl FleetCounters for Counted {
        async fn count(&self, _key: &str, _window: Seconds) -> Option<u32> {
            self.0
        }

        async fn add(&self, _key: &str, _delta: u32, _window: Seconds) -> Option<u32> {
            self.0
        }

        async fn adjust(&self, _key: &str, _delta: i64, _window: Seconds) -> Option<u32> {
            self.0
        }

        async fn read(&self, _key: &str) -> Option<u32> {
            self.0
        }

        async fn hold(&self, _key: &str, _lasts: Seconds) -> Option<()> {
            self.0.map(|_| ())
        }

        async fn add_distinct(
            &self,
            _key: &str,
            _members: &[String],
            _window: Seconds,
        ) -> Option<u32> {
            self.0
        }

        async fn claim_once(&self, _key: &str, _ttl: Seconds) -> Option<bool> {
            None
        }
    }

    const FIRST: Counted = Counted(Some(1));

    struct Shop {
        sign_in: AppSignIn,
        host: DomainName,
        tenant: TenantId,
        service: ServiceId,
    }

    /// The shop: its sign-in under `/.ianua`, on `shop.example.com`.
    fn shop() -> Shop {
        Shop {
            sign_in: AppSignIn::new(AppSignInParams {
                hosts: vec![DomainName::new("shop.example.com").unwrap()],
                prefix: Setting::Unset,
                moved: BTreeMap::new(),
                after_sign_in: Setting::Unset,
                signed_out_browsers: SignedOutBrowsers::Refuse,
            })
            .unwrap(),
            host: DomainName::new("shop.example.com").unwrap(),
            tenant: TenantId::new(),
            service: ServiceId::new(),
        }
    }

    fn request(
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> http::Request<Full<Bytes>> {
        let builder = headers.iter().fold(
            http::Request::builder().method(method).uri(uri),
            |builder, (name, value)| builder.header(*name, *value),
        );
        builder
            .body(Full::new(Bytes::from(body.to_owned())))
            .unwrap()
    }

    fn post(uri: &str, headers: &[(&str, &str)], body: &str) -> http::Request<Full<Bytes>> {
        request(Method::POST, uri, headers, body)
    }

    fn get(uri: &str, headers: &[(&str, &str)]) -> http::Request<Full<Bytes>> {
        request(Method::GET, uri, headers, "")
    }

    /// Sends `request` to the shop's host as the request layer would: only
    /// once it is found to be at a sign-in address.
    async fn send<B>(
        api: &Api,
        counters: &Counted,
        shop: &Shop,
        request: http::Request<B>,
    ) -> Response
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let (parts, body) = request.into_parts();
        let Addressed::SignIn(asked) = addressed(&shop.sign_in, &parts.method, parts.uri.path())
        else {
            panic!("{} is not a sign-in address", parts.uri);
        };
        let arrived = Arrived {
            inbound: Inbound {
                tenant: shop.tenant,
                service: shop.service,
                host: &shop.host,
                parts: &parts,
                client_ip: CLIENT,
            },
            sign_in: &shop.sign_in,
            asked,
        };
        let gate = Gate {
            broker: api,
            counters,
        };
        answer(&gate, &arrived, body).await
    }

    fn set_cookies(response: &Response) -> Vec<String> {
        response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect()
    }

    fn location(response: &Response) -> &str {
        response.headers()[LOCATION].to_str().unwrap()
    }

    fn later() -> i64 {
        clock::now().unix_timestamp() + 3600
    }

    /// A successful sign-in opens the shop session and returns to its orders page.
    fn signed_in() -> WireOutcome {
        WireOutcome::SignedIn {
            token: "tok".to_owned(),
            expires_at: later(),
            return_to: "/orders".to_owned(),
            hops: Vec::new(),
            remembered_device: None,
        }
    }

    /// A command acknowledged without opening a session or returning a token.
    fn accepted() -> WireOutcome {
        WireOutcome::Accepted
    }

    const LOG_IN: &str = "email=ann%40example.com&password=pw";

    /// Eve's page posts the shop's login form with her own account, to sign
    /// Ann's browser in as Eve. The gateway refuses it before the API hears
    /// of it.
    #[tokio::test]
    async fn a_cross_site_post_is_refused_and_never_relayed() {
        let (api, shop) = (Api::answering(|| Ok(signed_in())), shop());

        for headers in [
            vec![CROSS_SITE_PAGE, FORM],
            vec![("sec-fetch-site", "same-site"), FORM],
            vec![("origin", "https://evil.example.com"), FORM],
            vec![FORM],
        ] {
            let response = send(&api, &FIRST, &shop, post("/.ianua/login", &headers, LOG_IN)).await;

            assert_eq!(
                location(&response),
                "https://shop.example.com/.ianua/login?error=cross_site"
            );
            assert!(set_cookies(&response).is_empty());
        }
        assert!(!api.was_asked());
    }

    #[tokio::test]
    async fn a_cross_site_script_is_refused_with_forbidden() {
        let (api, shop) = (Api::answering(|| Ok(signed_in())), shop());

        let response = send(
            &api,
            &FIRST,
            &shop,
            post(
                "/.ianua/login",
                &[CROSS_SITE_PAGE, JSON],
                r#"{"email":"a@b.c","password":"pw"}"#,
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!api.was_asked());
    }

    #[tokio::test]
    async fn an_address_over_its_limit_is_refused() {
        let (api, shop) = (Api::answering(|| Ok(signed_in())), shop());
        let over = Counted(Some(PER_ADDRESS_PER_WINDOW + 1));

        let response = send(
            &api,
            &over,
            &shop,
            post("/.ianua/login", &[SAME_ORIGIN, JSON], "{}"),
        )
        .await;

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(!api.was_asked());
    }

    /// The count is shared by every gateway; one that cannot be made would
    /// let a flood through, so it refuses.
    #[tokio::test]
    async fn a_limit_that_cannot_be_counted_refuses() {
        let (api, shop) = (Api::answering(|| Ok(signed_in())), shop());

        let response = send(
            &api,
            &Counted(None),
            &shop,
            post(
                "/.ianua/login",
                &[SAME_ORIGIN, JSON],
                r#"{"email":"a@b.c","password":"pw"}"#,
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!api.was_asked());
    }

    #[tokio::test]
    async fn an_api_that_cannot_be_reached_refuses() {
        let (api, shop) = (Api::unreachable(), shop());

        let response = send(
            &api,
            &FIRST,
            &shop,
            post(
                "/.ianua/login",
                &[SAME_ORIGIN, JSON],
                r#"{"email":"a@b.c","password":"pw"}"#,
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(set_cookies(&response).is_empty());
    }

    #[tokio::test]
    async fn an_api_answer_that_does_not_fit_refuses() {
        let api = Api::answering(|| {
            Ok(WireOutcome::Page {
                html: "<p>".to_owned(),
            })
        });
        let shop = shop();

        let response = send(
            &api,
            &FIRST,
            &shop,
            post(
                "/.ianua/login",
                &[SAME_ORIGIN, JSON],
                r#"{"email":"a@b.c","password":"pw"}"#,
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn a_body_too_large_to_read_is_refused() {
        let (api, shop) = (Api::answering(|| Ok(signed_in())), shop());
        let body = format!("email=a&password={}", "x".repeat(MAX_BODY_BYTES));

        let response = send(
            &api,
            &FIRST,
            &shop,
            post("/.ianua/login", &[SAME_ORIGIN, FORM], &body),
        )
        .await;

        assert_eq!(
            location(&response),
            "https://shop.example.com/.ianua/login?error=malformed"
        );
        assert!(!api.was_asked());
    }

    /// Ann signs in from the shop's own page. The API hears where the
    /// request came from, and her browser gets the session in a cookie only
    /// this host can read.
    #[tokio::test]
    async fn logging_in_relays_the_form_and_sets_the_session_cookie() {
        let (api, shop) = (Api::answering(|| Ok(signed_in())), shop());

        let response = send(
            &api,
            &FIRST,
            &shop,
            post("/.ianua/login", &[SAME_ORIGIN, FORM], LOG_IN),
        )
        .await;

        let sent = api.last();
        assert_eq!(sent.v, WIRE_VERSION);
        assert_eq!(sent.ctx.tenant_id, shop.tenant);
        assert_eq!(sent.ctx.service_id, shop.service);
        assert_eq!(sent.ctx.host, shop.host);
        assert_eq!(sent.ctx.client_ip.as_deref(), Some("203.0.113.7"));
        assert!(
            matches!(sent.command, WireCommand::LogIn { email, .. } if email == "ann@example.com")
        );
        assert_eq!(location(&response), "https://shop.example.com/orders");
        let session = set_cookies(&response)
            .into_iter()
            .find(|cookie| cookie.starts_with("__Host-ianua_app=tok;"))
            .expect("no session cookie");
        for part in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
            assert!(session.contains(part), "{part} missing from {session}");
        }
        assert_eq!(response.headers()["cache-control"], "no-store");
    }

    #[tokio::test]
    async fn every_request_carries_a_fresh_nonce() {
        let (api, shop) = (Api::answering(|| Ok(signed_in())), shop());

        for _ in 0..2 {
            send(
                &api,
                &FIRST,
                &shop,
                post("/.ianua/login", &[SAME_ORIGIN, FORM], LOG_IN),
            )
            .await;
        }

        let (second, first) = (api.last(), api.last());
        assert_ne!(first.ctx.nonce, second.ctx.nonce);
    }

    #[tokio::test]
    async fn signing_up_is_relayed() {
        let (api, shop) = (Api::answering(|| Ok(accepted())), shop());

        let response = send(
            &api,
            &FIRST,
            &shop,
            post(
                "/.ianua/signup",
                &[SAME_ORIGIN, FORM],
                "email=a%40b.c&display_name=Ann&password=pw",
            ),
        )
        .await;

        assert!(matches!(api.last().command, WireCommand::SignUp { .. }));
        assert_eq!(
            location(&response),
            "https://shop.example.com/.ianua/login?check_email=1"
        );
    }

    #[tokio::test]
    async fn the_second_factor_is_relayed_with_the_challenge_cookie() {
        let (api, shop) = (Api::answering(|| Ok(signed_in())), shop());

        send(
            &api,
            &FIRST,
            &shop,
            post(
                "/.ianua/mfa",
                &[SAME_ORIGIN, FORM, ("cookie", "__Host-ianua_mfa=chal")],
                "code=123456",
            ),
        )
        .await;

        assert!(matches!(
            api.last().command,
            WireCommand::CompleteMfa { challenge, code, .. } if challenge == "chal" && code == "123456"
        ));
    }

    /// Bob's browser holds the device cookie of a laptop he remembered on
    /// the shop. His sign-in carries its secret to the API.
    #[tokio::test]
    async fn logging_in_carries_the_device_cookie() {
        let (api, shop) = (Api::answering(|| Ok(signed_in())), shop());

        send(
            &api,
            &FIRST,
            &shop,
            post(
                "/.ianua/login",
                &[SAME_ORIGIN, FORM, ("cookie", "__Host-ianua_device=d3v1c3")],
                LOG_IN,
            ),
        )
        .await;

        assert!(matches!(
            api.last().command,
            WireCommand::LogIn { device: Some(device), .. } if device == "d3v1c3"
        ));
    }

    /// A completed sign-in also returns the fresh secret for the remembered device cookie.
    fn remembered() -> WireOutcome {
        WireOutcome::SignedIn {
            token: "tok".to_owned(),
            expires_at: later(),
            return_to: "/orders".to_owned(),
            hops: Vec::new(),
            remembered_device: Some("ab".repeat(32)),
        }
    }

    /// Bob ticks "remember this device" with his code. The API is sent a
    /// fresh secret of 64 hex digits, and once it remembered the device the
    /// browser keeps the secret in the host's device cookie.
    #[tokio::test]
    async fn remembering_the_device_sends_a_fresh_secret_and_keeps_it() {
        let (api, shop) = (Api::answering(|| Ok(remembered())), shop());

        let response = send(
            &api,
            &FIRST,
            &shop,
            post(
                "/.ianua/mfa",
                &[SAME_ORIGIN, FORM, ("cookie", "__Host-ianua_mfa=chal")],
                "code=123456&remember_device=yes",
            ),
        )
        .await;

        let WireCommand::CompleteMfa {
            remember_device: Some(secret),
            ..
        } = api.last().command
        else {
            panic!("the device was not asked to be remembered");
        };
        assert_eq!(secret.len(), 64);
        assert!(secret.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let device = set_cookies(&response)
            .into_iter()
            .find(|cookie| cookie.starts_with("__Host-ianua_device="))
            .expect("no device cookie");
        assert!(device.starts_with(&format!("__Host-ianua_device={};", "ab".repeat(32))));
        assert!(device.contains("HttpOnly"));
    }

    /// A mailed link is opened from the mailbox, another site: it is not
    /// refused for that.
    #[tokio::test]
    async fn a_mailed_link_is_relayed_from_anywhere() {
        let (api, shop) = (Api::answering(|| Ok(accepted())), shop());

        let response = send(
            &api,
            &FIRST,
            &shop,
            get("/.ianua/verify?token=abc", &[CROSS_SITE_PAGE]),
        )
        .await;

        assert!(matches!(api.last().command, WireCommand::Verify { token } if token == "abc"));
        assert_eq!(
            location(&response),
            "https://shop.example.com/.ianua/login?verified=1"
        );
    }

    #[tokio::test]
    async fn a_confirm_link_in_the_waiting_browser_confirms_its_sign_in() {
        let (api, shop) = (Api::answering(|| Ok(signed_in())), shop());

        send(
            &api,
            &FIRST,
            &shop,
            get(
                "/.ianua/confirm-sign-in?token=abc",
                &[CROSS_SITE_PAGE, ("cookie", "__Host-ianua_mfa=chal")],
            ),
        )
        .await;

        assert!(matches!(
            api.last().command,
            WireCommand::ConfirmByEmail { challenge, link, .. } if challenge == "chal" && link == "abc"
        ));
    }

    /// Ann's sign-in waits on her mailbox when she opens an older link
    /// verifying her address. The verify address verifies, whatever cookie
    /// her browser holds: the two links are never told apart by one.
    #[tokio::test]
    async fn a_verify_link_in_a_waiting_browser_still_verifies() {
        let (api, shop) = (Api::answering(|| Ok(accepted())), shop());

        send(
            &api,
            &FIRST,
            &shop,
            get(
                "/.ianua/verify?token=abc",
                &[CROSS_SITE_PAGE, ("cookie", "__Host-ianua_mfa=chal")],
            ),
        )
        .await;

        assert!(matches!(api.last().command, WireCommand::Verify { token } if token == "abc"));
    }

    #[tokio::test]
    async fn signing_out_relays_the_session_and_clears_the_cookies() {
        let (api, shop) = (Api::answering(|| Ok(WireOutcome::SignedOut)), shop());

        let response = send(
            &api,
            &FIRST,
            &shop,
            post(
                "/.ianua/logout",
                &[SAME_ORIGIN, FORM, ("cookie", "__Host-ianua_app=tok")],
                "",
            ),
        )
        .await;

        assert!(matches!(
            api.last().command,
            WireCommand::LogOut { session } if session.as_deref() == Some("tok")
        ));
        assert!(
            set_cookies(&response)
                .iter()
                .any(|c| c.starts_with("__Host-ianua_app=;"))
        );
        assert!(
            !set_cookies(&response)
                .iter()
                .any(|c| c.starts_with("__Host-ianua_device=")),
            "signing out forgets no remembered device"
        );
    }

    /// Ann picks her company's provider on the login page: following the
    /// link starts the sign-on, and her browser keeps its secrets on the way.
    #[tokio::test]
    async fn a_single_sign_on_starts_from_the_login_pages_link() {
        let api = Api::answering(|| {
            Ok(WireOutcome::SsoRedirect {
                url: "https://idp.example.com/authorize".to_owned(),
                binding: "bind".to_owned(),
                hand_back: "back".to_owned(),
                return_to: Some("/orders".to_owned()),
            })
        });
        let shop = shop();
        let connection = uuid::Uuid::now_v7();

        let response = send(
            &api,
            &FIRST,
            &shop,
            get(
                &format!("/.ianua/sso?connection_id={connection}"),
                &[SAME_ORIGIN],
            ),
        )
        .await;

        assert!(matches!(
            api.last().command,
            WireCommand::Sso { connection_id, .. } if *connection_id.as_uuid() == connection
        ));
        assert_eq!(location(&response), "https://idp.example.com/authorize");
        assert!(
            set_cookies(&response)
                .iter()
                .any(|c| c.starts_with("__Host-ianua_sso="))
        );
    }

    #[tokio::test]
    async fn a_single_sign_on_started_by_another_site_is_refused() {
        let (api, shop) = (Api::answering(|| Ok(signed_in())), shop());
        let connection = uuid::Uuid::now_v7();

        send(
            &api,
            &FIRST,
            &shop,
            get(
                &format!("/.ianua/sso?connection_id={connection}"),
                &[CROSS_SITE_PAGE],
            ),
        )
        .await;

        assert!(!api.was_asked());
    }

    const KEPT: (&str, &str) = ("cookie", "__Host-ianua_sso=b=bind&h=back&r=%2Forders");

    /// An OIDC provider sends Ann's browser back with a `GET` from its own
    /// site; what her browser kept goes with the answer, and is spent.
    #[tokio::test]
    async fn an_oidc_return_is_relayed_with_what_the_browser_kept() {
        let (api, shop) = (Api::answering(|| Ok(signed_in())), shop());

        let response = send(
            &api,
            &FIRST,
            &shop,
            get(
                "/.ianua/sso-callback?state=st&code=co",
                &[CROSS_SITE_PAGE, KEPT],
            ),
        )
        .await;

        assert_oidc_return(&api.last().command);
        assert!(
            set_cookies(&response)
                .iter()
                .any(|c| c.starts_with("__Host-ianua_sso=;"))
        );
        assert!(
            set_cookies(&response)
                .iter()
                .any(|c| c.starts_with("__Host-ianua_app=tok;"))
        );
    }

    /// Checks both the provider's answer and the browser's retained sign-on secrets.
    fn assert_oidc_return(command: &WireCommand) {
        let WireCommand::SsoCallback {
            answer: WireSsoAnswer::Oidc { state, code },
            binding,
            hand_back,
            return_to,
        } = command
        else {
            panic!("an OIDC return was not relayed as one");
        };
        assert_eq!((state.as_str(), code.as_str()), ("st", "co"));
        assert_eq!((binding.as_str(), hand_back.as_str()), ("bind", "back"));
        assert_eq!(return_to.as_deref(), Some("/orders"));
    }

    /// A SAML provider posts Ann's browser back from its own site.
    #[tokio::test]
    async fn a_saml_return_is_relayed_from_the_posted_form() {
        let (api, shop) = (Api::answering(|| Ok(signed_in())), shop());

        send(
            &api,
            &FIRST,
            &shop,
            post(
                "/.ianua/sso-callback",
                &[CROSS_SITE_PAGE, FORM, KEPT],
                "SAMLResponse=PHNhbWw%2B&RelayState=id-1",
            ),
        )
        .await;

        assert!(matches!(
            api.last().command,
            WireCommand::SsoCallback {
                answer: WireSsoAnswer::Saml { relay_state, saml_response },
                ..
            } if relay_state == "id-1" && saml_response == "PHNhbWw+"
        ));
    }

    /// Eve sends Ann's browser the provider's answer for Eve's own sign-on.
    /// Ann's browser kept nothing, so it is refused, and anything kept is
    /// cleared all the same.
    #[tokio::test]
    async fn a_return_to_a_browser_that_started_nothing_is_refused() {
        let (api, shop) = (Api::answering(|| Ok(signed_in())), shop());

        let response = send(
            &api,
            &FIRST,
            &shop,
            get("/.ianua/sso-callback?state=st&code=co", &[CROSS_SITE_PAGE]),
        )
        .await;

        assert!(!api.was_asked());
        assert!(location(&response).contains("error=missing_single_sign_on"));
        assert!(
            set_cookies(&response)
                .iter()
                .any(|c| c.starts_with("__Host-ianua_sso=;"))
        );
    }

    #[tokio::test]
    async fn a_passkey_challenge_is_asked_for_and_answered_as_json() {
        let api = Api::answering(|| {
            Ok(WireOutcome::PasskeyChallenge {
                ceremony_id: CeremonyId::new(),
                options: vec![1, 2, 3],
            })
        });
        let shop = shop();

        let response = send(
            &api,
            &FIRST,
            &shop,
            post("/.ianua/passkey", &[SAME_ORIGIN, FORM], "email=a%40b.c"),
        )
        .await;

        assert!(matches!(
            api.last().command,
            WireCommand::PasskeyBegin { email } if email.as_deref() == Some("a@b.c")
        ));
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
    }

    #[tokio::test]
    async fn a_passkey_answer_is_relayed() {
        let (api, shop) = (Api::answering(|| Ok(signed_in())), shop());
        let ceremony = uuid::Uuid::now_v7();
        let body =
            format!(r#"{{"ceremony_id":"{ceremony}","credential_id":"AQID","response":"BAUG"}}"#);

        let response = send(
            &api,
            &FIRST,
            &shop,
            post("/.ianua/passkey", &[SAME_ORIGIN, JSON], &body),
        )
        .await;

        assert!(matches!(
            api.last().command,
            WireCommand::PasskeyConfirm { ceremony_id, .. } if *ceremony_id.as_uuid() == ceremony
        ));
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn asking_for_a_new_password_is_relayed() {
        let (api, shop) = (Api::answering(|| Ok(accepted())), shop());

        let response = send(
            &api,
            &FIRST,
            &shop,
            post(
                "/.ianua/forgot-password",
                &[SAME_ORIGIN, FORM],
                "email=a%40b.c",
            ),
        )
        .await;

        assert!(
            matches!(api.last().command, WireCommand::ForgotPassword { email } if email == "a@b.c")
        );
        assert_eq!(
            location(&response),
            "https://shop.example.com/.ianua/login?check_email=1"
        );
    }

    #[tokio::test]
    async fn a_reset_from_the_mailed_link_is_relayed() {
        let (api, shop) = (Api::answering(|| Ok(accepted())), shop());

        let response = send(
            &api,
            &FIRST,
            &shop,
            post(
                "/.ianua/reset-password",
                &[SAME_ORIGIN, FORM],
                "token=reset&password=new",
            ),
        )
        .await;

        assert!(
            matches!(api.last().command, WireCommand::ResetPassword { token, .. } if token == "reset")
        );
        assert_eq!(
            location(&response),
            "https://shop.example.com/.ianua/login?password_reset=1"
        );
    }

    /// Ann's password was set by an administrator. Her sign-in left the
    /// change in her challenge cookie; she sets a new password with a code
    /// from her own factor, and is signed in.
    #[tokio::test]
    async fn the_password_change_a_sign_in_owes_is_relayed_and_finishes_it() {
        let (api, shop) = (Api::answering(|| Ok(signed_in())), shop());

        let response = send(
            &api,
            &FIRST,
            &shop,
            post(
                "/.ianua/change-password",
                &[SAME_ORIGIN, FORM, ("cookie", "__Host-ianua_mfa=change")],
                "password=new&mfa_code=123456",
            ),
        )
        .await;

        assert!(matches!(
            api.last().command,
            WireCommand::ChangePassword { challenge, mfa_code, .. }
                if challenge == "change" && mfa_code.as_deref() == Some("123456")
        ));
        assert!(
            set_cookies(&response)
                .iter()
                .any(|c| c.starts_with("__Host-ianua_app=tok;"))
        );
    }

    #[tokio::test]
    async fn a_password_change_owed_keeps_its_token_for_the_next_step() {
        let api = Api::answering(|| {
            Ok(WireOutcome::PasswordChangeRequired {
                challenge: Some("change".to_owned()),
                proof: "own_factor".to_owned(),
                reason: "set_by_admin".to_owned(),
                expires_at: later(),
            })
        });
        let shop = shop();

        let response = send(
            &api,
            &FIRST,
            &shop,
            post("/.ianua/login", &[SAME_ORIGIN, FORM], LOG_IN),
        )
        .await;

        assert!(
            set_cookies(&response)
                .iter()
                .any(|c| c.starts_with("__Host-ianua_mfa=change;"))
        );
        assert!(
            !set_cookies(&response)
                .iter()
                .any(|c| c.starts_with("__Host-ianua_app="))
        );
        assert!(location(&response).starts_with(
            "https://shop.example.com/.ianua/change-password?password_change_required=1"
        ));
    }

    #[tokio::test]
    async fn a_token_is_relayed_for_the_owners_own_pages_only() {
        let api = Api::answering(|| Ok(issued_token()));
        let shop = shop();
        let ask = r#"{"audience":"shop-api"}"#;

        let foreign = send(
            &api,
            &FIRST,
            &shop,
            post("/.ianua/token", &[CROSS_SITE_PAGE, JSON], ask),
        )
        .await;
        assert_eq!(foreign.status(), StatusCode::FORBIDDEN);
        assert!(!api.was_asked());

        let own = send(
            &api,
            &FIRST,
            &shop,
            post(
                "/.ianua/token",
                &[SAME_ORIGIN, JSON, ("cookie", "__Host-ianua_app=tok")],
                ask,
            ),
        )
        .await;
        assert_eq!(own.status(), StatusCode::OK);
        assert!(matches!(
            api.last().command,
            WireCommand::IssueToken { session, audience }
                if session.as_deref() == Some("tok") && audience == "shop-api"
        ));
    }

    /// A short-lived token returned by the API for the shop's own pages.
    fn issued_token() -> WireOutcome {
        WireOutcome::Token {
            access_token: "access".to_owned(),
            expires_at: later(),
        }
    }

    #[tokio::test]
    async fn a_page_is_drawn_by_the_api_and_served_without_script() {
        let api = Api::answering(|| {
            Ok(WireOutcome::Page {
                html: "<!doctype html>".to_owned(),
            })
        });
        let shop = shop();

        let response = send(
            &api,
            &FIRST,
            &shop,
            get("/.ianua/reset-password?token=reset", &[]),
        )
        .await;

        assert!(matches!(
            api.last().command,
            WireCommand::ShowPage { page: WirePage::ResetPassword, token, .. }
                if token.as_deref() == Some("reset")
        ));
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("content-security-policy"));
    }

    #[tokio::test]
    async fn a_page_the_api_refuses_answers_its_status_and_never_redirects() {
        let api = Api::answering(|| {
            Ok(WireOutcome::Rejected {
                status: DenialStatus::FORBIDDEN,
                code: "forbidden".to_owned(),
            })
        });
        let shop = shop();

        let response = send(&api, &FIRST, &shop, get("/.ianua/signup", &[])).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().get(LOCATION).is_none());
    }

    /// The API's host `api.example.com`, keeping a cookie of its own for
    /// the shop's sign-in.
    const API_HOST: &str = "api.example.com";

    /// The hop cookie Ann's browser keeps on the API's host.
    const ANNS_HOP: &str = "__Host-ianua_hop=anns-value";

    async fn hop_to(api: &Api, uri: &str, headers: &[(&str, &str)]) -> Response {
        let shop = shop();
        let api_host = DomainName::new(API_HOST).unwrap();
        let (parts, _) = get(uri, headers).into_parts();
        let owner = vec![HostOrigin::new("https://shop.example.com").unwrap()];
        let onward = vec![
            HostOrigin::new("https://shop.example.com").unwrap(),
            HostOrigin::of(&api_host).unwrap(),
        ];
        let arrived = HopArrived {
            inbound: Inbound {
                tenant: shop.tenant,
                service: shop.service,
                host: &api_host,
                parts: &parts,
                client_ip: CLIENT,
            },
            onward_origins: &onward,
            owner_origins: &owner,
        };
        let gate = Gate {
            broker: api,
            counters: &FIRST,
        };
        hop(&gate, &arrived).await
    }

    /// A completed host hop returns the session token for that host's cookie.
    fn handed_over() -> WireOutcome {
        WireOutcome::HandedOver {
            token: "tok".to_owned(),
            expires_at: later(),
        }
    }

    /// Ann's browser arrives on the API's host from signing in on the shop.
    /// It is given a value of its own in this host's hop cookie and sent
    /// back to the shop for a code bound to that value's digest; the API is
    /// not asked anything yet.
    #[tokio::test]
    async fn a_hop_starts_by_keeping_a_value_and_asking_the_owner_for_its_code() {
        let api = Api::answering(|| Ok(handed_over()));

        let response = hop_to(
            &api,
            "/.ianua/hop?from=https%3A%2F%2Fshop.example.com&next=https%3A%2F%2Fshop.example.com%2Forders",
            &[CROSS_SITE_PAGE],
        )
        .await;

        assert!(!api.was_asked());
        let cookie = set_cookies(&response)
            .into_iter()
            .find(|c| c.starts_with("__Host-ianua_hop="))
            .expect("no hop cookie");
        let value = cookie["__Host-ianua_hop=".len()..]
            .split(';')
            .next()
            .unwrap();
        let fetch_code = location(&response);
        assert!(
            fetch_code
                .starts_with("https://shop.example.com/.ianua/hop?host=api.example.com&browser=")
        );
        assert!(fetch_code.contains(&format!("browser={}", browser_digest(value))));
        assert!(!fetch_code.contains(value));
        assert!(fetch_code.ends_with("&next=https%3A%2F%2Fshop.example.com%2Forders"));
    }

    /// A hop naming an unapproved owner origin returns 400 without setting
    /// cookies or a redirect location.
    #[tokio::test]
    async fn a_hop_never_fetches_its_code_from_anyone_but_the_owner() {
        let api = Api::answering(|| Ok(handed_over()));

        let response = hop_to(
            &api,
            "/.ianua/hop?from=https%3A%2F%2Fevil.example.com",
            &[CROSS_SITE_PAGE],
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(LOCATION).is_none());
        assert!(set_cookies(&response).is_empty());
    }

    /// Ann's browser comes back from the shop with the code, holding the
    /// value it was given. The code is relayed with that value's digest, the
    /// session is set, the value is spent, and the browser goes on.
    #[tokio::test]
    async fn a_hop_sets_the_session_in_the_browser_that_asked_and_sends_it_on() {
        let api = Api::answering(|| Ok(handed_over()));

        let response = hop_to(
            &api,
            "/.ianua/hop?code=one&next=https%3A%2F%2Fshop.example.com%2Forders",
            &[CROSS_SITE_PAGE, ("cookie", ANNS_HOP)],
        )
        .await;

        let digest = browser_digest("anns-value");
        assert!(matches!(
            api.last().command,
            WireCommand::Hop { code, browser } if code == "one" && browser == digest
        ));
        assert_eq!(location(&response), "https://shop.example.com/orders");
        assert!(
            set_cookies(&response)
                .iter()
                .any(|c| c.starts_with("__Host-ianua_app=tok;"))
        );
        assert!(
            set_cookies(&response)
                .iter()
                .any(|c| c.starts_with("__Host-ianua_hop=;"))
        );
    }

    /// A hop code arriving without the browser's hop cookie is not relayed
    /// and sets no session cookie; the browser returns to the allowed shop URL.
    #[tokio::test]
    async fn a_hop_link_opened_in_another_browser_sets_nothing() {
        let api = Api::answering(|| Ok(handed_over()));

        let response = hop_to(
            &api,
            "/.ianua/hop?code=eves&next=https%3A%2F%2Fshop.example.com%2F",
            &[CROSS_SITE_PAGE],
        )
        .await;

        assert!(!api.was_asked());
        assert!(
            !set_cookies(&response)
                .iter()
                .any(|c| c.starts_with("__Host-ianua_app="))
        );
        assert_eq!(location(&response), "https://shop.example.com/");
    }

    /// Ann's browser holds a hop value of its own from an earlier hop. Eve's
    /// code arrives beside it: the API is told Ann's digest, which Eve's
    /// code was not bound to, and refuses; nothing is set.
    #[tokio::test]
    async fn a_hop_link_beside_another_value_is_relayed_with_that_value_and_refused() {
        let api = Api::answering(|| {
            Ok(WireOutcome::Rejected {
                status: DenialStatus::NOT_FOUND,
                code: "not_found".to_owned(),
            })
        });

        let response = hop_to(&api, "/.ianua/hop?code=eves", &[("cookie", ANNS_HOP)]).await;

        assert!(matches!(
            api.last().command,
            WireCommand::Hop { browser, .. } if browser == browser_digest("anns-value")
        ));
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(set_cookies(&response).is_empty());
    }

    #[tokio::test]
    async fn a_hop_never_sends_the_browser_off_its_sign_in() {
        let api = Api::answering(|| Ok(handed_over()));

        let response = hop_to(
            &api,
            "/.ianua/hop?code=one&next=https%3A%2F%2Fevil.example.com",
            &[("cookie", ANNS_HOP)],
        )
        .await;

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(response.headers().get(LOCATION).is_none());
    }

    #[tokio::test]
    async fn a_hop_the_api_cannot_answer_sets_nothing() {
        let api = Api::unreachable();

        let response = hop_to(&api, "/.ianua/hop?code=one", &[("cookie", ANNS_HOP)]).await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(set_cookies(&response).is_empty());
    }

    /// Ann's browser, on its way through the API's host, asks the shop for
    /// the hop's code. The shop's session cookie and the browser's digest go
    /// to the API, and the browser is sent back to the API's host with the
    /// code it was handed.
    #[tokio::test]
    async fn the_owner_hands_a_browser_on_its_way_the_hops_code() {
        let api = Api::answering(|| {
            Ok(WireOutcome::HopIssued {
                host: DomainName::new(API_HOST).unwrap(),
                code: "c0de".to_owned(),
            })
        });
        let shop = shop();

        let response = send(
            &api,
            &FIRST,
            &shop,
            get(
                "/.ianua/hop?host=api.example.com&browser=d1g35t&next=https%3A%2F%2Fshop.example.com%2F",
                &[CROSS_SITE_PAGE, ("cookie", "__Host-ianua_app=tok")],
            ),
        )
        .await;

        assert!(matches!(
            api.last().command,
            WireCommand::IssueHop { session, host, browser }
                if session.as_deref() == Some("tok")
                    && host.as_str() == API_HOST
                    && browser == "d1g35t"
        ));
        assert_eq!(
            location(&response),
            "https://api.example.com/.ianua/hop?code=c0de&next=https%3A%2F%2Fshop.example.com%2F"
        );
    }

    /// A browser the API hands no code goes back to the shop, signed in
    /// there either way, never on to the host it named.
    #[tokio::test]
    async fn a_browser_handed_no_code_goes_back_to_the_owner() {
        let api = Api::answering(|| {
            Ok(WireOutcome::Rejected {
                status: DenialStatus::FORBIDDEN,
                code: "forbidden".to_owned(),
            })
        });
        let shop = shop();

        let response = send(
            &api,
            &FIRST,
            &shop,
            get(
                "/.ianua/hop?host=api.example.com&browser=d1g35t&next=https%3A%2F%2Fevil.example.com",
                &[CROSS_SITE_PAGE],
            ),
        )
        .await;

        assert_eq!(location(&response), "https://shop.example.com/");
    }

    /// The login page may run the gateway's passkey script, at its one
    /// address on this host; every other page runs none.
    #[tokio::test]
    async fn the_login_page_alone_may_run_the_passkey_script() {
        let api = Api::answering(|| {
            Ok(WireOutcome::Page {
                html: "<!doctype html>".to_owned(),
            })
        });
        let shop = shop();

        let login = send(&api, &FIRST, &shop, get("/.ianua/login", &[])).await;
        let forgot = send(&api, &FIRST, &shop, get("/.ianua/forgot-password", &[])).await;

        let policy = |response: &Response| {
            response.headers()[CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .to_owned()
        };
        assert!(policy(&login).contains("script-src https://shop.example.com/.ianua/passkey.js;"));
        assert!(!policy(&forgot).contains("script-src"));
    }

    #[tokio::test]
    async fn the_passkey_script_is_served_at_its_address_without_the_api() {
        let (api, shop) = (Api::unreachable(), shop());

        let response = send(&api, &FIRST, &shop, get("/.ianua/passkey.js", &[])).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[CONTENT_TYPE],
            "text/javascript; charset=utf-8"
        );
        assert!(!api.was_asked());
    }

    /// A body that never finishes holds nothing but its own connection: the
    /// read gives up and the request is refused.
    #[tokio::test]
    async fn a_body_that_never_arrives_is_refused() {
        tokio::time::pause();
        let (api, shop) = (Api::answering(|| Ok(signed_in())), shop());
        let never = http_body_util::StreamBody::new(futures_util::stream::pending::<
            Result<hyper::body::Frame<Bytes>, Infallible>,
        >());
        let mut request = http::Request::new(never);
        *request.method_mut() = Method::POST;
        *request.uri_mut() = "/.ianua/login".parse().unwrap();
        request
            .headers_mut()
            .insert("sec-fetch-site", "same-origin".parse().unwrap());

        let response = send(&api, &FIRST, &shop, request).await;

        assert!(location(&response).ends_with("error=malformed"));
        assert!(!api.was_asked());
    }

    #[tokio::test]
    async fn the_second_factor_without_its_challenge_cookie_never_reaches_the_api() {
        let (api, shop) = (Api::answering(|| Ok(signed_in())), shop());

        let response = send(
            &api,
            &FIRST,
            &shop,
            post(
                "/.ianua/mfa",
                &[SAME_ORIGIN, FORM, (COOKIE.as_str(), "theme=dark")],
                "code=1",
            ),
        )
        .await;

        assert_eq!(
            location(&response),
            "https://shop.example.com/.ianua/mfa?error=missing_challenge"
        );
        assert!(!api.was_asked());
    }
}
