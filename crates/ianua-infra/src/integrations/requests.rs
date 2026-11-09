//! The built-in HTTP request integration: one call to an address the
//! tenant chose, with or without an account's token.
//!
//! The address is the tenant's, so the call goes through the screened
//! client: an IP written out is checked first, a name when it resolves,
//! and a redirect is never followed. A token is kept in an account bound
//! to one origin, and is sent nowhere else, so a workflow cannot carry an
//! account's token to an address of its own.

use std::time::Duration;

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::{FieldName, FlowData, FlowValue};
use ianua_domain::domains::workflows::execution::ActionCall;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
use ianua_domain::domains::workflows::integration::guide::OperationGuide;
use ianua_domain::domains::workflows::integration::profile::IntegrationProfile;
use ianua_domain::domains::workflows::integration::{
    AccountNeed, InputNeed, InputSpec, IntegrationKey, OperationKey, OperationSpec,
    OperationSpecParams,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::chain::EventOrigin;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::answer::{LARGEST_ANSWER, failed, outcome_of, turned_away};
use ianua_integration::arguments::argument;
use ianua_integration::describe::{BuiltInText, built_in_profile};
use ianua_integration::{Called, Integration};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};

use crate::http::client::{ensure_reachable, refused_by_screen, screened};

mod guides;

use self::guides::guides_of;

/// The header a call names its execution's depth in its chain with, so a
/// workflow it sets off in the tenant continues the chain.
pub(crate) const CHAIN_HEADER: &str = "ianua-chain-depth";

/// Headers a step may not set: the integration sets them itself, or they
/// would let a step forge who is calling or how the body is framed.
const HEADERS_NOT_SET: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "te",
    "upgrade",
    CHAIN_HEADER,
];

/// How the HTTP request integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct RequestSettings {
    /// The networks a call may reach.
    pub networks: UpstreamNetworks,
    /// How long one call may take.
    pub timeout: Duration,
    /// The largest answer read, in bytes. Anything past 349,000 is read as
    /// that, so the answer's text and values fit in workflow data.
    pub most_answer: usize,
    /// The most sensitive data a step may send, and so the most sensitive
    /// an answer is counted as, since it may echo what it was sent.
    pub ceiling: DataClassLevel,
}

/// The HTTP request integration, installed under `http`.
pub struct HttpRequests {
    profile: IntegrationProfile,
    operations: Vec<OperationSpec>,
    guides: Vec<OperationGuide>,
    client: reqwest::Client,
    settings: RequestSettings,
}

/// How the integration presents itself.
const PROFILE: BuiltInText<'static> = BuiltInText {
    title: "HTTP request",
    description: "Calls a web address the workflow names, bare or with an account's token bound to one origin.",
    icon: "http",
    brand: "334155",
};

impl HttpRequests {
    /// The integration, set up by `settings`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(settings: RequestSettings) -> Result<Self, DomainError> {
        let key = IntegrationKey::new("http")?;
        let operations = operations_of(&key, settings.ceiling)?;
        let guides = guides_of()?;
        let client = screened(settings.timeout, settings.networks.clone())?;
        let settings = RequestSettings {
            most_answer: settings.most_answer.min(LARGEST_ANSWER),
            ..settings
        };
        Ok(Self {
            profile: built_in_profile(&key, &PROFILE)?,
            operations,
            guides,
            client,
            settings,
        })
    }

    /// The request `call` asks for, or why none is sent.
    fn request(
        &self,
        call: &ActionCall,
        credential: Option<&Secret>,
    ) -> Result<reqwest::RequestBuilder, ActionOutcome> {
        let Some((method, access)) = operation_named(&call.operation) else {
            return Err(failed("the operation is not one this integration offers"));
        };
        let url = target(&call.arguments, &self.settings.networks)?;
        let mut headers = headers_of(&call.arguments)?;
        if let Some(bearer) = authorization(access, credential, &url)? {
            headers.insert(AUTHORIZATION, bearer);
        }
        if let Some(depth) = chain_depth(call.origin) {
            headers.insert(HeaderName::from_static(CHAIN_HEADER), depth);
        }
        let request = self.client.request(method.verb(), url).headers(headers);
        with_body(request, method, &call.arguments)
    }

    /// How `call` went, sent with `credential`.
    async fn made(&self, call: &ActionCall, credential: Option<&Secret>) -> ActionOutcome {
        let request = match self.request(call, credential) {
            Ok(request) => request,
            Err(refused) => return refused,
        };
        match request.send().await {
            Ok(response) => {
                outcome_of(response, self.settings.most_answer, self.settings.ceiling).await
            }
            Err(error) if refused_by_screen(&error) => {
                failed("the address resolves to one this deployment may not reach")
            }
            Err(error) if error.is_connect() => turned_away("the address could not be reached"),
            Err(_) => failed("the call did not complete, and may have reached the address"),
        }
    }
}

#[async_trait]
impl Integration for HttpRequests {
    fn profile(&self) -> &IntegrationProfile {
        &self.profile
    }

    fn operations(&self) -> &[OperationSpec] {
        &self.operations
    }

    fn guides(&self) -> &[OperationGuide] {
        &self.guides
    }

    /// An account here holds a token for an origin the tenant chose, which
    /// has no question to ask of it, so it is kept unchecked.
    async fn check_account(&self, _credential: &Secret) -> AccountCheck {
        AccountCheck::NotCheckable
    }

    async fn call(&self, call: &ActionCall, credential: Option<&Secret>) -> Called {
        self.made(call, credential).await.into()
    }
}

/// An HTTP method a step may call with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl Method {
    /// Every method offered.
    pub(super) const ALL: [Self; 5] = [Self::Get, Self::Post, Self::Put, Self::Patch, Self::Delete];

    /// The method's name, which its bare operation is called.
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Post => "post",
            Self::Put => "put",
            Self::Patch => "patch",
            Self::Delete => "delete",
        }
    }

    /// The method as the client sends it.
    pub(super) fn verb(self) -> reqwest::Method {
        match self {
            Self::Get => reqwest::Method::GET,
            Self::Post => reqwest::Method::POST,
            Self::Put => reqwest::Method::PUT,
            Self::Patch => reqwest::Method::PATCH,
            Self::Delete => reqwest::Method::DELETE,
        }
    }

    /// What a call with it does. A read only reads and a delete deletes;
    /// a write to an address nobody described could send a message or move
    /// money, so it is undeclared, which counts as high risk.
    pub(super) fn effect(self) -> DeclaredAction {
        match self {
            Self::Get => DeclaredAction::Declared(ActionClass::Read),
            Self::Delete => DeclaredAction::Declared(ActionClass::Delete),
            Self::Post | Self::Put | Self::Patch => DeclaredAction::Undeclared,
        }
    }

    /// Whether a call with it carries a body.
    pub(super) fn body(self) -> Body {
        match self {
            Self::Get | Self::Delete => Body::None,
            Self::Post | Self::Put | Self::Patch => Body::Json,
        }
    }
}

/// Whether a method carries a body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Body {
    None,
    Json,
}

/// Whether a call goes out bare or with an account's token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    Open,
    WithAccount,
}

impl Access {
    /// Both ways a call goes out.
    const ALL: [Self; 2] = [Self::Open, Self::WithAccount];

    /// The operation calling with `method` this way.
    fn operation(self, method: Method) -> String {
        match self {
            Self::Open => method.name().to_owned(),
            Self::WithAccount => format!("{}-with-account", method.name()),
        }
    }

    /// Whether the operation acts through an account.
    fn need(self) -> AccountNeed {
        match self {
            Self::Open => AccountNeed::NoAccount,
            Self::WithAccount => AccountNeed::Account,
        }
    }
}

/// Every operation: each method, bare and with an account.
fn operations_of(
    key: &IntegrationKey,
    ceiling: DataClassLevel,
) -> Result<Vec<OperationSpec>, DomainError> {
    Method::ALL
        .into_iter()
        .flat_map(|method| Access::ALL.into_iter().map(move |access| (method, access)))
        .map(|(method, access)| {
            OperationSpec::new(OperationSpecParams {
                integration: key.clone(),
                operation: OperationKey::new(access.operation(method))?,
                inputs: inputs_of(method)?,
                effect: method.effect(),
                account: access.need(),
                ceiling,
            })
        })
        .collect()
}

/// The inputs a call with `method` takes: the address, headers, and a body
/// for a method that carries one.
fn inputs_of(method: Method) -> Result<Vec<InputSpec>, DomainError> {
    let mut inputs = vec![
        InputSpec::new(FieldName::new("url")?, InputNeed::Required),
        InputSpec::new(FieldName::new("headers")?, InputNeed::Optional),
    ];
    if method.body() == Body::Json {
        inputs.push(InputSpec::new(FieldName::new("body")?, InputNeed::Optional));
    }
    Ok(inputs)
}

/// The method and access the operation `key` names.
fn operation_named(key: &OperationKey) -> Option<(Method, Access)> {
    Method::ALL
        .into_iter()
        .flat_map(|method| Access::ALL.into_iter().map(move |access| (method, access)))
        .find(|(method, access)| access.operation(*method) == key.as_str())
}

/// The address to call, refused when it is not an `http` or `https`
/// address the deployment may reach.
fn target(arguments: &FlowData, networks: &UpstreamNetworks) -> Result<url::Url, ActionOutcome> {
    let Some(FlowValue::Text(written)) = argument(arguments, "url").map(FlowData::value) else {
        return Err(failed("the url is missing or not text"));
    };
    let Ok(url) = url::Url::parse(written) else {
        return Err(failed("the url is not an address"));
    };
    if !matches!(url.scheme(), "http" | "https") {
        return Err(failed("the url is not an http or https address"));
    }
    if ensure_reachable(&url, networks).is_err() {
        return Err(failed("the address is one this deployment may not reach"));
    }
    Ok(url)
}

/// The headers the step set, each a text value, none of those the
/// integration sets itself.
pub(super) fn headers_of(arguments: &FlowData) -> Result<HeaderMap, ActionOutcome> {
    let mut headers = HeaderMap::new();
    let Some(given) = argument(arguments, "headers") else {
        return Ok(headers);
    };
    let FlowValue::Map(entries) = given.value() else {
        return Err(failed("the headers are not named values"));
    };
    for (name, value) in entries {
        let (name, value) = header_of(name, value)?;
        headers.insert(name, value);
    }
    Ok(headers)
}

/// One header the step set, refused when the integration sets it itself
/// or it cannot be sent as given.
fn header_of(
    name: &FieldName,
    value: &FlowData,
) -> Result<(HeaderName, HeaderValue), ActionOutcome> {
    let lower = name.as_str().to_ascii_lowercase();
    if HEADERS_NOT_SET.contains(&lower.as_str()) {
        return Err(failed("a header the integration sets itself was given"));
    }
    let FlowValue::Text(text) = value.value() else {
        return Err(failed("a header's value is not text"));
    };
    let (Ok(name), Ok(value)) = (
        HeaderName::from_bytes(lower.as_bytes()),
        HeaderValue::from_str(text),
    ) else {
        return Err(failed("a header cannot be sent as given"));
    };
    Ok((name, value))
}

/// The bearer header a call with an account carries, refused when the
/// address is not the origin the account's token is bound to.
fn authorization(
    access: Access,
    credential: Option<&Secret>,
    url: &url::Url,
) -> Result<Option<HeaderValue>, ActionOutcome> {
    if access == Access::Open {
        return Ok(None);
    }
    let Some(account) = credential.and_then(BoundToken::read) else {
        return Err(failed("the account holds no token bound to an origin"));
    };
    if account.origin != url.origin() {
        return Err(failed(
            "the address is not the origin the account is bound to",
        ));
    }
    let Ok(mut value) = HeaderValue::from_str(&format!("Bearer {}", account.token.expose())) else {
        return Err(failed("the account's token cannot be sent"));
    };
    value.set_sensitive(true);
    Ok(Some(value))
}

/// The token an account holds, and the one origin it may be sent to.
///
/// An account of this integration holds `{"origin": .., "token": ..}`.
struct BoundToken {
    origin: url::Origin,
    token: Secret,
}

/// The account as sealed, read only to become a [`BoundToken`].
#[derive(serde::Deserialize)]
struct Kept {
    origin: String,
    token: String,
}

impl BoundToken {
    /// The token `credential` holds with its origin, or none when it is
    /// not an account of this integration.
    fn read(credential: &Secret) -> Option<Self> {
        let kept: Kept = serde_json::from_str(credential.expose()).ok()?;
        let origin = url::Url::parse(&kept.origin).ok()?.origin();
        Some(Self {
            origin,
            token: Secret::new(kept.token),
        })
    }
}

/// The depth header a call from inside an execution carries.
pub(super) fn chain_depth(origin: EventOrigin) -> Option<HeaderValue> {
    match origin {
        EventOrigin::Outside => None,
        EventOrigin::Execution(depth) => Some(HeaderValue::from(u16::from(depth.get()))),
    }
}

/// `request` with the step's body, refused for a method that carries none.
pub(super) fn with_body(
    request: reqwest::RequestBuilder,
    method: Method,
    arguments: &FlowData,
) -> Result<reqwest::RequestBuilder, ActionOutcome> {
    let given = argument(arguments, "body");
    match (method.body(), given) {
        (Body::None | Body::Json, None) => Ok(request),
        (Body::None, Some(_)) => Err(failed("this method carries no body")),
        (Body::Json, Some(body)) => Ok(request
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .body(body.render())),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::integration::ActionAccount;
    use ianua_domain::shared::events::chain::ChainDepth;
    use ianua_domain::types::{ActionCallId, CidrRange};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn loopback() -> UpstreamNetworks {
        UpstreamNetworks::new(vec![
            CidrRange::new("127.0.0.0/8").unwrap(),
            CidrRange::new("::1/128").unwrap(),
        ])
    }

    fn integration(networks: UpstreamNetworks) -> HttpRequests {
        HttpRequests::new(RequestSettings {
            networks,
            timeout: Duration::from_millis(500),
            most_answer: 1024,
            ceiling: DataClassLevel::Internal,
        })
        .unwrap()
    }

    /// The mock's address by name, so the call goes through the resolver.
    fn by_name(server: &MockServer, route: &str) -> String {
        format!("{}{route}", server.uri().replace("127.0.0.1", "localhost"))
    }

    fn text(value: &str) -> FlowData {
        FlowData::text(value).unwrap()
    }

    fn arguments(entries: Vec<(&str, FlowData)>) -> FlowData {
        FlowData::map(
            entries
                .into_iter()
                .map(|(name, value)| (FieldName::new(name).unwrap(), value))
                .collect(),
        )
        .unwrap()
    }

    fn call(operation: &str, arguments: FlowData, origin: EventOrigin) -> ActionCall {
        ActionCall {
            call_id: ActionCallId::new(),
            integration: IntegrationKey::new("http").unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            account: ActionAccount::NoAccount,
            arguments,
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin,
        }
    }

    fn get(url: &str) -> ActionCall {
        call(
            "get",
            arguments(vec![("url", text(url))]),
            EventOrigin::Outside,
        )
    }

    async fn answering(route: &str, response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(path(route))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    async fn requests_made(server: &MockServer) -> usize {
        server.received_requests().await.unwrap().len()
    }

    fn token_for(server: &MockServer) -> Secret {
        Secret::new(format!(
            r#"{{"origin": "{}", "token": "tok-distinctive"}}"#,
            by_name(server, "")
        ))
    }

    fn reason(outcome: &ActionOutcome) -> &str {
        match outcome {
            ActionOutcome::Failed(why) | ActionOutcome::TurnedAway(why) => why.as_str(),
            ActionOutcome::Succeeded { .. } | ActionOutcome::NotYet { .. } => "",
        }
    }

    /// Each method is offered bare and with an account; a read is declared
    /// a read, and a write to an undescribed address undeclared.
    #[test]
    fn every_method_is_offered_and_declared_honestly() {
        let http = integration(loopback());

        let named = |key: &str| {
            http.operations()
                .iter()
                .find(|spec| spec.operation().as_str() == key)
                .unwrap()
                .clone()
        };

        assert_eq!(http.operations().len(), 10);
        assert_eq!(
            named("get").effect(),
            DeclaredAction::Declared(ActionClass::Read)
        );
        assert_eq!(named("post").effect(), DeclaredAction::Undeclared);
        assert_eq!(named("delete-with-account").account(), AccountNeed::Account);
        assert_eq!(named("get").account(), AccountNeed::NoAccount);
    }

    /// A call answered with JSON succeeds with the status and the values,
    /// counted at the integration's ceiling.
    #[tokio::test]
    async fn an_answer_becomes_the_steps_output() {
        let server = answering(
            "/rows",
            ResponseTemplate::new(200).set_body_string(r#"{"rows": 3}"#),
        )
        .await;
        let http = integration(loopback());

        let outcome = http
            .call(&get(&by_name(&server, "/rows")), None)
            .await
            .outcome;

        let ActionOutcome::Succeeded { output, exposure } = outcome else {
            panic!("the call should succeed, got {outcome:?}");
        };
        assert_eq!(exposure, DataClassLevel::Internal);
        let rows = output
            .field(&FieldName::new("json").unwrap())
            .and_then(|json| json.field(&FieldName::new("rows").unwrap()))
            .map(FlowData::value);
        assert_eq!(rows, Some(FlowValue::Number(3.0)));
    }

    /// A call made from inside an execution names its depth, and a body is
    /// sent as JSON.
    #[tokio::test]
    async fn a_call_from_an_execution_names_its_depth() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header(CHAIN_HEADER, "1"))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        let http = integration(loopback());
        let given = arguments(vec![
            ("url", text(&by_name(&server, "/in"))),
            ("body", text("hello")),
        ]);

        let outcome = http
            .call(
                &call("post", given, EventOrigin::Execution(ChainDepth::FIRST)),
                None,
            )
            .await
            .outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
    }

    /// A call with an account carries the account's token to the origin it
    /// is bound to, and the outcome never holds it.
    #[tokio::test]
    async fn an_accounts_token_reaches_its_own_origin() {
        let server = MockServer::start().await;
        Mock::given(header("authorization", "Bearer tok-distinctive"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;
        let http = integration(loopback());
        let given = arguments(vec![("url", text(&by_name(&server, "/sheet")))]);

        let outcome = http
            .call(
                &call("get-with-account", given, EventOrigin::Outside),
                Some(&token_for(&server)),
            )
            .await
            .outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
        assert!(!format!("{outcome:?}").contains("tok-distinctive"));
    }

    /// Using an account token at another origin fails without contacting that
    /// destination or exposing the token in the reason.
    #[tokio::test]
    async fn an_accounts_token_is_never_sent_to_another_origin() {
        let bound = MockServer::start().await;
        let elsewhere = answering("/steal", ResponseTemplate::new(200)).await;
        let http = integration(loopback());
        let given = arguments(vec![("url", text(&by_name(&elsewhere, "/steal")))]);

        let outcome = http
            .call(
                &call("get-with-account", given, EventOrigin::Outside),
                Some(&token_for(&bound)),
            )
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        assert_eq!(requests_made(&elsewhere).await, 0);
        assert!(!reason(&outcome).contains("tok-distinctive"));
    }

    /// A literal metadata-service address fails with the network-policy refusal.
    #[tokio::test]
    async fn an_address_outside_the_networks_is_refused() {
        let http = integration(UpstreamNetworks::public_only());

        let outcome = http
            .call(&get("http://169.254.169.254/latest/meta-data/"), None)
            .await
            .outcome;

        assert_eq!(
            reason(&outcome),
            "the address is one this deployment may not reach"
        );
        assert!(matches!(outcome, ActionOutcome::Failed(_)));
    }

    /// A name resolving to loopback fails under public-only networks without
    /// reaching the server.
    #[tokio::test]
    async fn a_name_resolving_inside_the_deployment_is_not_reached() {
        let server = answering("/ok", ResponseTemplate::new(200)).await;
        let http = integration(UpstreamNetworks::public_only());

        let outcome = http
            .call(&get(&by_name(&server, "/ok")), None)
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        assert_eq!(requests_made(&server).await, 0);
    }

    /// A redirect to a metadata-service address produces a failed outcome naming
    /// the original 302 response.
    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let server = answering(
            "/start",
            ResponseTemplate::new(302)
                .insert_header("location", "http://169.254.169.254/latest/meta-data/"),
        )
        .await;
        let http = integration(loopback());

        let outcome = http
            .call(&get(&by_name(&server, "/start")), None)
            .await
            .outcome;

        assert_eq!(reason(&outcome), "the address answered 302");
        assert!(matches!(outcome, ActionOutcome::Failed(_)));
    }

    /// A response body larger than the configured limit produces a failed step.
    #[tokio::test]
    async fn an_answer_past_its_limit_fails() {
        let server = answering(
            "/big",
            ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 4096]),
        )
        .await;
        let http = integration(loopback());

        let outcome = http
            .call(&get(&by_name(&server, "/big")), None)
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
    }

    /// A busy or rate-limiting address did nothing, so the call is turned
    /// away and made again later.
    #[tokio::test]
    async fn a_busy_address_turns_the_call_away() {
        for status in [429, 503] {
            let server = answering("/busy", ResponseTemplate::new(status)).await;
            let http = integration(loopback());

            let outcome = http
                .call(&get(&by_name(&server, "/busy")), None)
                .await
                .outcome;

            assert!(
                matches!(outcome, ActionOutcome::TurnedAway(_)),
                "{status}: {outcome:?}"
            );
        }
    }

    /// A server response of 500 produces a failed call outcome.
    #[tokio::test]
    async fn a_server_error_fails_the_call() {
        let server = answering("/broken", ResponseTemplate::new(500)).await;
        let http = integration(loopback());

        let outcome = http
            .call(&get(&by_name(&server, "/broken")), None)
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
    }

    /// An address nothing listens on was never reached, so the call is
    /// turned away.
    #[tokio::test]
    async fn an_address_nothing_listens_on_turns_the_call_away() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let http = integration(loopback());

        let outcome = http
            .call(&get(&format!("http://localhost:{port}/")), None)
            .await
            .outcome;

        assert!(
            matches!(outcome, ActionOutcome::TurnedAway(_)),
            "{outcome:?}"
        );
    }

    /// A response delayed beyond the call's timeout produces a failed outcome.
    #[tokio::test]
    async fn a_call_past_its_time_fails() {
        let server = answering(
            "/slow",
            ResponseTemplate::new(200).set_delay(Duration::from_secs(3)),
        )
        .await;
        let http = integration(loopback());

        let outcome = http
            .call(&get(&by_name(&server, "/slow")), None)
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)), "{outcome:?}");
    }

    /// A step-supplied Authorization header fails the call without contacting
    /// the server.
    #[tokio::test]
    async fn a_header_the_integration_sets_is_refused() {
        let server = answering("/in", ResponseTemplate::new(200)).await;
        let http = integration(loopback());
        let headers = arguments(vec![("Authorization", text("Bearer pasted"))]);
        let given = arguments(vec![
            ("url", text(&by_name(&server, "/in"))),
            ("headers", headers),
        ]);

        let outcome = http
            .call(&call("get", given, EventOrigin::Outside), None)
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        assert_eq!(requests_made(&server).await, 0);
    }

    /// A GET call carrying a body fails without contacting the server.
    #[tokio::test]
    async fn a_read_with_a_body_is_refused() {
        let server = answering("/in", ResponseTemplate::new(200)).await;
        let http = integration(loopback());
        let given = arguments(vec![
            ("url", text(&by_name(&server, "/in"))),
            ("body", text("payload")),
        ]);

        let outcome = http
            .call(&call("get", given, EventOrigin::Outside), None)
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        assert_eq!(requests_made(&server).await, 0);
    }
}
