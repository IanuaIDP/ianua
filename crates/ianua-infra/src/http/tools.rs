//! An agent's tool call, made through the zero-trust gateway.
//!
//! The run's loop has already decided which tool may be called. This
//! adapter makes the call that tool is registered for: it fills the tool's
//! path from the arguments, sends the rest as the query of a `GET` or
//! `DELETE` or as the JSON body otherwise, and hands back the answer.
//!
//! Every call goes to the gateway, bearing the run's task token, so the
//! gateway authorizes the call as it is really made. There is no direct
//! route: with no gateway configured, no call is made at all. The gateway's
//! address is screened like any other, at each connection, and a redirect
//! is never followed, since it would be a second request made from the
//! worker past the gateway.
//!
//! The arguments come from the model. Each value that fills the path is a
//! [`PathValue`], always one plain segment, so no argument can move the
//! call to another path. Each call carries an idempotency key made from the
//! run, the step, the tool and the exact arguments: a run taken over after
//! a crash makes the same call with the same key, so an upstream that
//! honours the key does its work once.

use std::time::Duration;

use async_trait::async_trait;
use data_encoding::HEXLOWER;
use ianua_app::ports::agents::{ToolInvocationContext, ToolInvoker};
use ianua_domain::domains::agents::execution::run::ToolArguments;
use ianua_domain::domains::agents::execution::tool::{
    AgentTool, PathValue, PathValues, ToolMethod,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::CanonicalPath;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::http::client::{body_within, ensure_reachable, screened};

/// The longest answer a tool may give, in bytes. The answer goes back into
/// the model's context, so a longer one is refused rather than read.
const MOST_ANSWER_BYTES: usize = 16_384;

/// The header the idempotency key travels in.
const IDEMPOTENCY_HEADER: &str = "Idempotency-Key";

/// Makes an agent's permitted tool calls through the gateway.
#[derive(Debug)]
pub struct HttpToolInvoker {
    client: reqwest::Client,
    gateway: Option<Url>,
    networks: UpstreamNetworks,
}

impl HttpToolInvoker {
    /// An invoker sending every call to `gateway`, each held to `timeout`
    /// and reaching only what `networks` permits. With no gateway, every
    /// call is refused.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when `gateway` is not a plain
    /// `http` or `https` address, and `DomainError::Infrastructure` when
    /// the client cannot be built.
    pub fn new(
        gateway: Option<Url>,
        networks: UpstreamNetworks,
        timeout: Duration,
    ) -> Result<Self, DomainError> {
        if let Some(address) = &gateway {
            ensure_plain(address)?;
        }
        Ok(Self {
            client: screened(timeout, networks.clone())?,
            gateway,
            networks,
        })
    }

    /// The gateway's address for `target`.
    fn address_of(&self, target: &CanonicalPath) -> Result<Url, DomainError> {
        let Some(gateway) = &self.gateway else {
            return Err(DomainError::infra_msg(
                "no gateway is configured to carry agent tool calls",
            ));
        };
        let mut address = gateway.clone();
        let joined = format!(
            "{}{}",
            gateway.path().trim_end_matches('/'),
            target.as_str()
        );
        address.set_path(&joined);
        ensure_reachable(&address, &self.networks)?;
        Ok(address)
    }
}

/// Refuses a gateway address that is not `http` or `https`, or that
/// carries a query or fragment a tool's path would be pasted after.
fn ensure_plain(address: &Url) -> Result<(), DomainError> {
    let plain = matches!(address.scheme(), "http" | "https")
        && address.query().is_none()
        && address.fragment().is_none();
    if !plain {
        return Err(DomainError::invalid(message!(
            "infra-the-gateway-must-be-a-plain",
            "the gateway must be a plain http or https address"
        )));
    }
    Ok(())
}

#[async_trait]
impl ToolInvoker for HttpToolInvoker {
    async fn invoke(
        &self,
        tool: &AgentTool<ResolvedTenant>,
        arguments: &ToolArguments,
        context: &ToolInvocationContext,
    ) -> Result<String, DomainError> {
        let given = parsed(arguments)?;
        let (values, rest) = split_off_path(tool, given)?;
        let address = self.address_of(&tool.path().resolve(&values)?)?;
        let request = self
            .client
            .request(method_of(tool.method()), address)
            .header(
                IDEMPOTENCY_HEADER,
                idempotency_key(tool, arguments, context),
            )
            .bearer_auth(context.authorization.reveal());
        let request = match tool.method() {
            ToolMethod::Get | ToolMethod::Delete => request.query(&rest),
            ToolMethod::Post | ToolMethod::Put | ToolMethod::Patch => {
                request.json(&Value::Object(rest))
            }
        };
        let response = request.send().await.map_err(DomainError::infra)?;
        let status = response.status();
        let body = body_within(response, MOST_ANSWER_BYTES).await?;
        Ok(answer(status, &body))
    }
}

/// The arguments as a JSON object. No arguments at all are an empty one;
/// anything else that is not an object is refused, so the call sent is the
/// call the run records.
fn parsed(arguments: &ToolArguments) -> Result<Map<String, Value>, DomainError> {
    let text = arguments.as_str();
    if text.trim().is_empty() {
        return Ok(Map::new());
    }
    let Ok(Value::Object(given)) = serde_json::from_str::<Value>(text) else {
        return Err(DomainError::invalid(message!(
            "infra-tool-arguments-must-be-a-json",
            "tool arguments must be a JSON object"
        )));
    };
    Ok(given)
}

/// The values that fill `tool`'s path, and the arguments left over.
fn split_off_path(
    tool: &AgentTool<ResolvedTenant>,
    mut given: Map<String, Value>,
) -> Result<(PathValues, Map<String, Value>), DomainError> {
    let mut values = PathValues::new();
    for name in tool.path().placeholders() {
        let value = given.remove(name).ok_or_else(|| {
            DomainError::invalid(message!(
                "agents-the-call-gives-no-value-for",
                "the call gives no value for a part of the tool's path"
            ))
        })?;
        values = values.with(name, path_value(&value)?);
    }
    Ok((values, given))
}

/// A string or number argument as the one path segment it fills.
fn path_value(value: &Value) -> Result<PathValue, DomainError> {
    let text = match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => {
            return Err(DomainError::invalid(message!(
                "infra-a-part-of-the-tool-s",
                "a part of the tool's path takes a string or a number"
            )));
        }
    };
    Ok(PathValue::new(text)?)
}

/// The HTTP method a tool is registered with.
fn method_of(method: ToolMethod) -> reqwest::Method {
    match method {
        ToolMethod::Get => reqwest::Method::GET,
        ToolMethod::Post => reqwest::Method::POST,
        ToolMethod::Put => reqwest::Method::PUT,
        ToolMethod::Patch => reqwest::Method::PATCH,
        ToolMethod::Delete => reqwest::Method::DELETE,
    }
}

/// The key of one call: the same run, step, tool and arguments always give
/// the same key, and any difference gives another.
fn idempotency_key(
    tool: &AgentTool<ResolvedTenant>,
    arguments: &ToolArguments,
    context: &ToolInvocationContext,
) -> String {
    let digest = Sha256::new()
        .chain_update(context.run_id.as_uuid().as_bytes())
        .chain_update(context.step.to_be_bytes())
        .chain_update(tool.id().as_uuid().as_bytes())
        .chain_update(arguments.as_str().as_bytes())
        .finalize();
    HEXLOWER.encode(&digest)
}

/// What the run reads back: the body of a success, and the status ahead of
/// the body otherwise, so the model sees the call did not go through.
fn answer(status: reqwest::StatusCode, body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    if status.is_success() {
        return text.into_owned();
    }
    format!("HTTP {}: {text}", status.as_u16())
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::agents::TaskToken;
    use ianua_domain::domains::agents::execution::tool::{
        AgentToolRow, ToolDescription, ToolName, ToolPath, ToolSchema, ToolStatus,
    };
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::types::{
        ActionClass, AgentRunId, AgentToolId, CidrRange, DeclaredAction, HttpMethod, RouteId,
    };
    use time::OffsetDateTime;
    use wiremock::matchers::{body_json, header, header_exists, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn loopback() -> UpstreamNetworks {
        UpstreamNetworks::new(vec![
            CidrRange::new("127.0.0.0/8").unwrap(),
            CidrRange::new("::1/128").unwrap(),
        ])
    }

    fn tool(method: ToolMethod, template: &str) -> AgentTool<ResolvedTenant> {
        AgentTool::reconstitute(AgentToolRow {
            id: AgentToolId::new(),
            name: ToolName::new("orders").unwrap(),
            description: ToolDescription::new("Works on orders").unwrap(),
            schema: ToolSchema::new(r#"{"type":"object"}"#).unwrap(),
            method,
            path: ToolPath::new(template).unwrap(),
            route_id: RouteId::new(),
            declared_action: DeclaredAction::Undeclared,
            action_class: ActionClass::for_route(
                HttpMethod::from(method),
                template,
                DeclaredAction::Undeclared,
            ),
            classification: DataClassLevel::Internal,
            status: ToolStatus::Active,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        })
        .unwrap()
    }

    fn context(step: u32) -> ToolInvocationContext {
        ToolInvocationContext {
            run_id: AgentRunId::new(),
            step,
            authorization: TaskToken::new("run.task.token"),
        }
    }

    fn arguments(text: &str) -> ToolArguments {
        ToolArguments::new(text).unwrap()
    }

    /// The gateway's address by name, so the call goes through the
    /// screening resolver.
    fn through(server: &MockServer) -> HttpToolInvoker {
        let named = server.uri().replace("127.0.0.1", "localhost");
        HttpToolInvoker::new(
            Some(Url::parse(&named).unwrap()),
            loopback(),
            Duration::from_secs(5),
        )
        .unwrap()
    }

    async fn gateway(route: &str, response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(path(route))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    /// A call reaches the gateway at the filled path, bearing the run's
    /// task token, with the rest of the arguments as its query.
    #[tokio::test]
    async fn a_call_goes_to_the_gateway_bearing_the_task_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orders/42"))
            .and(query_param("expand", "lines"))
            .and(header("authorization", "Bearer run.task.token"))
            .and(header_exists(IDEMPOTENCY_HEADER))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"total":9}"#))
            .mount(&server)
            .await;

        let answer = through(&server)
            .invoke(
                &tool(ToolMethod::Get, "/orders/{id}"),
                &arguments(r#"{"id":42,"expand":"lines"}"#),
                &context(1),
            )
            .await
            .unwrap();

        assert_eq!(answer, r#"{"total":9}"#);
    }

    /// A write sends what is left of the arguments as its JSON body.
    #[tokio::test]
    async fn a_write_sends_the_rest_as_its_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/orders"))
            .and(body_json(serde_json::json!({"item": "pen", "count": 2})))
            .respond_with(ResponseTemplate::new(201).set_body_string("made"))
            .mount(&server)
            .await;

        let answer = through(&server)
            .invoke(
                &tool(ToolMethod::Post, "/orders"),
                &arguments(r#"{"item":"pen","count":2}"#),
                &context(1),
            )
            .await
            .unwrap();

        assert_eq!(answer, "made");
    }

    /// Invoking a tool without a configured gateway returns an infrastructure
    /// error.
    #[tokio::test]
    async fn without_a_gateway_no_call_is_made() {
        let invoker = HttpToolInvoker::new(None, loopback(), Duration::from_secs(5)).unwrap();

        let result = invoker
            .invoke(
                &tool(ToolMethod::Get, "/orders/{id}"),
                &arguments(r#"{"id":1}"#),
                &context(1),
            )
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// Parent traversal in a tool's path argument returns a validation
    /// error without sending a request to the gateway.
    #[tokio::test]
    async fn a_value_climbing_out_of_its_segment_sends_nothing() {
        let server = gateway("/orders/1", ResponseTemplate::new(200)).await;

        for hostile in [
            r#"{"id":"../admin/roles"}"#,
            r#"{"id":"1/../../admin"}"#,
            r#"{"id":".."}"#,
        ] {
            let result = through(&server)
                .invoke(
                    &tool(ToolMethod::Get, "/orders/{id}"),
                    &arguments(hostile),
                    &context(1),
                )
                .await;
            assert!(
                matches!(result, Err(DomainError::Validation(_))),
                "{hostile}"
            );
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// A missing path argument, a nested object or a boolean returns a
    /// validation error.
    #[tokio::test]
    async fn a_missing_or_structured_path_value_is_refused() {
        let server = gateway("/orders/1", ResponseTemplate::new(200)).await;

        for given in ["{}", r#"{"id":{"nested":1}}"#, r#"{"id":true}"#] {
            let result = through(&server)
                .invoke(
                    &tool(ToolMethod::Get, "/orders/{id}"),
                    &arguments(given),
                    &context(1),
                )
                .await;
            assert!(matches!(result, Err(DomainError::Validation(_))), "{given}");
        }
    }

    /// Arrays, strings, numbers and malformed JSON arguments return
    /// validation errors without sending a request to the gateway.
    #[tokio::test]
    async fn arguments_that_are_not_an_object_are_refused() {
        let server = gateway("/orders", ResponseTemplate::new(200)).await;

        for given in ["[1,2]", "\"text\"", "42", "{not json"] {
            let result = through(&server)
                .invoke(
                    &tool(ToolMethod::Post, "/orders"),
                    &arguments(given),
                    &context(1),
                )
                .await;
            assert!(matches!(result, Err(DomainError::Validation(_))), "{given}");
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// A gateway redirect to the metadata address is returned as HTTP 302.
    #[tokio::test]
    async fn a_redirect_is_reported_and_never_followed() {
        let server = gateway(
            "/orders/1",
            ResponseTemplate::new(302)
                .insert_header("location", "http://169.254.169.254/latest/meta-data/"),
        )
        .await;

        let answer = through(&server)
            .invoke(
                &tool(ToolMethod::Get, "/orders/{id}"),
                &arguments(r#"{"id":1}"#),
                &context(1),
            )
            .await
            .unwrap();

        assert!(answer.starts_with("HTTP 302"), "{answer}");
    }

    /// A refusal from the gateway or the upstream is handed back with its
    /// status, so the model sees the call did not go through.
    #[tokio::test]
    async fn a_refused_call_is_reported_with_its_status() {
        let server = gateway(
            "/orders",
            ResponseTemplate::new(403).set_body_string("denied"),
        )
        .await;

        let answer = through(&server)
            .invoke(
                &tool(ToolMethod::Post, "/orders"),
                &arguments("{}"),
                &context(1),
            )
            .await
            .unwrap();

        assert_eq!(answer, "HTTP 403: denied");
    }

    /// A tool answer exceeding the byte limit returns an infrastructure error.
    #[tokio::test]
    async fn an_answer_past_its_bound_is_refused() {
        let server = gateway(
            "/orders/1",
            ResponseTemplate::new(200).set_body_bytes(vec![b'x'; MOST_ANSWER_BYTES * 4]),
        )
        .await;

        let result = through(&server)
            .invoke(
                &tool(ToolMethod::Get, "/orders/{id}"),
                &arguments(r#"{"id":1}"#),
                &context(1),
            )
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A gateway response delayed beyond the configured timeout returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_hung_call_is_given_up_on() {
        let server = gateway(
            "/orders/1",
            ResponseTemplate::new(200).set_delay(Duration::from_secs(10)),
        )
        .await;
        let named = server.uri().replace("127.0.0.1", "localhost");
        let invoker = HttpToolInvoker::new(
            Some(Url::parse(&named).unwrap()),
            loopback(),
            Duration::from_millis(200),
        )
        .unwrap();

        let result = invoker
            .invoke(
                &tool(ToolMethod::Get, "/orders/{id}"),
                &arguments(r#"{"id":1}"#),
                &context(1),
            )
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A gateway outside the permitted networks returns an error without
    /// receiving a request.
    #[tokio::test]
    async fn a_gateway_outside_the_permitted_networks_is_not_reached() {
        let server = gateway("/orders/1", ResponseTemplate::new(200)).await;
        let invoker = HttpToolInvoker::new(
            Some(Url::parse(&server.uri()).unwrap()),
            UpstreamNetworks::public_only(),
            Duration::from_secs(5),
        )
        .unwrap();

        let result = invoker
            .invoke(
                &tool(ToolMethod::Get, "/orders/{id}"),
                &arguments(r#"{"id":1}"#),
                &context(1),
            )
            .await;

        assert!(result.is_err());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// The same call made again after a crash carries the same key; another
    /// step or other arguments carry another.
    #[test]
    fn the_key_is_stable_for_one_call_and_differs_otherwise() {
        let orders = tool(ToolMethod::Post, "/orders");
        let first = context(1);
        let same = ToolInvocationContext {
            run_id: first.run_id,
            step: 1,
            authorization: TaskToken::new("a.renewed.token"),
        };
        let later = ToolInvocationContext {
            run_id: first.run_id,
            step: 2,
            authorization: TaskToken::new("run.task.token"),
        };
        let key = idempotency_key(&orders, &arguments(r#"{"x":1}"#), &first);

        assert_eq!(
            key,
            idempotency_key(&orders, &arguments(r#"{"x":1}"#), &same)
        );
        assert_ne!(
            key,
            idempotency_key(&orders, &arguments(r#"{"x":1}"#), &later)
        );
        assert_ne!(
            key,
            idempotency_key(&orders, &arguments(r#"{"x":2}"#), &first)
        );
    }

    /// A gateway URL containing a query fails invoker construction with a
    /// validation error.
    #[test]
    fn a_gateway_with_a_query_is_refused() {
        let result = HttpToolInvoker::new(
            Some(Url::parse("https://gateway.example.com/?next=").unwrap()),
            loopback(),
            Duration::from_secs(5),
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }
}
