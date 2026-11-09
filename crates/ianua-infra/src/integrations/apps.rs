//! The built-in Protected apps integration: one call to an app behind the
//! gateway, on a route the tenant opened to workflows, acting as the person
//! the run acts for.
//!
//! The call goes to the gateway's workflow listener alone, an address the
//! deployment set, never one a step names. It carries the pass made for
//! it, which names the route; the gateway finds the route by the pass and
//! asks its policy of the person, as it would of them signing in. The step
//! names only the path on the app, held to start with one `/`, so it can
//! never point the call at another address.

use std::time::Duration;

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::FieldName;
use ianua_domain::domains::workflows::execution::ActionCall;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
use ianua_domain::domains::workflows::integration::guide::OperationGuide;
use ianua_domain::domains::workflows::integration::profile::IntegrationProfile;
use ianua_domain::domains::workflows::integration::{
    AccountNeed, InputNeed, InputSpec, IntegrationKey, OperationKey, OperationSpec,
    OperationSpecParams, ROUTE_INPUT,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_integration::answer::{LARGEST_ANSWER, failed, outcome_of, turned_away};
use ianua_integration::arguments::required_text;
use ianua_integration::describe::{BuiltInText, built_in_profile};
use ianua_integration::{Called, Integration};
use reqwest::header::{AUTHORIZATION, HeaderName, HeaderValue};

use crate::http::client::InternalLink;
use crate::integrations::requests::{
    Body, CHAIN_HEADER, Method, chain_depth, headers_of, with_body,
};

mod guides;

use self::guides::guides_of;

/// How the Protected apps integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct AppSettings {
    /// `GATEWAY_WORKFLOW_URL`: the gateway's workflow listener, inside the
    /// deployment's own network.
    pub gateway: url::Url,
    /// How the calls to it are protected.
    pub link: InternalLink,
    /// How long one call may take.
    pub timeout: Duration,
    /// The largest answer read, in bytes, at most 349,000.
    pub most_answer: usize,
    /// The most sensitive data a step may send, and so the most sensitive
    /// an answer is counted as.
    pub ceiling: DataClassLevel,
}

/// The Protected apps integration, installed under `apps`.
pub struct ProtectedApps {
    profile: IntegrationProfile,
    operations: Vec<OperationSpec>,
    guides: Vec<OperationGuide>,
    client: reqwest::Client,
    settings: AppSettings,
}

/// How the integration presents itself.
const PROFILE: BuiltInText<'static> = BuiltInText {
    title: "Protected apps",
    description: "Calls an app behind the gateway as the person the run acts for, on a route opened to workflows.",
    icon: "apps",
    brand: "0f766e",
};

impl ProtectedApps {
    /// The integration, set up by `settings`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(settings: AppSettings) -> Result<Self, DomainError> {
        let key = IntegrationKey::new("apps")?;
        let operations = operations_of(&key, settings.ceiling)?;
        let client = settings.link.client(settings.timeout)?;
        let settings = AppSettings {
            most_answer: settings.most_answer.min(LARGEST_ANSWER),
            ..settings
        };
        Ok(Self {
            profile: built_in_profile(&key, &PROFILE)?,
            operations,
            guides: guides_of()?,
            client,
            settings,
        })
    }

    /// The request `call` asks for, carrying `pass`, or why none is sent.
    fn request(
        &self,
        call: &ActionCall,
        pass: Option<&Secret>,
    ) -> Result<reqwest::RequestBuilder, ActionOutcome> {
        let Some(method) = Method::ALL
            .into_iter()
            .find(|method| method.name() == call.operation.as_str())
        else {
            return Err(failed("the operation is not one this integration offers"));
        };
        let Some(pass) = pass else {
            return Err(failed("the call carries no pass"));
        };
        let url = on_gateway(
            &self.settings.gateway,
            required_text(&call.arguments, "path")?,
        )?;
        let mut headers = headers_of(&call.arguments)?;
        headers.insert(AUTHORIZATION, bearer(pass)?);
        if let Some(depth) = chain_depth(call.origin) {
            headers.insert(HeaderName::from_static(CHAIN_HEADER), depth);
        }
        let request = self.client.request(method.verb(), url).headers(headers);
        with_body(request, method, &call.arguments)
    }

    /// How `call` went, sent with `pass`.
    async fn made(&self, call: &ActionCall, pass: Option<&Secret>) -> ActionOutcome {
        let request = match self.request(call, pass) {
            Ok(request) => request,
            Err(refused) => return refused,
        };
        match request.send().await {
            Ok(response) => {
                outcome_of(response, self.settings.most_answer, self.settings.ceiling).await
            }
            Err(error) if error.is_connect() => turned_away("the gateway could not be reached"),
            Err(_) => failed("the call did not complete, and may have reached the app"),
        }
    }
}

#[async_trait]
impl Integration for ProtectedApps {
    fn profile(&self) -> &IntegrationProfile {
        &self.profile
    }

    fn operations(&self) -> &[OperationSpec] {
        &self.operations
    }

    fn guides(&self) -> &[OperationGuide] {
        &self.guides
    }

    /// Protected apps keeps no accounts: each call carries a pass of its
    /// own.
    async fn check_account(&self, _credential: &Secret) -> AccountCheck {
        AccountCheck::NotCheckable
    }

    async fn call(&self, call: &ActionCall, credential: Option<&Secret>) -> Called {
        self.made(call, credential).await.into()
    }
}

/// Every operation: one per method, each acting as the run's person.
fn operations_of(
    key: &IntegrationKey,
    ceiling: DataClassLevel,
) -> Result<Vec<OperationSpec>, DomainError> {
    Method::ALL
        .into_iter()
        .map(|method| {
            OperationSpec::new(OperationSpecParams {
                integration: key.clone(),
                operation: OperationKey::new(method.name())?,
                inputs: inputs_of(method)?,
                effect: method.effect(),
                account: AccountNeed::RunPerson,
                ceiling,
            })
        })
        .collect()
}

/// The inputs a call with `method` takes: the route, the path on it,
/// headers, and a body for a method that carries one.
fn inputs_of(method: Method) -> Result<Vec<InputSpec>, DomainError> {
    let mut inputs = vec![
        InputSpec::new(FieldName::new(ROUTE_INPUT)?, InputNeed::Required),
        InputSpec::new(FieldName::new("path")?, InputNeed::Required),
        InputSpec::new(FieldName::new("headers")?, InputNeed::Optional),
    ];
    if method.body() == Body::Json {
        inputs.push(InputSpec::new(FieldName::new("body")?, InputNeed::Optional));
    }
    Ok(inputs)
}

/// `path` on the gateway's workflow listener, refused unless it is a path
/// alone: starting with one `/`, with no backslash, and landing on the
/// listener's own origin.
fn on_gateway(gateway: &url::Url, path: &str) -> Result<url::Url, ActionOutcome> {
    let rooted = path.starts_with('/') && !path.starts_with("//") && !path.contains('\\');
    if !rooted {
        return Err(failed("the path does not start with one /"));
    }
    let Ok(url) = gateway.join(path) else {
        return Err(failed("the path is not one an address can hold"));
    };
    if url.origin() != gateway.origin() {
        return Err(failed("the path leads away from the gateway"));
    }
    Ok(url)
}

/// The bearer header carrying `pass`, kept out of every log.
fn bearer(pass: &Secret) -> Result<HeaderValue, ActionOutcome> {
    let Ok(mut value) = HeaderValue::from_str(&format!("Bearer {}", pass.expose())) else {
        return Err(failed("the pass cannot be sent"));
    };
    value.set_sensitive(true);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::FlowData;
    use ianua_domain::domains::workflows::integration::ActionAccount;
    use ianua_domain::shared::events::chain::EventOrigin;
    use ianua_domain::types::{ActionCallId, ActionClass, DeclaredAction};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn integration(gateway: &str) -> ProtectedApps {
        ProtectedApps::new(AppSettings {
            gateway: url::Url::parse(gateway).unwrap(),
            link: InternalLink::PlainInDevelopment,
            timeout: Duration::from_millis(500),
            most_answer: 1024,
            ceiling: DataClassLevel::Internal,
        })
        .unwrap()
    }

    fn text(value: &str) -> FlowData {
        FlowData::text(value).unwrap()
    }

    fn call(operation: &str, at: &str) -> ActionCall {
        ActionCall {
            call_id: ActionCallId::new(),
            integration: IntegrationKey::new("apps").unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            account: ActionAccount::NoAccount,
            arguments: FlowData::map(vec![
                (FieldName::new(ROUTE_INPUT).unwrap(), text("route")),
                (FieldName::new("path").unwrap(), text(at)),
            ])
            .unwrap(),
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    fn pass() -> Secret {
        Secret::new("a pass for one call")
    }

    /// Ann's run reads her orders: the call reaches the gateway's workflow
    /// listener on the path the step names, carrying its pass, and the
    /// app's answer is the step's outcome.
    #[tokio::test]
    async fn a_call_reaches_the_workflow_listener_with_its_pass() {
        let gateway = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orders/7"))
            .and(header("authorization", "Bearer a pass for one call"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"id\":7}"))
            .expect(1)
            .mount(&gateway)
            .await;

        let called = integration(&gateway.uri())
            .call(&call("get", "/orders/7"), Some(&pass()))
            .await;

        assert!(matches!(called.outcome, ActionOutcome::Succeeded { .. }));
    }

    /// Absolute, protocol-relative and backslash-containing paths fail without
    /// sending a request to the gateway.
    #[tokio::test]
    async fn a_path_leading_away_from_the_gateway_is_refused() {
        let gateway = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&gateway)
            .await;
        let apps = integration(&gateway.uri());

        for away in [
            "//evil.example/steal",
            "https://evil.example/steal",
            "/\\evil.example",
        ] {
            let called = apps.call(&call("get", away), Some(&pass())).await;

            assert!(matches!(called.outcome, ActionOutcome::Failed(_)), "{away}");
        }
    }

    /// A call without a pass fails without sending a request to the gateway.
    #[tokio::test]
    async fn a_call_without_a_pass_is_not_sent() {
        let gateway = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&gateway)
            .await;

        let called = integration(&gateway.uri())
            .call(&call("get", "/orders"), None)
            .await;

        assert!(matches!(called.outcome, ActionOutcome::Failed(_)));
    }

    /// A gateway response of 403 becomes a failed step outcome.
    #[tokio::test]
    async fn a_refusal_by_the_gateway_fails_the_step() {
        let gateway = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&gateway)
            .await;

        let called = integration(&gateway.uri())
            .call(&call("post", "/orders"), Some(&pass()))
            .await;

        assert!(matches!(called.outcome, ActionOutcome::Failed(_)));
    }

    /// Every method acts as the run's person and names its route; a read
    /// reads, a delete deletes, and a write is undeclared, so it needs an
    /// approval before it.
    #[test]
    fn every_operation_acts_as_the_run_s_person() {
        let apps = integration("http://gateway.internal:8082");

        let effects: Vec<_> = apps
            .operations()
            .iter()
            .map(|spec| (spec.operation().as_str().to_owned(), spec.effect()))
            .collect();

        assert!(
            apps.operations()
                .iter()
                .all(|spec| spec.account() == AccountNeed::RunPerson)
        );
        assert_eq!(
            effects[..2],
            [
                (
                    "get".to_owned(),
                    DeclaredAction::Declared(ActionClass::Read)
                ),
                ("post".to_owned(), DeclaredAction::Undeclared),
            ]
        );
    }
}
