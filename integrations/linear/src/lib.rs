//! Linear as a workflow integration, installed under `linear`: a step
//! reads, searches, creates, edits, moves, assigns, comments on and
//! archives issues, and lists a workspace's teams, states, labels, projects
//! and people, through the API key of an account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService): its
//! profile, its operations in `operations/`, how an account reaches Linear,
//! and the request that proves a key. Linear's API is GraphQL alone, so
//! every step posts one fixed document to `graphql` with its inputs among
//! the variables, and Linear answers a refusal with success and an
//! `errors` list: the SDK reads it as GraphQL, so an error fails the step
//! and a rate limit turns it away.
//!
//! The account holds a personal API key, which Linear takes in the
//! `Authorization` header with nothing before it. It is asked about at
//! Linear before it is kept, with a query for the key's own person sent as
//! a `GET`, and sent only to the Linear API this deployment names, never to
//! an address a step chooses. No redirect is followed. A workflow may also
//! start on an issue created or changed in one team (`events`), through a
//! webhook registered with an admin's key and proven by its own secret.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

mod events;
mod operations;

use std::time::Duration;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::integration::form::{PreviewKind, PreviewPart};
use ianua_domain::shared::errors::DomainError;
use ianua_integration::ServiceEndpoint;
use ianua_integration::describe::ProfileText;
use ianua_integration::form::PreviewText;
use ianua_integration::rest::access::Access;
use ianua_integration::rest::event::ServiceEvents;
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::service::{Answers, Probe, RestService, RestServiceParams};
use ianua_integration::rest::watch::WatchCalls;

use crate::events::Hooks;

/// Linear's public API.
pub const PUBLIC_API: &str = "https://api.linear.app/";

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Linear",
    description: "Creates, changes, moves, assigns, comments on and archives issues in a team's Linear workspace, through an API key the tenant connects.",
    icon: "linear",
    picture: include_str!("../assets/icon.svg"),
    brand: "5e6ad2",
};

/// How creating an issue is previewed: as Linear shows one.
const PREVIEWS: &[PreviewText] = &[PreviewText {
    operation: "create-issue",
    kind: PreviewKind::Issue,
    parts: &[
        (PreviewPart::Place, "team"),
        (PreviewPart::Title, "title"),
        (PreviewPart::Body, "description"),
        (PreviewPart::Labels, "labels"),
    ],
}];

/// The headers every call carries. Linear refuses a `GET` that names
/// none of the headers a browser cannot send across sites without asking
/// first, and the probe is a `GET`.
const HEADERS: &[(&str, &str)] = &[
    ("apollo-require-preflight", "true"),
    ("user-agent", "ianua-workflows"),
];

/// How the Linear integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct LinearSettings {
    /// Where Linear's API answers: [`PUBLIC_API`], or a stand-in's.
    pub endpoint: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send to Linear, and so the most
    /// sensitive an answer or an event is counted as.
    pub ceiling: DataClassLevel,
}

/// The Linear integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: LinearSettings) -> Result<RestService, DomainError> {
    let access = Access::Scheme {
        endpoint: settings.endpoint,
        scheme: "",
    };
    let hooks = Hooks::new(
        WatchCalls::new(access.clone(), HEADERS, settings.timeout)?,
        settings.ceiling,
    );
    RestService::new(RestServiceParams {
        key: "linear",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: PREVIEWS,
        access,
        headers: HEADERS,
        probe: Probe {
            verb: Verb::Get,
            path: &["graphql"],
            query: &[("query", "{ viewer { id } }")],
        },
        answers: Answers::GraphQl,
        timeout: settings.timeout,
        ceiling: settings.ceiling,
        sign_in: None,
        events: Some(ServiceEvents {
            described: events::all(),
            watcher: Box::new(hooks),
        }),
    })
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::{DataPath, FieldName, FlowData, FlowValue};
    use ianua_domain::domains::workflows::execution::ActionCall;
    use ianua_domain::domains::workflows::execution::step::ActionOutcome;
    use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
    use ianua_domain::domains::workflows::integration::{
        ActionAccount, IntegrationKey, OperationKey,
    };
    use ianua_domain::shared::events::chain::EventOrigin;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{ActionCallId, DeclaredAction, IntegrationAccountId};
    use ianua_integration::Integration;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// A key as a test writes it: not shaped like a real one.
    const KEY: &str = "test key for ann";

    fn linear(server: &MockServer) -> RestService {
        integration(LinearSettings {
            endpoint: ServiceEndpoint::at(&server.uri()).unwrap(),
            timeout: Duration::from_secs(2),
            ceiling: DataClassLevel::Internal,
        })
        .unwrap()
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

    fn text(value: &str) -> FlowData {
        FlowData::text(value).unwrap()
    }

    fn new_issue() -> ActionCall {
        ActionCall {
            call_id: ActionCallId::new(),
            integration: IntegrationKey::new("linear").unwrap(),
            operation: OperationKey::new("create-issue").unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments: arguments(vec![
                ("team", text("team one")),
                ("title", text("Nightly build failed")),
            ]),
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    fn key() -> Secret {
        Secret::new(KEY.to_owned())
    }

    /// Ann's workflow creates an issue: Linear is asked with her key alone
    /// in the header and the title among the variables, and the new issue's
    /// identifier comes back in the step's output.
    #[tokio::test]
    async fn an_issue_is_created_with_the_accounts_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(header("authorization", KEY))
            .and(header("content-type", "application/json"))
            .and(body_partial_json(json!({
                "variables": { "input": { "teamId": "team one", "title": "Nightly build failed" } }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "issueCreate": { "success": true, "issue": { "identifier": "ENG-42" } } }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let outcome = linear(&server)
            .call(&new_issue(), Some(&key()))
            .await
            .outcome;

        let ActionOutcome::Succeeded { output, .. } = outcome else {
            panic!("the issue was not created: {outcome:?}");
        };
        let identifier = output
            .at(&DataPath::parse("json.data.issueCreate.issue.identifier").unwrap())
            .map(FlowData::value);
        assert_eq!(identifier, Some(FlowValue::Text("ENG-42")));
    }

    /// A GraphQL team error in Linear's HTTP success response fails the
    /// issue step with the provider's message; a rate limit turns it away.
    #[tokio::test]
    async fn an_error_in_a_successful_answer_fails_the_step() {
        let refused = MockServer::start().await;
        Mock::given(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": null,
                "errors": [{ "message": "Entity not found: Team", "extensions": { "code": "INVALID_INPUT" } }]
            })))
            .mount(&refused)
            .await;
        let busy = MockServer::start().await;
        Mock::given(path("/graphql"))
            .respond_with(ResponseTemplate::new(429).set_body_json(json!({
                "errors": [{ "message": "Rate limit exceeded", "extensions": { "code": "RATELIMITED" } }]
            })))
            .mount(&busy)
            .await;

        let no = linear(&refused)
            .call(&new_issue(), Some(&key()))
            .await
            .outcome;
        let later = linear(&busy).call(&new_issue(), Some(&key())).await.outcome;

        let ActionOutcome::Failed(why) = no else {
            panic!("a refusal counted as done: {no:?}");
        };
        assert!(why.as_str().contains("Entity not found: Team"));
        assert!(matches!(later, ActionOutcome::TurnedAway(_)));
    }

    /// A missing key fails the issue step without sending a request to Linear.
    #[tokio::test]
    async fn no_key_sends_nothing() {
        let server = MockServer::start().await;

        let outcome = linear(&server).call(&new_issue(), None).await.outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// Linear answering who a key belongs to: data for the key it knows,
    /// `401` for any other.
    async fn checked(key: &str) -> AccountCheck {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/graphql"))
            .and(query_param("query", "{ viewer { id } }"))
            .and(header("apollo-require-preflight", "true"))
            .and(header("authorization", KEY))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "viewer": { "id": "ann's id" } }
            })))
            .mount(&server)
            .await;
        Mock::given(path("/graphql"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "errors": [{ "message": "Authentication required, not authenticated" }]
            })))
            .mount(&server)
            .await;
        linear(&server)
            .check_account(&Secret::new(key.to_owned()))
            .await
    }

    /// Tess connects the team's key: Linear knows whose it is, so it is
    /// taken.
    #[tokio::test]
    async fn a_key_linear_knows_is_accepted() {
        assert_eq!(checked(KEY).await, AccountCheck::Accepted);
    }

    /// Linear's 401 response to a mistyped key refuses the account check.
    #[tokio::test]
    async fn a_key_linear_does_not_know_is_refused() {
        let answer = checked("a mistyped key").await;

        assert!(matches!(answer, AccountCheck::Refused(_)), "{answer:?}");
    }

    /// Linear presents itself with a title, icon and brand colour, explains
    /// every one of its operations and offers its events.
    #[tokio::test]
    async fn linear_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let linear = linear(&server);

        assert_eq!(linear.profile().title().as_str(), "Linear");
        assert_eq!(linear.profile().icon().as_str(), "linear");
        assert_eq!(linear.guides().len(), linear.operations().len());
        assert_eq!(linear.events().len(), 2);
    }
}
