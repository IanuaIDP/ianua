//! Asana as a workflow integration, installed under `asana`: a step
//! creates, reads, edits, completes, reopens, deletes and searches tasks,
//! comments on one, and puts one in a project or section, through the
//! token of an account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService): its
//! profile, its operations, each described once in `operations/`, how an
//! account reaches Asana, and the request that proves a token. Requests,
//! refusals, answers and token checks are the SDK's.
//!
//! The account holds the token alone, such as a personal access token. It
//! is asked about at Asana before it is kept, and sent only to the Asana
//! API this deployment names, never to an address a step chooses: a step
//! names a workspace, project or task by its gid, and the address is built
//! from them with every part checked and escaped. No redirect is followed.
//!
//! Workflows do not start on Asana's events: Asana hands a webhook's
//! signing secret over in a handshake the platform must answer with a
//! header, which the SDK's events do not offer.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

mod operations;

use std::time::Duration;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::integration::form::{PreviewKind, PreviewPart};
use ianua_domain::shared::errors::DomainError;
use ianua_integration::ServiceEndpoint;
use ianua_integration::describe::ProfileText;
use ianua_integration::form::PreviewText;
use ianua_integration::rest::access::Access;
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::service::{Answers, Probe, RestService, RestServiceParams};

/// Asana's public API.
pub const PUBLIC_API: &str = "https://app.asana.com/api/1.0/";

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Asana",
    description: "Creates, updates, completes and searches tasks, comments on them and places them in projects in a team's Asana workspaces, through a token the tenant connects.",
    icon: "asana",
    picture: include_str!("../assets/icon.svg"),
    brand: "f06a6a",
};

/// How creating a task is previewed: as an item of work in its workspace.
const PREVIEWS: &[PreviewText] = &[PreviewText {
    operation: "create-task",
    kind: PreviewKind::Issue,
    parts: &[
        (PreviewPart::Place, "workspace"),
        (PreviewPart::Title, "name"),
        (PreviewPart::Body, "notes"),
    ],
}];

/// The headers every call carries.
const HEADERS: &[(&str, &str)] = &[("accept", "application/json")];

/// How the Asana integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct AsanaSettings {
    /// Where Asana's API answers: [`PUBLIC_API`], or a stand-in's.
    pub endpoint: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send to Asana, and so the most
    /// sensitive an answer is counted as.
    pub ceiling: DataClassLevel,
}

/// The Asana integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: AsanaSettings) -> Result<RestService, DomainError> {
    RestService::new(RestServiceParams {
        key: "asana",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: PREVIEWS,
        access: Access::Bearer {
            endpoint: settings.endpoint,
        },
        headers: HEADERS,
        probe: Probe {
            verb: Verb::Get,
            path: &["users", "me"],
            query: &[],
        },
        answers: Answers::ByStatus,
        timeout: settings.timeout,
        ceiling: settings.ceiling,
        sign_in: None,
        events: None,
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
    use ianua_integration::rest::openapi::Description;
    use serde_json::json;
    use wiremock::matchers::{body_json, body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::operations::all;

    /// Asana's own description of its API, which every operation is
    /// checked against. Asana publishes it as YAML at
    /// `Asana/openapi/defs/asana_oas.yaml`; what the operations use of it
    /// is kept in `api-description.json`. To refresh it, download the
    /// file, convert it to JSON (such as with `yq -o=json`), and run the
    /// tests with `IANUA_ASANA_API_DESCRIPTION=/path/to/asana_oas.json`.
    fn description() -> Description {
        Description {
            kept: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("api-description.json"),
            setting: "IANUA_ASANA_API_DESCRIPTION",
            lead: &[],
        }
    }

    /// Every operation calls an endpoint Asana describes, with only the
    /// query parameters and body properties it knows, always sending those
    /// it requires, and promising only outputs and statuses its answer
    /// carries; and the extract holds exactly those endpoints.
    #[test]
    fn every_operation_fits_asanas_api_description() {
        let description = description();
        let extract = description.extract(all()).unwrap();

        let wrong = description.misfits(all(), &extract);

        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        assert_eq!(
            Description::kept_endpoints(&extract),
            Description::called_endpoints(all()),
            "refresh the extract with IANUA_ASANA_API_DESCRIPTION"
        );
    }

    /// A token as a test writes it: not shaped like a real one.
    const TOKEN: &str = "test token for ann";

    fn asana(server: &MockServer) -> RestService {
        integration(AsanaSettings {
            endpoint: ServiceEndpoint::at(&format!("{}/api/1.0/", server.uri())).unwrap(),
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

    fn call(operation: &str, arguments: FlowData) -> ActionCall {
        ActionCall {
            call_id: ActionCallId::new(),
            integration: IntegrationKey::new("asana").unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments,
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    fn new_task(workspace: &str) -> ActionCall {
        call(
            "create-task",
            arguments(vec![
                ("workspace", text(workspace)),
                ("name", text("Renew the support contract")),
                ("notes", text("The current one ends in December.")),
            ]),
        )
    }

    async fn requests_made(server: &MockServer) -> usize {
        server.received_requests().await.unwrap().len()
    }

    /// Ann's workflow creates a task in her workspace: Asana is asked with
    /// her token and the name and notes wrapped in `data`, and the new
    /// task's gid comes back in the step's output.
    #[tokio::test]
    async fn a_task_is_created_with_the_accounts_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/1.0/tasks"))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .and(body_json(json!({ "data": {
                "workspace": "1100",
                "name": "Renew the support contract",
                "notes": "The current one ends in December."
            } })))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(json!({ "data": { "gid": "3300", "name": "Renew" } })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let outcome = asana(&server)
            .call(&new_task("1100"), Some(&Secret::new(TOKEN.to_owned())))
            .await
            .outcome;

        let ActionOutcome::Succeeded { output, .. } = outcome else {
            panic!("the task was not created: {outcome:?}");
        };
        let gid = output
            .at(&DataPath::parse("json.data.gid").unwrap())
            .map(FlowData::value);
        assert_eq!(gid, Some(FlowValue::Text("3300")));
    }

    /// Missing tokens, creating a task without a workspace, and deleting a
    /// task named `..` each fail without sending a request to Asana.
    #[tokio::test]
    async fn no_token_no_workspace_or_a_crooked_task_sends_nothing() {
        let server = MockServer::start().await;
        let asana = asana(&server);
        let token = Secret::new(TOKEN.to_owned());
        let unplaced = call(
            "create-task",
            arguments(vec![("name", text("Renew the support contract"))]),
        );
        let crooked = call("delete-task", arguments(vec![("task", text(".."))]));

        let without = asana.call(&new_task("1100"), None).await.outcome;
        let nowhere = asana.call(&unplaced, Some(&token)).await.outcome;
        let climbed = asana.call(&crooked, Some(&token)).await.outcome;

        for outcome in [without, nowhere, climbed] {
            assert!(matches!(outcome, ActionOutcome::Failed(_)), "{outcome:?}");
        }
        assert_eq!(requests_made(&server).await, 0);
    }

    /// Asana refusing the token fails the step; Asana limiting the rate
    /// turns it away, to be tried again.
    #[tokio::test]
    async fn a_refusal_fails_and_a_busy_asana_turns_away() {
        let server = MockServer::start().await;
        Mock::given(path("/api/1.0/tasks"))
            .and(body_partial_json(
                json!({ "data": { "workspace": "1100" } }),
            ))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        Mock::given(path("/api/1.0/tasks"))
            .and(body_partial_json(
                json!({ "data": { "workspace": "1200" } }),
            ))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;
        let asana = asana(&server);
        let token = Secret::new(TOKEN.to_owned());

        let refused = asana.call(&new_task("1100"), Some(&token)).await.outcome;
        let busy = asana.call(&new_task("1200"), Some(&token)).await.outcome;

        assert!(matches!(refused, ActionOutcome::Failed(_)), "{refused:?}");
        assert!(matches!(busy, ActionOutcome::TurnedAway(_)), "{busy:?}");
    }

    /// Asana answering who a token belongs to `status`.
    async fn checked(status: u16, token: &str) -> AccountCheck {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/1.0/users/me"))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        Mock::given(path("/api/1.0/users/me"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        asana(&server)
            .check_account(&Secret::new(token.to_owned()))
            .await
    }

    /// Tess connects the team's token: Asana knows whose it is, so it is
    /// taken.
    #[tokio::test]
    async fn a_token_asana_knows_is_accepted() {
        assert_eq!(checked(200, TOKEN).await, AccountCheck::Accepted);
    }

    /// Asana's 401 response to a mistyped token refuses the account check.
    #[tokio::test]
    async fn a_token_asana_does_not_know_is_refused() {
        let answer = checked(200, "a mistyped token").await;

        assert!(matches!(answer, AccountCheck::Refused(_)));
    }

    /// Asana limiting the rate or failing says nothing of the token, so the
    /// check is unreachable, never accepted.
    #[tokio::test]
    async fn a_busy_or_failing_asana_says_nothing_of_the_token() {
        for status in [429, 500, 503] {
            assert_eq!(checked(status, TOKEN).await, AccountCheck::Unreachable);
        }
    }

    /// Asana presents itself with a title, icon and brand colour white
    /// stays readable on, and explains every one of its operations.
    #[tokio::test]
    async fn asana_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let asana = asana(&server);

        assert_eq!(asana.profile().title().as_str(), "Asana");
        assert_eq!(asana.profile().icon().as_str(), "asana");
        assert_eq!(asana.profile().brand().as_str(), "f06a6a");
        assert_eq!(asana.guides().len(), asana.operations().len());
    }
}
