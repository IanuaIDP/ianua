//! ClickUp as a workflow integration, installed under `clickup`: a step
//! creates, reads, edits, moves to another status, tags, comments on and
//! deletes tasks, and lists the workspaces, spaces, folders, lists and
//! people they sit among, through the token of an account the tenant
//! connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService): its
//! profile, its operations, each described once in `operations/`, how an
//! account reaches ClickUp, and the request that proves a token. Requests,
//! refusals, answers and token checks are the SDK's.
//!
//! The account holds the token alone, a personal API token, which ClickUp
//! takes in the authorization header with nothing before it. It is asked
//! about at ClickUp before it is kept, and sent only to the ClickUp API
//! this deployment names, never to an address a step chooses: a step names
//! a workspace, space, folder, list or task by its id, and the address is
//! built from them with every part checked and escaped. No redirect is
//! followed.
//!
//! Workflows do not start on ClickUp's events: ClickUp chooses a webhook's
//! signing secret itself and hands it back when the webhook is made, while
//! the SDK's events sign with a secret the platform makes and keeps.

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

/// ClickUp's public API.
pub const PUBLIC_API: &str = "https://api.clickup.com/api/v2/";

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "ClickUp",
    description: "Creates, updates, moves, tags and comments on tasks in a team's ClickUp lists, and finds the workspaces, spaces, folders and lists they sit in, through a token the tenant connects.",
    icon: "clickup",
    picture: include_str!("../assets/icon.svg"),
    brand: "7b68ee",
};

/// How creating a task is previewed: as an item of work in its list.
const PREVIEWS: &[PreviewText] = &[PreviewText {
    operation: "create-task",
    kind: PreviewKind::Issue,
    parts: &[
        (PreviewPart::Place, "list"),
        (PreviewPart::Title, "name"),
        (PreviewPart::Body, "description"),
    ],
}];

/// The headers every call carries.
const HEADERS: &[(&str, &str)] = &[("accept", "application/json")];

/// How the ClickUp integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct ClickUpSettings {
    /// Where ClickUp's API answers: [`PUBLIC_API`], or a stand-in's.
    pub endpoint: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send to ClickUp, and so the most
    /// sensitive an answer is counted as.
    pub ceiling: DataClassLevel,
}

/// The ClickUp integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: ClickUpSettings) -> Result<RestService, DomainError> {
    RestService::new(RestServiceParams {
        key: "clickup",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: PREVIEWS,
        access: Access::Scheme {
            endpoint: settings.endpoint,
            scheme: "",
        },
        headers: HEADERS,
        probe: Probe {
            verb: Verb::Get,
            path: &["user"],
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
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::operations::all;

    /// ClickUp's own description of its API, which every operation is
    /// checked against. ClickUp publishes it at
    /// `https://developer.clickup.com/openapi/clickup-api-v2-reference.json`;
    /// what the operations use of it is kept in `api-description.json`. To
    /// refresh it, download the file and run the tests with
    /// `IANUA_CLICKUP_API_DESCRIPTION=/path/to/clickup-api-v2-reference.json`.
    /// Its paths start with `v2`, which the account's address already
    /// holds.
    fn description() -> Description {
        Description {
            kept: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("api-description.json"),
            setting: "IANUA_CLICKUP_API_DESCRIPTION",
            lead: &["v2"],
        }
    }

    /// Every operation calls an endpoint ClickUp describes, with only the
    /// query parameters and body properties it knows, always sending those
    /// it requires, and promising only outputs and statuses its answer
    /// carries; and the extract holds exactly those endpoints.
    #[test]
    fn every_operation_fits_clickups_api_description() {
        let description = description();
        let extract = description.extract(all()).unwrap();

        let wrong = description.misfits(all(), &extract);

        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        assert_eq!(
            Description::kept_endpoints(&extract),
            Description::called_endpoints(all()),
            "refresh the extract with IANUA_CLICKUP_API_DESCRIPTION"
        );
    }

    /// A token as a test writes it: not shaped like a real one.
    const TOKEN: &str = "test token for ann";

    fn clickup(server: &MockServer) -> RestService {
        integration(ClickUpSettings {
            endpoint: ServiceEndpoint::at(&format!("{}/api/v2/", server.uri())).unwrap(),
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
            integration: IntegrationKey::new("clickup").unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments,
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    fn new_task(list: &str) -> ActionCall {
        call(
            "create-task",
            arguments(vec![
                ("list", text(list)),
                ("name", text("Renew the support contract")),
                ("description", text("The current one ends in December.")),
            ]),
        )
    }

    async fn requests_made(server: &MockServer) -> usize {
        server.received_requests().await.unwrap().len()
    }

    /// Ann's workflow creates a task in her list: ClickUp is asked with her
    /// token alone in the authorization header, and the new task's id
    /// comes back in the step's output.
    #[tokio::test]
    async fn a_task_is_created_with_the_accounts_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v2/list/9001/task"))
            .and(header("authorization", TOKEN))
            .and(body_json(json!({
                "name": "Renew the support contract",
                "markdown_content": "The current one ends in December."
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "id": "86abc", "name": "Renew" })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let outcome = clickup(&server)
            .call(&new_task("9001"), Some(&Secret::new(TOKEN.to_owned())))
            .await
            .outcome;

        let ActionOutcome::Succeeded { output, .. } = outcome else {
            panic!("the task was not created: {outcome:?}");
        };
        let id = output
            .at(&DataPath::parse("json.id").unwrap())
            .map(FlowData::value);
        assert_eq!(id, Some(FlowValue::Text("86abc")));
    }

    /// Missing tokens, creating a task without a list, and deleting a task
    /// named `..` each fail without sending a request to ClickUp.
    #[tokio::test]
    async fn no_token_no_list_or_a_crooked_task_sends_nothing() {
        let server = MockServer::start().await;
        let clickup = clickup(&server);
        let token = Secret::new(TOKEN.to_owned());
        let unplaced = call(
            "create-task",
            arguments(vec![("name", text("Renew the support contract"))]),
        );
        let crooked = call("delete-task", arguments(vec![("task", text(".."))]));

        let without = clickup.call(&new_task("9001"), None).await.outcome;
        let nowhere = clickup.call(&unplaced, Some(&token)).await.outcome;
        let climbed = clickup.call(&crooked, Some(&token)).await.outcome;

        for outcome in [without, nowhere, climbed] {
            assert!(matches!(outcome, ActionOutcome::Failed(_)), "{outcome:?}");
        }
        assert_eq!(requests_made(&server).await, 0);
    }

    /// ClickUp refusing the token fails the step; ClickUp limiting the rate
    /// turns it away, to be tried again.
    #[tokio::test]
    async fn a_refusal_fails_and_a_busy_clickup_turns_away() {
        let server = MockServer::start().await;
        Mock::given(path("/api/v2/list/9001/task"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        Mock::given(path("/api/v2/list/9002/task"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;
        let clickup = clickup(&server);
        let token = Secret::new(TOKEN.to_owned());

        let refused = clickup.call(&new_task("9001"), Some(&token)).await.outcome;
        let busy = clickup.call(&new_task("9002"), Some(&token)).await.outcome;

        assert!(matches!(refused, ActionOutcome::Failed(_)), "{refused:?}");
        assert!(matches!(busy, ActionOutcome::TurnedAway(_)), "{busy:?}");
    }

    /// ClickUp answering who a token belongs to with `status`.
    async fn checked(status: u16, token: &str) -> AccountCheck {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/user"))
            .and(header("authorization", TOKEN))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        Mock::given(path("/api/v2/user"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        clickup(&server)
            .check_account(&Secret::new(token.to_owned()))
            .await
    }

    /// Tess connects the team's token: ClickUp knows whose it is, so it is
    /// taken.
    #[tokio::test]
    async fn a_token_clickup_knows_is_accepted() {
        assert_eq!(checked(200, TOKEN).await, AccountCheck::Accepted);
    }

    /// ClickUp's 401 response to a mistyped token refuses the account check.
    #[tokio::test]
    async fn a_token_clickup_does_not_know_is_refused() {
        let answer = checked(200, "a mistyped token").await;

        assert!(matches!(answer, AccountCheck::Refused(_)));
    }

    /// ClickUp limiting the rate or failing says nothing of the token, so
    /// the check is unreachable, never accepted.
    #[tokio::test]
    async fn a_busy_or_failing_clickup_says_nothing_of_the_token() {
        for status in [429, 500, 503] {
            assert_eq!(checked(status, TOKEN).await, AccountCheck::Unreachable);
        }
    }

    /// ClickUp presents itself with a title, icon and brand colour white
    /// stays readable on, and explains every one of its operations.
    #[tokio::test]
    async fn clickup_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let clickup = clickup(&server);

        assert_eq!(clickup.profile().title().as_str(), "ClickUp");
        assert_eq!(clickup.profile().icon().as_str(), "clickup");
        assert_eq!(clickup.profile().brand().as_str(), "7b68ee");
        assert_eq!(clickup.guides().len(), clickup.operations().len());
    }
}
