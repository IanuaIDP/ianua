//! Notion as a workflow integration, installed under `notion`: a step
//! finds pages and databases, reads and adds pages, changes their
//! properties, reads and adds their content, comments, and lists the
//! workspace's people, through an account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService). A Notion
//! account holds an integration's secret, sent as a bearer token only to
//! the API, with the API version every call names. Notion sees only the
//! pages and databases a workspace shared with that integration. A secret
//! is proven by reading the integration's own bot user.
//!
//! Notion publishes no OpenAPI description, so the steps follow its API
//! reference for version 2025-09-03 and are held to the SDK's rules alone.
//! From that version a database holds one or more data sources, and its
//! entries live in those: a step queries, reads and adds to a data source,
//! which older versions refuse once a database holds more than one.
//! Notion's webhooks are set up in an integration's settings page, not
//! through the API, so no workflow starts on them here.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

mod operations;

use std::time::Duration;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::shared::errors::DomainError;
use ianua_integration::ServiceEndpoint;
use ianua_integration::describe::ProfileText;
use ianua_integration::rest::access::Access;
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::service::{Answers, Probe, RestService, RestServiceParams};

/// Notion's public API.
pub const PUBLIC_API: &str = "https://api.notion.com/v1/";

/// The API version every call names.
const VERSION: &str = "2025-09-03";

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Notion",
    description: "Finds, adds and changes a team's Notion pages and database entries, adds content and comments, through an integration secret the tenant connects.",
    icon: "notion",
    picture: include_str!("../assets/icon.svg"),
    brand: "000000",
};

/// How the Notion integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct NotionSettings {
    /// Where Notion's API answers: [`PUBLIC_API`], or a stand-in's.
    pub endpoint: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send, and so the most sensitive
    /// an answer is counted as.
    pub ceiling: DataClassLevel,
}

/// The Notion integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: NotionSettings) -> Result<RestService, DomainError> {
    RestService::new(RestServiceParams {
        key: "notion",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: &[],
        access: Access::Bearer {
            endpoint: settings.endpoint,
        },
        headers: &[("notion-version", VERSION)],
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
    use ianua_domain::domains::workflows::data::{FieldName, FlowData};
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
    use ianua_integration::answer::flow_of;
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// A secret as a test writes it: not shaped like a real one.
    const SECRET: &str = "acme notion integration secret";

    fn notion(server: &MockServer) -> RestService {
        integration(NotionSettings {
            endpoint: ServiceEndpoint::at(&format!("{}/v1/", server.uri())).unwrap(),
            timeout: Duration::from_secs(2),
            ceiling: DataClassLevel::Internal,
        })
        .unwrap()
    }

    fn secret() -> Secret {
        Secret::new(SECRET.to_owned())
    }

    fn step(operation: &str, entries: Vec<(&str, FlowData)>) -> ActionCall {
        let arguments = FlowData::map(
            entries
                .into_iter()
                .map(|(name, value)| (FieldName::new(name).unwrap(), value))
                .collect(),
        )
        .unwrap();
        ActionCall {
            call_id: ActionCallId::new(),
            integration: IntegrationKey::new("notion").unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments,
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    /// Ann's workflow comments on a page: the secret signs it, the API
    /// version is named, and the comment goes to the page.
    #[tokio::test]
    async fn a_comment_is_sent_with_the_secret_and_the_version() {
        let server = MockServer::start().await;
        let text = json!([{ "text": { "content": "Looks good" } }]);
        Mock::given(method("POST"))
            .and(path("/v1/comments"))
            .and(header("authorization", format!("Bearer {SECRET}").as_str()))
            .and(header("notion-version", VERSION))
            .and(body_json(json!({
                "parent": { "page_id": "p-1" },
                "rich_text": text
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "c-1" })))
            .expect(1)
            .mount(&server)
            .await;
        let comment = step(
            "comment-on-page",
            vec![
                ("page", FlowData::text("p-1").unwrap()),
                ("text", flow_of(&text).unwrap()),
            ],
        );

        let outcome = notion(&server)
            .call(&comment, Some(&secret()))
            .await
            .outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
    }

    /// Notion reading the integration's bot user for a secret, answering
    /// `status`.
    async fn checked(status: u16) -> AccountCheck {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/users/me"))
            .and(header("authorization", format!("Bearer {SECRET}").as_str()))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({ "type": "bot" })))
            .mount(&server)
            .await;
        notion(&server).check_account(&secret()).await
    }

    /// Tess connects the secret: Notion knows its bot, so it is taken; a
    /// secret Notion does not know is refused, and Notion being down says
    /// nothing of it.
    #[tokio::test]
    async fn a_known_secret_is_accepted_and_an_unknown_one_refused() {
        assert_eq!(checked(200).await, AccountCheck::Accepted);
        assert!(matches!(checked(401).await, AccountCheck::Refused(_)));
        assert_eq!(checked(503).await, AccountCheck::Unreachable);
    }

    /// A page read without an account secret fails without contacting Notion.
    #[tokio::test]
    async fn no_secret_sends_nothing() {
        let server = MockServer::start().await;
        let read = step("get-page", vec![("page", FlowData::text("p-1").unwrap())]);

        let outcome = notion(&server).call(&read, None).await.outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        assert_eq!(server.received_requests().await.unwrap().len(), 0);
    }

    /// Notion presents itself with a title, icon and brand colour, explains
    /// every operation and starts no workflow.
    #[tokio::test]
    async fn notion_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let notion = notion(&server);

        assert_eq!(notion.profile().icon().as_str(), "notion");
        assert_eq!(notion.profile().brand().as_str(), "000000");
        assert_eq!(notion.guides().len(), notion.operations().len());
        assert!(notion.events().is_empty());
    }
}
