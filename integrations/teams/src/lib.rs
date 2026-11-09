//! Microsoft Teams as a workflow integration, installed under `teams`: a
//! step lists the account's teams, their members, channels and messages
//! and its chats, posts to a channel, replies in it, sends to a chat, and
//! creates, archives and deletes a channel, through Microsoft Graph and an
//! account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService). A
//! Microsoft account holds `{"client_id", "client_secret",
//! "refresh_token"}`: the tenant's own Entra app and a delegated grant to
//! the Teams permissions its steps need. Before each call the grant is
//! exchanged at Microsoft's token address for a token lasting about an
//! hour, which signs the call; the grant never leaves for Graph. Microsoft
//! hands back a new refresh token with each exchange, and the account keeps
//! it in the old one's place. The exchange names no scope, which Microsoft
//! allows: the token then carries what the grant was given, so the app
//! should be granted Graph's permissions alone. Reading the account's own
//! profile (`GET me`) proves a grant.
//!
//! No step starts on what Teams sends: Graph checks a subscription's
//! address by calling it with a token to echo before the subscription
//! exists, and the platform keeps a registration only once the service
//! took it, so that first call finds no registration to answer for.

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

/// Microsoft Graph's public API, the default of `TEAMS_API_URL`.
pub const PUBLIC_API: &str = "https://graph.microsoft.com/v1.0/";

/// Microsoft's token address for work, school and personal accounts, where
/// a grant is exchanged for a token: the default of `MICROSOFT_TOKEN_URL`.
pub const PUBLIC_TOKEN: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Microsoft Teams",
    description: "Posts and reads messages in a team's channels and chats, and sets up channels, through a Microsoft grant the tenant connects.",
    icon: "teams",
    picture: include_str!("../assets/icon.svg"),
    brand: "4b53bc",
};

/// How posting to a channel and sending to a chat are previewed: as the
/// message in Teams.
const PREVIEWS: &[PreviewText] = &[
    PreviewText {
        operation: "post-message",
        kind: PreviewKind::ChatMessage,
        parts: &[
            (PreviewPart::Place, "channel"),
            (PreviewPart::Title, "subject"),
            (PreviewPart::Body, "text"),
        ],
    },
    PreviewText {
        operation: "reply-to-message",
        kind: PreviewKind::ChatMessage,
        parts: &[(PreviewPart::Place, "channel"), (PreviewPart::Body, "text")],
    },
    PreviewText {
        operation: "send-chat-message",
        kind: PreviewKind::ChatMessage,
        parts: &[(PreviewPart::Place, "chat"), (PreviewPart::Body, "text")],
    },
];

/// How the Microsoft Teams integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct TeamsSettings {
    /// Where Microsoft Graph answers: [`PUBLIC_API`], or a stand-in's.
    pub endpoint: ServiceEndpoint,
    /// Where a grant is exchanged for a token: [`PUBLIC_TOKEN`], or a
    /// stand-in's.
    pub token: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send, and so the most sensitive
    /// an answer is counted as.
    pub ceiling: DataClassLevel,
}

/// The Microsoft Teams integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: TeamsSettings) -> Result<RestService, DomainError> {
    RestService::new(RestServiceParams {
        key: "teams",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: PREVIEWS,
        access: Access::Refreshed {
            endpoint: settings.endpoint,
            token: settings.token,
        },
        headers: &[],
        probe: Probe {
            verb: Verb::Get,
            path: &["me"],
            query: &[("$select", "id")],
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
    use ianua_integration::rest::openapi::Description;
    use ianua_integration::{Integration, Renewed};
    use serde_json::json;
    use wiremock::matchers::{body_json, body_string_contains, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::operations::all;

    /// Microsoft Graph's API described as OpenAPI 3, which every operation
    /// is checked against. Microsoft publishes it as YAML at
    /// `https://raw.githubusercontent.com/microsoftgraph/msgraph-metadata/master/openapi/v1.0/openapi.yaml`;
    /// convert it to JSON (`yq -o=json`), and what the operations use of it
    /// is kept in `api-description.json`. To refresh it, run the tests with
    /// `IANUA_TEAMS_API_DESCRIPTION=/path/to/openapi.json`.
    fn description() -> Description {
        Description {
            kept: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("api-description.json"),
            setting: "IANUA_TEAMS_API_DESCRIPTION",
            lead: &[],
        }
    }

    /// What Microsoft's description marks required on every entity it
    /// takes, though Graph creates channels and messages without it: the
    /// OData type annotation, which Graph reads from the address.
    const ANNOTATION: &str = "requires @odata.type,";

    /// Every operation calls an endpoint Microsoft describes, with only the
    /// parameters and body properties it knows, always sending those it
    /// requires but the type annotation, and promising only outputs its
    /// answer carries; and the extract holds exactly those endpoints.
    #[test]
    fn every_operation_fits_microsofts_api_description() {
        let description = description();
        let extract = description.extract(all()).unwrap();

        let wrong: Vec<String> = description
            .misfits(all(), &extract)
            .into_iter()
            .filter(|misfit| !misfit.contains(ANNOTATION))
            .collect();

        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        assert_eq!(
            Description::kept_endpoints(&extract),
            Description::called_endpoints(all()),
            "refresh the extract with IANUA_TEAMS_API_DESCRIPTION"
        );
    }

    /// A grant as a test writes it: not shaped like a real one.
    const GRANT: &str = r#"{"client_id": "contoso app", "client_secret": "app words", "refresh_token": "lasting grant"}"#;

    /// Microsoft's stand-in: its token address issuing `short token` for
    /// the grant and handing back `next grant` in its place, and Graph
    /// under `/v1.0`.
    async fn microsoft() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=lasting+grant"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "short token",
                "refresh_token": "next grant",
                "expires_in": 3599
            })))
            .mount(&server)
            .await;
        server
    }

    fn teams(server: &MockServer) -> RestService {
        integration(TeamsSettings {
            endpoint: ServiceEndpoint::at(&format!("{}/v1.0/", server.uri())).unwrap(),
            token: ServiceEndpoint::at(&format!("{}/token", server.uri())).unwrap(),
            timeout: Duration::from_secs(2),
            ceiling: DataClassLevel::Internal,
        })
        .unwrap()
    }

    fn grant() -> Secret {
        Secret::new(GRANT.to_owned())
    }

    fn text(value: &str) -> FlowData {
        FlowData::text(value).unwrap()
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
            integration: IntegrationKey::new("teams").unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments,
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    fn deploy_note() -> ActionCall {
        step(
            "post-message",
            vec![
                ("team", text("team-1")),
                ("channel", text("19:general@thread.tacv2")),
                ("text", text("Deploy finished")),
            ],
        )
    }

    /// Ann's workflow posts the deploy note: the grant is exchanged for a
    /// token, which signs the message sent to the channel, and the account
    /// keeps the refresh token Microsoft handed back.
    #[tokio::test]
    async fn a_message_is_posted_with_a_token_the_grant_was_exchanged_for() {
        let server = microsoft().await;
        Mock::given(method("POST"))
            .and(path(
                "/v1.0/teams/team-1/channels/19:general@thread.tacv2/messages",
            ))
            .and(header("authorization", "Bearer short token"))
            .and(body_json(
                json!({ "body": { "content": "Deploy finished" } }),
            ))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(json!({ "id": "1730700000000" })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let called = teams(&server).call(&deploy_note(), Some(&grant())).await;

        assert!(
            matches!(called.outcome, ActionOutcome::Succeeded { .. }),
            "{:?}",
            called.outcome
        );
        let Renewed::To(kept) = called.renewed else {
            panic!("the new grant was not kept");
        };
        assert!(kept.expose().contains("next grant"));
    }

    /// Posting a message without text fails without sending any request
    /// to Microsoft, including a token exchange.
    #[tokio::test]
    async fn a_step_that_cannot_be_sent_never_exchanges_the_grant() {
        let server = MockServer::start().await;
        let wordless = step(
            "post-message",
            vec![
                ("team", text("team-1")),
                ("channel", text("19:general@thread.tacv2")),
            ],
        );

        let outcome = teams(&server).call(&wordless, Some(&grant())).await.outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        assert_eq!(server.received_requests().await.unwrap().len(), 0);
    }

    /// Microsoft's invalid-grant response fails the message step; all
    /// requests stay at the token endpoint.
    #[tokio::test]
    async fn a_revoked_grant_fails_without_calling_graph() {
        let server = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(
                ResponseTemplate::new(400).set_body_json(json!({ "error": "invalid_grant" })),
            )
            .mount(&server)
            .await;

        let outcome = teams(&server)
            .call(&deploy_note(), Some(&grant()))
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        let calls = server.received_requests().await.unwrap();
        assert!(calls.iter().all(|call| call.url.path() == "/token"));
    }

    /// Graph reading the account's own profile for a grant, answering
    /// `status`.
    async fn checked(server: &MockServer, status: u16) -> AccountCheck {
        Mock::given(method("GET"))
            .and(path("/v1.0/me"))
            .and(query_param("$select", "id"))
            .and(header("authorization", "Bearer short token"))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({ "id": "u1" })))
            .mount(server)
            .await;
        teams(server).check_account(&grant()).await
    }

    /// Tess connects the grant: Microsoft issues a token and Graph reads
    /// her profile, so it is taken; a token Graph refuses is refused.
    #[tokio::test]
    async fn a_live_grant_is_accepted_and_one_graph_refuses_is_refused() {
        assert_eq!(
            checked(&microsoft().await, 200).await,
            AccountCheck::Accepted
        );
        assert!(matches!(
            checked(&microsoft().await, 401).await,
            AccountCheck::Refused(_)
        ));
    }

    /// A rejected grant fails the account check, while a 503 response from
    /// Microsoft's token endpoint reports the account as unreachable.
    #[tokio::test]
    async fn a_revoked_grant_is_refused_and_a_down_token_address_says_nothing() {
        let revoked = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&revoked)
            .await;
        let down = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&down)
            .await;

        let refused = teams(&revoked).check_account(&grant()).await;
        let unknown = teams(&down).check_account(&grant()).await;

        assert!(matches!(refused, AccountCheck::Refused(_)));
        assert_eq!(unknown, AccountCheck::Unreachable);
    }

    /// Microsoft Teams presents itself with its title, icon and purple,
    /// explains every operation, and offers no events.
    #[tokio::test]
    async fn teams_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let teams = teams(&server);

        assert_eq!(teams.profile().icon().as_str(), "teams");
        assert_eq!(teams.guides().len(), teams.operations().len());
        assert!(teams.events().is_empty());
        assert!(teams.watcher().is_none());
    }
}
