//! Trello as a workflow integration, installed under `trello`: a step lists
//! the member's boards and a board's lists, labels and members, reads,
//! creates, edits, moves, archives and deletes a card, comments on it and
//! labels it, through an account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService): its
//! profile, its operations, each described once in `operations/`, how an
//! account reaches Trello, and the request that proves a credential.
//! Requests, refusals, answers and credential checks are the SDK's.
//!
//! A Trello account holds `{"key", "token"}`: an API key and a token its
//! member granted. Both go in Trello's `OAuth` header, never in the
//! address, so they stay out of logs that record addresses. Reading the
//! member they belong to proves them before the account is kept. They are
//! sent only to the Trello API this deployment names, never to an address a
//! step chooses, and no redirect is followed.
//!
//! A workflow may also start on a card created, moved or commented on in
//! one board (`events`), through a webhook registered with the account's
//! key and token. Trello has no sign-in for apps here, so its accounts are
//! always connected with a key and token pasted in.

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

use crate::events::Webhooks;

/// Trello's public API.
pub const PUBLIC_API: &str = "https://api.trello.com/1/";

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Trello",
    description: "Creates, moves, labels and comments on cards on a team's Trello boards, through an API key and token the tenant connects.",
    icon: "trello",
    picture: include_str!("../assets/icon.svg"),
    brand: "0052cc",
};

/// How creating a card is previewed: as an issue on its list.
const PREVIEWS: &[PreviewText] = &[PreviewText {
    operation: "create-card",
    kind: PreviewKind::Issue,
    parts: &[
        (PreviewPart::Place, "list"),
        (PreviewPart::Title, "name"),
        (PreviewPart::Body, "description"),
    ],
}];

/// The headers Trello asks every call to carry.
const HEADERS: &[(&str, &str)] = &[("accept", "application/json")];

/// How the Trello integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct TrelloSettings {
    /// Where Trello's API answers: [`PUBLIC_API`], or a stand-in's.
    pub endpoint: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send to Trello, and so the most
    /// sensitive an answer or an event is counted as.
    pub ceiling: DataClassLevel,
}

/// The Trello integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: TrelloSettings) -> Result<RestService, DomainError> {
    let access = Access::KeyAndToken {
        endpoint: settings.endpoint,
    };
    let webhooks = Webhooks::new(
        WatchCalls::new(access.clone(), HEADERS, settings.timeout)?,
        settings.ceiling,
    );
    RestService::new(RestServiceParams {
        key: "trello",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: PREVIEWS,
        access,
        headers: HEADERS,
        probe: Probe {
            verb: Verb::Get,
            path: &["members", "me"],
            query: &[],
        },
        answers: Answers::ByStatus,
        timeout: settings.timeout,
        ceiling: settings.ceiling,
        sign_in: None,
        events: Some(ServiceEvents {
            described: events::all(),
            watcher: Box::new(webhooks),
        }),
    })
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::{FieldName, FlowData, FlowValue};
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
    use ianua_integration::rest::operation::{Operation, Segment};
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::*;
    use crate::operations::all;

    /// Trello's own description of its REST API, which every operation is
    /// checked against. Atlassian publishes it at
    /// `https://developer.atlassian.com/cloud/trello/swagger.v3.json`; what
    /// the operations use of it is kept in `api-description.json`. To
    /// refresh it, download the file and run the tests with
    /// `IANUA_TRELLO_API_DESCRIPTION=/path/to/swagger.v3.json`.
    fn description() -> Description {
        Description {
            kept: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("api-description.json"),
            setting: "IANUA_TRELLO_API_DESCRIPTION",
            lead: &[],
        }
    }

    /// The member's boards as Trello's description writes the path, with
    /// the member as `{id}` where a step names the signed-in one, `me`.
    const MEMBER_BOARDS: &[Segment] = &[
        Segment::Fixed("members"),
        Segment::Input("member"),
        Segment::Fixed("boards"),
    ];

    /// Every operation as Trello's description writes it.
    fn as_described() -> Vec<Operation> {
        all()
            .map(|operation| match operation.path {
                [
                    Segment::Fixed("members"),
                    Segment::Fixed("me"),
                    Segment::Fixed("boards"),
                ] => Operation {
                    path: MEMBER_BOARDS,
                    ..*operation
                },
                _ => *operation,
            })
            .collect()
    }

    /// Every operation calls an endpoint Trello describes, with only the
    /// query parameters it knows, and promising only outputs and statuses
    /// its answer carries; and the extract holds exactly those endpoints.
    /// Trello's key and token are security schemes there, not parameters,
    /// so sending them in the header leaves nothing required unsent.
    #[test]
    fn every_operation_fits_trellos_api_description() {
        let operations = as_described();
        let description = description();
        let extract = description.extract(&operations).unwrap();

        let wrong = description.misfits(&operations, &extract);

        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        assert_eq!(
            Description::kept_endpoints(&extract),
            Description::called_endpoints(&operations),
            "refresh the extract with IANUA_TRELLO_API_DESCRIPTION"
        );
    }

    /// A key and token as a test writes them: plain words, not shaped like
    /// real ones.
    const KEY_AND_TOKEN: &str = r#"{"key":"testkeyforacme","token":"testtokenforann"}"#;

    /// The header Trello is sent them in.
    const SIGNED: &str =
        r#"OAuth oauth_consumer_key="testkeyforacme", oauth_token="testtokenforann""#;

    /// Whether `request` carries the key and token in Trello's header,
    /// read whole: wiremock's header matcher splits a value at its commas.
    fn signed(request: &Request) -> bool {
        request
            .headers
            .get("authorization")
            .is_some_and(|value| value == SIGNED)
    }

    fn trello(server: &MockServer) -> RestService {
        integration(TrelloSettings {
            endpoint: ServiceEndpoint::at(&format!("{}/1/", server.uri())).unwrap(),
            timeout: Duration::from_secs(2),
            ceiling: DataClassLevel::Internal,
        })
        .unwrap()
    }

    fn credential() -> Secret {
        Secret::new(KEY_AND_TOKEN.to_owned())
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

    fn new_card(list: &str) -> ActionCall {
        ActionCall {
            call_id: ActionCallId::new(),
            integration: IntegrationKey::new("trello").unwrap(),
            operation: OperationKey::new("create-card").unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments: arguments(vec![
                ("list", text(list)),
                ("name", text("Call the supplier")),
            ]),
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    async fn requests_made(server: &MockServer) -> usize {
        server.received_requests().await.unwrap().len()
    }

    /// Ann's workflow creates a card on the Inbox list: Trello is asked
    /// with her key and token in its header, the list and name in the
    /// query, and the new card's id comes back in the step's output.
    #[tokio::test]
    async fn a_card_is_created_with_the_accounts_key_and_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/1/cards"))
            .and(signed)
            .and(query_param("idList", "inboxlist1"))
            .and(query_param("name", "Call the supplier"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "card42" })))
            .expect(1)
            .mount(&server)
            .await;

        let outcome = trello(&server)
            .call(&new_card("inboxlist1"), Some(&credential()))
            .await
            .outcome;

        let ActionOutcome::Succeeded { output, .. } = outcome else {
            panic!("the card was not created: {outcome:?}");
        };
        let id = output
            .field(&FieldName::new("json").unwrap())
            .and_then(|json| json.field(&FieldName::new("id").unwrap()))
            .map(FlowData::value);
        assert_eq!(id, Some(FlowValue::Text("card42")));
    }

    /// Missing credentials, a bare token, and a token containing a quote
    /// each fail the card step without sending a request to Trello.
    #[tokio::test]
    async fn a_missing_or_crooked_credential_sends_nothing() {
        let server = MockServer::start().await;
        let trello = trello(&server);

        let without = trello.call(&new_card("inboxlist1"), None).await.outcome;
        let bare = trello
            .call(
                &new_card("inboxlist1"),
                Some(&Secret::new("just a token".to_owned())),
            )
            .await
            .outcome;
        let quoted = trello
            .call(
                &new_card("inboxlist1"),
                Some(&Secret::new(
                    r#"{"key":"testkeyforacme","token":"a\" b"}"#.to_owned(),
                )),
            )
            .await
            .outcome;

        for outcome in [without, bare, quoted] {
            assert!(matches!(outcome, ActionOutcome::Failed(_)), "{outcome:?}");
        }
        assert_eq!(requests_made(&server).await, 0);
    }

    /// Trello refusing the token fails the step; Trello saying it is busy
    /// turns it away, to be tried again.
    #[tokio::test]
    async fn a_refusal_fails_and_a_busy_trello_turns_away() {
        let server = MockServer::start().await;
        Mock::given(path("/1/cards"))
            .and(query_param("idList", "lockedlist"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        Mock::given(path("/1/cards"))
            .and(query_param("idList", "busylist"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;
        let trello = trello(&server);

        let refused = trello
            .call(&new_card("lockedlist"), Some(&credential()))
            .await
            .outcome;
        let busy = trello
            .call(&new_card("busylist"), Some(&credential()))
            .await
            .outcome;

        assert!(matches!(refused, ActionOutcome::Failed(_)));
        assert!(matches!(busy, ActionOutcome::TurnedAway(_)));
    }

    /// Trello answering who a key and token belong to `status`, when they
    /// are the ones it knows.
    async fn checked(status: u16, credential: &str) -> AccountCheck {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/1/members/me"))
            .and(signed)
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        Mock::given(path("/1/members/me"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        trello(&server)
            .check_account(&Secret::new(credential.to_owned()))
            .await
    }

    /// Tess connects the team's key and token: Trello knows whose they are,
    /// so they are taken.
    #[tokio::test]
    async fn a_key_and_token_trello_knows_are_accepted() {
        assert_eq!(checked(200, KEY_AND_TOKEN).await, AccountCheck::Accepted);
    }

    /// Trello's 401 response to a mistyped token refuses the account check.
    #[tokio::test]
    async fn a_token_trello_does_not_know_is_refused() {
        let answer = checked(200, r#"{"key":"testkeyforacme","token":"mistyped"}"#).await;

        assert!(matches!(answer, AccountCheck::Refused(_)));
    }

    /// Trello limiting the rate or failing says nothing of the key and
    /// token, so the check is unreachable, never accepted.
    #[tokio::test]
    async fn a_busy_or_failing_trello_says_nothing_of_the_credential() {
        for status in [429, 500, 503] {
            assert_eq!(
                checked(status, KEY_AND_TOKEN).await,
                AccountCheck::Unreachable
            );
        }
    }

    /// Trello presents itself with a title, icon and brand colour, explains
    /// every one of its operations, and offers its three events.
    #[tokio::test]
    async fn trello_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let trello = trello(&server);

        assert_eq!(trello.profile().title().as_str(), "Trello");
        assert_eq!(trello.profile().icon().as_str(), "trello");
        assert_eq!(trello.guides().len(), trello.operations().len());
        assert_eq!(trello.event_guides().len(), 3);
    }
}
