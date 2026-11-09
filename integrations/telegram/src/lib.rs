//! Telegram as a workflow integration, installed under `telegram`: a step
//! sends, forwards, edits, pins and deletes a bot's messages, and reads a
//! chat, through an account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService). A
//! Telegram account holds a bot's token, which the Bot API takes as part
//! of the address, `bot<token>/<method>`, and nowhere else. The token may
//! hold only the characters a bot token has, so it is always one part of
//! the address, and it reaches only the API. A token is proven by asking
//! the bot who it is.
//!
//! Telegram publishes no OpenAPI description of the Bot API, so the steps
//! follow its reference and are held to the SDK's rules alone. A bot has
//! one webhook for everything it hears, not one per workflow, so no
//! workflow starts on Telegram's updates here.

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

/// Telegram's Bot API.
pub const PUBLIC_API: &str = "https://api.telegram.org/";

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Telegram",
    description: "Sends, forwards, edits and pins a team bot's Telegram messages and reads its chats, through a bot token the tenant connects.",
    icon: "telegram",
    picture: include_str!("../assets/icon.svg"),
    brand: "1b7bb3",
};

/// How the Telegram integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct TelegramSettings {
    /// Where the Bot API answers: [`PUBLIC_API`], or a stand-in's.
    pub endpoint: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send, and so the most sensitive
    /// an answer is counted as.
    pub ceiling: DataClassLevel,
}

/// The Telegram integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: TelegramSettings) -> Result<RestService, DomainError> {
    RestService::new(RestServiceParams {
        key: "telegram",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: &[],
        access: Access::PathToken {
            endpoint: settings.endpoint,
            prefix: "bot",
        },
        headers: &[],
        probe: Probe {
            verb: Verb::Get,
            path: &["getMe"],
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
    use serde_json::json;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// A bot's token as a test writes it: shaped as Telegram's are, made
    /// up, and never sent anywhere but the stand-in.
    const TOKEN: &str = "4242:acme-test-bot";

    fn telegram(server: &MockServer) -> RestService {
        integration(TelegramSettings {
            endpoint: ServiceEndpoint::at(&format!("{}/", server.uri())).unwrap(),
            timeout: Duration::from_secs(2),
            ceiling: DataClassLevel::Internal,
        })
        .unwrap()
    }

    fn token() -> Secret {
        Secret::new(TOKEN.to_owned())
    }

    /// A workflow's call to send `text` to the chat `chat`.
    fn send_message(chat: &str, text: &str) -> ActionCall {
        let field = |name: &str, value: &str| {
            (
                FieldName::new(name).unwrap(),
                FlowData::text(value).unwrap(),
            )
        };
        ActionCall {
            call_id: ActionCallId::new(),
            integration: IntegrationKey::new("telegram").unwrap(),
            operation: OperationKey::new("send-message").unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments: FlowData::map(vec![field("chat", chat), field("text", text)]).unwrap(),
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    /// Ann's workflow posts in the team's group: the message goes to the
    /// method under the bot's own address, and no header carries the
    /// token.
    #[tokio::test]
    async fn a_message_is_sent_under_the_bots_address() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/bot{TOKEN}/sendMessage")))
            .and(body_json(json!({ "chat_id": "-100", "text": "Done." })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true, "result": { "message_id": 7, "chat": { "id": -100 } }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let send = send_message("-100", "Done.");

        let outcome = telegram(&server).call(&send, Some(&token())).await.outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
        let calls = server.received_requests().await.unwrap();
        assert!(calls[0].headers.get("authorization").is_none());
    }

    /// Telegram saying who a bot is, answering `status`.
    async fn checked(status: u16) -> AccountCheck {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/bot{TOKEN}/getMe")))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({ "ok": true })))
            .mount(&server)
            .await;
        telegram(&server).check_account(&token()).await
    }

    /// Tess connects the bot: Telegram knows it, so it is taken; a token
    /// Telegram does not know is refused, and Telegram being down says
    /// nothing of it.
    #[tokio::test]
    async fn a_known_bot_is_accepted_and_an_unknown_one_refused() {
        assert_eq!(checked(200).await, AccountCheck::Accepted);
        assert!(matches!(checked(401).await, AccountCheck::Refused(_)));
        assert_eq!(checked(503).await, AccountCheck::Unreachable);
    }

    /// Telegram presents itself with a title, icon and brand colour,
    /// explains every operation and starts no workflow.
    #[tokio::test]
    async fn telegram_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let telegram = telegram(&server);

        assert_eq!(telegram.profile().icon().as_str(), "telegram");
        assert_eq!(telegram.profile().brand().as_str(), "1b7bb3");
        assert_eq!(telegram.guides().len(), telegram.operations().len());
        assert!(telegram.events().is_empty());
    }
}
