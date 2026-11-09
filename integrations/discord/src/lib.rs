//! Discord as a workflow integration, installed under `discord`: a step
//! lists the bot's servers and a server's channels and roles, posts, edits
//! and deletes a message, reacts to one, starts a thread from one, reads a
//! channel's recent messages and gives a member a role, through the bot
//! token of an account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService): its
//! profile, its operations, each described once in `operations/`, how an
//! account reaches Discord, the headers Discord asks for, and the request
//! that proves a token. Requests, refusals, answers and token checks are
//! the SDK's. Discord answers a refusal with its status and a JSON
//! `code` and `message`, and a rate limit with `429` and `retry_after`,
//! so a refusal fails the step and a rate limit turns it away.
//!
//! The account holds a bot token alone, sent as `Bot <token>`. It is asked
//! about at Discord before it is kept, and sent only to the Discord API
//! this deployment names, never to an address a step chooses: a step names
//! the server, channel and message, and the address is built from them
//! with every part checked and escaped. No redirect is followed.
//!
//! Discord offers no events here: it delivers a bot's events over its
//! Gateway, a lasting websocket the bot holds open, not as webhooks a
//! workflow could start on.

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

/// Discord's public API, at the version the calls are written for.
pub const PUBLIC_API: &str = "https://discord.com/api/v10/";

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Discord",
    description: "Posts, edits and reacts to messages, starts threads and gives roles in a team's Discord servers, through a bot token the tenant connects.",
    icon: "discord",
    picture: include_str!("../assets/icon.svg"),
    brand: "5865f2",
};

/// How posting a message is previewed: as the message in its channel.
const PREVIEWS: &[PreviewText] = &[PreviewText {
    operation: "post-message",
    kind: PreviewKind::ChatMessage,
    parts: &[
        (PreviewPart::Place, "channel"),
        (PreviewPart::Body, "content"),
    ],
}];

/// The headers Discord asks every call to carry: a user agent naming the
/// bot's library, its address and version.
const HEADERS: &[(&str, &str)] = &[(
    "user-agent",
    concat!(
        "DiscordBot (https://github.com/IanuaIDP/ianua, ",
        env!("CARGO_PKG_VERSION"),
        ")"
    ),
)];

/// How the Discord integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct DiscordSettings {
    /// Where Discord's API answers: [`PUBLIC_API`], or a stand-in's.
    pub endpoint: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may post, and so the most sensitive
    /// an answer is counted as.
    pub ceiling: DataClassLevel,
}

/// The Discord integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: DiscordSettings) -> Result<RestService, DomainError> {
    RestService::new(RestServiceParams {
        key: "discord",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: PREVIEWS,
        access: Access::Scheme {
            endpoint: settings.endpoint,
            scheme: "Bot ",
        },
        headers: HEADERS,
        probe: Probe {
            verb: Verb::Get,
            path: &["users", "@me"],
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
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::*;
    use crate::operations::all;

    /// Discord's own description of its HTTP API, which every operation is
    /// checked against. Discord publishes it at
    /// `discord/discord-api-spec/specs/openapi.json`; what the operations
    /// use of it is kept in `api-description.json`. To refresh it, download
    /// the file and run the tests with
    /// `IANUA_DISCORD_API_DESCRIPTION=/path/to/openapi.json`.
    fn description() -> Description {
        Description {
            kept: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("api-description.json"),
            setting: "IANUA_DISCORD_API_DESCRIPTION",
            lead: &[],
        }
    }

    /// Every operation calls an endpoint Discord describes, with only the
    /// query parameters and body properties it knows, always sending those
    /// it requires, and promising only outputs and statuses its answer
    /// carries; and the extract holds exactly those endpoints.
    #[test]
    fn every_operation_fits_discords_api_description() {
        let description = description();
        let extract = description.extract(all()).unwrap();

        let wrong = description.misfits(all(), &extract);

        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        assert_eq!(
            Description::kept_endpoints(&extract),
            Description::called_endpoints(all()),
            "refresh the extract with IANUA_DISCORD_API_DESCRIPTION"
        );
    }

    /// A bot token as a test writes it: not shaped like a real one.
    const TOKEN: &str = "test bot token for acme";

    /// Whether `request` carries Discord's user agent, read whole:
    /// wiremock's header matcher splits a value at its commas.
    fn introduced(request: &Request) -> bool {
        request
            .headers
            .get("user-agent")
            .is_some_and(|value| value == HEADERS[0].1)
    }

    fn discord(server: &MockServer) -> RestService {
        integration(DiscordSettings {
            endpoint: ServiceEndpoint::at(&format!("{}/api/v10/", server.uri())).unwrap(),
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

    fn new_message(channel: &str) -> ActionCall {
        ActionCall {
            call_id: ActionCallId::new(),
            integration: IntegrationKey::new("discord").unwrap(),
            operation: OperationKey::new("post-message").unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments: arguments(vec![
                ("channel", text(channel)),
                ("content", text("The nightly build failed.")),
            ]),
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    fn token() -> Secret {
        Secret::new(TOKEN.to_owned())
    }

    async fn requests_made(server: &MockServer) -> usize {
        server.received_requests().await.unwrap().len()
    }

    /// Ann's workflow posts to the on-call channel: Discord is asked with
    /// the bot's token, Discord's user agent and the text, and the new
    /// message's id comes back in the step's output.
    #[tokio::test]
    async fn a_message_is_posted_with_the_bots_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v10/channels/1100000000000000001/messages"))
            .and(header("authorization", format!("Bot {TOKEN}").as_str()))
            .and(introduced)
            .and(body_json(json!({
                "content": "The nightly build failed.",
                "allowed_mentions": { "parse": [] }
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "id": "1200000000000000002" })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let outcome = discord(&server)
            .call(&new_message("1100000000000000001"), Some(&token()))
            .await
            .outcome;

        let ActionOutcome::Succeeded { output, .. } = outcome else {
            panic!("the message was not posted: {outcome:?}");
        };
        let id = output
            .field(&FieldName::new("json").unwrap())
            .and_then(|json| json.field(&FieldName::new("id").unwrap()))
            .map(FlowData::value);
        assert_eq!(id, Some(FlowValue::Text("1200000000000000002")));
    }

    /// Missing or blank tokens and a channel ID of `..` each fail the
    /// message step without sending a request to Discord.
    #[tokio::test]
    async fn no_token_or_a_crooked_channel_sends_nothing() {
        let server = MockServer::start().await;
        let discord = discord(&server);

        let without = discord
            .call(&new_message("1100000000000000001"), None)
            .await
            .outcome;
        let blank = discord
            .call(
                &new_message("1100000000000000001"),
                Some(&Secret::new("  ".to_owned())),
            )
            .await
            .outcome;
        let crooked = discord
            .call(&new_message(".."), Some(&token()))
            .await
            .outcome;

        for outcome in [without, blank, crooked] {
            assert!(matches!(outcome, ActionOutcome::Failed(_)), "{outcome:?}");
        }
        assert_eq!(requests_made(&server).await, 0);
    }

    /// Discord refusing the bot with its code and message fails the step;
    /// Discord limiting the rate with a time to wait turns it away, to be
    /// tried again.
    #[tokio::test]
    async fn a_refusal_fails_and_a_rate_limit_turns_away() {
        let server = MockServer::start().await;
        Mock::given(path("/api/v10/channels/1100000000000000009/messages"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_json(json!({ "code": 50013, "message": "Missing Permissions" })),
            )
            .mount(&server)
            .await;
        Mock::given(path("/api/v10/channels/1100000000000000008/messages"))
            .respond_with(ResponseTemplate::new(429).set_body_json(json!({
                "message": "You are being rate limited.",
                "retry_after": 0.5,
                "global": false
            })))
            .mount(&server)
            .await;
        let discord = discord(&server);

        let refused = discord
            .call(&new_message("1100000000000000009"), Some(&token()))
            .await
            .outcome;
        let limited = discord
            .call(&new_message("1100000000000000008"), Some(&token()))
            .await
            .outcome;

        assert!(matches!(refused, ActionOutcome::Failed(_)), "{refused:?}");
        assert!(
            matches!(limited, ActionOutcome::TurnedAway(_)),
            "{limited:?}"
        );
    }

    /// Discord answering who a bot token belongs to `status`, when it is
    /// the one it knows.
    async fn checked(status: u16, token: &str) -> AccountCheck {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v10/users/@me"))
            .and(header("authorization", format!("Bot {TOKEN}").as_str()))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        Mock::given(path("/api/v10/users/@me"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        discord(&server)
            .check_account(&Secret::new(token.to_owned()))
            .await
    }

    /// Tess connects the team's bot token: Discord knows whose it is, so it
    /// is taken.
    #[tokio::test]
    async fn a_bot_token_discord_knows_is_accepted() {
        assert_eq!(checked(200, TOKEN).await, AccountCheck::Accepted);
    }

    /// Discord's 401 response to a mistyped bot token refuses the account
    /// check.
    #[tokio::test]
    async fn a_token_discord_does_not_know_is_refused() {
        let answer = checked(200, "a mistyped bot token").await;

        assert!(matches!(answer, AccountCheck::Refused(_)));
    }

    /// Discord limiting the rate or failing says nothing of the token, so
    /// the check is unreachable, never accepted.
    #[tokio::test]
    async fn a_busy_or_failing_discord_says_nothing_of_the_token() {
        for status in [429, 500, 503] {
            assert_eq!(checked(status, TOKEN).await, AccountCheck::Unreachable);
        }
    }

    /// Discord presents itself with a title, icon and brand colour,
    /// explains every one of its operations, and offers no events.
    #[tokio::test]
    async fn discord_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let discord = discord(&server);

        assert_eq!(discord.profile().title().as_str(), "Discord");
        assert_eq!(discord.profile().icon().as_str(), "discord");
        assert_eq!(discord.guides().len(), discord.operations().len());
        assert!(discord.event_guides().is_empty());
    }
}
