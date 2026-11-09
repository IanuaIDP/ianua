//! Slack as a workflow integration, installed under `slack`: a step posts,
//! schedules, edits or deletes a message, reacts to one, finds or reads a
//! member, and lists, reads, creates, fills and archives channels, through
//! the bot token of an account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService): its
//! profile, its operations in `operations/`, the bot token sent to Slack's
//! Web API, and `auth.test` to prove a token. Slack answers a refused call
//! with success and `"ok": false`, so it says yes by that flag: a refusal
//! fails the step, and being rate limited turns it away.
//!
//! With the deployment's Slack app set, a person connects a workspace by
//! signing in at Slack instead, and the bot token Slack issues is kept the
//! same way. With the app's signing secret set, a workflow may also start
//! on a message posted in a channel (`events`).

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

mod events;
mod operations;

use std::time::Duration;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::integration::form::{PreviewKind, PreviewPart};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_integration::ServiceEndpoint;
use ianua_integration::connect::SignIn;
use ianua_integration::describe::ProfileText;
use ianua_integration::form::PreviewText;
use ianua_integration::rest::access::Access;
use ianua_integration::rest::event::ServiceEvents;
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::service::{Answers, Probe, RestService, RestServiceParams};
use ianua_integration::rest::sign_in::{
    Keeps, OAuthSignIn, OAuthSignInParams, SignInSettings, TokenBody,
};
use ianua_integration::rest::watch::WatchCalls;

use crate::events::AppEvents;

/// Slack's public Web API.
pub const PUBLIC_API: &str = "https://slack.com/api/";

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Slack",
    description: "Posts and manages messages, finds members and manages channels in a team's Slack workspace, through a bot token the tenant connects.",
    icon: "slack",
    picture: include_str!("../assets/icon.svg"),
    brand: "4a154b",
};

/// How posting a message is previewed: as the message in its channel.
const PREVIEWS: &[PreviewText] = &[PreviewText {
    operation: "post-message",
    kind: PreviewKind::ChatMessage,
    parts: &[(PreviewPart::Place, "channel"), (PreviewPart::Body, "text")],
}];

/// How the Slack integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct SlackSettings {
    /// Where Slack's Web API answers: [`PUBLIC_API`], or a stand-in's.
    pub endpoint: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may post, and so the most sensitive
    /// an answer or an event is counted as.
    pub ceiling: DataClassLevel,
    /// The deployment's Slack app, at [`PUBLIC_AUTHORIZE`] and
    /// [`PUBLIC_TOKEN`] or a stand-in's, when one is registered; without
    /// it, accounts are connected with a bot token pasted in.
    pub sign_in: Option<SignInSettings>,
    /// The app's signing secret, which Slack signs every event with; events
    /// are offered only with it.
    pub signing_secret: Option<Secret>,
}

/// Where Slack signs people in for an app.
pub const PUBLIC_AUTHORIZE: &str = "https://slack.com/oauth/v2/authorize";

/// Where Slack swaps an app's code for a bot token.
pub const PUBLIC_TOKEN: &str = "https://slack.com/api/oauth.v2.access";

/// The bot scopes a signed-in account needs: every step's, and for events
/// reading public channels' messages and joining a watched channel.
const SCOPES: &[&str] = &[
    "chat:write",
    "chat:write.public",
    "channels:read",
    "channels:history",
    "channels:manage",
    "channels:join",
    "groups:read",
    "groups:history",
    "groups:write",
    "im:write",
    "mpim:write",
    "reactions:write",
    "users:read",
    "users:read.email",
];

/// The Slack integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: SlackSettings) -> Result<RestService, DomainError> {
    let access = Access::Bearer {
        endpoint: settings.endpoint,
    };
    let events = settings
        .signing_secret
        .map(|signing| service_events(&access, signing, settings.timeout, settings.ceiling))
        .transpose()?;
    RestService::new(RestServiceParams {
        key: "slack",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: PREVIEWS,
        access,
        headers: &[],
        probe: Probe {
            verb: Verb::Get,
            path: &["auth.test"],
            query: &[],
        },
        answers: Answers::OkFlag,
        timeout: settings.timeout,
        ceiling: settings.ceiling,
        sign_in: settings
            .sign_in
            .map(|at| sign_in(at, settings.timeout))
            .transpose()?,
        events,
    })
}

/// Builds the signed event listener using the same account access as Slack calls.
fn service_events(
    access: &Access,
    signing: Secret,
    timeout: Duration,
    ceiling: DataClassLevel,
) -> Result<ServiceEvents, DomainError> {
    let calls = WatchCalls::new(access.clone(), &[], timeout)?;
    Ok(ServiceEvents {
        described: events::all(),
        watcher: Box::new(AppEvents::new(calls, signing, ceiling)),
    })
}

/// Signing in at Slack through the deployment's app `at`; Slack separates
/// scopes with commas and answers a refused code with `"ok": false`.
fn sign_in(at: SignInSettings, timeout: Duration) -> Result<Box<dyn SignIn>, DomainError> {
    let oauth = OAuthSignIn::new(OAuthSignInParams {
        at,
        scopes: SCOPES,
        scope_separator: ",",
        extra: &[],
        swap_extra: &[],
        token_body: TokenBody::Form,
        keeps: Keeps::AccessToken,
        place: None,
        timeout,
    })?;
    Ok(Box::new(oauth))
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
    use ianua_integration::rest::openapi::Description;
    use serde_json::{Value, json};
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::operations::all;

    /// Slack's own description of its Web API, which every operation is
    /// checked against. Slack publishes it at
    /// `slackapi/slack-api-specs/web-api/slack_web_openapi_v2.json`; what
    /// the operations use of it is kept in `api-description.json`. To
    /// refresh it, download the file and run the tests with
    /// `IANUA_SLACK_API_DESCRIPTION=/path/to/slack_web_openapi_v2.json`.
    fn description() -> Description {
        Description {
            kept: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("api-description.json"),
            setting: "IANUA_SLACK_API_DESCRIPTION",
            lead: &[],
        }
    }

    /// Every operation calls a method Slack describes, with only the
    /// parameters it knows, always sending those it requires, and promising
    /// only outputs its answer carries; and the extract holds exactly those
    /// methods.
    #[test]
    fn every_operation_fits_slacks_api_description() {
        let description = description();
        let extract = description.extract(all()).unwrap();

        let wrong = description.misfits(all(), &extract);

        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        assert_eq!(
            Description::kept_endpoints(&extract),
            Description::called_endpoints(all()),
            "refresh the extract with IANUA_SLACK_API_DESCRIPTION"
        );
    }

    /// A token as a test writes it: not shaped like a real one.
    const TOKEN: &str = "test bot token for acme";

    fn slack(server: &MockServer) -> RestService {
        integration(SlackSettings {
            endpoint: ServiceEndpoint::at(&server.uri()).unwrap(),
            timeout: Duration::from_secs(2),
            ceiling: DataClassLevel::Internal,
            sign_in: None,
            signing_secret: None,
        })
        .unwrap()
    }

    fn text(value: &str) -> FlowData {
        FlowData::text(value).unwrap()
    }

    fn post(entries: Vec<(&str, FlowData)>) -> ActionCall {
        let arguments = FlowData::map(
            entries
                .into_iter()
                .map(|(name, value)| (FieldName::new(name).unwrap(), value))
                .collect(),
        )
        .unwrap();
        ActionCall {
            call_id: ActionCallId::new(),
            integration: IntegrationKey::new("slack").unwrap(),
            operation: OperationKey::new("post-message").unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments,
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    fn on_call() -> ActionCall {
        post(vec![
            ("channel", text("C0ONCALL")),
            ("text", text("The nightly build failed")),
        ])
    }

    async fn answering(answer: Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(path("/chat.postMessage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(answer))
            .mount(&server)
            .await;
        server
    }

    fn token() -> Secret {
        Secret::new(TOKEN.to_owned())
    }

    /// Ann's workflow posts to the on-call channel with the bot's token,
    /// and Slack's confirmation is the step's output.
    #[tokio::test]
    async fn a_message_is_posted_with_the_bots_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat.postMessage"))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .and(body_json(json!({
                "channel": "C0ONCALL",
                "text": "The nightly build failed"
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "ok": true, "ts": "1.2" })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let outcome = slack(&server)
            .call(&on_call(), Some(&token()))
            .await
            .outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
    }

    /// A reply names the thread it belongs in, under Slack's name for it.
    #[tokio::test]
    async fn a_reply_names_its_thread() {
        let server = MockServer::start().await;
        Mock::given(body_json(json!({
            "channel": "C0ONCALL",
            "text": "Fixed",
            "thread_ts": "1.2"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
        .expect(1)
        .mount(&server)
        .await;
        let reply = post(vec![
            ("channel", text("C0ONCALL")),
            ("text", text("Fixed")),
            ("thread", text("1.2")),
        ]);

        let outcome = slack(&server).call(&reply, Some(&token())).await.outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
    }

    /// Slack's `not_in_channel` error fails the message step despite HTTP
    /// success, preserving the provider's reason.
    #[tokio::test]
    async fn a_message_slack_refuses_fails_the_step() {
        let server = answering(json!({ "ok": false, "error": "not_in_channel" })).await;

        let outcome = slack(&server)
            .call(&on_call(), Some(&token()))
            .await
            .outcome;

        let ActionOutcome::Failed(why) = outcome else {
            panic!("a refused message counted as posted: {outcome:?}");
        };
        assert!(why.as_str().contains("not_in_channel"));
    }

    /// Slack rate limiting the token turns the call away, to be tried again.
    #[tokio::test]
    async fn a_rate_limited_token_turns_the_call_away() {
        let server = answering(json!({ "ok": false, "error": "ratelimited" })).await;

        let outcome = slack(&server)
            .call(&on_call(), Some(&token()))
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::TurnedAway(_)));
    }

    /// An HTML page returned with HTTP success fails the message step
    /// because it supplies no Slack verdict.
    #[tokio::test]
    async fn an_answer_without_a_verdict_fails() {
        let server = MockServer::start().await;
        Mock::given(path("/chat.postMessage"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>ok</html>"))
            .mount(&server)
            .await;

        let outcome = slack(&server)
            .call(&on_call(), Some(&token()))
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
    }

    /// A missing token or message text fails the step without sending a
    /// request to Slack.
    #[tokio::test]
    async fn no_token_or_no_text_sends_nothing() {
        let server = answering(json!({ "ok": true })).await;
        let slack = slack(&server);

        let without = slack.call(&on_call(), None).await.outcome;
        let silent = slack
            .call(&post(vec![("channel", text("C0ONCALL"))]), Some(&token()))
            .await
            .outcome;

        assert!(matches!(without, ActionOutcome::Failed(_)));
        assert!(matches!(silent, ActionOutcome::Failed(_)));
        assert_eq!(server.received_requests().await.unwrap().len(), 0);
    }

    /// Slack's `auth.test` answering `answer` for a token.
    async fn checked(answer: Value) -> AccountCheck {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth.test"))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(answer))
            .expect(1)
            .mount(&server)
            .await;
        slack(&server).check_account(&token()).await
    }

    /// Tess connects the bot's token: Slack says it is live, so it is
    /// taken.
    #[tokio::test]
    async fn a_live_token_is_accepted() {
        let answer = checked(json!({ "ok": true, "team": "Acme" })).await;

        assert_eq!(answer, AccountCheck::Accepted);
    }

    /// Slack's `token_revoked` error refuses the account check despite HTTP
    /// success, preserving the provider's reason.
    #[tokio::test]
    async fn a_revoked_token_is_refused() {
        let answer = checked(json!({ "ok": false, "error": "token_revoked" })).await;

        let AccountCheck::Refused(why) = answer else {
            panic!("a revoked token was not refused: {answer:?}");
        };
        assert!(why.as_str().contains("token_revoked"));
    }

    /// Slack limiting the rate, or an answer with no verdict, says nothing
    /// of the token: unreachable, never accepted.
    #[tokio::test]
    async fn a_limited_or_unclear_answer_says_nothing_of_the_token() {
        let limited = checked(json!({ "ok": false, "error": "ratelimited" })).await;
        let unclear = checked(json!({ "team": "Acme" })).await;

        assert_eq!(limited, AccountCheck::Unreachable);
        assert_eq!(unclear, AccountCheck::Unreachable);
    }

    /// Slack presents itself with a title and icon, and explains every
    /// operation.
    #[tokio::test]
    async fn slack_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let slack = slack(&server);

        assert_eq!(slack.profile().icon().as_str(), "slack");
        assert_eq!(slack.guides().len(), slack.operations().len());
    }
}
