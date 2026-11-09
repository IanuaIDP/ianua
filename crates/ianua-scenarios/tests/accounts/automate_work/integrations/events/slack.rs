//! Slack connected by signing in, and starting workflows: Tess signs in at
//! a stand-in for Slack instead of pasting a bot token, and Ann publishes a
//! workflow that starts when someone posts in #support and answers in the
//! message's thread. Publishing has the bot join the channel. Slack sends
//! every event of the platform's Slack app to one address; Pat's message,
//! signed with the app's signing secret, starts one run. A delivery signed
//! with another secret, and the bot's own reply, start nothing.

use ianua_scenarios::api::workflows::{self, ServiceDelivery};
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::{Graph, Trigger, Workflow};
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::connect::{SignIn, runs_now, runs_started, signed, signed_in};
use crate::support::{Action, action, drafted, ended, published, read, written};

/// The bot token Slack issues for Tess's sign-in: a sentence, so no
/// scanner takes it for a key.
const TOKEN: &str = "acme slack bot token issued at sign in";

/// The platform's Slack app.
const CLIENT_ID: &str = "acme platform slack app";

/// The app's client secret.
const CLIENT_SECRET: &str = "acme platform slack app secret words";

/// The app's signing secret, which Slack signs every event with.
const SIGNING: &str = "acme platform slack signing words";

/// Where Slack swaps the code for a bot token.
const TOKEN_PATH: &str = "/oauth.v2.access";

/// Where Slack says whose a token is, and which workspace.
const AUTH_TEST: &str = "/auth.test";

/// Where the bot joins a channel.
const JOIN: &str = "/conversations.join";

/// Where the run's reply is posted.
const POST: &str = "/chat.postMessage";

/// Where Slack sends every event of the platform's app.
const EVENTS: &str = "/api/v1/integrations/slack/events";

/// Tess signs in at Slack to connect Acme's workspace, and the bot token
/// Slack issues is tried before it is kept. Ann publishes a workflow on
/// messages posted in #support, which has the bot join #support. Slack
/// first asks the platform to prove it holds the events address, and is
/// answered. Pat posts "The login page is down": the delivery, signed with
/// the app's signing secret, starts one run for Ann, which replies in
/// Pat's thread. Mallory's copy signed with her own secret is refused, and
/// the bot's own reply arriving as an event starts nothing. The token is
/// nowhere in the trail.
#[tokio::test]
async fn a_message_posted_in_slack_starts_the_workflow_signed_in_for() {
    let slack = slack().await;
    let stack = Stack::start(profile(&slack))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connect_slack(&world, &slack).await;
    let workflow = publish_replies(&world, &account).await;
    check_joined_channel(&slack);
    let sender = deliver_message(&stack).await;
    check_reply_run(&world, &slack, &workflow.id).await;
    ignore_own_reply(&world, &sender, &workflow.id).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess signs in at Slack and the token is checked before the account is connected.
async fn connect_slack(world: &World<'_>, slack: &CannedApp) -> String {
    let base = slack.url().trim_end_matches('/').to_owned();
    let authorize = format!("{base}/oauth/v2/authorize");

    let account = signed_in(
        world,
        &SignIn {
            integration: "slack",
            authorize: &authorize,
            client_id: CLIENT_ID,
            place: None,
        },
    )
    .await;
    assert_eq!(slack.asked_for(TOKEN_PATH), 1, "the code was swapped once");
    assert_eq!(slack.asked_for(AUTH_TEST), 1, "the token was tried first");
    account
}

/// Messages in support start the published reply workflow.
async fn publish_replies(world: &World<'_>, account: &str) -> Workflow {
    let trigger = Trigger::Service {
        integration: "slack".to_owned(),
        event: "message-posted".to_owned(),
        account_id: account.to_owned(),
        filters: [("channel".to_owned(), "C0SUPPORT".to_owned())].into(),
    };
    let draft = drafted(world, trigger, reply_graph(account)).await;
    published(world, &draft).await
}

/// The reply targets the thread timestamp from the incoming support message.
fn reply_graph(account: &str) -> Graph {
    let reply = action(
        Action {
            integration: "slack",
            operation: "post-message",
        },
        account,
        "communicate",
        vec![
            ("channel", written("C0SUPPORT")),
            ("text", written("Thanks, we are on it.")),
            ("thread", read("trigger.event.ts")),
        ],
    );
    Graph {
        nodes: vec![reply],
        edges: vec![],
    }
}

/// Publishing joins the bot to the support channel exactly once.
fn check_joined_channel(slack: &CannedApp) {
    let joined: Vec<_> = slack
        .received()
        .into_iter()
        .filter(|call| call.path == JOIN)
        .collect();
    assert_eq!(joined.len(), 1, "publishing had the bot join the channel");
    assert_eq!(joined[0].json()["channel"], "C0SUPPORT");
}

/// Slack's challenge and signed event are accepted, while Mallory's signature is refused.
async fn deliver_message(stack: &Stack) -> Client {
    let sender = Client::new(stack, "slack").expect("Slack's client");
    let mallory = Client::new(stack, "mallory").expect("Mallory's client");
    let challenge = json!({ "type": "url_verification", "challenge": "prove it" }).to_string();
    let proved = delivered(&sender, &challenge, SIGNING).await;
    assert_eq!(proved.status(), Status::OK);
    assert_eq!(proved.value().map(String::as_str), Some("prove it"));

    let message = posted(&json!({ "user": "U0PAT" }), "Ev0001").to_string();
    delivered(&mallory, &message, "mallory's own signing words")
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let taken = delivered(&sender, &message, SIGNING).await;
    assert_eq!(taken.status(), Status::NO_CONTENT);
    sender
}

/// The service-caused run sends one authenticated reply in Pat's thread.
async fn check_reply_run(world: &World<'_>, slack: &CannedApp, workflow_id: &str) {
    let runs = runs_started(world, workflow_id).await;
    assert_eq!(runs[0].cause, "service");
    ended(world, &runs[0].id, "succeeded").await;
    let replies: Vec<_> = slack
        .received()
        .into_iter()
        .filter(|call| call.path == POST)
        .collect();
    assert_eq!(replies.len(), 1, "the run replied once");
    assert_eq!(replies[0].json()["thread_ts"], "1700000000.000100");
    assert_eq!(
        replies[0].header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
}

/// The bot's own event starts no second run and the trail exposes no connection or signing secrets.
async fn ignore_own_reply(world: &World<'_>, sender: &Client, workflow_id: &str) {
    let own_reply = posted(&json!({ "bot_id": "B0IANUA" }), "Ev0002").to_string();
    let skipped = delivered(sender, &own_reply, SIGNING).await;
    assert_eq!(skipped.status(), Status::NO_CONTENT);
    assert_eq!(
        runs_now(world, workflow_id).await.len(),
        1,
        "the bot's own reply started nothing"
    );
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[TOKEN, SIGNING]);
    }
}

/// The Slack stand-in: it issues the bot token, names Acme's workspace,
/// lets the bot join and takes a message.
async fn slack() -> CannedApp {
    CannedApp::start([
        (
            TOKEN_PATH,
            Canned::json(&json!({
                "ok": true,
                "access_token": TOKEN,
                "team": { "id": "T0ACME" }
            })),
        ),
        (
            AUTH_TEST,
            Canned::json(&json!({ "ok": true, "team_id": "T0ACME" })),
        ),
        (JOIN, Canned::json(&json!({ "ok": true }))),
        (
            POST,
            Canned::json(&json!({ "ok": true, "ts": "1700000001.1" })),
        ),
    ])
    .await
    .expect("the Slack stand-in starts")
}

/// The standard deployment with the platform's Slack app at `slack`.
fn profile(slack: &CannedApp) -> Profile {
    let base = slack.url().trim_end_matches('/').to_owned();
    Profile::standard()
        .with("SLACK_API_URL", &slack.url())
        .with("SLACK_CLIENT_ID", CLIENT_ID)
        .with("SLACK_CLIENT_SECRET", CLIENT_SECRET)
        .with("SLACK_SIGNING_SECRET", SIGNING)
        .with("SLACK_AUTHORIZE_URL", &format!("{base}/oauth/v2/authorize"))
        .with("SLACK_TOKEN_URL", &format!("{base}{TOKEN_PATH}"))
}

/// A message in #support of Acme's workspace, as Slack sends it, with
/// `event` added to it, under Slack's id `id`.
fn posted(event: &Value, id: &str) -> Value {
    let mut message = json!({
        "type": "message",
        "channel": "C0SUPPORT",
        "text": "The login page is down",
        "ts": "1700000000.000100"
    });
    if let (Some(message), Some(added)) = (message.as_object_mut(), event.as_object()) {
        message.extend(added.clone());
    }
    json!({
        "type": "event_callback",
        "team_id": "T0ACME",
        "event_id": id,
        "event": message
    })
}

/// `body` delivered to the app's events address as Slack sends it, signed
/// now with `signing`.
async fn delivered(client: &Client, body: &str, signing: &str) -> Answer<String> {
    let at = OffsetDateTime::now_utc().unix_timestamp().to_string();
    let signature = signed(signing, &[b"v0:", at.as_bytes(), b":", body.as_bytes()]);
    workflows::deliver_event(&ServiceDelivery {
        path: EVENTS,
        content_type: "application/json",
        headers: &[
            ("x-slack-request-timestamp", &at),
            ("x-slack-signature", &format!("v0={signature}")),
        ],
        body,
    })
    .send_text(client)
    .await
}
