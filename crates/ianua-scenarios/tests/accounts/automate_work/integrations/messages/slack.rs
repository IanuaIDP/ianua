//! Slack as a workflow step: Tess connects the team's bot token, Ann
//! publishes a workflow that posts to the on-call channel, and a stand-in
//! for Slack's API shows what arrived. A message Slack refuses fails the
//! run, though Slack answers it with success.

use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::{Graph, Trigger, Workflow};
use ianua_scenarios::world::World;
use serde_json::{Value, json};

use crate::support::{Action, account_at, action, drafted, ended, published, started, written};

/// The bot token the team's Slack account holds: a sentence, so no
/// scanner takes it for a key.
const TOKEN: &str = "acme slack bot token for workflows";

/// Where Slack takes a new message.
const POST_MESSAGE: &str = "/chat.postMessage";

/// Where Slack says whether a token is live.
const AUTH_TEST: &str = "/auth.test";

/// Tess connects the team's bot token, and Ann publishes a workflow that
/// posts to the on-call channel as a reply in a thread. Tess runs it:
/// Slack receives the channel, the text and the thread with the token, and
/// the run succeeds. The token is nowhere in the trail.
#[tokio::test]
async fn a_run_posts_to_the_channel_through_the_bots_token() {
    let slack = slack_answering(json!({ "ok": true, "ts": "1700000000.1" })).await;
    let stack = Stack::start(profile(&slack))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let workflow = posting_workflow(&world).await;

    let decided = started(&world, &workflow).await;
    ended(&world, &decided.execution_id, "succeeded").await;

    check_posted_message(&slack);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[TOKEN]);
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// Slack receives one authenticated post in the expected channel and thread.
fn check_posted_message(slack: &CannedApp) {
    assert_eq!(slack.asked_for(AUTH_TEST), 1, "the token was checked once");
    let received: Vec<_> = slack
        .received()
        .into_iter()
        .filter(|call| call.path == POST_MESSAGE)
        .collect();
    assert_eq!(received.len(), 1, "Slack was called once");
    assert_eq!(
        received[0].header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    assert_eq!(
        received[0].json(),
        json!({
            "channel": "C0ONCALL",
            "text": "The nightly build failed",
            "thread_ts": "1700000000.1"
        })
    );
}

/// Slack answers the post with HTTP success but `"ok": false` and
/// `not_in_channel`. The post step and its run fail after one request;
/// the worker does not retry the refusal.
#[tokio::test]
async fn a_message_slack_refuses_fails_the_run() {
    let slack = slack_answering(json!({ "ok": false, "error": "not_in_channel" })).await;
    let stack = Stack::start(profile(&slack))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let workflow = posting_workflow(&world).await;

    let decided = started(&world, &workflow).await;
    let run = ended(&world, &decided.execution_id, "failed").await;

    assert_eq!(
        slack.asked_for(POST_MESSAGE),
        1,
        "a refusal is not tried again"
    );
    let step = run
        .steps
        .iter()
        .find(|step| step.key == "slack-post-message")
        .expect("the post step is in the run");
    assert_eq!(step.phase, "failed", "the post step failed");

    stack.stop().await.expect("the stack stops cleanly");
}

/// A Slack stand-in taking the bot's token and answering every post with
/// `answer`.
async fn slack_answering(answer: Value) -> CannedApp {
    CannedApp::start([
        (AUTH_TEST, Canned::json(&json!({ "ok": true }))),
        (POST_MESSAGE, Canned::json(&answer)),
    ])
    .await
    .expect("the Slack stand-in starts")
}

/// The standard deployment, its Slack steps calling `slack`.
fn profile(slack: &CannedApp) -> Profile {
    Profile::standard().with("SLACK_API_URL", &slack.url())
}

/// Ann's published workflow posting to the on-call channel through the
/// bot token Tess connected.
async fn posting_workflow(world: &World<'_>) -> Workflow {
    let account = account_at(world, "slack", TOKEN).await;
    let post = action(
        Action {
            integration: "slack",
            operation: "post-message",
        },
        &account,
        "communicate",
        vec![
            ("channel", written("C0ONCALL")),
            ("text", written("The nightly build failed")),
            ("thread", written("1700000000.1")),
        ],
    );
    let graph = Graph {
        nodes: vec![post],
        edges: vec![],
    };
    let draft = drafted(world, Trigger::Manual, graph).await;
    published(world, &draft).await
}
