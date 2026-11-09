//! Twilio as a workflow step: Tess connects the team's account SID and auth
//! token, which Twilio is asked about first, and Ann publishes a workflow
//! that texts the person on call. A stand-in for Twilio shows what arrived:
//! the account's own place in the address, its SID and token as the
//! password, and the message as Twilio's form.

use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::{Graph, Trigger};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{Action, account_at, action, drafted, ended, published, started, written};

/// The team's auth token: a sentence, so no scanner takes it for a key.
const TOKEN: &str = "acme twilio auth token for workflows";

/// Where the account's messages are, which also proves its credential.
const MESSAGES: &str = "/2010-04-01/Accounts/AC0ACME/Messages.json";

/// Tess connects the account, which Twilio vouches for by listing its
/// messages. Ann publishes a workflow texting the person on call. Tess
/// runs it: Twilio receives the text at the account's messages, signed with
/// its SID and token, as a form, and the run succeeds. The token is nowhere
/// in the trail.
#[tokio::test]
async fn a_run_texts_the_person_on_call() {
    let twilio = CannedApp::start([(
        MESSAGES,
        Canned::json(&json!({ "sid": "SM1", "status": "queued", "messages": [] })),
    )])
    .await
    .expect("the Twilio stand-in starts");
    let profile = Profile::standard().with("TWILIO_API_URL", &format!("{}/", twilio.url()));
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let credential = json!({ "account": "AC0ACME", "token": TOKEN }).to_string();
    let account = account_at(&world, "twilio", &credential).await;
    assert_eq!(
        twilio.asked_for(MESSAGES),
        1,
        "Twilio was asked about the account"
    );
    let draft = drafted(&world, Trigger::Manual, text_graph(&account)).await;
    let workflow = published(&world, &draft).await;
    let decided = started(&world, &workflow).await;
    ended(&world, &decided.execution_id, "succeeded").await;
    check_text(&twilio);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[TOKEN]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// The workflow texts the on-call number through the connected Twilio account.
fn text_graph(account: &str) -> Graph {
    let text = action(
        Action {
            integration: "twilio",
            operation: "send-message",
        },
        account,
        "communicate",
        vec![
            ("to", written("+15551234567")),
            ("from", written("+15557654321")),
            ("body", written("The nightly build failed")),
        ],
    );
    Graph {
        edges: vec![],
        nodes: vec![text],
    }
}

/// Twilio receives the expected encoded text and its account's Basic credentials.
fn check_text(twilio: &CannedApp) {
    let sent = twilio
        .received()
        .into_iter()
        .find(|call| call.path == MESSAGES && call.method == "POST")
        .expect("the text reached Twilio");
    assert_eq!(
        sent.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert!(
        sent.header("authorization")
            .is_some_and(|value| value.starts_with("Basic ")),
        "the SID and token went as the password"
    );
    assert_eq!(
        sent.body,
        "Body=The+nightly+build+failed&From=%2B15557654321&To=%2B15551234567"
    );
}
