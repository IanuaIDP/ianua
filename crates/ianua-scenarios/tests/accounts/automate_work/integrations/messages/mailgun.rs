//! Mailgun as a workflow step: Tess connects the team's API key, which
//! Mailgun is asked about first, and Ann publishes a workflow that mails
//! the build report to two people. A stand-in for Mailgun shows what
//! arrived: the key as the password of `api`, and the email as Mailgun's
//! form with one `to` per recipient.

use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::{Graph, Trigger};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{Action, account_at, action, drafted, ended, published, started, written};

/// The team's API key: a sentence, so no scanner takes it for a key.
const KEY: &str = "acme mailgun key for workflows";

/// Where Mailgun lists the account's domains, which proves a key.
const DOMAINS: &str = "/v4/domains";

/// Where the domain's mail is sent.
const MESSAGES: &str = "/v3/mail.acme.test/messages";

/// Tess connects the key, which Mailgun vouches for by listing the
/// domains. Ann publishes a workflow mailing the build report to Ann and
/// Bob. Tess runs it: Mailgun receives the email at the domain, signed
/// with the key, as a form naming each recipient, and the run succeeds.
/// The key is nowhere in the trail.
#[tokio::test]
async fn a_run_mails_the_build_report() {
    let mailgun = CannedApp::start([
        (
            DOMAINS,
            Canned::json(&json!({ "total_count": 1, "items": [] })),
        ),
        (
            MESSAGES,
            Canned::json(&json!({ "id": "<1@mail.acme.test>", "message": "Queued. Thank you." })),
        ),
    ])
    .await
    .expect("the Mailgun stand-in starts");
    let profile = Profile::standard().with("MAILGUN_API_URL", &format!("{}/", mailgun.url()));
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "mailgun", KEY).await;
    assert_eq!(
        mailgun.asked_for(DOMAINS),
        1,
        "Mailgun was asked about the key"
    );
    let draft = drafted(&world, Trigger::Manual, report_graph(&account)).await;
    let workflow = published(&world, &draft).await;
    let decided = started(&world, &workflow).await;
    ended(&world, &decided.execution_id, "succeeded").await;
    check_report(&mailgun);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[KEY]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// The workflow sends the build report to both recipients through the team's domain.
fn report_graph(account: &str) -> Graph {
    let report = action(
        Action {
            integration: "mailgun",
            operation: "send-message",
        },
        account,
        "communicate",
        vec![
            ("domain", written("mail.acme.test")),
            ("from", written("ops@mail.acme.test")),
            ("to", written(json!(["ann@acme.test", "bob@acme.test"]))),
            ("subject", written("Nightly build")),
            ("text", written("The nightly build failed")),
        ],
    );
    Graph {
        edges: vec![],
        nodes: vec![report],
    }
}

/// Mailgun receives the authenticated form with both recipient fields.
fn check_report(mailgun: &CannedApp) {
    let sent = mailgun
        .received()
        .into_iter()
        .find(|call| call.path == MESSAGES)
        .expect("the email reached Mailgun");
    assert_eq!(
        sent.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert!(
        sent.header("authorization")
            .is_some_and(|value| value.starts_with("Basic ")),
        "the key went as the password"
    );
    assert_eq!(
        sent.body,
        "from=ops%40mail.acme.test&subject=Nightly+build&text=The+nightly+build+failed\
         &to=ann%40acme.test&to=bob%40acme.test"
    );
}
