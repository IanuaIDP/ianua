//! Mailgun's events starting workflows: Ann publishes a workflow that
//! starts when mail from the domain fails for good, and mails the team who
//! bounced. Publishing adds a webhook on the domain whose address carries
//! the registration's secret; Mailgun's delivery to it starts one run. A
//! delivery to the bare address, without the secret, starts nothing.

use ianua_scenarios::api::workflows::{self, ServiceDelivery};
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::{Graph, Trigger, Workflow};
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;
use serde_json::json;

use super::connect::{path_and_query, runs_started};
use crate::support::{Action, account_at, action, drafted, ended, published, read, written};

/// The team's API key: a sentence, so no scanner takes it for a key.
const KEY: &str = "acme mailgun key for bounce workflows";

/// Where Mailgun lists the account's domains, which proves a key.
const DOMAINS: &str = "/v4/domains";

/// Where the domain's webhooks are added.
const WEBHOOKS: &str = "/v4/domains/mail.acme.test/webhooks";

/// Where the run's mail is sent.
const MESSAGES: &str = "/v3/mail.acme.test/messages";

/// Tess connects the key. Ann publishes a workflow on mail failing for
/// good, which adds a permanent-failure webhook on mail.acme.test. Mailgun
/// says mail to nobody@globex.test bounced: the delivery to the webhook's
/// address starts one run, which mails the team naming who bounced.
/// Mallory's delivery to the address without its secret is refused. The
/// key and the secret are nowhere in the trail.
#[tokio::test]
async fn a_bounce_at_mailgun_starts_the_workflow() {
    let mailgun = mailgun().await;
    let profile = Profile::standard().with("MAILGUN_API_URL", &format!("{}/", mailgun.url()));
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "mailgun", KEY).await;
    let workflow = publish_bounce_mail(&world, &account).await;
    let address = registered_hook(&mailgun);
    deliver_bounce(&stack, &address).await;
    check_bounce_run(&world, &mailgun, &workflow.id, &address).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Permanent failures on the team's domain start the published notification workflow.
async fn publish_bounce_mail(world: &World<'_>, account: &str) -> Workflow {
    let trigger = Trigger::Service {
        integration: "mailgun".to_owned(),
        event: "message-failed".to_owned(),
        account_id: account.to_owned(),
        filters: [("domain".to_owned(), "mail.acme.test".to_owned())].into(),
    };
    let draft = drafted(world, trigger, notification_graph(account)).await;
    published(world, &draft).await
}

/// The notification's text identifies the recipient whose message bounced.
fn notification_graph(account: &str) -> Graph {
    let notify = action(
        Action {
            integration: "mailgun",
            operation: "send-message",
        },
        account,
        "communicate",
        vec![
            ("domain", written("mail.acme.test")),
            ("from", written("ops@mail.acme.test")),
            ("to", written(json!(["ops@acme.test"]))),
            ("subject", written("A message bounced")),
            ("text", read("trigger.event-data.recipient")),
        ],
    );
    Graph {
        nodes: vec![notify],
        edges: vec![],
    }
}

/// Publishing adds one permanent-failure webhook and supplies its delivery address.
fn registered_hook(mailgun: &CannedApp) -> String {
    let added: Vec<_> = mailgun
        .received()
        .into_iter()
        .filter(|call| call.path == WEBHOOKS)
        .collect();
    assert_eq!(added.len(), 1, "publishing added one webhook");
    let form: Vec<(String, String)> = url::form_urlencoded::parse(added[0].body.as_bytes())
        .into_owned()
        .collect();
    assert!(form.contains(&("event_types".to_owned(), "permanent_fail".to_owned())));
    form.iter()
        .find(|(name, _)| name == "url")
        .map(|(_, value)| value.clone())
        .expect("the webhook names the platform's address")
}

/// The bare address refuses Mallory's bounce, while Mailgun's secret-bearing address accepts it.
async fn deliver_bounce(stack: &Stack, address: &str) {
    let secret_path = path_and_query(address);
    let bare_path = secret_path
        .split_once('?')
        .map_or(secret_path.as_str(), |(path, _)| path)
        .to_owned();

    let sender = Client::new(stack, "mailgun").expect("Mailgun's client");
    let mallory = Client::new(stack, "mallory").expect("Mallory's client");
    let bounce = bounced().to_string();
    delivered(&mallory, &bare_path, &bounce)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let taken = delivered(&sender, &secret_path, &bounce).await;
    assert_eq!(taken.status(), Status::NO_CONTENT);
}

/// The bounce starts a successful notification with neither account nor hook secrets in the trail.
async fn check_bounce_run(
    world: &World<'_>,
    mailgun: &CannedApp,
    workflow_id: &str,
    address: &str,
) {
    let runs = runs_started(world, workflow_id).await;
    ended(world, &runs[0].id, "succeeded").await;
    assert_eq!(mailgun.asked_for(MESSAGES), 1, "the run mailed the team");
    let secret = address
        .split("token=")
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[KEY, &secret]);
    }
}

/// The Mailgun stand-in: it lists domains, adds webhooks and takes mail.
async fn mailgun() -> CannedApp {
    CannedApp::start([
        (
            DOMAINS,
            Canned::json(&json!({ "total_count": 1, "items": [] })),
        ),
        (WEBHOOKS, Canned::json(&json!({ "webhooks": {} }))),
        (
            MESSAGES,
            Canned::json(&json!({ "id": "<2@mail.acme.test>", "message": "Queued." })),
        ),
    ])
    .await
    .expect("the Mailgun stand-in starts")
}

/// Mail to nobody@globex.test failing for good, as Mailgun sends it.
fn bounced() -> serde_json::Value {
    json!({
        "signature": { "timestamp": "1700000000", "token": "t", "signature": "s" },
        "event-data": {
            "id": "Ase-bounce-1",
            "event": "failed",
            "severity": "permanent",
            "reason": "bounce",
            "recipient": "nobody@globex.test",
            "timestamp": 1_700_000_000.5,
            "message": { "headers": { "message-id": "m1@mail.acme.test", "subject": "Invoice" } }
        }
    })
}

/// `body` delivered to `path` as Mailgun sends it.
async fn delivered(client: &Client, path: &str, body: &str) -> Answer<String> {
    workflows::deliver_event(&ServiceDelivery {
        path,
        content_type: "application/json",
        headers: &[],
        body,
    })
    .send_text(client)
    .await
}
