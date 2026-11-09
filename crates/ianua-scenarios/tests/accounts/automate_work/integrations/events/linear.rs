//! Linear's events starting workflows: Tess connects the team's API key,
//! and Ann publishes a workflow that starts when an issue is created in
//! the engineering team. Publishing registers a webhook for the team's
//! issues with the registration's secret; Linear's delivery of Pat's new
//! issue, signed with that secret and sent just now, starts one run. A
//! delivery signed otherwise, and a signed one sent minutes ago, start
//! nothing.

use std::time::{SystemTime, UNIX_EPOCH};

use ianua_scenarios::api::workflows::{self, ServiceDelivery};
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::Trigger;
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;
use serde_json::{Value, json};

use super::connect::{delivering_on, path_of, runs_now, runs_started, signed};
use crate::service::Service;
use crate::support::{account_at, ended};

/// The team's API key: a sentence, so no scanner takes it for a key.
const KEY: &str = "acme linear key for issue workflows";

/// Where every call to Linear goes.
const GRAPHQL: &str = "/graphql";

/// The engineering team, as Linear names it.
const TEAM: &str = "team-eng";

/// Three minutes, in milliseconds: further from now than Linear's
/// deliveries may be.
const MINUTES_AGO_MS: i64 = 180_000;

/// Tess connects the key, which Linear is asked about before it is kept.
/// Ann publishes a workflow on issues created in the engineering team,
/// which registers a webhook for its issues with the key. A delivery of
/// ENG-7 signed minutes ago is taken and starts nothing; Mallory's,
/// signed with her own secret, is refused; Linear's, signed just now,
/// starts one run, which delivers once. Neither the key nor the webhook's
/// secret is in the trail.
#[tokio::test]
async fn an_issue_created_in_linear_starts_the_workflow() {
    let linear = linear().await;
    let service = Service::start().await;
    let profile = Profile::standard().with("LINEAR_API_URL", &format!("{}/", linear.url()));
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "linear", KEY).await;
    let workflow = delivering_on(&world, &service, issues_created(&account)).await;
    let hook = registered_hook(&linear);

    deliver_issue(&stack, &hook).await;
    let runs = runs_started(&world, &workflow.id).await;
    ended(&world, &runs[0].id, "succeeded").await;

    assert_eq!(runs[0].cause, "service");
    assert_eq!(service.delivered(), 1, "the run delivered once");
    assert_eq!(
        runs_now(&world, &workflow.id).await.len(),
        1,
        "the old delivery started nothing"
    );
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[KEY, &hook.secret]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// The Linear stand-in: one GraphQL address answering whose the key is
/// and taking the webhook.
async fn linear() -> CannedApp {
    let answer = json!({
        "data": {
            "viewer": { "id": "ann's id" },
            "webhookCreate": { "success": true, "webhook": { "id": "webhook one", "enabled": true } }
        }
    });
    CannedApp::start([(GRAPHQL, Canned::json(&answer))])
        .await
        .expect("the Linear stand-in starts")
}

/// Issues created in the engineering team, watched through `account`.
fn issues_created(account: &str) -> Trigger {
    Trigger::Service {
        integration: "linear".to_owned(),
        event: "issue-created".to_owned(),
        account_id: account.to_owned(),
        filters: [("team".to_owned(), TEAM.to_owned())].into(),
    }
}

/// The webhook's address and the secret its deliveries are signed with.
struct Hook {
    address: String,
    secret: String,
}

/// Publishing registered one webhook for the team's issues, with the key.
fn registered_hook(linear: &CannedApp) -> Hook {
    let created: Vec<_> = linear
        .received()
        .into_iter()
        .filter(|call| call.method == "POST" && call.body.contains("webhookCreate"))
        .collect();
    assert_eq!(created.len(), 1, "publishing registered one webhook");
    assert_eq!(created[0].header("authorization"), Some(KEY));
    let input = &created[0].json()["variables"]["input"];
    assert_eq!(input["teamId"], TEAM);
    assert_eq!(input["resourceTypes"], json!(["Issue"]));
    Hook {
        address: input["url"]
            .as_str()
            .expect("the webhook names the platform's address")
            .to_owned(),
        secret: input["secret"]
            .as_str()
            .expect("the webhook carries its secret")
            .to_owned(),
    }
}

/// A signed delivery from minutes ago starts nothing, Mallory's signature
/// is refused, and Linear's delivery of now is taken.
async fn deliver_issue(stack: &Stack, hook: &Hook) {
    let sender = Client::new(stack, "linear").expect("Linear's client");
    let mallory = Client::new(stack, "mallory").expect("Mallory's client");
    let path = path_of(&hook.address);
    let now = now_ms();
    let stale = created_issue(now - MINUTES_AGO_MS).to_string();
    let fresh = created_issue(now).to_string();
    let [before, forged, current] = copies(&path, &hook.secret, &stale, &fresh);

    let skipped = delivered(&sender, &before).await;
    delivered(&mallory, &forged)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let taken = delivered(&sender, &current).await;
    assert_ne!(
        skipped.status(),
        Status::UNAUTHORIZED,
        "an old signature is still Linear's"
    );
    assert_eq!(taken.status(), Status::NO_CONTENT);
}

/// The three copies sent to `path`: the `stale` body signed with
/// `secret`, then the `fresh` one signed by Mallory, then signed with
/// `secret`.
fn copies<'a>(path: &'a str, secret: &'a str, stale: &'a str, fresh: &'a str) -> [Sent<'a>; 3] {
    let before = Sent {
        path,
        id: "delivery from before",
        body: stale,
        secret,
    };
    let forged = Sent {
        id: "delivery of now",
        body: fresh,
        secret: "mallory's own secret words",
        ..before
    };
    let current = Sent { secret, ..forged };
    [before, forged, current]
}

/// One copy of a delivery: where it goes, Linear's id for it, its body,
/// and the secret it is signed with.
#[derive(Clone, Copy)]
struct Sent<'a> {
    path: &'a str,
    id: &'a str,
    body: &'a str,
    secret: &'a str,
}

/// The time now, in milliseconds since the epoch, as Linear stamps a
/// delivery.
fn now_ms() -> i64 {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is past the epoch");
    i64::try_from(since.as_millis()).expect("the time fits")
}

/// ENG-7 created in the engineering team, as Linear sends it, stamped
/// `sent_ms`.
fn created_issue(sent_ms: i64) -> Value {
    json!({
        "action": "create",
        "type": "Issue",
        "webhookTimestamp": sent_ms,
        "url": "https://linear.app/acme/issue/ENG-7",
        "actor": { "name": "Pat" },
        "data": {
            "id": "issue seven",
            "identifier": "ENG-7",
            "title": "Login fails on Safari",
            "description": "Steps to reproduce attached.",
            "priority": 2,
            "teamId": TEAM,
            "team": { "key": "ENG" },
            "state": { "name": "Todo" },
            "assignee": { "name": "Pat" }
        }
    })
}

/// `sent` delivered as Linear sends it, its body signed with its secret.
async fn delivered(client: &Client, sent: &Sent<'_>) -> Answer<String> {
    let signature = signed(sent.secret, &[sent.body.as_bytes()]);
    workflows::deliver_event(&ServiceDelivery {
        path: sent.path,
        content_type: "application/json",
        headers: &[
            ("linear-delivery", sent.id),
            ("linear-event", "Issue"),
            ("linear-signature", &signature),
        ],
        body: sent.body,
    })
    .send_text(client)
    .await
}
