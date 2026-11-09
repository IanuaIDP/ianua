//! PagerDuty's events starting workflows: Tess connects the team's API
//! key, and Ann publishes a workflow that starts when an incident is
//! triggered on the checkout service. Publishing makes a webhook
//! subscription for that one event on that one service, with the
//! registration's secret in a header of its own; PagerDuty's delivery of
//! the incident, carrying that header, starts one run. A delivery without
//! the secret, one about another service, and the same event sent again,
//! start nothing.

use ianua_scenarios::api::workflows::{self, ServiceDelivery};
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::Trigger;
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;
use serde_json::{Value, json};

use super::connect::{delivering_on, path_of, runs_now, runs_started};
use crate::service::Service;
use crate::support::{account_at, ended};

/// The team's API key: a sentence, so no scanner takes it for a key.
const KEY: &str = "acme pagerduty key for incident workflows";

/// Where PagerDuty says what a key may do, which proves it.
const ABILITIES: &str = "/abilities";

/// Where webhook subscriptions are made.
const SUBSCRIPTIONS: &str = "/webhook_subscriptions";

/// The checkout service, as PagerDuty names it.
const CHECKOUT: &str = "PWIXJZS";

/// The header PagerDuty sends the registration's secret back in.
const SECRET_HEADER: &str = "x-ianua-token";

/// Tess connects the key, asked about at PagerDuty before it is kept.
/// Ann publishes a workflow on incidents triggered on checkout, which
/// subscribes to that one event on that one service with the key. Mallory
/// sends the incident without the secret: refused. PagerDuty sends an
/// incident on the search service, which starts nothing, then the
/// checkout incident, which starts one run that delivers once, then the
/// checkout incident again, which starts nothing more. Neither the key nor
/// the secret is in the trail.
#[tokio::test]
async fn an_incident_triggered_at_pagerduty_starts_the_workflow() {
    let pagerduty = pagerduty().await;
    let service = Service::start().await;
    let profile = Profile::standard().with("PAGERDUTY_API_URL", &format!("{}/", pagerduty.url()));
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "pagerduty", KEY).await;
    let workflow = delivering_on(&world, &service, incidents_on_checkout(&account)).await;
    let subscription = subscribed(&pagerduty);

    deliver_incidents(&stack, &subscription).await;
    let runs = runs_started(&world, &workflow.id).await;
    ended(&world, &runs[0].id, "succeeded").await;

    assert_eq!(
        pagerduty.asked_for(ABILITIES),
        1,
        "the key was asked about before it was kept"
    );
    assert_eq!(runs[0].cause, "service");
    assert_eq!(service.delivered(), 1, "the run delivered once");
    assert_eq!(
        runs_now(&world, &workflow.id).await.len(),
        1,
        "one incident, one run"
    );
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[KEY, &subscription.secret]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// The PagerDuty stand-in: it answers what a key may do and takes
/// subscriptions.
async fn pagerduty() -> CannedApp {
    CannedApp::start([
        (ABILITIES, Canned::json(&json!({ "abilities": ["teams"] }))),
        (
            SUBSCRIPTIONS,
            Canned::json(&json!({ "webhook_subscription": { "id": "PSUB001" } })),
        ),
    ])
    .await
    .expect("the PagerDuty stand-in starts")
}

/// Incidents triggered on checkout, watched through `account`.
fn incidents_on_checkout(account: &str) -> Trigger {
    Trigger::Service {
        integration: "pagerduty".to_owned(),
        event: "incident-triggered".to_owned(),
        account_id: account.to_owned(),
        filters: [("service".to_owned(), CHECKOUT.to_owned())].into(),
    }
}

/// The subscription's address and the secret its deliveries carry.
struct Subscription {
    address: String,
    secret: String,
}

/// Publishing made one subscription, with the key, for incidents
/// triggered on checkout alone, sending the secret in its own header.
fn subscribed(pagerduty: &CannedApp) -> Subscription {
    let made: Vec<_> = pagerduty
        .received()
        .into_iter()
        .filter(|call| call.path == SUBSCRIPTIONS)
        .collect();
    assert_eq!(made.len(), 1, "publishing made one subscription");
    assert_eq!(
        made[0].header("authorization"),
        Some(format!("Token token={KEY}").as_str())
    );
    let subscription = &made[0].json()["webhook_subscription"];
    assert_eq!(subscription["events"], json!(["incident.triggered"]));
    assert_eq!(subscription["filter"]["id"], CHECKOUT);
    let delivery = &subscription["delivery_method"];
    assert_eq!(delivery["custom_headers"][0]["name"], SECRET_HEADER);
    Subscription {
        address: delivery["url"]
            .as_str()
            .expect("the subscription names the platform's address")
            .to_owned(),
        secret: delivery["custom_headers"][0]["value"]
            .as_str()
            .expect("the subscription carries its secret")
            .to_owned(),
    }
}

/// Mallory's copy without the secret is refused; PagerDuty's incident on
/// search, on checkout and on checkout again are taken.
async fn deliver_incidents(stack: &Stack, subscription: &Subscription) {
    let sender = Client::new(stack, "pagerduty").expect("PagerDuty's client");
    let mallory = Client::new(stack, "mallory").expect("Mallory's client");
    let path = path_of(&subscription.address);
    let elsewhere = triggered("01SEARCHDOWN", "PSEARCH").to_string();
    let checkout = triggered("01CHECKOUTDOWN", CHECKOUT).to_string();

    delivered(&mallory, &path, &checkout, "mallory's guessed secret")
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    for body in [&elsewhere, &checkout, &checkout] {
        let taken = delivered(&sender, &path, body, &subscription.secret).await;
        assert_eq!(taken.status(), Status::NO_CONTENT);
    }
}

/// An incident triggered on the service `service`, as PagerDuty sends
/// it, its event named `event_id`.
fn triggered(event_id: &str, service: &str) -> Value {
    json!({
        "event": {
            "id": event_id,
            "event_type": "incident.triggered",
            "resource_type": "incident",
            "occurred_at": "2026-11-08T09:00:00Z",
            "agent": { "summary": "Pat" },
            "data": {
                "id": "Q1INCIDENT",
                "number": 7,
                "title": "Checkout is down",
                "status": "triggered",
                "urgency": "high",
                "html_url": "https://acme.pagerduty.com/incidents/Q1INCIDENT",
                "service": { "id": service, "summary": "Checkout" }
            }
        }
    })
}

/// `body` delivered to `path` as PagerDuty sends it, with `secret` in its
/// header.
async fn delivered(client: &Client, path: &str, body: &str, secret: &str) -> Answer<String> {
    workflows::deliver_event(&ServiceDelivery {
        path,
        content_type: "application/json",
        headers: &[(SECRET_HEADER, secret)],
        body,
    })
    .send_text(client)
    .await
}
