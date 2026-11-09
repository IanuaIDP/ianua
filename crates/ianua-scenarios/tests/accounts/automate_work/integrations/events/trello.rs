//! Trello's check of an event address: before it takes a webhook, Trello
//! asks the address with a `HEAD` request, while the registration is
//! still being made, and takes the webhook only when it answers.
//!
//! Trello's deliveries: Ann's workflow on cards created on the Web board
//! registers a webhook whose address carries the registration's secret,
//! as Trello signs with a secret the platform does not hold. A card
//! created there, delivered to that address, starts one run; the same
//! delivery to the bare address starts nothing.

use ianua_scenarios::api::workflows::{self, ServiceDelivery};
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::Trigger;
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;
use serde_json::{Value, json};

use super::connect::{delivering_on, path_and_query, runs_now, runs_started};
use crate::service::Service;
use crate::support::{account_at, ended};

/// The team's key and token, as the account holds them: plain words, not
/// shaped like real ones.
const KEY_AND_TOKEN: &str = r#"{"key":"scenariokeyforacme","token":"scenariotokenforann"}"#;

/// Where Trello says whose a key and token are, which proves them.
const ME: &str = "/members/me";

/// Where webhooks are registered.
const WEBHOOKS: &str = "/webhooks";

/// The Web board, by its id.
const BOARD: &str = "webboard42";

/// Trello checks two event addresses with no session: one no registration
/// holds yet, as while a registration is being made, and another made up.
/// Both answer 200 and alike, so the check says nothing of which
/// registrations exist.
#[tokio::test]
async fn trellos_check_of_an_event_address_is_answered_alike() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let client = world.anonymous().client();

    let pending = workflows::check_event_address(
        "/api/v1/integrations/events/6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5",
    )
    .send_text(client)
    .await;
    let made_up = workflows::check_event_address(
        "/api/v1/integrations/events/00000000-0000-4000-8000-000000000000",
    )
    .send_text(client)
    .await;

    assert_eq!(pending.status(), Status::OK);
    assert_eq!(made_up.status(), Status::OK);

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess connects the team's key and token, tried at Trello before they are
/// kept. Ann publishes a workflow on cards created on the Web board, which
/// registers a webhook there whose address carries the secret. Mallory
/// sends Pat's new card to the bare address: refused. Trello sends it to
/// the address it was given: one run starts and delivers once. Neither the
/// key and token nor the secret is in the trail.
#[tokio::test]
async fn a_card_created_at_trello_starts_the_workflow() {
    let trello = trello().await;
    let service = Service::start().await;
    let profile = Profile::standard().with("TRELLO_API_URL", &format!("{}/", trello.url()));
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "trello", KEY_AND_TOKEN).await;
    let workflow = delivering_on(&world, &service, cards_created(&account)).await;
    let address = registered_address(&trello);

    deliver_card(&stack, &address).await;
    let runs = runs_started(&world, &workflow.id).await;
    ended(&world, &runs[0].id, "succeeded").await;

    assert_eq!(
        trello.asked_for(ME),
        1,
        "the key and token were tried before they were kept"
    );
    assert_eq!(runs[0].cause, "service");
    assert_eq!(service.delivered(), 1, "the run delivered once");
    assert_eq!(
        runs_now(&world, &workflow.id).await.len(),
        1,
        "one card, one run"
    );
    nothing_secret_in_the_trail(&world, &address).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Neither the key and token nor the secret the webhook `address` carries
/// is in the trail.
async fn nothing_secret_in_the_trail(world: &World<'_>, address: &str) {
    let secret = address.split("token=").nth(1).unwrap_or_default();
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[KEY_AND_TOKEN, secret]);
    }
}

/// The Trello stand-in: it knows whose the key and token are and takes
/// webhooks.
async fn trello() -> CannedApp {
    CannedApp::start([
        (
            ME,
            Canned::json(&json!({ "id": "member one", "username": "ann" })),
        ),
        (WEBHOOKS, Canned::json(&json!({ "id": "webhook one" }))),
    ])
    .await
    .expect("the Trello stand-in starts")
}

/// Cards created on the Web board, watched through `account`.
fn cards_created(account: &str) -> Trigger {
    Trigger::Service {
        integration: "trello".to_owned(),
        event: "card-created".to_owned(),
        account_id: account.to_owned(),
        filters: [("board".to_owned(), BOARD.to_owned())].into(),
    }
}

/// Publishing registered one webhook on the Web board; the address Trello
/// was given, the secret in it.
fn registered_address(trello: &CannedApp) -> String {
    let made: Vec<_> = trello
        .received()
        .into_iter()
        .filter(|call| call.path == WEBHOOKS)
        .collect();
    assert_eq!(made.len(), 1, "publishing registered one webhook");
    let query = made[0].query_pairs();
    let value = |name: &str| {
        query
            .iter()
            .find(|(asked, _)| asked == name)
            .map(|(_, value)| value.clone())
    };
    assert_eq!(value("idModel").as_deref(), Some(BOARD));
    value("callbackURL").expect("the webhook names the platform's address")
}

/// Mallory's delivery to the bare address is refused; Trello's to the
/// address it was given is taken.
async fn deliver_card(stack: &Stack, address: &str) {
    let sender = Client::new(stack, "trello").expect("Trello's client");
    let mallory = Client::new(stack, "mallory").expect("Mallory's client");
    let with_secret = path_and_query(address);
    let bare = with_secret
        .split_once('?')
        .map_or(with_secret.as_str(), |(path, _)| path)
        .to_owned();
    let body = created_card().to_string();

    delivered(&mallory, &bare, &body)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let taken = delivered(&sender, &with_secret, &body).await;
    assert_eq!(taken.status(), Status::NO_CONTENT);
}

/// Pat's card created on the Web board, as Trello sends it.
fn created_card() -> Value {
    json!({
        "model": { "id": BOARD },
        "action": {
            "id": "action one",
            "type": "createCard",
            "memberCreator": { "fullName": "Pat" },
            "data": {
                "card": { "id": "card seven", "name": "Fix the Safari login" },
                "list": { "id": "list one", "name": "To do" },
                "board": { "id": BOARD, "name": "Web" }
            }
        }
    })
}

/// `body` delivered to `path` as Trello sends it.
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
