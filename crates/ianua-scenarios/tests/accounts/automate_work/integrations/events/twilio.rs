//! Twilio's events starting workflows: Ann publishes a workflow that starts
//! when someone texts the support number, and texts them back. Publishing
//! points the number's incoming texts at the registration's address, which
//! carries its secret; Twilio's delivery of Pat's text starts one run. A
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

/// The account's auth token: a sentence, so no scanner takes it for one.
const TOKEN: &str = "acme twilio auth token for text workflows";

/// Where Twilio lists the account's messages, which proves a credential,
/// and where the run's reply is sent.
const MESSAGES: &str = "/2010-04-01/Accounts/AC0ACME/Messages.json";

/// Where the account's numbers are listed.
const NUMBERS: &str = "/2010-04-01/Accounts/AC0ACME/IncomingPhoneNumbers.json";

/// Where the support number is pointed.
const NUMBER: &str = "/2010-04-01/Accounts/AC0ACME/IncomingPhoneNumbers/PN0SUPPORT.json";

/// The support number.
const SUPPORT: &str = "+15551230000";

/// Tess connects the account. Ann publishes a workflow on texts to the
/// support number, which points the number's incoming texts at the
/// registration. Pat texts "My order never arrived": Twilio's delivery to
/// the number's address starts one run, which texts Pat back. Mallory's
/// delivery to the address without its secret is refused. The token and
/// the secret are nowhere in the trail.
#[tokio::test]
async fn a_text_to_the_support_number_starts_the_workflow() {
    let twilio = twilio().await;
    let profile = Profile::standard().with("TWILIO_API_URL", &format!("{}/", twilio.url()));
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let credential = json!({ "account": "AC0ACME", "token": TOKEN }).to_string();
    let account = account_at(&world, "twilio", &credential).await;
    let workflow = publish_reply(&world, &account).await;
    let address = registered_hook(&twilio);
    deliver_text(&stack, &address).await;
    check_reply_run(&world, &twilio, &workflow.id, &address).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Texts to the support number start the published reply workflow.
async fn publish_reply(world: &World<'_>, account: &str) -> Workflow {
    let trigger = Trigger::Service {
        integration: "twilio".to_owned(),
        event: "text-received".to_owned(),
        account_id: account.to_owned(),
        filters: [("number".to_owned(), SUPPORT.to_owned())].into(),
    };
    let draft = drafted(world, trigger, reply_graph(account)).await;
    published(world, &draft).await
}

/// The reply is sent from support to the sender named in the trigger.
fn reply_graph(account: &str) -> Graph {
    let reply = action(
        Action {
            integration: "twilio",
            operation: "send-message",
        },
        account,
        "communicate",
        vec![
            ("to", read("trigger.from")),
            ("from", written(SUPPORT)),
            ("body", written("Thanks, we are looking into your order.")),
        ],
    );
    Graph {
        nodes: vec![reply],
        edges: vec![],
    }
}

/// Publishing points the number once at the platform's incoming-text address.
fn registered_hook(twilio: &CannedApp) -> String {
    let pointed: Vec<_> = twilio
        .received()
        .into_iter()
        .filter(|call| call.path == NUMBER)
        .collect();
    assert_eq!(pointed.len(), 1, "publishing pointed the number once");
    let form: Vec<(String, String)> = url::form_urlencoded::parse(pointed[0].body.as_bytes())
        .into_owned()
        .collect();
    form.iter()
        .find(|(name, _)| name == "SmsUrl")
        .map(|(_, value)| value.clone())
        .expect("the number points at the platform's address")
}

/// The platform refuses a text without the delivery secret and accepts Twilio's delivery.
async fn deliver_text(stack: &Stack, address: &str) {
    let secret_path = path_and_query(address);
    let bare_path = secret_path
        .split_once('?')
        .map_or(secret_path.as_str(), |(path, _)| path)
        .to_owned();

    let sender = Client::new(stack, "twilio").expect("Twilio's client");
    let mallory = Client::new(stack, "mallory").expect("Mallory's client");
    let text = texted();
    delivered(&mallory, &bare_path, &text)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let taken = delivered(&sender, &secret_path, &text).await;
    assert_eq!(taken.status(), Status::NO_CONTENT);
}

/// One reply reaches Pat and neither credential nor delivery secret appears in the trail.
async fn check_reply_run(world: &World<'_>, twilio: &CannedApp, workflow_id: &str, address: &str) {
    let runs = runs_started(world, workflow_id).await;
    ended(world, &runs[0].id, "succeeded").await;
    let replies: Vec<_> = twilio
        .received()
        .into_iter()
        .filter(|call| call.path == MESSAGES && call.method == "POST")
        .collect();
    assert_eq!(replies.len(), 1, "the run texted Pat back");
    assert!(replies[0].body.contains("To=%2B15559870000"));
    let secret = address
        .split("token=")
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[TOKEN, &secret]);
    }
}

/// The Twilio stand-in: it lists messages and numbers, points a number and
/// takes a text.
async fn twilio() -> CannedApp {
    CannedApp::start([
        (
            MESSAGES,
            Canned::json(&json!({ "messages": [], "sid": "SM0REPLY" })),
        ),
        (
            NUMBERS,
            Canned::json(&json!({
                "incoming_phone_numbers": [{
                    "sid": "PN0SUPPORT",
                    "sms_url": "",
                    "sms_application_sid": ""
                }]
            })),
        ),
        (NUMBER, Canned::json(&json!({ "sid": "PN0SUPPORT" }))),
    ])
    .await
    .expect("the Twilio stand-in starts")
}

/// Pat's text to the support number, as Twilio sends it.
fn texted() -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("MessageSid", "SM0PAT")
        .append_pair("From", "+15559870000")
        .append_pair("To", SUPPORT)
        .append_pair("Body", "My order never arrived")
        .finish()
}

/// `body` delivered to `path` as Twilio sends it, a form.
async fn delivered(client: &Client, path: &str, body: &str) -> Answer<String> {
    workflows::deliver_event(&ServiceDelivery {
        path,
        content_type: "application/x-www-form-urlencoded",
        headers: &[],
        body,
    })
    .send_text(client)
    .await
}
