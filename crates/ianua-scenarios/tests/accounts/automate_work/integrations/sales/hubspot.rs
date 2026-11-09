//! HubSpot as a workflow step: Tess connects the team's private app token,
//! which HubSpot is asked about first by listing one contact, and Ann
//! publishes a workflow that adds a contact and then gives it a phone
//! number. A stand-in for HubSpot's CRM shows what arrived: the token, the
//! contact's properties, and the change to the contact HubSpot gave its
//! id. A token HubSpot refuses is never connected, and a contact HubSpot
//! refuses, as one with an address it already has, fails the run.

use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::Graph;
use ianua_scenarios::world::World;
use serde_json::json;

use crate::integrations::calls::{Offered, chain, failed_step, never_connected, only_call, ran};
use crate::support::{Action, account_at, action, read, written};

/// The team's token: a sentence, so no scanner takes it for a key.
const TOKEN: &str = "acme hubspot token for workflows";

/// Where HubSpot's contacts are listed and added.
const CONTACTS: &str = "/crm/v3/objects/contacts";

/// Where the contact HubSpot gave the id 5101 is changed.
const CONTACT: &str = "/crm/v3/objects/contacts/5101";

/// Tess connects the token, which HubSpot takes for listing one contact.
/// Ann publishes a workflow adding Dana from the signup form and giving
/// the contact HubSpot answered with her phone number. Tess runs it:
/// HubSpot receives the new contact and the change to contact 5101, each
/// signed with the token, and the run succeeds. The token is nowhere in
/// the trail.
#[tokio::test]
async fn a_run_adds_a_contact_and_changes_it() {
    let hubspot = hubspot_answering(Canned::json(&json!({ "id": "5101", "properties": {} }))).await;
    let stack = Stack::start(profile(&hubspot))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "hubspot", TOKEN).await;
    let asked = only_call(&hubspot, "GET", CONTACTS);
    assert_eq!(asked.query.as_deref(), Some("limit=1"));
    ran(&world, contact_graph(&account), "succeeded").await;
    check_contact_and_change(&hubspot);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[TOKEN]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// HubSpot refuses the contact with 409, as it does an address it already
/// has. The add step and the run fail after one request, and nothing is
/// changed.
#[tokio::test]
async fn a_contact_hubspot_refuses_fails_the_run() {
    let hubspot = hubspot_answering(Canned::refusing(409)).await;
    let stack = Stack::start(profile(&hubspot))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "hubspot", TOKEN).await;

    let run = ran(&world, contact_graph(&account), "failed").await;

    failed_step(&run, "hubspot-create-contact");
    only_call(&hubspot, "POST", CONTACTS);
    assert_eq!(hubspot.asked_for(CONTACT), 0, "no contact was changed");
    stack.stop().await.expect("the stack stops cleanly");
}

/// HubSpot does not know Tess's mistyped token: asked once, it answers
/// 401, and no account is connected.
#[tokio::test]
async fn a_token_hubspot_refuses_is_never_connected() {
    let hubspot = CannedApp::start([(CONTACTS, Canned::refusing(401))])
        .await
        .expect("the HubSpot stand-in starts");
    let stack = Stack::start(profile(&hubspot))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let offered = Offered {
        integration: "hubspot",
        credential: "a mistyped hubspot token",
    };

    never_connected(&world, offered).await;

    assert_eq!(
        hubspot.asked_for(CONTACTS),
        1,
        "HubSpot was asked about the token"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The workflow adds Dana and gives the contact HubSpot gave back her
/// phone number.
fn contact_graph(account: &str) -> Graph {
    let create = action(
        Action {
            integration: "hubspot",
            operation: "create-contact",
        },
        account,
        "write",
        vec![(
            "properties",
            written(json!({ "email": "dana@customer.test", "firstname": "Dana" })),
        )],
    );
    let change = action(
        Action {
            integration: "hubspot",
            operation: "update-contact",
        },
        account,
        "write",
        vec![
            ("contact", read("hubspot-create-contact.json.id")),
            ("properties", written(json!({ "phone": "+15551234567" }))),
        ],
    );
    chain(vec![create, change])
}

/// HubSpot received the new contact and then the change to contact 5101,
/// each signed with the token.
fn check_contact_and_change(hubspot: &CannedApp) {
    let created = only_call(hubspot, "POST", CONTACTS);
    let changed = only_call(hubspot, "PATCH", CONTACT);
    for call in [&created, &changed] {
        assert_eq!(
            call.header("authorization"),
            Some(format!("Bearer {TOKEN}").as_str())
        );
    }
    assert_eq!(
        created.json(),
        json!({ "properties": { "email": "dana@customer.test", "firstname": "Dana" } })
    );
    assert_eq!(
        changed.json(),
        json!({ "properties": { "phone": "+15551234567" } })
    );
}

/// A HubSpot stand-in that lists one contact for the probe, answers a new
/// contact with `contact`, and takes any change.
async fn hubspot_answering(contact: Canned) -> CannedApp {
    CannedApp::start([
        (
            "GET /crm/v3/objects/contacts",
            Canned::json(&json!({ "results": [] })),
        ),
        ("POST /crm/v3/objects/contacts", contact),
        (
            CONTACT,
            Canned::json(&json!({ "id": "5101", "properties": { "phone": "+15551234567" } })),
        ),
    ])
    .await
    .expect("the HubSpot stand-in starts")
}

/// The standard deployment, its HubSpot steps calling `hubspot`.
fn profile(hubspot: &CannedApp) -> Profile {
    Profile::standard().with("HUBSPOT_API_URL", &hubspot.url())
}
