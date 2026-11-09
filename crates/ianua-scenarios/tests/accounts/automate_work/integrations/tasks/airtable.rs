//! Airtable as a workflow step: Tess connects the team's personal access
//! token, which Airtable is asked about first, and Ann publishes a workflow
//! that adds a ticket to the support base's Tickets table and then closes
//! it. A stand-in for Airtable's API shows what arrived: the token, the
//! base and table in the address, the record's fields, and the change to
//! the record Airtable gave its id, its text read into the fields' own
//! types. A token Airtable refuses is never connected, and a record
//! Airtable refuses fails the run.

use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::{Graph, Node, Source};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::integrations::calls::{Offered, chain, failed_step, never_connected, only_call, ran};
use crate::support::{Action, account_at, action, read, written};

/// The team's token: a sentence, so no scanner takes it for a key.
const TOKEN: &str = "acme airtable token for workflows";

/// Where Airtable says whose a token is.
const WHO: &str = "/meta/whoami";

/// Where the support base's tickets are.
const TICKETS: &str = "/appAcmeSupport/Tickets";

/// Where the ticket Airtable gave the id recTicket42 is changed.
const TICKET: &str = "/appAcmeSupport/Tickets/recTicket42";

/// Tess connects the token, which Airtable is asked about once. Ann
/// publishes a workflow adding the printer ticket to the Tickets table and
/// then marking that record done. Tess runs it: Airtable receives the new
/// record and the change to recTicket42, each signed with the token, and
/// the run succeeds. The token is nowhere in the trail.
#[tokio::test]
async fn a_run_adds_a_record_and_changes_it() {
    let airtable = airtable_answering(Canned::json(&json!({
        "id": "recTicket42",
        "fields": { "Name": "Printer offline" }
    })))
    .await;
    let stack = Stack::start(profile(&airtable))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "airtable", TOKEN).await;
    let asked = only_call(&airtable, "GET", WHO);
    assert_eq!(
        asked.header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    ran(&world, ticket_graph(&account), "succeeded").await;
    check_record_and_change(&airtable);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[TOKEN]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Airtable refuses the record with 422, as for a field the table does not
/// have. The add step and the run fail after one request, and nothing is
/// changed.
#[tokio::test]
async fn a_record_airtable_refuses_fails_the_run() {
    let airtable = airtable_answering(Canned::refusing(422)).await;
    let stack = Stack::start(profile(&airtable))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "airtable", TOKEN).await;

    let run = ran(&world, ticket_graph(&account), "failed").await;

    failed_step(&run, "airtable-create-record");
    assert_eq!(
        airtable.asked_for(TICKETS),
        1,
        "a refusal is not tried again"
    );
    assert_eq!(airtable.asked_for(TICKET), 0, "no record was changed");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Airtable does not know Tess's mistyped token: asked once, it answers
/// 401, and no account is connected.
#[tokio::test]
async fn a_token_airtable_refuses_is_never_connected() {
    let airtable = CannedApp::start([(WHO, Canned::refusing(401))])
        .await
        .expect("the Airtable stand-in starts");
    let stack = Stack::start(profile(&airtable))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let offered = Offered {
        integration: "airtable",
        credential: "a mistyped airtable token",
    };

    never_connected(&world, offered).await;

    assert_eq!(
        airtable.asked_for(WHO),
        1,
        "Airtable was asked about the token"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The workflow adds the printer ticket and marks the record Airtable gave
/// back as done.
fn ticket_graph(account: &str) -> Graph {
    let create = vec![
        ("base", written("appAcmeSupport")),
        ("table", written("Tickets")),
        (
            "fields",
            written(json!({ "Name": "Printer offline", "Priority": "High" })),
        ),
    ];
    let close = vec![
        ("base", written("appAcmeSupport")),
        ("table", written("Tickets")),
        ("record", read("airtable-create-record.json.id")),
        ("fields", written(json!({ "Status": "Done" }))),
        ("convert", written(true)),
    ];
    chain(vec![
        airtable_step("create-record", account, create),
        airtable_step("update-record", account, close),
    ])
}

/// Airtable's step `operation` through `account`, writing `inputs`.
fn airtable_step(operation: &str, account: &str, inputs: Vec<(&str, Source)>) -> Node {
    let named = Action {
        integration: "airtable",
        operation,
    };
    action(named, account, "write", inputs)
}

/// Airtable received the new record's fields and then the change to
/// recTicket42, each signed with the token.
fn check_record_and_change(airtable: &CannedApp) {
    let created = only_call(airtable, "POST", TICKETS);
    let changed = only_call(airtable, "PATCH", TICKET);
    for call in [&created, &changed] {
        assert_eq!(
            call.header("authorization"),
            Some(format!("Bearer {TOKEN}").as_str())
        );
    }
    assert_eq!(
        created.json(),
        json!({ "fields": { "Name": "Printer offline", "Priority": "High" } })
    );
    assert_eq!(
        changed.json(),
        json!({ "fields": { "Status": "Done" }, "typecast": true })
    );
}

/// An Airtable stand-in that knows the token, answers a new record with
/// `record`, and takes any change.
async fn airtable_answering(record: Canned) -> CannedApp {
    CannedApp::start([
        (WHO, Canned::json(&json!({ "id": "usrTess" }))),
        (TICKETS, record),
        (
            TICKET,
            Canned::json(&json!({ "id": "recTicket42", "fields": { "Status": "Done" } })),
        ),
    ])
    .await
    .expect("the Airtable stand-in starts")
}

/// The standard deployment, its Airtable steps calling `airtable`.
fn profile(airtable: &CannedApp) -> Profile {
    Profile::standard().with("AIRTABLE_API_URL", &airtable.url())
}
