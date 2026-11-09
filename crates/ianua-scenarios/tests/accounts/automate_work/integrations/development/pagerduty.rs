//! PagerDuty as a workflow step: Tess connects the team's account-wide API
//! key with the person its changes are made for, which PagerDuty is asked
//! about first, and Ann publishes a workflow that opens an incident and
//! adds a note to it. A stand-in for PagerDuty's API shows what arrived:
//! the key after `Token token=`, PagerDuty's versioned media type, the
//! person in `From`, and the note on the incident PagerDuty gave its id. A
//! user's own key sends no `From`; a key PagerDuty refuses is never
//! connected, and an incident PagerDuty refuses fails the run.

use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::Graph;
use ianua_scenarios::world::World;
use serde_json::json;

use crate::integrations::calls::{Offered, chain, failed_step, never_connected, only_call, ran};
use crate::support::{Action, account_at, action, read, written};

/// The team's API key: a sentence, so no scanner takes it for a key.
const KEY: &str = "acme pagerduty key for workflows";

/// The person at PagerDuty an account-wide key's changes are made for.
const ACTING_FOR: &str = "tess@acme.test";

/// Where PagerDuty says what a key may do, which proves it.
const ABILITIES: &str = "/abilities";

/// Where an incident is opened.
const INCIDENTS: &str = "/incidents";

/// Where the note goes: on the incident PagerDuty gave the id PINC0042.
const NOTES: &str = "/incidents/PINC0042/notes";

/// PagerDuty's media type, version 2, which every call asks for.
const MEDIA_TYPE: &str = "application/vnd.pagerduty+json;version=2";

/// Tess connects the account-wide key with herself as the person it acts
/// for, and PagerDuty is asked about the key once. Ann publishes a
/// workflow opening a high-urgency incident on the checkout service and
/// adding a note to it by the id PagerDuty answered with. Tess runs it:
/// PagerDuty receives both, each with the key after `Token token=` and
/// Tess in `From`, and the run succeeds. The key is nowhere in the trail.
#[tokio::test]
async fn a_run_opens_an_incident_and_notes_it_on_behalf_of_tess() {
    let pagerduty = pagerduty_answering(Canned::json(
        &json!({ "incident": { "id": "PINC0042", "number": 42 } }),
    ))
    .await;
    let stack = Stack::start(profile(&pagerduty))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let credential = json!({ "token": KEY, "from": ACTING_FOR }).to_string();
    let account = account_at(&world, "pagerduty", &credential).await;
    let asked = only_call(&pagerduty, "GET", ABILITIES);
    assert_eq!(
        asked.header("authorization"),
        Some(format!("Token token={KEY}").as_str())
    );
    ran(&world, incident_graph(&account), "succeeded").await;
    check_incident_and_note(&pagerduty);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[KEY]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess connects her own user key, which names nobody to act for.
/// PagerDuty refuses the incident with 400, as for a service it does not
/// have: the incident step and the run fail after one request, which
/// carried no `From`, and no note is added.
#[tokio::test]
async fn an_incident_pagerduty_refuses_fails_the_run() {
    let pagerduty = pagerduty_answering(Canned::refusing(400)).await;
    let stack = Stack::start(profile(&pagerduty))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "pagerduty", KEY).await;

    let run = ran(&world, incident_graph(&account), "failed").await;

    failed_step(&run, "pagerduty-create-incident");
    let refused = only_call(&pagerduty, "POST", INCIDENTS);
    assert_eq!(
        refused.header("from"),
        None,
        "a user's own key acts for nobody else"
    );
    assert_eq!(
        pagerduty.asked_for(NOTES),
        0,
        "nothing was noted on a missing incident"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// PagerDuty does not know Tess's mistyped key: asked once, it answers
/// 401, and no account is connected.
#[tokio::test]
async fn a_key_pagerduty_refuses_is_never_connected() {
    let pagerduty = CannedApp::start([(ABILITIES, Canned::refusing(401))])
        .await
        .expect("the PagerDuty stand-in starts");
    let stack = Stack::start(profile(&pagerduty))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let offered = Offered {
        integration: "pagerduty",
        credential: "a mistyped pagerduty key",
    };

    never_connected(&world, offered).await;

    assert_eq!(
        pagerduty.asked_for(ABILITIES),
        1,
        "PagerDuty was asked about the key"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The workflow opens an incident on the checkout service and notes it by
/// the id PagerDuty gave back.
fn incident_graph(account: &str) -> Graph {
    let open = action(
        Action {
            integration: "pagerduty",
            operation: "create-incident",
        },
        account,
        "communicate",
        vec![
            ("service", written("PSVC001")),
            ("title", written("Checkout is failing")),
            ("urgency", written("high")),
            ("details", written("Payments time out since 02:10.")),
        ],
    );
    let note = action(
        Action {
            integration: "pagerduty",
            operation: "add-note",
        },
        account,
        "write",
        vec![
            (
                "incident",
                read("pagerduty-create-incident.json.incident.id"),
            ),
            ("content", written("Rolled back the payments release.")),
        ],
    );
    chain(vec![open, note])
}

/// PagerDuty received the incident and the note on it, each signed with
/// the key, asking for version 2 and made on Tess's behalf.
fn check_incident_and_note(pagerduty: &CannedApp) {
    let incident = only_call(pagerduty, "POST", INCIDENTS);
    let note = only_call(pagerduty, "POST", NOTES);
    for call in [&incident, &note] {
        assert_eq!(
            call.header("authorization"),
            Some(format!("Token token={KEY}").as_str())
        );
        assert_eq!(call.header("accept"), Some(MEDIA_TYPE));
        assert_eq!(call.header("from"), Some(ACTING_FOR));
    }
    assert_eq!(
        incident.json(),
        json!({ "incident": {
            "type": "incident",
            "title": "Checkout is failing",
            "urgency": "high",
            "service": { "id": "PSVC001", "type": "service_reference" },
            "body": { "type": "incident_body", "details": "Payments time out since 02:10." }
        } })
    );
    assert_eq!(
        note.json(),
        json!({ "note": { "content": "Rolled back the payments release." } })
    );
}

/// A PagerDuty stand-in that takes the key, answers a new incident with
/// `incident`, and takes any note.
async fn pagerduty_answering(incident: Canned) -> CannedApp {
    CannedApp::start([
        (ABILITIES, Canned::json(&json!({ "abilities": ["teams"] }))),
        (INCIDENTS, incident),
        (NOTES, Canned::json(&json!({ "note": { "id": "PNOTE1" } }))),
    ])
    .await
    .expect("the PagerDuty stand-in starts")
}

/// The standard deployment, its PagerDuty steps calling `pagerduty`.
fn profile(pagerduty: &CannedApp) -> Profile {
    Profile::standard().with("PAGERDUTY_API_URL", &pagerduty.url())
}
