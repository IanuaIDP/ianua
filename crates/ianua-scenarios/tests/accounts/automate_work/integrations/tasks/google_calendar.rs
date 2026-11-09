//! Google Calendar as a workflow step: Tess connects the team's OAuth
//! grant, which is exchanged for a token and checked first, and Ann
//! publishes a workflow that books the incident review. A stand-in for
//! Google shows what arrived: the grant only at the token address, and
//! the event at the calendar signed with the token it issued.

use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::{Graph, Trigger};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{Action, account_at, action, drafted, ended, published, started, written};

/// The grant's refresh token: a sentence, so no scanner takes it for a
/// key.
const GRANT: &str = "acme google refresh grant for workflows";

/// Where a grant is exchanged for a token.
const TOKEN: &str = "/token";

/// The token the stand-in issues for the grant.
const ISSUED: &str = "acme short calendar token";

/// Where Google lists the account's calendars, which proves a grant.
const CALENDARS: &str = "/calendar/v3/users/me/calendarList";

/// Where an event is booked in the account's own calendar.
const EVENTS: &str = "/calendar/v3/calendars/primary/events";

/// Tess connects the grant: it is exchanged for a token, which lists the
/// calendars. Ann publishes a workflow booking the incident review with
/// Bob invited. Tess runs it: the grant is exchanged again, the event
/// reaches the calendar signed with the issued token and its times nested
/// where Google reads them, and the run succeeds. The grant went only to
/// the token address and is nowhere in the trail.
#[tokio::test]
async fn a_run_books_an_event_with_a_token_the_grant_was_exchanged_for() {
    let google = google().await;
    let profile = Profile::standard()
        .with(
            "GOOGLE_CALENDAR_API_URL",
            &format!("{}/calendar/v3/", google.url()),
        )
        .with("GOOGLE_TOKEN_URL", &format!("{}{TOKEN}", google.url()));
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connect_grant(&world, &google).await;
    let draft = drafted(&world, Trigger::Manual, booking_graph(&account)).await;
    let workflow = published(&world, &draft).await;
    let decided = started(&world, &workflow).await;
    ended(&world, &decided.execution_id, "succeeded").await;
    check_booking(&google);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[GRANT, ISSUED]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Google exchanges the grant, lists calendars and accepts the event booking.
async fn google() -> CannedApp {
    CannedApp::start([
        (
            TOKEN,
            Canned::json(&json!({ "access_token": ISSUED, "expires_in": 3599 })),
        ),
        (CALENDARS, Canned::json(&json!({ "items": [] }))),
        (
            EVENTS,
            Canned::json(&json!({ "id": "e1", "status": "confirmed" })),
        ),
    ])
    .await
    .expect("the Google stand-in starts")
}

/// Connecting the tenant's grant first proves it by listing its calendars.
async fn connect_grant(world: &World<'_>, google: &CannedApp) -> String {
    let credential = json!({
        "client_id": "acme calendar app",
        "client_secret": "acme calendar app words",
        "refresh_token": GRANT
    })
    .to_string();
    let account = account_at(world, "google-calendar", &credential).await;
    assert_eq!(
        google.asked_for(CALENDARS),
        1,
        "Google was asked about the grant"
    );
    account
}

/// The booking step invites Bob to the incident review at the specified local times.
fn booking_graph(account: &str) -> Graph {
    let book = action(
        Action {
            integration: "google-calendar",
            operation: "create-event",
        },
        account,
        "communicate",
        vec![
            ("calendar", written("primary")),
            ("summary", written("Incident review")),
            ("start", written("2026-11-03T09:00:00+01:00")),
            ("end", written("2026-11-03T09:30:00+01:00")),
            ("attendees", written(json!([{ "email": "bob@acme.test" }]))),
        ],
    );
    Graph {
        edges: vec![],
        nodes: vec![book],
    }
}

/// Google receives a booking with nested dates, signed with the token kept
/// since connecting, and the grant reaches only its token endpoint.
fn check_booking(google: &CannedApp) {
    let received = google.received();
    assert_eq!(
        google.asked_for(TOKEN),
        1,
        "the grant was exchanged once to connect, and the run reused the token kept from it"
    );
    let booked = received
        .iter()
        .find(|call| call.path == EVENTS)
        .expect("the event reached the calendar");
    assert_eq!(
        booked.header("authorization"),
        Some(format!("Bearer {ISSUED}").as_str())
    );
    assert_eq!(
        booked.json(),
        json!({
            "summary": "Incident review",
            "start": { "dateTime": "2026-11-03T09:00:00+01:00" },
            "end": { "dateTime": "2026-11-03T09:30:00+01:00" },
            "attendees": [{ "email": "bob@acme.test" }]
        })
    );
    for call in received.iter().filter(|call| call.path != TOKEN) {
        no_secret_leaked(&call.body, &[GRANT]);
    }
}
