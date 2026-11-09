//! Google Calendar connected by signing in, and starting workflows: Tess
//! signs in at a stand-in for Google instead of pasting a client and a
//! grant, and Ann publishes a workflow that starts when the team calendar
//! changes and lists its events. Publishing opens a watch channel with the
//! registration's secret as its token; Google's notification of a change,
//! carrying that token, starts one run. A notification with another token,
//! and Google's first message on the channel, start nothing.

use ianua_scenarios::api::workflows::{self, ServiceDelivery};
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::{Graph, Trigger, Workflow};
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;
use serde_json::json;

use super::connect::{SignIn, path_of, runs_now, runs_started, signed_in};
use crate::support::{Action, action, drafted, ended, published, read};

/// The grant Google issues for Tess's sign-in: a sentence, so no scanner
/// takes it for a key.
const GRANT: &str = "acme google grant issued at sign in";

/// The platform's OAuth client at Google.
const CLIENT_ID: &str = "acme platform google client";

/// The client's secret.
const CLIENT_SECRET: &str = "acme platform google client secret words";

/// Where Google swaps codes and exchanges grants.
const TOKEN_PATH: &str = "/token";

/// Where a grant is proven: the account's calendars.
const CALENDARS: &str = "/calendar/v3/users/me/calendarList";

/// Where the watch channel is opened on the team calendar.
const WATCH: &str = "/calendar/v3/calendars/team@acme.example/events/watch";

/// Where the run lists the team calendar's events.
const EVENTS: &str = "/calendar/v3/calendars/team@acme.example/events";

/// Tess signs in at Google to connect the team's calendars, and the grant
/// Google issues is tried before it is kept. Ann publishes a workflow on
/// changes to the team calendar, which opens a watch channel there. Google
/// says the channel is open, which starts nothing; then that the calendar
/// changed, with the channel's token, which starts one run listing the
/// calendar's events. Mallory's notification with her own token is
/// refused. The grant is nowhere in the trail.
#[tokio::test]
async fn a_calendar_change_starts_the_workflow_signed_in_for() {
    let google = google().await;
    let stack = Stack::start(profile(&google))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connect_google(&world, &google).await;
    let workflow = publish_calendar_watch(&world, &account).await;
    let channel = registered_channel(&google);
    notify_channel(&stack, &channel).await;
    check_calendar_run(&world, &google, &workflow.id, &channel.token).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess connects Google's grant and the platform proves it by reading calendars.
async fn connect_google(world: &World<'_>, google: &CannedApp) -> String {
    let base = google.url().trim_end_matches('/').to_owned();
    let authorize = format!("{base}/o/oauth2/v2/auth");

    let account = signed_in(
        world,
        &SignIn {
            integration: "google-calendar",
            authorize: &authorize,
            client_id: CLIENT_ID,
            place: None,
        },
    )
    .await;
    assert_eq!(google.asked_for(CALENDARS), 1, "the grant was tried first");
    account
}

/// The published workflow watches the team calendar and lists its events after changes.
async fn publish_calendar_watch(world: &World<'_>, account: &str) -> Workflow {
    let list = action(
        Action {
            integration: "google-calendar",
            operation: "list-events",
        },
        account,
        "read",
        vec![("calendar", read("trigger.calendar"))],
    );
    let trigger = Trigger::Service {
        integration: "google-calendar".to_owned(),
        event: "calendar-changed".to_owned(),
        account_id: account.to_owned(),
        filters: [("calendar".to_owned(), "team@acme.example".to_owned())].into(),
    };
    let graph = Graph {
        nodes: vec![list],
        edges: vec![],
    };
    let draft = drafted(world, trigger, graph).await;
    published(world, &draft).await
}

/// The address and proof Google uses for its registered watch channel.
struct Channel {
    path: String,
    token: String,
    id: String,
}

impl Channel {
    /// Builds a notification for this registered channel with the chosen token and sequence.
    fn notice<'a>(&'a self, token: &'a str, state: &'a str, number: &'a str) -> Notice<'a> {
        Notice {
            token,
            channel: &self.id,
            state,
            number,
        }
    }
}

/// Publishing opens exactly one watch channel with its own token and identifier.
fn registered_channel(google: &CannedApp) -> Channel {
    let watches: Vec<_> = google
        .received()
        .into_iter()
        .filter(|call| call.path == WATCH)
        .collect();
    assert_eq!(watches.len(), 1, "publishing opened one channel");
    let channel = watches[0].json();
    let path = path_of(channel["address"].as_str().expect("the channel's address"));
    let token = channel["token"]
        .as_str()
        .expect("the channel's token")
        .to_owned();
    let id = channel["id"].as_str().expect("the channel's id").to_owned();
    Channel { path, token, id }
}

/// Sync is accepted, a wrong token is refused, and the authenticated change is accepted.
async fn notify_channel(stack: &Stack, channel: &Channel) {
    let google_client = Client::new(stack, "google").expect("Google's client");
    let mallory = Client::new(stack, "mallory").expect("Mallory's client");
    let opened = notified(
        &google_client,
        &channel.path,
        channel.notice(&channel.token, "sync", "1"),
    )
    .await;
    assert_eq!(opened.status(), Status::NO_CONTENT);
    notified(
        &mallory,
        &channel.path,
        channel.notice("mallory's own words", "exists", "2"),
    )
    .await
    .refused(Status::UNAUTHORIZED, "unauthenticated");
    let changed = notified(
        &google_client,
        &channel.path,
        channel.notice(&channel.token, "exists", "3"),
    )
    .await;
    assert_eq!(changed.status(), Status::NO_CONTENT);
}

/// Only the calendar change starts a run, and both secrets remain absent from the trail.
async fn check_calendar_run(world: &World<'_>, google: &CannedApp, workflow_id: &str, token: &str) {
    let runs = runs_started(world, workflow_id).await;
    assert_eq!(runs.len(), 1, "only the change started a run");
    ended(world, &runs[0].id, "succeeded").await;
    assert_eq!(google.asked_for(EVENTS), 1, "the run listed the events");
    assert_eq!(runs_now(world, workflow_id).await.len(), 1);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[GRANT, token]);
    }
}

/// The Google stand-in: it issues the grant and an hour's token, lists
/// calendars and events, and opens a channel.
async fn google() -> CannedApp {
    CannedApp::start([
        (
            TOKEN_PATH,
            Canned::json(&json!({
                "access_token": "an hour's token",
                "refresh_token": GRANT,
                "expires_in": 3599
            })),
        ),
        (CALENDARS, Canned::json(&json!({ "items": [] }))),
        (
            WATCH,
            Canned::json(&json!({ "resourceId": "res-1", "expiration": "1900000000000" })),
        ),
        (EVENTS, Canned::json(&json!({ "items": [] }))),
    ])
    .await
    .expect("the Google stand-in starts")
}

/// The standard deployment with the platform's Google client at `google`.
fn profile(google: &CannedApp) -> Profile {
    let base = google.url().trim_end_matches('/').to_owned();
    Profile::standard()
        .with("GOOGLE_CALENDAR_API_URL", &format!("{base}/calendar/v3/"))
        .with("GOOGLE_TOKEN_URL", &format!("{base}{TOKEN_PATH}"))
        .with("GOOGLE_CLIENT_ID", CLIENT_ID)
        .with("GOOGLE_CLIENT_SECRET", CLIENT_SECRET)
        .with("GOOGLE_AUTHORIZE_URL", &format!("{base}/o/oauth2/v2/auth"))
}

/// One notification as Google sends it.
struct Notice<'a> {
    /// The channel's token it carries.
    token: &'a str,
    /// The channel it comes from.
    channel: &'a str,
    /// `sync` when the channel opens, `exists` when the calendar changed.
    state: &'a str,
    /// Its number on the channel.
    number: &'a str,
}

/// `notice` sent to `path` as Google sends it, with no body.
async fn notified(client: &Client, path: &str, notice: Notice<'_>) -> Answer<String> {
    workflows::deliver_event(&ServiceDelivery {
        path,
        content_type: "application/json",
        headers: &[
            ("x-goog-channel-token", notice.token),
            ("x-goog-channel-id", notice.channel),
            ("x-goog-resource-state", notice.state),
            ("x-goog-message-number", notice.number),
        ],
        body: "",
    })
    .send_text(client)
    .await
}
