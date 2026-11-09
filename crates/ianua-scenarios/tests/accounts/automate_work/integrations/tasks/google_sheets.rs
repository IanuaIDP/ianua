//! Google Sheets as a workflow step: Tess connects the team's OAuth grant,
//! which is exchanged for a token that reads a sample spreadsheet first,
//! and Ann publishes a workflow that creates the incident log and adds a
//! tab for the month. A stand-in for Google shows what arrived: the grant
//! only at the token address, the new spreadsheet's title, and the tab as
//! an `addSheet` request in a batch update of the spreadsheet Google gave
//! its id, both signed with the token kept from connecting. A grant Google
//! refuses is never connected, and a tab Google refuses fails the run.

use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::Graph;
use ianua_scenarios::world::World;
use serde_json::json;

use crate::integrations::calls::{Offered, chain, failed_step, never_connected, only_call, ran};
use crate::support::{Action, account_at, action, read, written};

/// The grant's refresh token: a sentence, so no scanner takes it for a
/// key.
const GRANT: &str = "acme google sheets grant for workflows";

/// The token Google issues for the grant.
const ISSUED: &str = "acme short sheets token";

/// Where a grant is exchanged for a token.
const TOKEN: &str = "/token";

/// The public sample spreadsheet any token with the spreadsheets scope
/// may read, which proves a grant.
const SAMPLE: &str = "/v4/spreadsheets/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms";

/// Where a spreadsheet is created.
const SPREADSHEETS: &str = "/v4/spreadsheets";

/// Where the tab is added: a batch update of the spreadsheet Google gave
/// the id log-2026.
const BATCH: &str = "/v4/spreadsheets/log-2026:batchUpdate";

/// Tess connects the grant: it is exchanged once for a token, which reads
/// the sample spreadsheet. Ann publishes a workflow creating the incident
/// log and adding a November tab to the spreadsheet Google answered with.
/// Tess runs it: Google receives the title and the `addSheet` request,
/// both signed with the token kept from connecting, so the token address
/// is not asked again. The grant is nowhere in the trail.
#[tokio::test]
async fn a_run_creates_a_spreadsheet_and_adds_a_tab_to_it() {
    let google = google_answering(Canned::json(
        &json!({ "spreadsheetId": "log-2026", "replies": [{}] }),
    ))
    .await;
    let stack = Stack::start(profile(&google))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "google-sheets", &grant()).await;
    let probe = only_call(&google, "GET", SAMPLE);
    assert_eq!(
        probe.header("authorization"),
        Some(format!("Bearer {ISSUED}").as_str())
    );
    ran(&world, log_graph(&account), "succeeded").await;
    assert_eq!(
        google.asked_for(TOKEN),
        1,
        "the run reused the token kept from connecting"
    );
    check_spreadsheet_and_tab(&google);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[GRANT, ISSUED]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Google refuses the tab with 400, as for a name the spreadsheet already
/// has. The spreadsheet was created, the tab step and the run fail after
/// one request.
#[tokio::test]
async fn a_tab_google_refuses_fails_the_run() {
    let google = google_answering(Canned::refusing(400)).await;
    let stack = Stack::start(profile(&google))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "google-sheets", &grant()).await;

    let run = ran(&world, log_graph(&account), "failed").await;

    failed_step(&run, "google-sheets-add-tab");
    assert_eq!(
        google.asked_for(SPREADSHEETS),
        1,
        "the spreadsheet was created"
    );
    assert_eq!(google.asked_for(BATCH), 1, "a refusal is not tried again");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Google's token address refuses Tess's grant, as for one that was
/// revoked: no account is connected, and Sheets is never reached.
#[tokio::test]
async fn a_grant_google_refuses_is_never_connected() {
    let google = CannedApp::start([(TOKEN, Canned::refusing(400))])
        .await
        .expect("the Google stand-in starts");
    let stack = Stack::start(profile(&google))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let offered = grant();

    never_connected(
        &world,
        Offered {
            integration: "google-sheets",
            credential: &offered,
        },
    )
    .await;

    assert_eq!(google.asked_for(TOKEN), 1, "the grant was offered once");
    assert_eq!(google.asked_for(SAMPLE), 0, "Sheets was never reached");
    stack.stop().await.expect("the stack stops cleanly");
}

/// The workflow creates the incident log and adds a November tab to the
/// spreadsheet Google gave back.
fn log_graph(account: &str) -> Graph {
    let create = action(
        Action {
            integration: "google-sheets",
            operation: "create-spreadsheet",
        },
        account,
        "write",
        vec![("title", written("Incident log 2026"))],
    );
    let tab = action(
        Action {
            integration: "google-sheets",
            operation: "add-tab",
        },
        account,
        "write",
        vec![
            (
                "spreadsheet",
                read("google-sheets-create-spreadsheet.json.spreadsheetId"),
            ),
            ("title", written("November")),
        ],
    );
    chain(vec![create, tab])
}

/// Google received the spreadsheet's title and the tab as one `addSheet`
/// request, both signed with the token kept from connecting.
fn check_spreadsheet_and_tab(google: &CannedApp) {
    let created = only_call(google, "POST", SPREADSHEETS);
    let tab = only_call(google, "POST", BATCH);
    for call in [&created, &tab] {
        assert_eq!(
            call.header("authorization"),
            Some(format!("Bearer {ISSUED}").as_str())
        );
        no_secret_leaked(&call.body, &[GRANT]);
    }
    assert_eq!(
        created.json(),
        json!({ "properties": { "title": "Incident log 2026" } })
    );
    assert_eq!(
        tab.json(),
        json!({ "requests": [{ "addSheet": { "properties": { "title": "November" } } }] })
    );
}

/// A Google stand-in that exchanges the grant for [`ISSUED`], shows the
/// sample spreadsheet, creates the incident log and answers the batch
/// update with `batch`.
async fn google_answering(batch: Canned) -> CannedApp {
    CannedApp::start([
        (
            TOKEN,
            Canned::json(&json!({ "access_token": ISSUED, "expires_in": 3599 })),
        ),
        (SAMPLE, Canned::json(&json!({ "spreadsheetId": "sample" }))),
        (
            SPREADSHEETS,
            Canned::json(&json!({ "spreadsheetId": "log-2026" })),
        ),
        (BATCH, batch),
    ])
    .await
    .expect("the Google stand-in starts")
}

/// The standard deployment, Sheets and Google's token address both at
/// `google`.
fn profile(google: &CannedApp) -> Profile {
    Profile::standard()
        .with("GOOGLE_SHEETS_API_URL", &format!("{}/v4/", google.url()))
        .with("GOOGLE_TOKEN_URL", &format!("{}{TOKEN}", google.url()))
}

/// The team's OAuth client and its grant, as the account holds them.
fn grant() -> String {
    json!({
        "client_id": "acme sheets app",
        "client_secret": "acme sheets app words",
        "refresh_token": GRANT
    })
    .to_string()
}
