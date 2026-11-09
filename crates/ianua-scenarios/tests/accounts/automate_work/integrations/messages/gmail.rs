//! Gmail as a workflow step: Tess connects the team's OAuth grant, which is
//! exchanged for a token that reads the mailbox's profile first, and Ann
//! publishes a workflow that mails the build report and stars the sent
//! message. A stand-in for Google shows what arrived: the grant only at the
//! token address, the email whole as Gmail takes it, a message in `raw`,
//! and the label on the message Gmail gave its id, both signed with the
//! token kept from connecting. A grant Google refuses is never connected,
//! and an email Gmail refuses fails the run.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
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
const GRANT: &str = "acme gmail grant for workflows";

/// The token Google issues for the grant.
const ISSUED: &str = "acme short gmail token";

/// Where a grant is exchanged for a token.
const TOKEN: &str = "/token";

/// Where Gmail tells the mailbox's address, which proves a grant.
const PROFILE: &str = "/gmail/v1/users/me/profile";

/// Where an email is sent from the account's own address.
const SEND: &str = "/gmail/v1/users/me/messages/send";

/// Where the label goes: on the message Gmail gave the id msg-77.
const MODIFY: &str = "/gmail/v1/users/me/messages/msg-77/modify";

/// What the report says.
const TEXT: &str = "The nightly build failed at the database step.";

/// Tess connects the grant: it is exchanged once for a token, which reads
/// the mailbox's profile. Ann publishes a workflow mailing the build report
/// to Ann and Bob and starring the message Gmail answered with. Tess runs
/// it: Gmail receives the whole email in `raw` and the label, both signed
/// with the token kept from connecting, so the token address is not asked
/// again. The grant is nowhere in the trail.
#[tokio::test]
async fn a_run_mails_the_report_and_stars_it() {
    let google = google_answering(Canned::json(
        &json!({ "id": "msg-77", "threadId": "thread-7" }),
    ))
    .await;
    let stack = Stack::start(profile(&google))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "gmail", &grant()).await;
    let probe = only_call(&google, "GET", PROFILE);
    assert_eq!(
        probe.header("authorization"),
        Some(format!("Bearer {ISSUED}").as_str())
    );
    ran(&world, report_graph(&account), "succeeded").await;
    assert_eq!(
        google.asked_for(TOKEN),
        1,
        "the run reused the token kept from connecting"
    );
    check_report(&google);
    check_star(&google);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[GRANT, ISSUED]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Gmail refuses the email with 400, as for an address it cannot read.
/// The send step and the run fail after one request, and nothing is
/// starred.
#[tokio::test]
async fn an_email_gmail_refuses_fails_the_run() {
    let google = google_answering(Canned::refusing(400)).await;
    let stack = Stack::start(profile(&google))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "gmail", &grant()).await;

    let run = ran(&world, report_graph(&account), "failed").await;

    failed_step(&run, "gmail-send-message");
    assert_eq!(google.asked_for(SEND), 1, "a refusal is not tried again");
    assert_eq!(google.asked_for(MODIFY), 0, "nothing was starred");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Google's token address refuses Tess's grant, as for one that was
/// revoked: no account is connected, and Gmail is never reached.
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
            integration: "gmail",
            credential: &offered,
        },
    )
    .await;

    assert_eq!(google.asked_for(TOKEN), 1, "the grant was offered once");
    assert_eq!(google.asked_for(PROFILE), 0, "Gmail was never reached");
    stack.stop().await.expect("the stack stops cleanly");
}

/// The workflow mails the build report to Ann and Bob and stars the
/// message Gmail gave back.
fn report_graph(account: &str) -> Graph {
    let send = action(
        Action {
            integration: "gmail",
            operation: "send-message",
        },
        account,
        "communicate",
        vec![
            ("to", written(json!(["ann@acme.test", "bob@acme.test"]))),
            ("subject", written("Nightly build")),
            ("text", written(TEXT)),
        ],
    );
    let star = action(
        Action {
            integration: "gmail",
            operation: "change-labels",
        },
        account,
        "write",
        vec![
            ("message", read("gmail-send-message.json.id")),
            ("add", written(json!(["STARRED"]))),
        ],
    );
    chain(vec![send, star])
}

/// Gmail received the report as one RFC 5322 message, base64url in `raw`:
/// both recipients in one `To`, the subject, and the text in base64.
fn check_report(google: &CannedApp) {
    let sent = only_call(google, "POST", SEND);
    assert_eq!(
        sent.header("authorization"),
        Some(format!("Bearer {ISSUED}").as_str())
    );
    let raw = sent.json()["raw"]
        .as_str()
        .map(str::to_owned)
        .expect("the email is in raw");
    let message = String::from_utf8(URL_SAFE_NO_PAD.decode(raw).expect("raw is base64url"))
        .expect("the message is text");
    let (head, body) = message
        .split_once("\r\n\r\n")
        .expect("the headers end before the body");
    let headers: Vec<&str> = head.split("\r\n").collect();
    assert!(
        headers.contains(&"To: ann@acme.test, bob@acme.test"),
        "{head}"
    );
    assert!(headers.contains(&"Subject: Nightly build"), "{head}");
    assert!(
        headers.contains(&"Content-Transfer-Encoding: base64"),
        "{head}"
    );
    assert_eq!(body.replace("\r\n", ""), STANDARD.encode(TEXT));
}

/// Gmail received the star on the message it numbered msg-77.
fn check_star(google: &CannedApp) {
    let starred = only_call(google, "POST", MODIFY);
    assert_eq!(
        starred.header("authorization"),
        Some(format!("Bearer {ISSUED}").as_str())
    );
    assert_eq!(starred.json(), json!({ "addLabelIds": ["STARRED"] }));
}

/// A Google stand-in that exchanges the grant for [`ISSUED`], tells the
/// mailbox's address, answers a sent email with `sent`, and takes any
/// label.
async fn google_answering(sent: Canned) -> CannedApp {
    CannedApp::start([
        (
            TOKEN,
            Canned::json(&json!({ "access_token": ISSUED, "expires_in": 3599 })),
        ),
        (
            PROFILE,
            Canned::json(&json!({ "emailAddress": "ops@acme.test" })),
        ),
        (SEND, sent),
        (
            MODIFY,
            Canned::json(&json!({ "id": "msg-77", "labelIds": ["STARRED", "SENT"] })),
        ),
    ])
    .await
    .expect("the Google stand-in starts")
}

/// The standard deployment, Gmail and Google's token address both at
/// `google`.
fn profile(google: &CannedApp) -> Profile {
    Profile::standard()
        .with("GMAIL_API_URL", &format!("{}/gmail/v1/", google.url()))
        .with("GOOGLE_TOKEN_URL", &format!("{}{TOKEN}", google.url()))
}

/// The team's OAuth client and its grant, as the account holds them.
fn grant() -> String {
    json!({
        "client_id": "acme gmail app",
        "client_secret": "acme gmail app words",
        "refresh_token": GRANT
    })
    .to_string()
}
