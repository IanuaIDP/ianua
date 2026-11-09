//! Microsoft Teams as a workflow step: Tess connects the team's Entra app
//! and its delegated grant, which is exchanged at Microsoft's token address
//! for an hour's token that proves the account first, and Ann publishes a
//! workflow that posts to the Ops channel and replies in its thread. A
//! stand-in for Microsoft shows what arrived: the grant only at the token
//! address, and both messages at Graph signed with the token kept from
//! connecting. A grant Microsoft refuses is never connected, and a message
//! Graph refuses fails the run.

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
const GRANT: &str = "acme microsoft refresh grant for workflows";

/// The refresh token Microsoft hands back in the old one's place.
const RENEWED: &str = "acme microsoft grant renewed";

/// The hour's token Microsoft issues for the grant.
const ISSUED: &str = "acme hour long graph token";

/// Where a grant is exchanged for a token.
const TOKEN: &str = "/token";

/// Where Graph says whose a token is, which proves a grant.
const ME: &str = "/v1.0/me";

/// Where messages go in the Ops channel of Acme's team.
const MESSAGES: &str = "/v1.0/teams/team-acme/channels/19:ops@thread.tacv2/messages";

/// Where the reply goes: in the thread of the message Graph gave the id
/// 1700000000001.
const REPLIES: &str =
    "/v1.0/teams/team-acme/channels/19:ops@thread.tacv2/messages/1700000000001/replies";

/// Tess connects the grant: it is exchanged once for a token, which Graph
/// takes for her profile. Ann publishes a workflow posting the build news
/// to the Ops channel and replying in its thread by the id Graph gave the
/// message. Tess runs it: Graph receives both, signed with the token kept
/// from connecting, so the token address is not asked again; the grant
/// went only to the token address and is nowhere in the trail.
#[tokio::test]
async fn a_run_posts_to_a_channel_and_replies_with_the_token_kept() {
    let microsoft = microsoft_answering(Canned::json(&json!({ "id": "1700000000001" }))).await;
    let stack = Stack::start(profile(&microsoft))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "teams", &grant()).await;
    check_exchange(&microsoft);
    ran(&world, message_graph(&account), "succeeded").await;
    assert_eq!(
        microsoft.asked_for(TOKEN),
        1,
        "the run reused the token kept from connecting"
    );
    check_messages(&microsoft);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[GRANT, RENEWED, ISSUED]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Graph refuses the post with 403, as for a channel the account cannot
/// write in. The post step and the run fail after one request, and no
/// reply is sent.
#[tokio::test]
async fn a_message_graph_refuses_fails_the_run() {
    let microsoft = microsoft_answering(Canned::refusing(403)).await;
    let stack = Stack::start(profile(&microsoft))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "teams", &grant()).await;

    let run = ran(&world, message_graph(&account), "failed").await;

    failed_step(&run, "teams-post-message");
    assert_eq!(
        microsoft.asked_for(MESSAGES),
        1,
        "a refusal is not tried again"
    );
    assert_eq!(
        microsoft.asked_for(REPLIES),
        0,
        "nothing was said in a missing thread"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Microsoft's token address refuses Tess's grant, as for one that was
/// revoked: no account is connected, and Graph is never reached.
#[tokio::test]
async fn a_grant_microsoft_refuses_is_never_connected() {
    let microsoft = CannedApp::start([(TOKEN, Canned::refusing(400))])
        .await
        .expect("the Microsoft stand-in starts");
    let stack = Stack::start(profile(&microsoft))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let offered = grant();

    never_connected(
        &world,
        Offered {
            integration: "teams",
            credential: &offered,
        },
    )
    .await;

    assert_eq!(microsoft.asked_for(TOKEN), 1, "the grant was offered once");
    assert_eq!(microsoft.asked_for(ME), 0, "Graph was never reached");
    stack.stop().await.expect("the stack stops cleanly");
}

/// The grant was exchanged once, as a form naming the app and the refresh
/// token, and Graph was asked for the profile with the token issued.
fn check_exchange(microsoft: &CannedApp) {
    let exchange = only_call(microsoft, "POST", TOKEN);
    let form: Vec<(String, String)> = url::form_urlencoded::parse(exchange.body.as_bytes())
        .into_owned()
        .collect();
    assert!(form.contains(&("grant_type".to_owned(), "refresh_token".to_owned())));
    assert!(form.contains(&("refresh_token".to_owned(), GRANT.to_owned())));
    let asked = only_call(microsoft, "GET", ME);
    assert_eq!(
        asked.header("authorization"),
        Some(format!("Bearer {ISSUED}").as_str())
    );
}

/// The workflow posts to the Ops channel and replies in the thread of the
/// message Graph gave back.
fn message_graph(account: &str) -> Graph {
    let post = action(
        Action {
            integration: "teams",
            operation: "post-message",
        },
        account,
        "communicate",
        vec![
            ("team", written("team-acme")),
            ("channel", written("19:ops@thread.tacv2")),
            ("text", written("The nightly build failed")),
        ],
    );
    let reply = action(
        Action {
            integration: "teams",
            operation: "reply-to-message",
        },
        account,
        "communicate",
        vec![
            ("team", written("team-acme")),
            ("channel", written("19:ops@thread.tacv2")),
            ("message", read("teams-post-message.json.id")),
            ("text", written("Rolled back; looking into it.")),
        ],
    );
    chain(vec![post, reply])
}

/// Graph received the message and the reply in its thread, each signed
/// with the token kept from connecting and its text where Graph reads it;
/// neither carried the grant.
fn check_messages(microsoft: &CannedApp) {
    let message = only_call(microsoft, "POST", MESSAGES);
    let reply = only_call(microsoft, "POST", REPLIES);
    for call in [&message, &reply] {
        assert_eq!(
            call.header("authorization"),
            Some(format!("Bearer {ISSUED}").as_str())
        );
        no_secret_leaked(&call.body, &[GRANT, RENEWED]);
    }
    assert_eq!(
        message.json(),
        json!({ "body": { "content": "The nightly build failed" } })
    );
    assert_eq!(
        reply.json(),
        json!({ "body": { "content": "Rolled back; looking into it." } })
    );
}

/// A Microsoft stand-in that exchanges the grant for [`ISSUED`] and a
/// renewed grant, tells Graph's profile, answers a channel message with
/// `message`, and takes any reply.
async fn microsoft_answering(message: Canned) -> CannedApp {
    CannedApp::start([
        (
            TOKEN,
            Canned::json(&json!({
                "access_token": ISSUED,
                "refresh_token": RENEWED,
                "expires_in": 3599
            })),
        ),
        (ME, Canned::json(&json!({ "id": "tess" }))),
        (MESSAGES, message),
        (REPLIES, Canned::json(&json!({ "id": "1700000000002" }))),
    ])
    .await
    .expect("the Microsoft stand-in starts")
}

/// The standard deployment, Graph and Microsoft's token address both at
/// `microsoft`.
fn profile(microsoft: &CannedApp) -> Profile {
    Profile::standard()
        .with("TEAMS_API_URL", &format!("{}/v1.0/", microsoft.url()))
        .with(
            "MICROSOFT_TOKEN_URL",
            &format!("{}{TOKEN}", microsoft.url()),
        )
}

/// The team's Entra app and its grant, as the account holds them.
fn grant() -> String {
    json!({
        "client_id": "acme teams app",
        "client_secret": "acme teams app words",
        "refresh_token": GRANT
    })
    .to_string()
}
