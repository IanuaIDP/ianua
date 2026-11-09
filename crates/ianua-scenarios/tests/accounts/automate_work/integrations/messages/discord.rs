//! Discord as a workflow step: Tess connects the team bot's token, which
//! Discord is asked about first, and Ann publishes a workflow that posts
//! to the ops channel and starts a thread from the message. A stand-in for
//! Discord's API shows what arrived: the token after `Bot `, the bot's own
//! user agent, a message that pings nobody, and the thread on the message
//! Discord gave its id. The server Tess picked only to fill the channel
//! picker is never sent. A token Discord refuses is never connected, and a
//! message Discord refuses fails the run.

use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::Graph;
use ianua_scenarios::world::World;
use serde_json::json;

use crate::integrations::calls::{Offered, chain, failed_step, never_connected, only_call, ran};
use crate::support::{Action, account_at, action, read, written};

/// The bot's token: a sentence, so no scanner takes it for a key.
const TOKEN: &str = "acme discord bot token for workflows";

/// Where Discord says which bot a token is.
const ME: &str = "/users/@me";

/// Where messages go in the ops channel.
const MESSAGES: &str = "/channels/1100000000000000001/messages";

/// Where the thread starts: from the message Discord gave the id
/// 1200000000000000001.
const THREADS: &str = "/channels/1100000000000000001/messages/1200000000000000001/threads";

/// The server Tess picks to fill the channel picker, which Discord is
/// never told.
const SERVER: &str = "1000000000000000042";

/// Tess connects the bot's token, which Discord is asked about once. Ann
/// publishes a workflow posting the build news to the ops channel, picked
/// from Acme's server, and starting a thread from that message. Tess runs
/// it: Discord receives the message, pinging nobody, and the thread on the
/// message it numbered, each signed `Bot` with the token; the server
/// reaches Discord nowhere. The token is nowhere in the trail.
#[tokio::test]
async fn a_run_posts_a_message_and_starts_a_thread_from_it() {
    let discord = discord_answering(Canned::json(&json!({
        "id": "1200000000000000001",
        "channel_id": "1100000000000000001"
    })))
    .await;
    let stack = Stack::start(profile(&discord))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "discord", TOKEN).await;
    let asked = only_call(&discord, "GET", ME);
    assert_eq!(
        asked.header("authorization"),
        Some(format!("Bot {TOKEN}").as_str())
    );
    ran(&world, message_graph(&account), "succeeded").await;
    check_message_and_thread(&discord);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[TOKEN]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Discord refuses the message with 403, as for a channel the bot cannot
/// see. The post step and the run fail after one request, and no thread
/// is started.
#[tokio::test]
async fn a_message_discord_refuses_fails_the_run() {
    let discord = discord_answering(Canned::refusing(403)).await;
    let stack = Stack::start(profile(&discord))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "discord", TOKEN).await;

    let run = ran(&world, message_graph(&account), "failed").await;

    failed_step(&run, "discord-post-message");
    assert_eq!(
        discord.asked_for(MESSAGES),
        1,
        "a refusal is not tried again"
    );
    assert_eq!(
        discord.asked_for(THREADS),
        0,
        "no thread on a missing message"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Discord does not know Tess's mistyped token: asked once, it answers
/// 401, and no account is connected.
#[tokio::test]
async fn a_token_discord_refuses_is_never_connected() {
    let discord = CannedApp::start([(ME, Canned::refusing(401))])
        .await
        .expect("the Discord stand-in starts");
    let stack = Stack::start(profile(&discord))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let offered = Offered {
        integration: "discord",
        credential: "a mistyped discord token",
    };

    never_connected(&world, offered).await;

    assert_eq!(
        discord.asked_for(ME),
        1,
        "Discord was asked about the token"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The workflow posts to the ops channel, picked from Acme's server, and
/// starts a thread from the message Discord gave back.
fn message_graph(account: &str) -> Graph {
    let post = action(
        Action {
            integration: "discord",
            operation: "post-message",
        },
        account,
        "communicate",
        vec![
            ("server", written(SERVER)),
            ("channel", written("1100000000000000001")),
            ("content", written("The nightly build failed @everyone")),
        ],
    );
    let thread = action(
        Action {
            integration: "discord",
            operation: "start-thread",
        },
        account,
        "write",
        vec![
            ("channel", written("1100000000000000001")),
            ("message", read("discord-post-message.json.id")),
            ("name", written("Nightly build")),
        ],
    );
    chain(vec![post, thread])
}

/// Discord received the message, its mentions pinging nobody, and the
/// thread on it, each signed `Bot` with the token under the bot's own user
/// agent, and the server nowhere.
fn check_message_and_thread(discord: &CannedApp) {
    let message = only_call(discord, "POST", MESSAGES);
    let thread = only_call(discord, "POST", THREADS);
    for call in [&message, &thread] {
        assert_eq!(
            call.header("authorization"),
            Some(format!("Bot {TOKEN}").as_str())
        );
        assert!(
            call.header("user-agent")
                .is_some_and(|agent| agent.starts_with("DiscordBot (")),
            "Discord is told the bot's own user agent"
        );
        assert!(!call.body.contains(SERVER), "the server stayed home");
    }
    assert_eq!(
        message.json(),
        json!({
            "content": "The nightly build failed @everyone",
            "allowed_mentions": { "parse": [] }
        })
    );
    assert_eq!(thread.json(), json!({ "name": "Nightly build" }));
}

/// A Discord stand-in that knows the token, answers a message with
/// `message`, and starts any thread.
async fn discord_answering(message: Canned) -> CannedApp {
    CannedApp::start([
        (
            ME,
            Canned::json(&json!({ "id": "1300000000000000001", "bot": true })),
        ),
        (MESSAGES, message),
        (
            THREADS,
            Canned::json(&json!({ "id": "1400000000000000001", "name": "Nightly build" })),
        ),
    ])
    .await
    .expect("the Discord stand-in starts")
}

/// The standard deployment, its Discord steps calling `discord`.
fn profile(discord: &CannedApp) -> Profile {
    Profile::standard().with("DISCORD_API_URL", &discord.url())
}
