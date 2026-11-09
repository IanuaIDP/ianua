//! Telegram as a workflow step: Tess connects the team bot's token, which
//! the bot is asked about first, and Ann publishes a workflow that sends
//! the build news to the ops group and pins it. Telegram's Bot API takes
//! the token as part of the address, `bot<token>/<method>`, and nowhere
//! else, so a stand-in for it shows each call at that address with no
//! `Authorization` header, and the pin naming the message Telegram gave
//! its id. A token Telegram refuses is never connected, and a message
//! Telegram refuses fails the run.

use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::Graph;
use ianua_scenarios::world::World;
use serde_json::json;

use crate::integrations::calls::{Offered, chain, failed_step, never_connected, only_call, ran};
use crate::support::{Action, account_at, action, read, written};

/// The bot's token: words joined by dashes, the characters a bot token
/// may hold, so no scanner takes it for a real one.
const TOKEN: &str = "acme-telegram-bot-for-workflows";

/// Where the bot says who it is, which proves the token.
const GET_ME: &str = "/botacme-telegram-bot-for-workflows/getMe";

/// Where the bot sends a message.
const SEND: &str = "/botacme-telegram-bot-for-workflows/sendMessage";

/// Where the bot pins a message.
const PIN: &str = "/botacme-telegram-bot-for-workflows/pinChatMessage";

/// The ops group's chat.
const CHAT: &str = "-1001234567890";

/// Tess connects the bot's token, which Telegram vouches for when the bot
/// is asked who it is. Ann publishes a workflow sending the build news to
/// the ops group and pinning the message Telegram answered with. Tess runs
/// it: Telegram receives both at the bot's own address and with no
/// `Authorization` header, and the run succeeds. The token is nowhere in
/// the trail.
#[tokio::test]
async fn a_run_sends_a_message_and_pins_it() {
    let telegram = telegram_answering(Canned::json(&json!({
        "ok": true,
        "result": { "message_id": 77, "chat": { "id": -1_001_234_567_890_i64 } }
    })))
    .await;
    let stack = Stack::start(profile(&telegram))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "telegram", TOKEN).await;
    assert_eq!(
        only_call(&telegram, "GET", GET_ME).header("authorization"),
        None
    );
    ran(&world, news_graph(&account), "succeeded").await;
    check_message_and_pin(&telegram);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[TOKEN]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Telegram refuses the message with 400, as for a chat the bot is not
/// in. The send step and the run fail after one request, and nothing is
/// pinned.
#[tokio::test]
async fn a_message_telegram_refuses_fails_the_run() {
    let telegram = telegram_answering(Canned::refusing(400)).await;
    let stack = Stack::start(profile(&telegram))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "telegram", TOKEN).await;

    let run = ran(&world, news_graph(&account), "failed").await;

    failed_step(&run, "telegram-send-message");
    assert_eq!(telegram.asked_for(SEND), 1, "a refusal is not tried again");
    assert_eq!(telegram.asked_for(PIN), 0, "nothing was pinned");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Telegram does not know Tess's mistyped token: the bot's address answers
/// 401, and no account is connected.
#[tokio::test]
async fn a_token_telegram_refuses_is_never_connected() {
    let telegram = CannedApp::start([("/botacme-mistyped-bot/getMe", Canned::refusing(401))])
        .await
        .expect("the Telegram stand-in starts");
    let stack = Stack::start(profile(&telegram))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let offered = Offered {
        integration: "telegram",
        credential: "acme-mistyped-bot",
    };

    never_connected(&world, offered).await;

    assert_eq!(
        telegram.received().len(),
        1,
        "Telegram was asked about the token once"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The workflow sends the build news to the ops group and pins the message
/// Telegram gave back.
fn news_graph(account: &str) -> Graph {
    let send = action(
        Action {
            integration: "telegram",
            operation: "send-message",
        },
        account,
        "communicate",
        vec![
            ("chat", written(CHAT)),
            ("text", written("The nightly build failed")),
        ],
    );
    let pin = action(
        Action {
            integration: "telegram",
            operation: "pin-message",
        },
        account,
        "write",
        vec![
            ("chat", written(CHAT)),
            (
                "message",
                read("telegram-send-message.json.result.message_id"),
            ),
        ],
    );
    chain(vec![send, pin])
}

/// Telegram received the message and the pin of message 77 at the bot's
/// own address, neither with an `Authorization` header.
fn check_message_and_pin(telegram: &CannedApp) {
    let sent = only_call(telegram, "POST", SEND);
    let pinned = only_call(telegram, "POST", PIN);
    for call in [&sent, &pinned] {
        assert_eq!(
            call.header("authorization"),
            None,
            "the token is only in the address"
        );
        no_secret_leaked(&call.body, &[TOKEN]);
    }
    assert_eq!(
        sent.json(),
        json!({ "chat_id": CHAT, "text": "The nightly build failed" })
    );
    assert_eq!(pinned.json(), json!({ "chat_id": CHAT, "message_id": 77 }));
}

/// A Telegram stand-in that tells the bot's name, answers a sent message
/// with `sent`, and pins any message.
async fn telegram_answering(sent: Canned) -> CannedApp {
    CannedApp::start([
        (
            GET_ME,
            Canned::json(&json!({ "ok": true, "result": { "username": "acme_ops_bot" } })),
        ),
        (SEND, sent),
        (PIN, Canned::json(&json!({ "ok": true, "result": true }))),
    ])
    .await
    .expect("the Telegram stand-in starts")
}

/// The standard deployment, its Telegram steps calling `telegram`.
fn profile(telegram: &CannedApp) -> Profile {
    Profile::standard().with("TELEGRAM_API_URL", &telegram.url())
}
