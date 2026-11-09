//! Trello as a workflow step: Tess connects the team's API key and token,
//! which Trello is asked about first, and Ann publishes a workflow that
//! creates a card and comments on it. A stand-in for Trello's API shows
//! what arrived: the key and token together in Trello's `OAuth` header,
//! never in the address, and the card's inputs in the query. The board
//! Tess picked only to fill the list picker is never sent. A key Trello
//! refuses is never connected, and a card Trello refuses fails the run.

use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp, Received};
use ianua_scenarios::wire::workflows::Graph;
use ianua_scenarios::world::World;
use serde_json::json;

use crate::integrations::calls::{Offered, chain, failed_step, never_connected, only_call, ran};
use crate::support::{Action, account_at, action, read, written};

/// Where Trello says whose a key and token are.
const ME: &str = "/members/me";

/// Where a card is created.
const CARDS: &str = "/cards";

/// Where the comment goes: on the card Trello gave the id card-42.
const COMMENTS: &str = "/cards/card-42/actions/comments";

/// The board Tess picks to fill the list picker, which Trello is never
/// told.
const BOARD: &str = "board-ops";

/// Tess connects the key and token, which Trello vouches for when asked
/// whose they are. Ann publishes a workflow creating a card on the Doing
/// list, picked from the Ops board, and commenting on it by the id Trello
/// gave back. Tess runs it: Trello receives the card's list, name and
/// description in the query and the comment on card-42, each with the key
/// and token in the `OAuth` header and nowhere in the address; the board
/// reaches Trello nowhere. The token is nowhere in the trail.
#[tokio::test]
async fn a_run_creates_a_card_and_comments_on_it() {
    let trello = trello_answering(Canned::json(
        &json!({ "id": "card-42", "name": "Call the supplier" }),
    ))
    .await;
    let stack = Stack::start(profile(&trello))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "trello", &credential()).await;
    let asked = only_call(&trello, "GET", ME);
    assert_eq!(asked.header("authorization"), Some(header().as_str()));
    ran(&world, card_graph(&account), "succeeded").await;
    check_card_and_comment(&trello);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[token().as_str()]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Trello refuses the card with 400, as for a list that is not there. The
/// card step and the run fail after one request, and no comment is posted.
#[tokio::test]
async fn a_card_trello_refuses_fails_the_run() {
    let trello = trello_answering(Canned::refusing(400)).await;
    let stack = Stack::start(profile(&trello))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "trello", &credential()).await;

    let run = ran(&world, card_graph(&account), "failed").await;

    failed_step(&run, "trello-create-card");
    assert_eq!(trello.asked_for(CARDS), 1, "a refusal is not tried again");
    assert_eq!(
        trello.asked_for(COMMENTS),
        0,
        "nothing was said on a missing card"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Trello does not know Tess's key and token: asked once, it answers 401,
/// and no account is connected.
#[tokio::test]
async fn a_key_trello_refuses_is_never_connected() {
    let trello = CannedApp::start([(ME, Canned::refusing(401))])
        .await
        .expect("the Trello stand-in starts");
    let stack = Stack::start(profile(&trello))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let offered = credential();

    never_connected(
        &world,
        Offered {
            integration: "trello",
            credential: &offered,
        },
    )
    .await;

    assert_eq!(trello.asked_for(ME), 1, "Trello was asked about the key");
    stack.stop().await.expect("the stack stops cleanly");
}

/// The workflow creates a card on the Doing list, picked from the Ops
/// board, and comments on it by the id Trello gave back.
fn card_graph(account: &str) -> Graph {
    let create = action(
        Action {
            integration: "trello",
            operation: "create-card",
        },
        account,
        "write",
        vec![
            ("board", written(BOARD)),
            ("list", written("list-doing")),
            ("name", written("Call the supplier")),
            ("description", written("About the late delivery.")),
        ],
    );
    let comment = action(
        Action {
            integration: "trello",
            operation: "comment-on-card",
        },
        account,
        "communicate",
        vec![
            ("card", read("trello-create-card.json.id")),
            ("text", written("Called; they ship Monday.")),
        ],
    );
    chain(vec![create, comment])
}

/// Trello received the card's inputs and the comment in the query, each
/// signed with the `OAuth` header, and the board nowhere.
fn check_card_and_comment(trello: &CannedApp) {
    let card = only_call(trello, "POST", CARDS);
    let comment = only_call(trello, "POST", COMMENTS);
    assert_eq!(
        card.query_pairs(),
        pairs(&[
            ("idList", "list-doing"),
            ("name", "Call the supplier"),
            ("desc", "About the late delivery."),
        ])
    );
    assert_eq!(
        comment.query_pairs(),
        pairs(&[("text", "Called; they ship Monday.")])
    );
    for call in [&card, &comment] {
        check_signed_outside_the_address(call);
    }
}

/// `call` carried the key and token in its `OAuth` header, and neither
/// they nor the board in its address or body.
fn check_signed_outside_the_address(call: &Received) {
    assert_eq!(call.header("authorization"), Some(header().as_str()));
    let address = call.query.clone().unwrap_or_default();
    no_secret_leaked(&address, &[token().as_str(), key().as_str()]);
    assert!(
        !address.contains(BOARD) && !call.body.contains(BOARD),
        "the board stayed home"
    );
}

/// `entries` as the name and value pairs of a query.
fn pairs(entries: &[(&str, &str)]) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

/// A Trello stand-in that knows the key and token, answers a new card with
/// `card`, and takes any comment.
async fn trello_answering(card: Canned) -> CannedApp {
    CannedApp::start([
        (
            ME,
            Canned::json(&json!({ "id": "member-1", "username": "tess" })),
        ),
        (CARDS, card),
        (COMMENTS, Canned::json(&json!({ "id": "action-7" }))),
    ])
    .await
    .expect("the Trello stand-in starts")
}

/// The standard deployment, its Trello steps calling `trello`.
fn profile(trello: &CannedApp) -> Profile {
    Profile::standard().with("TRELLO_API_URL", &trello.url())
}

/// The key and token the team's account holds, as Trello takes them:
/// letters and digits only, put together at run time so no scanner takes
/// them for real ones.
fn credential() -> String {
    json!({ "key": key(), "token": token() }).to_string()
}

/// The team's API key.
fn key() -> String {
    ["acme", "trello", "key"].concat()
}

/// The token the team's member granted.
fn token() -> String {
    ["acme", "trello", "token", "for", "workflows"].concat()
}

/// The `OAuth` header Trello reads the key and token from.
fn header() -> String {
    format!(
        "OAuth oauth_consumer_key=\"{}\", oauth_token=\"{}\"",
        key(),
        token()
    )
}
