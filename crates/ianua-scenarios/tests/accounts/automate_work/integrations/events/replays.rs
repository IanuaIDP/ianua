//! Mallory replays the steps of connecting an account by signing in at a
//! service: a state nobody issued brought to the platform's callback, the
//! callback Tess's browser already used sent again, and the one-time code
//! Tess finished with used a second time. None of them reaches GitHub for
//! another token or connects another account.

use ianua_scenarios::api::workflows;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::workflows::{FinishConnection, NewConnection};
use ianua_scenarios::world::World;
use serde_json::json;

use super::connect::CODE;

/// Where GitHub swaps a code for a token.
const TOKEN_PATH: &str = "/login/oauth/access_token";

/// The deployment's OAuth app at GitHub.
const CLIENT_ID: &str = "acme deployment app";

/// Mallory brings a made-up state to the callback: no code comes back
/// and GitHub is not asked. Tess begins a connection, and her browser's
/// callback swaps GitHub's code once. Mallory sends that same callback
/// again: no code comes back and GitHub is not asked again. Tess finishes
/// with her one-time code, and the same code is refused the second time.
#[tokio::test]
async fn replayed_connection_steps_reach_no_token_and_connect_nothing() {
    let github = CannedApp::start([
        (
            TOKEN_PATH,
            Canned::json(&json!({ "access_token": "a token for Tess", "token_type": "bearer" })),
        ),
        ("/user", Canned::json(&json!({ "login": "acme-bot" }))),
    ])
    .await
    .expect("the GitHub stand-in starts");
    let base = github.url().trim_end_matches('/').to_owned();
    let stack = Stack::start(
        Profile::standard()
            .with("GITHUB_API_URL", &github.url())
            .with("GITHUB_CLIENT_ID", CLIENT_ID)
            .with("GITHUB_CLIENT_SECRET", "acme deployment app secret words")
            .with(
                "GITHUB_AUTHORIZE_URL",
                &format!("{base}/login/oauth/authorize"),
            )
            .with("GITHUB_TOKEN_URL", &format!("{base}{TOKEN_PATH}")),
    )
    .await
    .expect("the stack starts");
    let world = World::new(&stack).await;
    let mallory = world.anonymous().client();

    let made_up = workflows::answer_connection("a state nobody issued", CODE)
        .send_text(mallory)
        .await;
    assert_eq!(
        github.asked_for(TOKEN_PATH),
        0,
        "a made-up state asks GitHub nothing"
    );
    let begun = workflows::begin_connection(
        world.tenant(),
        &NewConnection {
            integration: "github".to_owned(),
            name: "Team GitHub".to_owned(),
            sharing: "tenant".to_owned(),
            place: None,
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    let state = url::Url::parse(&begun.address)
        .expect("the sign-in address")
        .query_pairs()
        .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
        .expect("the sign-in carries a state");
    let first = workflows::answer_connection(&state, CODE)
        .send_text(world.admin().client())
        .await;
    let replayed = workflows::answer_connection(&state, CODE)
        .send_text(mallory)
        .await;
    let code = one_time_code(first.header("location")).expect("Tess's browser got a code");
    let finish = FinishConnection { code };
    workflows::finish_connection(world.tenant(), &begun.connection_id, &finish)
        .send(world.admin().client())
        .await
        .ok();
    let again = workflows::finish_connection(world.tenant(), &begun.connection_id, &finish)
        .send(world.admin().client())
        .await;

    assert!(
        one_time_code(made_up.header("location")).is_none(),
        "a made-up state gets no code: {}",
        made_up.summary()
    );
    assert!(
        one_time_code(replayed.header("location")).is_none(),
        "a replayed callback gets no code: {}",
        replayed.summary()
    );
    assert_eq!(github.asked_for(TOKEN_PATH), 1, "GitHub swapped one code");
    assert!(
        again.status().is_client_error() && again.status() != Status::TOO_MANY_REQUESTS,
        "a spent one-time code finishes nothing: {}",
        again.summary()
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The one-time code the dashboard address `location` carries in its
/// fragment, when it carries one.
fn one_time_code(location: Option<&str>) -> Option<String> {
    let (_, fragment) = location?.split_once('#')?;
    url::form_urlencoded::parse(fragment.as_bytes())
        .find_map(|(name, value)| (name == "code").then(|| value.into_owned()))
}
