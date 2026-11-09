//! GitLab as a workflow step: Tess connects the team's access token, which
//! GitLab is asked about first, and Ann publishes a workflow that opens an
//! issue in acme/web and comments on it. A stand-in for GitLab's API shows
//! what arrived: the token, the project as one escaped part of the address,
//! the issue and the comment on the issue GitLab numbered. An account Tess
//! connects by signing in at GitLab keeps the token its grant was exchanged
//! for and reuses it. A token GitLab refuses is never connected, and an
//! issue GitLab refuses fails the run.

use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::{Graph, Node};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::integrations::calls::{
    Offered, chain, failed_step, never_connected, only_call, output_of, ran,
};
use crate::integrations::events::connect::{SignIn, signed_in};
use crate::support::{Action, account_at, action, read, written};

/// The team's access token: a sentence, so no scanner takes it for a key.
const TOKEN: &str = "acme gitlab token for workflows";

/// Where GitLab says whose a token is.
const WHO: &str = "/user";

/// Where an issue is opened in acme/web, the project's path one part.
const ISSUES: &str = "/projects/acme%2Fweb/issues";

/// Where the comment goes: on the issue GitLab numbered 42.
const NOTES: &str = "/projects/acme%2Fweb/issues/42/notes";

/// The platform's app at GitLab.
const CLIENT_ID: &str = "acme platform gitlab app";

/// Where GitLab swaps codes and exchanges grants.
const TOKEN_PATH: &str = "/oauth/token";

/// The refresh grant GitLab issues at sign-in: a sentence, so no scanner
/// takes it for a key.
const GRANT: &str = "acme gitlab grant issued at sign in";

/// The two-hour token GitLab issues for the grant.
const ISSUED: &str = "acme two hour gitlab token";

/// Tess connects the team's token, which GitLab is asked about once. Ann
/// publishes a workflow that opens an issue in acme/web and comments on
/// the issue GitLab numbered, read from the first step's answer. Tess runs
/// it: GitLab receives both, signed with the token, and the run succeeds
/// with GitLab's number as the first step's output. The token is nowhere
/// in the trail.
#[tokio::test]
async fn a_run_opens_an_issue_and_comments_through_the_pasted_token() {
    let gitlab = gitlab_answering(Canned::json(&json!({ "iid": 42, "id": 9001 }))).await;
    let stack = Stack::start(api_profile(&gitlab))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "gitlab", TOKEN).await;
    let signed = format!("Bearer {TOKEN}");
    let asked = only_call(&gitlab, "GET", WHO);
    assert_eq!(asked.header("authorization"), Some(signed.as_str()));
    let run = ran(&world, issue_graph(&account), "succeeded").await;
    check_issue_and_note(
        &gitlab,
        Reached {
            api: "",
            authorization: &signed,
        },
    );
    assert_eq!(output_of(&run, "gitlab-create-issue")["json"]["iid"], 42);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[TOKEN]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// GitLab does not know Tess's mistyped token: asked once, it answers 401,
/// and no account is connected.
#[tokio::test]
async fn a_token_gitlab_refuses_is_never_connected() {
    let gitlab = CannedApp::start([(WHO, Canned::refusing(401))])
        .await
        .expect("the GitLab stand-in starts");
    let stack = Stack::start(api_profile(&gitlab))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let offered = Offered {
        integration: "gitlab",
        credential: "a mistyped gitlab token",
    };

    never_connected(&world, offered).await;

    assert_eq!(gitlab.asked_for(WHO), 1, "GitLab was asked about the token");
    stack.stop().await.expect("the stack stops cleanly");
}

/// GitLab refuses the issue with 403, as for a token without access to
/// acme/web. The issue step and the run fail after one request, and the
/// comment is never sent.
#[tokio::test]
async fn an_issue_gitlab_refuses_fails_the_run() {
    let gitlab = gitlab_answering(Canned::refusing(403)).await;
    let stack = Stack::start(api_profile(&gitlab))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "gitlab", TOKEN).await;

    let run = ran(&world, issue_graph(&account), "failed").await;

    failed_step(&run, "gitlab-create-issue");
    assert_eq!(gitlab.asked_for(ISSUES), 1, "a refusal is not tried again");
    assert_eq!(
        gitlab.asked_for(NOTES),
        0,
        "nothing was said on a missing issue"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess signs in at GitLab through the platform's app. GitLab swaps the
/// code for a grant, which is exchanged for a two-hour token that proves
/// the account before it is kept. Ann's workflow then opens an issue and
/// comments on it: both calls carry the token kept from connecting, the
/// token address is not asked again, and the grant never reaches the API.
#[tokio::test]
async fn a_signed_in_account_reuses_the_token_its_grant_was_exchanged_for() {
    let gitlab = signing_in_gitlab().await;
    let stack = Stack::start(signing_in_profile(&gitlab))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connect_by_signing_in(&world, &gitlab).await;
    let exchanges = gitlab.asked_for(TOKEN_PATH);

    ran(&world, issue_graph(&account), "succeeded").await;

    assert_eq!(
        gitlab.asked_for(TOKEN_PATH),
        exchanges,
        "the run reused the token kept from connecting"
    );
    let signed = format!("Bearer {ISSUED}");
    check_issue_and_note(
        &gitlab,
        Reached {
            api: "/api/v4",
            authorization: &signed,
        },
    );
    grant_kept_from_the_api(&world, &gitlab).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// The grant reached no call but the token exchange, and neither it nor
/// the token it was exchanged for is in the trail.
async fn grant_kept_from_the_api(world: &World<'_>, gitlab: &CannedApp) {
    for call in gitlab
        .received()
        .iter()
        .filter(|call| call.path != TOKEN_PATH)
    {
        no_secret_leaked(&call.body, &[GRANT]);
    }
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[GRANT, ISSUED]);
    }
}

/// Tess signs in at the GitLab stand-in; the account is proven with the
/// token its grant was exchanged for.
async fn connect_by_signing_in(world: &World<'_>, gitlab: &CannedApp) -> String {
    let authorize = format!("{}/oauth/authorize", gitlab.url());
    let account = signed_in(
        world,
        &SignIn {
            integration: "gitlab",
            authorize: &authorize,
            client_id: CLIENT_ID,
            place: None,
        },
    )
    .await;
    let asked = only_call(gitlab, "GET", &format!("/api/v4{WHO}"));
    assert_eq!(
        asked.header("authorization"),
        Some(format!("Bearer {ISSUED}").as_str())
    );
    account
}

/// The workflow opens an issue in acme/web and comments on the number
/// GitLab gave it.
fn issue_graph(account: &str) -> Graph {
    let comment = action(
        Action {
            integration: "gitlab",
            operation: "comment-on-issue",
        },
        account,
        "communicate",
        vec![
            ("project", written("acme/web")),
            ("issue", read("gitlab-create-issue.json.iid")),
            ("body", written("Rolled back; looking into it.")),
        ],
    );
    chain(vec![opening_step(account), comment])
}

/// The first step files the failed-build issue in acme/web.
fn opening_step(account: &str) -> Node {
    action(
        Action {
            integration: "gitlab",
            operation: "create-issue",
        },
        account,
        "write",
        vec![
            ("project", written("acme/web")),
            ("title", written("Nightly build failed")),
            (
                "description",
                written("The deploy job stopped at the database step."),
            ),
        ],
    )
}

/// Where a GitLab account's calls reached the stand-in and what signed
/// them.
#[derive(Clone, Copy)]
struct Reached<'a> {
    /// Where the API sits on the stand-in: its root for a pasted token, or
    /// `/api/v4` beside the sign-in addresses.
    api: &'a str,
    /// The `Authorization` header every call carried.
    authorization: &'a str,
}

/// GitLab received the issue and the comment on issue 42 where `reached`
/// says, each signed as it says and asking for JSON.
fn check_issue_and_note(gitlab: &CannedApp, reached: Reached<'_>) {
    let api = reached.api;
    let issue = only_call(gitlab, "POST", &format!("{api}{ISSUES}"));
    let note = only_call(gitlab, "POST", &format!("{api}{NOTES}"));
    for call in [&issue, &note] {
        assert_eq!(call.header("authorization"), Some(reached.authorization));
        assert_eq!(call.header("accept"), Some("application/json"));
    }
    assert_eq!(
        issue.json(),
        json!({
            "title": "Nightly build failed",
            "description": "The deploy job stopped at the database step."
        })
    );
    assert_eq!(
        note.json(),
        json!({ "body": "Rolled back; looking into it." })
    );
}

/// A GitLab stand-in that knows the token, answers an opened issue with
/// `issue`, and takes any comment.
async fn gitlab_answering(issue: Canned) -> CannedApp {
    CannedApp::start([
        (WHO, Canned::json(&json!({ "username": "acme-bot" }))),
        (ISSUES, issue),
        (NOTES, Canned::json(&json!({ "id": 7 }))),
    ])
    .await
    .expect("the GitLab stand-in starts")
}

/// A GitLab stand-in with its sign-in beside its API under `/api/v4`: it
/// swaps codes and exchanges grants for [`ISSUED`], and takes the issue and
/// the comment.
async fn signing_in_gitlab() -> CannedApp {
    CannedApp::start([
        (
            TOKEN_PATH,
            Canned::json(&json!({
                "access_token": ISSUED,
                "refresh_token": GRANT,
                "token_type": "Bearer",
                "expires_in": 7200
            })),
        ),
        ("/api/v4/user", Canned::json(&json!({ "username": "tess" }))),
        (
            "/api/v4/projects/acme%2Fweb/issues",
            Canned::json(&json!({ "iid": 42 })),
        ),
        (
            "/api/v4/projects/acme%2Fweb/issues/42/notes",
            Canned::json(&json!({ "id": 7 })),
        ),
    ])
    .await
    .expect("the GitLab stand-in starts")
}

/// The standard deployment, its GitLab steps calling `gitlab`.
fn api_profile(gitlab: &CannedApp) -> Profile {
    Profile::standard().with("GITLAB_API_URL", &gitlab.url())
}

/// The standard deployment with the platform's app at the GitLab
/// stand-in, its API under `/api/v4`.
fn signing_in_profile(gitlab: &CannedApp) -> Profile {
    let base = gitlab.url();
    Profile::standard()
        .with("GITLAB_API_URL", &format!("{base}/api/v4/"))
        .with("GITLAB_CLIENT_ID", CLIENT_ID)
        .with("GITLAB_CLIENT_SECRET", "acme platform gitlab app words")
        .with("GITLAB_AUTHORIZE_URL", &format!("{base}/oauth/authorize"))
        .with("GITLAB_TOKEN_URL", &format!("{base}{TOKEN_PATH}"))
}
