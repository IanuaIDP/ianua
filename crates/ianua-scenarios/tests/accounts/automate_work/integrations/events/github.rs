//! GitHub connected by signing in, and starting workflows: Tess signs in
//! at a stand-in for GitHub instead of pasting a token, and Ann publishes a
//! workflow that starts when an issue is opened in acme/web. Publishing
//! registers a webhook there with the account's token; GitHub's signed
//! delivery of Pat's new issue starts one run, which comments on that
//! issue. A delivery signed with another secret, and the same delivery
//! sent again, start nothing.

use ianua_scenarios::api::workflows::{self, ServiceDelivery};
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::{Graph, Trigger, Workflow};
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;
use serde_json::{Value, json};

use super::connect::{SignIn, path_of, runs_now, runs_started, signed, signed_in};
use crate::support::{Action, action, drafted, ended, published, read, written};

/// The token GitHub issues for Tess's sign-in: a sentence, so no scanner
/// takes it for a key.
const TOKEN: &str = "acme github token issued at sign in";

/// The deployment's OAuth app at GitHub.
const CLIENT_ID: &str = "acme deployment app";

/// The app's client secret.
const CLIENT_SECRET: &str = "acme deployment app secret words";

/// Where GitHub swaps the code for a token.
const TOKEN_PATH: &str = "/login/oauth/access_token";

/// Where GitHub says whose a token is.
const WHO: &str = "/user";

/// Where the webhook is registered.
const HOOKS: &str = "/repos/acme/web/hooks";

/// Where the run's comment goes: Pat's issue, number 7.
const COMMENTS: &str = "/repos/acme/web/issues/7/comments";

/// Tess signs in at GitHub to connect the team's account: the browser is
/// sent there with the deployment's app and a challenge, never the
/// verifier; GitHub's code is swapped once, with the verifier, for a token
/// that is tried before it is kept; and the browser lands on the dashboard
/// with a one-time code that only Tess can finish the connection with.
///
/// Ann publishes a workflow on issues opened in acme/web, which registers
/// a webhook there through the token. Pat opens issue 7: GitHub's signed
/// delivery starts one run for Ann, which comments on issue 7. Mallory's
/// copy signed with her own secret is refused, and GitHub sending the same
/// delivery again starts nothing more. Neither the token nor the webhook's
/// secret is anywhere in the trail.
#[tokio::test]
async fn an_issue_opened_at_github_starts_the_workflow_signed_in_for() {
    let github = github().await;
    let stack = Stack::start(profile(&github))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connect_github(&world, &github).await;
    check_token_exchange(&github);
    let workflow = publish_comments(&world, &account).await;
    let hook = registered_hook(&github);
    deliver_issue(&stack, &hook).await;
    check_issue_run(&world, &github, &workflow.id, &hook.secret).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// GitHub issues the token, verifies the account, registers the hook and accepts comments.
async fn github() -> CannedApp {
    CannedApp::start([
        (
            TOKEN_PATH,
            Canned::json(&json!({ "access_token": TOKEN, "token_type": "bearer" })),
        ),
        (WHO, Canned::json(&json!({ "login": "acme-bot" }))),
        (HOOKS, Canned::json(&json!({ "id": 12 }))),
        (COMMENTS, Canned::json(&json!({ "id": 99 }))),
    ])
    .await
    .expect("the GitHub stand-in starts")
}

/// The deployment connects its GitHub app to the stand-in's authorization and API endpoints.
fn profile(github: &CannedApp) -> Profile {
    let base = github.url().trim_end_matches('/').to_owned();
    Profile::standard()
        .with("GITHUB_API_URL", &github.url())
        .with("GITHUB_CLIENT_ID", CLIENT_ID)
        .with("GITHUB_CLIENT_SECRET", CLIENT_SECRET)
        .with(
            "GITHUB_AUTHORIZE_URL",
            &format!("{base}/login/oauth/authorize"),
        )
        .with("GITHUB_TOKEN_URL", &format!("{base}{TOKEN_PATH}"))
}

/// Tess completes the browser connection to the platform's GitHub app.
async fn connect_github(world: &World<'_>, github: &CannedApp) -> String {
    let base = github.url().trim_end_matches('/').to_owned();
    let authorize = format!("{base}/login/oauth/authorize");
    signed_in(
        world,
        &SignIn {
            integration: "github",
            authorize: &authorize,
            client_id: CLIENT_ID,
            place: None,
        },
    )
    .await
}

/// GitHub sees one code exchange with PKCE and then one account identity probe.
fn check_token_exchange(github: &CannedApp) {
    let swapped: Vec<_> = github
        .received()
        .into_iter()
        .filter(|call| call.path == TOKEN_PATH)
        .collect();
    assert_eq!(swapped.len(), 1, "the code was swapped once");
    assert!(swapped[0].body.contains("code_verifier="));
    assert!(swapped[0].body.contains("client_id=acme+deployment+app"));
    assert_eq!(
        github.asked_for(WHO),
        1,
        "the token was tried before it was kept"
    );
}

/// Publishing subscribes to issue openings in the team's repository.
async fn publish_comments(world: &World<'_>, account: &str) -> Workflow {
    let trigger = Trigger::Service {
        integration: "github".to_owned(),
        event: "issue-opened".to_owned(),
        account_id: account.to_owned(),
        filters: [("repository".to_owned(), "acme/web".to_owned())].into(),
    };
    let draft = drafted(world, trigger, comment_graph(account)).await;
    published(world, &draft).await
}

/// The comment targets the issue number carried by the webhook event.
fn comment_graph(account: &str) -> Graph {
    let comment = action(
        Action {
            integration: "github",
            operation: "comment-on-issue",
        },
        account,
        "communicate",
        vec![
            ("repository", written("acme/web")),
            ("issue", read("trigger.issue.number")),
            ("body", written("Thanks, we are looking into it.")),
        ],
    );
    Graph {
        nodes: vec![comment],
        edges: vec![],
    }
}

/// The webhook delivery address and signing secret returned in its registration.
struct Hook {
    address: String,
    secret: String,
}

/// Publication registers exactly one authenticated webhook for issue events.
fn registered_hook(github: &CannedApp) -> Hook {
    let hooks: Vec<_> = github
        .received()
        .into_iter()
        .filter(|call| call.path == HOOKS)
        .collect();
    assert_eq!(hooks.len(), 1, "publishing registered one webhook");
    assert_eq!(
        hooks[0].header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    let hook = hooks[0].json();
    assert_eq!(hook["events"], json!(["issues"]));
    let address = hook["config"]["url"]
        .as_str()
        .expect("the webhook names the platform's address")
        .to_owned();
    let secret = hook["config"]["secret"]
        .as_str()
        .expect("the webhook carries its secret")
        .to_owned();
    Hook { address, secret }
}

/// A wrong signature is refused; GitHub's event and its repeated delivery are accepted.
async fn deliver_issue(stack: &Stack, hook: &Hook) {
    let sender = Client::new(stack, "github").expect("GitHub's client");
    let mallory = Client::new(stack, "mallory").expect("Mallory's client");
    let body = opened_issue().to_string();
    let path = path_of(&hook.address);

    delivered(&mallory, &path, &body, "mallory's own secret words")
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let taken = delivered(&sender, &path, &body, &hook.secret).await;
    assert_eq!(taken.status(), Status::NO_CONTENT);
    let again = delivered(&sender, &path, &body, &hook.secret).await;
    assert_eq!(
        again.status(),
        Status::NO_CONTENT,
        "a resent delivery is taken"
    );
}

/// The repeated delivery creates only one service run and comment, with no secrets in audit details.
async fn check_issue_run(world: &World<'_>, github: &CannedApp, workflow_id: &str, secret: &str) {
    let runs = runs_started(world, workflow_id).await;
    assert_eq!(runs[0].cause, "service");
    let run = ended(world, &runs[0].id, "succeeded").await;
    assert_eq!(run.steps.len(), 1);
    assert_eq!(
        github.asked_for(COMMENTS),
        1,
        "the run commented on issue 7"
    );
    assert_eq!(
        runs_now(world, workflow_id).await.len(),
        1,
        "the resent delivery started nothing more"
    );
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[TOKEN, secret]);
    }
}

/// Pat's issue 7 opened in acme/web, as GitHub sends it.
fn opened_issue() -> Value {
    json!({
        "action": "opened",
        "issue": {
            "number": 7,
            "title": "Login fails on Safari",
            "body": "Steps to reproduce attached.",
            "html_url": "https://github.com/acme/web/issues/7",
            "user": { "login": "pat" }
        },
        "repository": { "full_name": "acme/web" },
        "sender": { "login": "pat" }
    })
}

/// `body` delivered to `path` as GitHub sends it, signed with `secret`.
async fn delivered(client: &Client, path: &str, body: &str, secret: &str) -> Answer<String> {
    let signature = signed(secret, &[body.as_bytes()]);
    workflows::deliver_event(&ServiceDelivery {
        path,
        content_type: "application/json",
        headers: &[
            ("x-github-event", "issues"),
            ("x-github-delivery", "delivery for issue 7"),
            ("x-hub-signature-256", &format!("sha256={signature}")),
        ],
        body,
    })
    .send_text(client)
    .await
}
