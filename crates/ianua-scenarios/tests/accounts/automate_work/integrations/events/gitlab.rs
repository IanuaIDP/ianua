//! GitLab's events starting workflows: Tess connects the team's token,
//! and Ann publishes a workflow that starts when an issue is opened in
//! project 42. Publishing registers a project webhook there, asking for
//! issues only and carrying the registration's secret as its token;
//! GitLab's delivery of Pat's new issue, with that token, starts one run.
//! A delivery with another token, and the same delivery sent again, start
//! nothing.

use ianua_scenarios::api::workflows::{self, ServiceDelivery};
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp, Received};
use ianua_scenarios::wire::workflows::Trigger;
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;
use serde_json::{Value, json};

use super::connect::{delivering_on, path_of, runs_now, runs_started};
use crate::service::Service;
use crate::support::{account_at, ended};

/// The team's token: a sentence, so no scanner takes it for a key.
const TOKEN: &str = "acme gitlab token for issue workflows";

/// Where GitLab says whose a token is, which proves it.
const WHO: &str = "/user";

/// Where project 42's webhooks are registered.
const HOOKS: &str = "/projects/42/hooks";

/// GitLab's id for the one delivery, which a resent delivery keeps.
const DELIVERY_ID: &str = "gitlab delivery of issue 7";

/// Tess connects the token, tried at GitLab before it is kept. Ann
/// publishes a workflow on issues opened in project 42, which registers a
/// webhook there for issues and no pushes, with the token. Pat opens
/// issue 7: GitLab's delivery with the webhook's token starts one run,
/// which delivers once. Mallory's copy with a guessed token is refused,
/// and GitLab sending the same delivery again starts nothing more.
/// Neither the token nor the webhook's secret is in the trail.
#[tokio::test]
async fn an_issue_opened_at_gitlab_starts_the_workflow() {
    let gitlab = gitlab().await;
    let service = Service::start().await;
    let profile = Profile::standard().with("GITLAB_API_URL", &format!("{}/", gitlab.url()));
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "gitlab", TOKEN).await;
    let workflow = delivering_on(&world, &service, issues_in(&account)).await;
    let hook = registered_hook(&gitlab);

    deliver_issue(&stack, &hook).await;
    let runs = runs_started(&world, &workflow.id).await;
    ended(&world, &runs[0].id, "succeeded").await;

    assert_eq!(
        gitlab.asked_for(WHO),
        1,
        "the token was tried before it was kept"
    );
    assert_eq!(runs[0].cause, "service");
    assert_eq!(service.delivered(), 1, "the run delivered once");
    assert_eq!(
        runs_now(&world, &workflow.id).await.len(),
        1,
        "the resent delivery started nothing"
    );
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[TOKEN, &hook.secret]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// The GitLab stand-in: it knows the token's owner and takes webhooks.
async fn gitlab() -> CannedApp {
    CannedApp::start([
        (
            WHO,
            Canned::json(&json!({ "id": 1, "username": "acme-bot" })),
        ),
        (HOOKS, Canned::json(&json!({ "id": 12 }))),
    ])
    .await
    .expect("the GitLab stand-in starts")
}

/// Issues opened in project 42, watched through `account`.
fn issues_in(account: &str) -> Trigger {
    Trigger::Service {
        integration: "gitlab".to_owned(),
        event: "issue-opened".to_owned(),
        account_id: account.to_owned(),
        filters: [("project".to_owned(), "42".to_owned())].into(),
    }
}

/// The webhook's address and the secret it carries as its token.
struct Hook {
    address: String,
    secret: String,
}

/// Publishing registered one webhook, with the account's token, asking
/// for issues and no pushes.
fn registered_hook(gitlab: &CannedApp) -> Hook {
    let hooks: Vec<Received> = gitlab
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
    assert_eq!(hook["issues_events"], true);
    assert_eq!(hook["push_events"], false);
    Hook {
        address: hook["url"]
            .as_str()
            .expect("the webhook names the platform's address")
            .to_owned(),
        secret: hook["token"]
            .as_str()
            .expect("the webhook carries its secret")
            .to_owned(),
    }
}

/// Mallory's guessed token is refused; GitLab's delivery and its resend
/// are taken.
async fn deliver_issue(stack: &Stack, hook: &Hook) {
    let sender = Client::new(stack, "gitlab").expect("GitLab's client");
    let mallory = Client::new(stack, "mallory").expect("Mallory's client");
    let body = opened_issue().to_string();
    let path = path_of(&hook.address);

    delivered(&mallory, &path, &body, "mallory's guessed token")
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

/// Pat's issue 7 opened in project 42, as GitLab sends it.
fn opened_issue() -> Value {
    json!({
        "object_kind": "issue",
        "event_type": "issue",
        "user": { "username": "pat" },
        "project": { "id": 42, "path_with_namespace": "acme/web" },
        "object_attributes": {
            "iid": 7,
            "title": "Login fails on Safari",
            "description": "Steps to reproduce attached.",
            "url": "https://gitlab.example/acme/web/-/issues/7",
            "action": "open",
            "confidential": false
        }
    })
}

/// `body` delivered to `path` as GitLab sends it, with `token`.
async fn delivered(client: &Client, path: &str, body: &str, token: &str) -> Answer<String> {
    workflows::deliver_event(&ServiceDelivery {
        path,
        content_type: "application/json",
        headers: &[
            ("x-gitlab-event", "Issue Hook"),
            ("x-gitlab-token", token),
            ("idempotency-key", DELIVERY_ID),
        ],
        body,
    })
    .send_text(client)
    .await
}
