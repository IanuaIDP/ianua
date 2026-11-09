//! Jira connected by signing in, and starting workflows: Tess signs in at a
//! stand-in for Atlassian naming acme.atlassian.net, and the account keeps
//! that site's cloud id. Ann publishes a workflow that starts when an issue
//! is created in OPS and comments on it; publishing registers a webhook
//! through Atlassian's gateway, its address carrying the registration's
//! secret. Jira's delivery of Pat's issue starts one run. A delivery
//! without the secret starts nothing.

use ianua_scenarios::api::workflows::{self, ServiceDelivery};
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::{Graph, Trigger, Workflow};
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;
use serde_json::json;

use super::connect::{SignIn, path_and_query, runs_started, signed_in};
use crate::support::{Action, action, drafted, ended, published, read, written};

/// The refresh grant Atlassian issues: a sentence, so no scanner takes it
/// for a key.
const GRANT: &str = "acme atlassian grant issued at sign in";

/// The platform's Atlassian app.
const CLIENT_ID: &str = "acme platform atlassian app";

/// The app's client secret.
const CLIENT_SECRET: &str = "acme platform atlassian app secret words";

/// Where Atlassian swaps codes and exchanges grants.
const TOKEN_PATH: &str = "/oauth/token";

/// Where Atlassian lists the sites a grant reaches.
const RESOURCES: &str = "/oauth/token/accessible-resources";

/// Where the gateway proves the account: who it is on Acme's site.
const MYSELF: &str = "/ex/jira/acme-cloud/rest/api/2/myself";

/// Where the webhook is registered on Acme's site.
const WEBHOOK: &str = "/ex/jira/acme-cloud/rest/api/2/webhook";

/// Where the run's comment goes: Pat's issue OPS-12.
const COMMENTS: &str = "/ex/jira/acme-cloud/rest/api/2/issue/OPS-12/comment";

/// Tess signs in at Atlassian naming acme.atlassian.net; the account
/// reaches Acme's site through the gateway and is tried there before it is
/// kept. Ann publishes a workflow on issues created in OPS, which
/// registers a webhook on Acme's site. Pat creates OPS-12: Jira's delivery
/// to the webhook's address starts one run, which comments on OPS-12.
/// Mallory's delivery without the secret is refused. The grant and the
/// secret are nowhere in the trail.
#[tokio::test]
async fn an_issue_created_in_jira_starts_the_workflow_signed_in_for() {
    let atlassian = atlassian().await;
    let stack = Stack::start(profile(&atlassian))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connect_jira(&world, &atlassian).await;
    let workflow = publish_comments(&world, &account).await;
    let address = registered_hook(&atlassian);
    deliver_created(&stack, &address).await;
    check_created_run(&world, &atlassian, &workflow.id, &address).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess connects Acme's site through Atlassian and the account is tried through its cloud id.
async fn connect_jira(world: &World<'_>, atlassian: &CannedApp) -> String {
    let base = atlassian.url().trim_end_matches('/').to_owned();
    let authorize = format!("{base}/authorize");

    let account = signed_in(
        world,
        &SignIn {
            integration: "jira",
            authorize: &authorize,
            client_id: CLIENT_ID,
            place: Some("acme.atlassian.net"),
        },
    )
    .await;
    assert_eq!(atlassian.asked_for(RESOURCES), 1, "the site was looked up");
    assert_eq!(
        atlassian.asked_for(MYSELF),
        1,
        "the account was tried on Acme's site"
    );
    account
}

/// The published workflow comments on issues created in OPS.
async fn publish_comments(world: &World<'_>, account: &str) -> Workflow {
    let trigger = Trigger::Service {
        integration: "jira".to_owned(),
        event: "issue-created".to_owned(),
        account_id: account.to_owned(),
        filters: [("project".to_owned(), "OPS".to_owned())].into(),
    };
    let draft = drafted(world, trigger, comment_graph(account)).await;
    published(world, &draft).await
}

/// The comment's issue key comes from the webhook's created issue.
fn comment_graph(account: &str) -> Graph {
    let comment = action(
        Action {
            integration: "jira",
            operation: "comment-on-issue",
        },
        account,
        "communicate",
        vec![
            ("issue", read("trigger.issue.key")),
            ("body", written("Thanks, we are on it.")),
        ],
    );
    Graph {
        nodes: vec![comment],
        edges: vec![],
    }
}

/// Publication registers one webhook and supplies its delivery address.
fn registered_hook(atlassian: &CannedApp) -> String {
    let registered: Vec<_> = atlassian
        .received()
        .into_iter()
        .filter(|call| call.path == WEBHOOK)
        .collect();
    assert_eq!(registered.len(), 1, "publishing registered one webhook");
    registered[0].json()["url"]
        .as_str()
        .expect("the webhook names the platform's address")
        .to_owned()
}

/// An unsigned address refuses Mallory, while the address carrying the hook secret accepts Jira.
async fn deliver_created(stack: &Stack, address: &str) {
    let secret_path = path_and_query(address);
    let bare_path = secret_path
        .split_once('?')
        .map_or(secret_path.as_str(), |(path, _)| path)
        .to_owned();

    let sender = Client::new(stack, "jira").expect("Jira's client");
    let mallory = Client::new(stack, "mallory").expect("Mallory's client");
    let created = created().to_string();
    delivered(&mallory, &bare_path, &created)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let taken = delivered(&sender, &secret_path, &created).await;
    assert_eq!(taken.status(), Status::NO_CONTENT);
}

/// The event run comments on OPS-12 without exposing its grant or delivery secret in the trail.
async fn check_created_run(
    world: &World<'_>,
    atlassian: &CannedApp,
    workflow_id: &str,
    address: &str,
) {
    let runs = runs_started(world, workflow_id).await;
    ended(world, &runs[0].id, "succeeded").await;
    assert_eq!(
        atlassian.asked_for(COMMENTS),
        1,
        "the run commented on OPS-12"
    );
    let secret = address
        .split("token=")
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[GRANT, &secret]);
    }
}

/// The Atlassian stand-in: it issues tokens and grants, lists Acme's site,
/// and answers Acme's Jira through the gateway.
async fn atlassian() -> CannedApp {
    CannedApp::start([
        (
            TOKEN_PATH,
            Canned::json(&json!({
                "access_token": "an hour's token",
                "refresh_token": GRANT,
                "expires_in": 3600
            })),
        ),
        (
            RESOURCES,
            Canned::json(&json!([
                { "id": "acme-cloud", "url": "https://acme.atlassian.net", "name": "acme" }
            ])),
        ),
        (MYSELF, Canned::json(&json!({ "accountId": "tess" }))),
        (
            WEBHOOK,
            Canned::json(&json!({ "webhookRegistrationResult": [{ "createdWebhookId": 1000 }] })),
        ),
        (COMMENTS, Canned::json(&json!({ "id": "10001" }))),
    ])
    .await
    .expect("the Atlassian stand-in starts")
}

/// The standard deployment with the platform's Atlassian app at
/// `atlassian`.
fn profile(atlassian: &CannedApp) -> Profile {
    let base = atlassian.url().trim_end_matches('/').to_owned();
    Profile::standard()
        .with("JIRA_CLIENT_ID", CLIENT_ID)
        .with("JIRA_CLIENT_SECRET", CLIENT_SECRET)
        .with("JIRA_AUTHORIZE_URL", &format!("{base}/authorize"))
        .with("JIRA_TOKEN_URL", &format!("{base}{TOKEN_PATH}"))
        .with("JIRA_GATEWAY_URL", &format!("{base}/"))
}

/// Pat's issue OPS-12 created, as Jira sends it.
fn created() -> serde_json::Value {
    json!({
        "webhookEvent": "jira:issue_created",
        "issue": {
            "key": "OPS-12",
            "fields": {
                "summary": "Disk full on db-2",
                "issuetype": { "name": "Bug" },
                "status": { "name": "To Do" },
                "project": { "key": "OPS" }
            }
        }
    })
}

/// `body` delivered to `path` as Jira sends it.
async fn delivered(client: &Client, path: &str, body: &str) -> Answer<String> {
    workflows::deliver_event(&ServiceDelivery {
        path,
        content_type: "application/json",
        headers: &[("x-atlassian-webhook-identifier", "delivery-ops-12")],
        body,
    })
    .send_text(client)
    .await
}
