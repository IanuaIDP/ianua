//! Azure DevOps connected by signing in, and starting workflows: Tess signs
//! in at a stand-in for Microsoft naming the acme organization. Ann
//! publishes a workflow that starts when a work item is created in Web and
//! comments on it; publishing subscribes a service hook to Web whose
//! address carries the registration's secret. Azure DevOps's delivery of
//! Pat's bug starts one run. A delivery without the secret starts nothing.

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

/// The refresh grant Microsoft issues: a sentence, so no scanner takes it
/// for a key.
const GRANT: &str = "acme microsoft grant issued at sign in";

/// The platform's app in Microsoft Entra.
const CLIENT_ID: &str = "acme platform entra app";

/// The app's client secret.
const CLIENT_SECRET: &str = "acme platform entra app secret words";

/// Where Microsoft swaps codes and exchanges grants.
const TOKEN_PATH: &str = "/token";

/// Where Azure DevOps lists the organization's projects, which proves an
/// account.
const PROJECTS: &str = "/acme/_apis/projects";

/// Where the Web project is looked up.
const WEB: &str = "/acme/_apis/projects/Web";

/// Where service hooks are subscribed.
const SUBSCRIPTIONS: &str = "/acme/_apis/hooks/subscriptions";

/// Where the run's comment goes: Pat's bug 42.
const COMMENTS: &str = "/acme/Web/_apis/wit/workItems/42/comments";

/// Tess signs in at Microsoft naming the acme organization; the grant is
/// tried there before it is kept. Ann publishes a workflow on work items
/// created in Web, which subscribes a service hook to Web. Pat files bug
/// 42: Azure DevOps's delivery to the hook's address starts one run, which
/// comments on bug 42. Mallory's delivery without the secret is refused.
/// The grant and the secret are nowhere in the trail.
#[tokio::test]
async fn a_work_item_created_in_azure_devops_starts_the_workflow_signed_in_for() {
    let azure = azure().await;
    let stack = Stack::start(profile(&azure))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connect_azure(&world, &azure).await;
    let workflow = publish_comments(&world, &account).await;
    let address = registered_hook(&azure);
    deliver_created(&stack, &address).await;
    check_created_run(&world, &azure, &workflow.id, &address).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess connects Acme's organization through Microsoft and the grant is tried there.
async fn connect_azure(world: &World<'_>, azure: &CannedApp) -> String {
    let base = azure.url().trim_end_matches('/').to_owned();
    let authorize = format!("{base}/authorize");

    let account = signed_in(
        world,
        &SignIn {
            integration: "azure-devops",
            authorize: &authorize,
            client_id: CLIENT_ID,
            place: Some("acme"),
        },
    )
    .await;
    assert_eq!(azure.asked_for(PROJECTS), 1, "the grant was tried in acme");
    account
}

/// Publishing the work-item trigger subscribes Web and replies with the created item's id.
async fn publish_comments(world: &World<'_>, account: &str) -> Workflow {
    let trigger = Trigger::Service {
        integration: "azure-devops".to_owned(),
        event: "work-item-created".to_owned(),
        account_id: account.to_owned(),
        filters: [("project".to_owned(), "Web".to_owned())].into(),
    };
    let draft = drafted(world, trigger, comment_graph(account)).await;
    published(world, &draft).await
}

/// The comment reads its work-item id from the trigger and writes to Web.
fn comment_graph(account: &str) -> Graph {
    let comment = action(
        Action {
            integration: "azure-devops",
            operation: "comment-on-work-item",
        },
        account,
        "communicate",
        vec![
            ("project", written("Web")),
            ("id", read("trigger.work_item.id")),
            ("text", written("Thanks, we are on it.")),
        ],
    );
    Graph {
        nodes: vec![comment],
        edges: vec![],
    }
}

/// Publishing registers exactly one hook for Web and names its delivery address.
fn registered_hook(azure: &CannedApp) -> String {
    let subscribed: Vec<_> = azure
        .received()
        .into_iter()
        .filter(|call| call.path == SUBSCRIPTIONS)
        .collect();
    assert_eq!(
        subscribed.len(),
        1,
        "publishing subscribed one service hook"
    );
    let hook = subscribed[0].json();
    assert_eq!(hook["publisherInputs"]["projectId"], "web-project");
    hook["consumerInputs"]["url"]
        .as_str()
        .expect("the hook names the platform's address")
        .to_owned()
}

/// The hook refuses a delivery without its secret and accepts Azure's authenticated delivery.
async fn deliver_created(stack: &Stack, address: &str) {
    let secret_path = path_and_query(address);
    let bare_path = secret_path
        .split_once('?')
        .map_or(secret_path.as_str(), |(path, _)| path)
        .to_owned();

    let sender = Client::new(stack, "azure").expect("Azure DevOps's client");
    let mallory = Client::new(stack, "mallory").expect("Mallory's client");
    let created = created().to_string();
    delivered(&mallory, &bare_path, &created)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let taken = delivered(&sender, &secret_path, &created).await;
    assert_eq!(taken.status(), Status::NO_CONTENT);
}

/// The accepted event produces one comment while the grant and hook secret stay out of audit details.
async fn check_created_run(world: &World<'_>, azure: &CannedApp, workflow_id: &str, address: &str) {
    let runs = runs_started(world, workflow_id).await;
    ended(world, &runs[0].id, "succeeded").await;
    assert_eq!(azure.asked_for(COMMENTS), 1, "the run commented on bug 42");
    let secret = address
        .split("token=")
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[GRANT, &secret]);
    }
}

/// The Microsoft and Azure DevOps stand-in: it issues tokens and grants,
/// lists and finds projects, subscribes hooks and takes comments.
async fn azure() -> CannedApp {
    CannedApp::start([
        (
            TOKEN_PATH,
            Canned::json(&json!({
                "access_token": "an hour's token",
                "refresh_token": GRANT,
                "expires_in": 3600
            })),
        ),
        (PROJECTS, Canned::json(&json!({ "count": 1, "value": [] }))),
        (
            WEB,
            Canned::json(&json!({ "id": "web-project", "name": "Web" })),
        ),
        (SUBSCRIPTIONS, Canned::json(&json!({ "id": "sub-1" }))),
        (COMMENTS, Canned::json(&json!({ "id": 7 }))),
    ])
    .await
    .expect("the Azure DevOps stand-in starts")
}

/// The standard deployment with the platform's Entra app at `azure`.
fn profile(azure: &CannedApp) -> Profile {
    let base = azure.url().trim_end_matches('/').to_owned();
    Profile::standard()
        .with("AZURE_DEVOPS_API_URL", &format!("{base}/"))
        .with("AZURE_DEVOPS_CLIENT_ID", CLIENT_ID)
        .with("AZURE_DEVOPS_CLIENT_SECRET", CLIENT_SECRET)
        .with("AZURE_DEVOPS_AUTHORIZE_URL", &format!("{base}/authorize"))
        .with("AZURE_DEVOPS_TOKEN_URL", &format!("{base}{TOKEN_PATH}"))
}

/// Pat's bug 42 created in Web, as Azure DevOps sends it.
fn created() -> serde_json::Value {
    json!({
        "id": "event-bug-42",
        "eventType": "workitem.created",
        "resource": {
            "id": 42,
            "fields": {
                "System.Title": "Login fails",
                "System.WorkItemType": "Bug",
                "System.State": "New",
                "System.TeamProject": "Web"
            },
            "_links": { "html": { "href": "https://dev.azure.com/acme/Web/_workitems/edit/42" } }
        }
    })
}

/// `body` delivered to `path` as Azure DevOps sends it.
async fn delivered(client: &Client, path: &str, body: &str) -> Answer<String> {
    workflows::deliver_event(&ServiceDelivery {
        path,
        content_type: "application/json",
        headers: &[],
        body,
    })
    .send_text(client)
    .await
}
