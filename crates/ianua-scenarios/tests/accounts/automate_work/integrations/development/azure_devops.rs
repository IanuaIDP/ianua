//! Azure DevOps as a workflow step: Tess connects the team's organization
//! and personal access token, which Azure DevOps is asked about first, and
//! Ann publishes a workflow that files a bug and comments on it. A stand-in
//! for Azure DevOps shows what arrived: the organization in the address,
//! the token as a password, the bug's fields as a JSON Patch, and the
//! comment on the bug the first step filed.

use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::{Edge, Graph, Node, Trigger};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{
    Action, account_at, action, drafted, ended, published, read, started, written,
};

/// The account the team connects: its organization and a token written as
/// a sentence, so no scanner takes it for a key.
const ACCOUNT: &str =
    r#"{"organization": "acme", "token": "acme azure devops token for workflows"}"#;

/// Where Azure DevOps says the token works.
const PROJECTS: &str = "/acme/_apis/projects";

/// Where a bug is filed in the Web project.
const NEW_BUG: &str = "/acme/Web/_apis/wit/workitems/$Bug";

/// Where the comment goes: on work item 42, which the stand-in files.
const COMMENTS: &str = "/acme/Web/_apis/wit/workItems/42/comments";

/// Tess connects the organization's token, which Azure DevOps vouches for.
/// Ann publishes a workflow filing a bug in the Web project and commenting
/// on it, the comment step reading the bug's number from the first step's
/// answer. Tess runs it: Azure DevOps receives the bug as a JSON Patch at
/// the organization and the comment on bug 42, both signed with the token,
/// and the run succeeds.
#[tokio::test]
async fn a_run_files_a_bug_and_comments_on_it() {
    let azure = CannedApp::start([
        (PROJECTS, Canned::json(&json!({ "count": 1 }))),
        (NEW_BUG, Canned::json(&json!({ "id": 42 }))),
        (COMMENTS, Canned::json(&json!({ "id": 7 }))),
    ])
    .await
    .expect("the Azure DevOps stand-in starts");
    let profile = Profile::standard().with("AZURE_DEVOPS_API_URL", &format!("{}/", azure.url()));
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "azure-devops", ACCOUNT).await;
    assert_eq!(
        azure.asked_for(PROJECTS),
        1,
        "Azure DevOps was asked about the token"
    );
    let draft = drafted(&world, Trigger::Manual, bug_graph(&account)).await;
    let workflow = published(&world, &draft).await;
    let decided = started(&world, &workflow).await;
    ended(&world, &decided.execution_id, "succeeded").await;
    check_bug_delivery(&azure);
    stack.stop().await.expect("the stack stops cleanly");
}

/// Filing a bug is followed by a comment using the resulting work-item id.
fn bug_graph(account: &str) -> Graph {
    let file = file_bug(account);
    let comment = action(
        Action {
            integration: "azure-devops",
            operation: "comment-on-work-item",
        },
        account,
        "communicate",
        vec![
            ("project", written("Web")),
            ("id", read("azure-devops-create-work-item.json.id")),
            ("text", written("Rolled back; looking into it.")),
        ],
    );
    Graph {
        edges: vec![Edge {
            from: file.key.clone(),
            to: comment.key.clone(),
        }],
        nodes: vec![file, comment],
    }
}

/// The bug step writes its title and tags in the team's Web project.
fn file_bug(account: &str) -> Node {
    action(
        Action {
            integration: "azure-devops",
            operation: "create-work-item",
        },
        account,
        "write",
        vec![
            ("project", written("Web")),
            ("type", written("Bug")),
            ("title", written("Login fails after the release")),
            ("tags", written("release; urgent")),
        ],
    )
}

/// Azure receives the authenticated JSON Patch and a comment on the returned work item.
fn check_bug_delivery(azure: &CannedApp) {
    let received = azure.received();
    let bug = received
        .iter()
        .find(|call| call.path == NEW_BUG)
        .expect("the bug was filed");
    assert_eq!(
        bug.header("content-type"),
        Some("application/json-patch+json")
    );
    assert!(
        bug.header("authorization")
            .is_some_and(|value| value.starts_with("Basic ")),
        "the token went as a password"
    );
    assert_eq!(
        bug.json(),
        json!([
            { "op": "add", "path": "/fields/System.Title", "value": "Login fails after the release" },
            { "op": "add", "path": "/fields/System.Tags", "value": "release; urgent" }
        ])
    );
    let note = received
        .iter()
        .find(|call| call.path == COMMENTS)
        .expect("the comment went to the bug the first step filed");
    assert_eq!(
        note.json(),
        json!({ "text": "Rolled back; looking into it." })
    );
}
