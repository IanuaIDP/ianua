//! Asana as a workflow step: Tess connects the team's personal access
//! token, which Asana is asked about first, and Ann publishes a workflow
//! that creates a task and comments on it. A stand-in for Asana's API
//! shows what arrived: the token, and each body wrapped in `data` as Asana
//! reads it, the comment on the task Asana gave its gid. A token Asana
//! refuses is never connected, and a task Asana refuses fails the run.

use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::Graph;
use ianua_scenarios::world::World;
use serde_json::json;

use crate::integrations::calls::{Offered, chain, failed_step, never_connected, only_call, ran};
use crate::support::{Action, account_at, action, read, written};

/// The team's token: a sentence, so no scanner takes it for a key.
const TOKEN: &str = "acme asana token for workflows";

/// Where Asana says whose a token is.
const ME: &str = "/users/me";

/// Where a task is created.
const TASKS: &str = "/tasks";

/// Where the comment goes: on the task Asana gave the gid 1204567890123456.
const STORIES: &str = "/tasks/1204567890123456/stories";

/// Tess connects the token, which Asana is asked about once. Ann publishes
/// a workflow creating the contract renewal task in Acme's workspace and
/// commenting on it by the gid Asana answered with. Tess runs it: Asana
/// receives the task and the comment, each wrapped in `data` and signed
/// with the token, and the run succeeds. The token is nowhere in the trail.
#[tokio::test]
async fn a_run_creates_a_task_and_comments_on_it() {
    let asana = asana_answering(Canned::json(&json!({
        "data": { "gid": "1204567890123456", "name": "Renew the support contract" }
    })))
    .await;
    let stack = Stack::start(profile(&asana))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "asana", TOKEN).await;
    let asked = only_call(&asana, "GET", ME);
    assert_eq!(
        asked.header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    ran(&world, task_graph(&account), "succeeded").await;
    check_task_and_comment(&asana);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[TOKEN]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Asana refuses the task with 403, as for a workspace the token cannot
/// reach. The task step and the run fail after one request, and no
/// comment is posted.
#[tokio::test]
async fn a_task_asana_refuses_fails_the_run() {
    let asana = asana_answering(Canned::refusing(403)).await;
    let stack = Stack::start(profile(&asana))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "asana", TOKEN).await;

    let run = ran(&world, task_graph(&account), "failed").await;

    failed_step(&run, "asana-create-task");
    assert_eq!(asana.asked_for(TASKS), 1, "a refusal is not tried again");
    assert_eq!(
        asana.asked_for(STORIES),
        0,
        "nothing was said on a missing task"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Asana does not know Tess's mistyped token: asked once, it answers 401,
/// and no account is connected.
#[tokio::test]
async fn a_token_asana_refuses_is_never_connected() {
    let asana = CannedApp::start([(ME, Canned::refusing(401))])
        .await
        .expect("the Asana stand-in starts");
    let stack = Stack::start(profile(&asana))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let offered = Offered {
        integration: "asana",
        credential: "a mistyped asana token",
    };

    never_connected(&world, offered).await;

    assert_eq!(asana.asked_for(ME), 1, "Asana was asked about the token");
    stack.stop().await.expect("the stack stops cleanly");
}

/// The workflow creates a task in Acme's workspace and comments on it by
/// the gid Asana gave back.
fn task_graph(account: &str) -> Graph {
    let create = action(
        Action {
            integration: "asana",
            operation: "create-task",
        },
        account,
        "write",
        vec![
            ("workspace", written("1100000000000001")),
            ("name", written("Renew the support contract")),
            ("notes", written("The contract ends in December.")),
        ],
    );
    let comment = action(
        Action {
            integration: "asana",
            operation: "comment-on-task",
        },
        account,
        "communicate",
        vec![
            ("task", read("asana-create-task.json.data.gid")),
            ("text", written("Legal has the draft.")),
        ],
    );
    chain(vec![create, comment])
}

/// Asana received the task and the comment on it, each signed with the
/// token and wrapped in `data`.
fn check_task_and_comment(asana: &CannedApp) {
    let task = only_call(asana, "POST", TASKS);
    let comment = only_call(asana, "POST", STORIES);
    for call in [&task, &comment] {
        assert_eq!(
            call.header("authorization"),
            Some(format!("Bearer {TOKEN}").as_str())
        );
        assert_eq!(call.header("accept"), Some("application/json"));
    }
    assert_eq!(
        task.json(),
        json!({ "data": {
            "workspace": "1100000000000001",
            "name": "Renew the support contract",
            "notes": "The contract ends in December."
        } })
    );
    assert_eq!(
        comment.json(),
        json!({ "data": { "text": "Legal has the draft." } })
    );
}

/// An Asana stand-in that knows the token, answers a new task with `task`,
/// and takes any comment.
async fn asana_answering(task: Canned) -> CannedApp {
    CannedApp::start([
        (
            ME,
            Canned::json(&json!({ "data": { "gid": "42", "name": "Tess" } })),
        ),
        (TASKS, task),
        (STORIES, Canned::json(&json!({ "data": { "gid": "77" } }))),
    ])
    .await
    .expect("the Asana stand-in starts")
}

/// The standard deployment, its Asana steps calling `asana`.
fn profile(asana: &CannedApp) -> Profile {
    Profile::standard().with("ASANA_API_URL", &asana.url())
}
