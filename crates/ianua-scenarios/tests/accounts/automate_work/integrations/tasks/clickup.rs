//! ClickUp as a workflow step: Tess connects the team's personal token,
//! which ClickUp is asked about first, and Ann publishes a workflow that
//! creates a task in a list and comments on it. A stand-in for ClickUp's
//! API shows what arrived: the token alone in `Authorization`, as ClickUp
//! takes it, the task in the list named in the address, and the comment on
//! the task ClickUp gave its id, telling only the people the task names. A
//! token ClickUp refuses is never connected, and a task ClickUp refuses
//! fails the run.

use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::Graph;
use ianua_scenarios::world::World;
use serde_json::json;

use crate::integrations::calls::{Offered, chain, failed_step, never_connected, only_call, ran};
use crate::support::{Action, account_at, action, read, written};

/// The team's token: a sentence, so no scanner takes it for a key.
const TOKEN: &str = "acme clickup token for workflows";

/// Where ClickUp says whose a token is.
const WHO: &str = "/user";

/// Where a task is created in list 901234567.
const TASKS: &str = "/list/901234567/task";

/// Where the comment goes: on the task ClickUp gave the id 86b1x2y3z.
const COMMENTS: &str = "/task/86b1x2y3z/comment";

/// Tess connects the token, which ClickUp is asked about once. Ann
/// publishes a workflow creating the contract renewal task in list
/// 901234567 and commenting on it by the id ClickUp answered with. Tess
/// runs it: ClickUp receives the task with its description in Markdown and
/// the comment, each with the token alone in `Authorization`, and the run
/// succeeds. The token is nowhere in the trail.
#[tokio::test]
async fn a_run_creates_a_task_and_comments_on_it() {
    let clickup = clickup_answering(Canned::json(
        &json!({ "id": "86b1x2y3z", "name": "Renew the support contract" }),
    ))
    .await;
    let stack = Stack::start(profile(&clickup))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "clickup", TOKEN).await;
    assert_eq!(
        only_call(&clickup, "GET", WHO).header("authorization"),
        Some(TOKEN)
    );
    ran(&world, task_graph(&account), "succeeded").await;
    check_task_and_comment(&clickup);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[TOKEN]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// ClickUp refuses the task with 401, as for a list the token cannot
/// reach. The task step and the run fail after one request, and no
/// comment is posted.
#[tokio::test]
async fn a_task_clickup_refuses_fails_the_run() {
    let clickup = clickup_answering(Canned::refusing(401)).await;
    let stack = Stack::start(profile(&clickup))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "clickup", TOKEN).await;

    let run = ran(&world, task_graph(&account), "failed").await;

    failed_step(&run, "clickup-create-task");
    assert_eq!(clickup.asked_for(TASKS), 1, "a refusal is not tried again");
    assert_eq!(
        clickup.asked_for(COMMENTS),
        0,
        "nothing was said on a missing task"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// ClickUp does not know Tess's mistyped token: asked once, it answers
/// 401, and no account is connected.
#[tokio::test]
async fn a_token_clickup_refuses_is_never_connected() {
    let clickup = CannedApp::start([(WHO, Canned::refusing(401))])
        .await
        .expect("the ClickUp stand-in starts");
    let stack = Stack::start(profile(&clickup))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let offered = Offered {
        integration: "clickup",
        credential: "a mistyped clickup token",
    };

    never_connected(&world, offered).await;

    assert_eq!(
        clickup.asked_for(WHO),
        1,
        "ClickUp was asked about the token"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The workflow creates a task in list 901234567 and comments on it by the
/// id ClickUp gave back.
fn task_graph(account: &str) -> Graph {
    let create = action(
        Action {
            integration: "clickup",
            operation: "create-task",
        },
        account,
        "write",
        vec![
            ("list", written("901234567")),
            ("name", written("Renew the support contract")),
            ("description", written("The contract ends in **December**.")),
        ],
    );
    let comment = action(
        Action {
            integration: "clickup",
            operation: "comment-on-task",
        },
        account,
        "communicate",
        vec![
            ("task", read("clickup-create-task.json.id")),
            ("text", written("Legal has the draft.")),
        ],
    );
    chain(vec![create, comment])
}

/// ClickUp received the task and the comment, each with the token alone,
/// the comment telling nobody but the task's own people.
fn check_task_and_comment(clickup: &CannedApp) {
    let task = only_call(clickup, "POST", TASKS);
    let comment = only_call(clickup, "POST", COMMENTS);
    for call in [&task, &comment] {
        assert_eq!(call.header("authorization"), Some(TOKEN));
    }
    assert_eq!(
        task.json(),
        json!({
            "name": "Renew the support contract",
            "markdown_content": "The contract ends in **December**."
        })
    );
    assert_eq!(
        comment.json(),
        json!({ "comment_text": "Legal has the draft.", "notify_all": false })
    );
}

/// A ClickUp stand-in that knows the token, answers a new task with
/// `task`, and takes any comment.
async fn clickup_answering(task: Canned) -> CannedApp {
    CannedApp::start([
        (
            WHO,
            Canned::json(&json!({ "user": { "id": 183, "username": "tess" } })),
        ),
        (TASKS, task),
        (COMMENTS, Canned::json(&json!({ "id": 458 }))),
    ])
    .await
    .expect("the ClickUp stand-in starts")
}

/// The standard deployment, its ClickUp steps calling `clickup`.
fn profile(clickup: &CannedApp) -> Profile {
    Profile::standard().with("CLICKUP_API_URL", &clickup.url())
}
