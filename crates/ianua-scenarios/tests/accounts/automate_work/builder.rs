//! The workflow builder: GitHub's forms fill their lists from the team's
//! own repositories and labels through a stand-in for GitHub, and a test
//! of a draft that is never published reads for real, stands in for the
//! step that would open an issue, and stays apart from real runs.

use ianua_scenarios::api::workflows::{self, PickedInput};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::workflows::{
    Choices, Edge, Execution, ExecutionSummary, Graph, Integration, ListChoices, Operation,
    StartExecution, StepData, Trigger,
};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{Action, account_at, action, drafted, ended, read, written};

/// The token the team's GitHub account holds: a sentence, so no scanner
/// takes it for a key.
const TOKEN: &str = "acme github token for the builder";

/// Where GitHub says whose a token is.
const WHO: &str = "/user";

/// Where GitHub lists the repositories the token reaches.
const REPOSITORIES: &str = "/user/repos";

/// Where GitHub lists acme/web's labels.
const LABELS: &str = "/repos/acme/web/labels";

/// Where GitHub answers issue 7 of acme/web.
const ISSUE: &str = "/repos/acme/web/issues/7";

/// Where an issue of acme/web would be opened.
const ISSUES: &str = "/repos/acme/web/issues";

/// Tess opens GitHub's "open an issue" form. The catalog says GitHub is
/// drawn in its own colour, that the repository and labels are picked
/// from lists, the labels once a repository is chosen, and that the step
/// is previewed as an issue. Her repository list comes from the team's
/// account, then acme/web's labels. A stranger from another company cannot
/// read the list, and an input with no list returns not found.
#[tokio::test]
async fn githubs_form_fills_its_lists_from_the_teams_account() {
    let github = github_forms().await;
    let profile = Profile::standard().with("GITHUB_API_URL", &github.url());
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "github", TOKEN).await;
    let integrations = workflows::integrations(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let operations = workflows::operations(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let repositories = list_choices(&world, &account, "repository", None).await;
    let labels = list_choices(&world, &account, "labels", Some(json!("acme/web"))).await;
    check_github_form(&integrations, &operations);
    check_choices(&github, &repositories, &labels);
    refuse_unavailable_choices(&world, &account).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// GitHub lists the connected account's repositories and the selected repository's labels.
async fn github_forms() -> CannedApp {
    CannedApp::start([
        (WHO, Canned::json(&json!({ "login": "acme-bot" }))),
        (
            REPOSITORIES,
            Canned::json(&json!([{ "full_name": "acme/web" }, { "full_name": "acme/api" }])),
        ),
        (
            LABELS,
            Canned::json(&json!([{ "name": "bug" }, { "name": "urgent" }])),
        ),
    ])
    .await
    .expect("the GitHub stand-in starts")
}

/// Loads one GitHub issue picker using the connected account and its selected dependency.
async fn list_choices(
    world: &World<'_>,
    account: &str,
    input: &str,
    depends_on: Option<serde_json::Value>,
) -> Choices {
    workflows::choices(
        world.tenant(),
        &PickedInput {
            integration: "github",
            operation: "create-issue",
            input,
        },
        &ListChoices {
            account_id: account.to_owned(),
            depends_on,
        },
    )
    .send(world.admin().client())
    .await
    .ok()
}

/// GitHub supplies its brand and an issue form with dependent label choices.
fn check_github_form(integrations: &[Integration], operations: &[Operation]) {
    let github_listed = integrations
        .iter()
        .find(|integration| integration.key == "github")
        .expect("GitHub is listed");
    assert_eq!(github_listed.brand, "#24292f");
    let open = operations
        .iter()
        .find(|listed| listed.integration == "github" && listed.operation == "create-issue")
        .expect("opening an issue is listed");
    let form_of = |name: &str| {
        open.inputs
            .iter()
            .find(|input| input.name == name)
            .and_then(|input| input.form.clone())
            .unwrap_or_else(|| panic!("{name} has a form"))
    };
    let labels_form = form_of("labels");
    assert_eq!(labels_form.block, "multi_picker");
    let picker = labels_form.picker.expect("labels are picked from a list");
    assert_eq!(picker.filled_by, "list-labels");
    assert_eq!(picker.depends_on.as_deref(), Some("repository"));
    assert_eq!(form_of("body").block, "long_text");
    assert_eq!(form_of("assignees").group, "more_options");
    check_issue_preview(open);
}

/// Opening an issue previews its title as an issue card.
fn check_issue_preview(open: &Operation) {
    let preview = open
        .preview
        .clone()
        .expect("opening an issue has a preview");
    assert_eq!(preview.kind, "issue");
    assert!(
        preview
            .parts
            .iter()
            .any(|part| part.part == "title" && part.input == "title")
    );
}

/// Picker values match the team's data and all form reads remain read-only.
fn check_choices(github: &CannedApp, repositories: &Choices, labels: &Choices) {
    let picked: Vec<_> = repositories
        .choices
        .iter()
        .map(|choice| choice.value.as_str())
        .collect();
    assert_eq!(picked, ["acme/web", "acme/api"]);
    let named: Vec<_> = labels
        .choices
        .iter()
        .map(|choice| choice.label.as_str())
        .collect();
    assert_eq!(named, ["bug", "urgent"]);
    assert_eq!(
        github.asked_for(LABELS),
        1,
        "labels were read from acme/web"
    );
    assert!(
        github.received().iter().all(|call| call.method == "GET"),
        "filling a form never changed anything at GitHub"
    );
}

/// A stranger cannot fill the account's picker, and free text inputs have no choices endpoint.
async fn refuse_unavailable_choices(world: &World<'_>, account: &str) {
    let asked = ListChoices {
        account_id: account.to_owned(),
        depends_on: None,
    };
    Matrix::new(
        "filling a list",
        workflows::choices(
            world.tenant(),
            &PickedInput {
                integration: "github",
                operation: "create-issue",
                input: "repository",
            },
            &asked,
        )
        .call(),
    )
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .run()
    .await;
    check_title_has_no_list(world, &asked).await;
}

/// The issue title input has no list to load.
async fn check_title_has_no_list(world: &World<'_>, asked: &ListChoices) {
    let unlisted = workflows::choices(
        world.tenant(),
        &PickedInput {
            integration: "github",
            operation: "create-issue",
            input: "title",
        },
        asked,
    )
    .send(world.admin().client())
    .await;
    assert_eq!(unlisted.status(), Status::NOT_FOUND, "a title has no list");
}

/// Tess drafts a workflow that reads issue 7 of acme/web and opens a new
/// issue with its title, and tests it before anyone publishes it. GitHub
/// is asked for issue 7, so the title is real, but no issue is opened:
/// that step stands in and says the title it would have used. The test
/// shows only among the workflow's tests, never its runs, and may not be
/// started again. The builder shows the opening step may read the read
/// step's title.
#[tokio::test]
async fn a_test_reads_for_real_and_stands_in_for_what_would_change_github() {
    let github = github_issues().await;
    let profile = Profile::standard().with("GITHUB_API_URL", &github.url());
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "github", TOKEN).await;
    let draft = drafted(&world, Trigger::Manual, copy_issue(&account)).await;
    let example = StartExecution {
        input: json!({ "note": "example data" }),
        exposure: "internal".to_owned(),
    };
    let decided = workflows::start_test(world.tenant(), &draft.id, &example)
        .send(world.admin().client())
        .await
        .ok();
    let test = ended(&world, &decided.execution_id, "succeeded").await;
    let view = test_view(&world, &draft.id, &decided.execution_id).await;
    check_stand_in(&github, &test);
    check_test_listing(&view, &decided.execution_id);
    check_readable_title(&view.readable);
    stack.stop().await.expect("the stack stops cleanly");
}

/// GitHub can return the source issue and would accept a newly opened issue.
async fn github_issues() -> CannedApp {
    CannedApp::start([
        (WHO, Canned::json(&json!({ "login": "acme-bot" }))),
        (
            ISSUE,
            Canned::json(&json!({ "number": 7, "title": "Login fails on Safari" })),
        ),
        (ISSUES, Canned::json(&json!({ "number": 8 }))),
    ])
    .await
    .expect("the GitHub stand-in starts")
}

/// The write step copies its title from the preceding read's output.
fn copy_issue(account: &str) -> Graph {
    let look = action(
        Action {
            integration: "github",
            operation: "get-issue",
        },
        account,
        "read",
        vec![("repository", written("acme/web")), ("issue", written(7))],
    );
    let open = action(
        Action {
            integration: "github",
            operation: "create-issue",
        },
        account,
        "write",
        vec![
            ("repository", written("acme/web")),
            ("title", read("github-get-issue.json.title")),
        ],
    );
    Graph {
        edges: vec![Edge {
            from: look.key.clone(),
            to: open.key.clone(),
        }],
        nodes: vec![look, open],
    }
}

/// The builder's separate execution lists, retry response and available step data.
struct TestView {
    tests: Vec<ExecutionSummary>,
    runs: Vec<ExecutionSummary>,
    retry: Status,
    readable: Vec<StepData>,
}

/// Reads the draft's test listing, run listing, retry response and step data in that order.
async fn test_view(world: &World<'_>, workflow_id: &str, execution_id: &str) -> TestView {
    let tests = workflows::tests(world.tenant(), workflow_id)
        .send(world.admin().client())
        .await
        .ok();
    let runs = workflows::executions(world.tenant(), workflow_id)
        .send(world.admin().client())
        .await
        .ok();
    let again = workflows::retry(world.tenant(), execution_id)
        .send(world.admin().client())
        .await;
    let readable = workflows::step_data(world.tenant(), workflow_id)
        .send(world.admin().client())
        .await
        .ok();
    TestView {
        tests: tests.items,
        runs: runs.items,
        retry: again.status(),
        readable,
    }
}

/// Testing performs the real read while reporting the write's intended input without sending it.
fn check_stand_in(github: &CannedApp, test: &Execution) {
    assert_eq!(github.asked_for(ISSUE), 1, "the read ran for real");
    assert_eq!(github.asked_for(ISSUES), 0, "no issue was opened");
    let stood_in = test
        .steps
        .iter()
        .find(|step| step.key == "github-create-issue")
        .and_then(|step| step.output.clone())
        .expect("the opening step's output is readable");
    assert_eq!(stood_in["stood_in"], true);
    assert_eq!(stood_in["would_use"]["title"], "Login fails on Safari");
}

/// The completed test appears only among tests and cannot be retried.
fn check_test_listing(view: &TestView, execution_id: &str) {
    assert_eq!(
        view.tests
            .iter()
            .map(|listed| (listed.id.as_str(), listed.mode.as_str()))
            .collect::<Vec<_>>(),
        [(execution_id, "test")]
    );
    assert!(view.runs.is_empty(), "a test is no run");
    assert_eq!(view.retry, Status::CONFLICT, "a test is not started again");
}

/// The builder exposes the read step's title as an available input for opening the issue.
fn check_readable_title(readable: &[StepData]) {
    let opening = readable
        .iter()
        .find(|step| step.key == "github-create-issue")
        .expect("the opening step's data is listed");
    assert!(
        opening
            .earlier
            .iter()
            .filter(|source| source.source == "github-get-issue")
            .flat_map(|source| &source.values)
            .any(|value| value.path == "github-get-issue.json.title"),
        "the opening step may read the issue's title"
    );
}
