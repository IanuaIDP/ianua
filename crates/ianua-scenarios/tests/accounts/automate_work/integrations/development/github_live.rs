//! GitHub for real: the whole platform against GitHub's own API, in a
//! throwaway repository, with a token that reaches only that repository.
//! It proves what a stand-in cannot: that GitHub takes what the steps send.
//!
//! It is ignored unless asked for, since it needs the internet, a token
//! and a repository nobody minds issues in. Run it with:
//!
//! ```text
//! IANUA_SCENARIO_GITHUB_TOKEN=... \
//! IANUA_SCENARIO_GITHUB_REPOSITORY=owner/sandbox \
//!   cargo nextest run <the scenarios' packages> --test automate_work \
//!   --run-ignored only -E 'test(/github_live/)'
//! ```
//!
//! The token is a fine-grained one for that repository alone, with read and
//! write on issues. Each run leaves one closed issue behind, since GitHub
//! lets no token delete an issue.

use ianua_scenarios::api::workflows;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::workflows::{Edge, Execution, Graph, NewAccount, Node, Trigger};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{
    Action, account_at, action, drafted, ended, published, read, started, written,
};

/// The setting holding the sandbox token.
const TOKEN: &str = "IANUA_SCENARIO_GITHUB_TOKEN";

/// The setting naming the sandbox repository, as owner/name.
const REPOSITORY: &str = "IANUA_SCENARIO_GITHUB_REPOSITORY";

/// The label every run puts on its issue, so its issues are found together.
const LABEL: &str = "ianua-scenario";

/// The setting `name`, which a live run needs.
///
/// # Panics
///
/// When it is not set: the run was asked for without what it needs.
fn needed(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is needed for the live GitHub run"))
}

/// Tess connects the sandbox token, which GitHub itself vouches for, and a
/// token GitHub does not know is refused by GitHub. Ann publishes a
/// workflow that opens an issue, comments on it, labels it, closes it as
/// completed and reads it back, each step reading the issue's number from
/// the first step's answer. The run succeeds, and GitHub's own answer says
/// the issue is closed, labelled and commented on.
#[tokio::test]
#[ignore = "needs the internet, IANUA_SCENARIO_GITHUB_TOKEN and IANUA_SCENARIO_GITHUB_REPOSITORY"]
async fn github_live_a_workflow_runs_an_issue_through_its_life_on_github() {
    let token = needed(TOKEN);
    let repository = needed(REPOSITORY);
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    refuse_invalid_token(&world).await;
    let account = account_at(&world, "github", &token).await;
    let title = format!("Scenario run {}", uuid::Uuid::new_v4().simple());
    let draft = drafted(
        &world,
        Trigger::Manual,
        issue_lifecycle(&account, &repository, &title),
    )
    .await;
    let workflow = published(&world, &draft).await;
    let decided = started(&world, &workflow).await;
    let run = ended(&world, &decided.execution_id, "succeeded").await;
    check_live_issue(&run, &title);
    stack.stop().await.expect("the stack stops cleanly");
}

/// GitHub refuses an invalid account token before the real connection is made.
async fn refuse_invalid_token(world: &World<'_>) {
    let refused = NewAccount {
        integration: "github".to_owned(),
        name: "Not a token".to_owned(),
        credential: "not a real github token".to_owned(),
        sharing: "tenant".to_owned(),
    };
    workflows::connect_account(world.tenant(), &refused)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
}

/// The issue is opened, commented on, labelled, closed and read back in that order.
fn issue_lifecycle(account: &str, repository: &str, title: &str) -> Graph {
    in_a_line(vec![
        open_issue(account, repository, title),
        comment_issue(account, repository),
        label_issue(account, repository),
        close_issue(account, repository),
        read_issue(account, repository),
    ])
}

/// The live run opens a uniquely named issue in its configured repository.
fn open_issue(account: &str, repository: &str, title: &str) -> Node {
    action(
        Action {
            integration: "github",
            operation: "create-issue",
        },
        account,
        "write",
        vec![
            ("repository", written(repository)),
            ("title", written(title)),
            ("body", written("Opened by the platform's live scenario.")),
        ],
    )
}

/// The comment targets the issue opened by the first step.
fn comment_issue(account: &str, repository: &str) -> Node {
    action(
        Action {
            integration: "github",
            operation: "comment-on-issue",
        },
        account,
        "communicate",
        vec![
            ("repository", written(repository)),
            ("issue", read("github-create-issue.json.number")),
            ("body", written("Commented on by the same run.")),
        ],
    )
}

/// The label groups this run's issue with other live scenario issues.
fn label_issue(account: &str, repository: &str) -> Node {
    action(
        Action {
            integration: "github",
            operation: "add-labels",
        },
        account,
        "write",
        vec![
            ("repository", written(repository)),
            ("issue", read("github-create-issue.json.number")),
            ("labels", written(json!([LABEL]))),
        ],
    )
}

/// Closing the issue leaves the disposable repository with no open scenario issue.
fn close_issue(account: &str, repository: &str) -> Node {
    action(
        Action {
            integration: "github",
            operation: "close-issue",
        },
        account,
        "write",
        vec![
            ("repository", written(repository)),
            ("issue", read("github-create-issue.json.number")),
            ("reason", written("completed")),
        ],
    )
}

/// The final read reports GitHub's actual state after all preceding changes.
fn read_issue(account: &str, repository: &str) -> Node {
    action(
        Action {
            integration: "github",
            operation: "get-issue",
        },
        account,
        "read",
        vec![
            ("repository", written(repository)),
            ("issue", read("github-create-issue.json.number")),
        ],
    )
}

/// GitHub's own responses show the named issue closed, labelled and commented on.
fn check_live_issue(run: &Execution, title: &str) {
    let output = |key: &str| {
        run.steps
            .iter()
            .find(|step| step.key == key)
            .and_then(|step| step.output.clone())
            .unwrap_or_else(|| panic!("{key}'s output is readable"))
    };
    let read_back = output("github-get-issue");
    assert_eq!(read_back["json"]["title"], title, "GitHub has the issue");
    assert_eq!(read_back["json"]["state"], "closed", "GitHub closed it");
    let labels = read_back["json"]["labels"]
        .as_array()
        .expect("the labels are listed");
    assert!(
        labels.iter().any(|label| label["name"] == LABEL),
        "GitHub put the label on it: {labels:?}"
    );
    assert!(
        output("github-comment-on-issue")["json"]["html_url"].is_string(),
        "GitHub made the comment"
    );
}

/// `steps` run one after another, in the order given.
fn in_a_line(steps: Vec<Node>) -> Graph {
    let edges = steps
        .windows(2)
        .map(|pair| Edge {
            from: pair[0].key.clone(),
            to: pair[1].key.clone(),
        })
        .collect();
    Graph {
        nodes: steps,
        edges,
    }
}
