//! GitHub as a workflow step: Tess connects the team's GitHub token, which
//! GitHub is asked about first, Ann publishes a workflow that opens an
//! issue and comments on it, and a stand-in for GitHub's API shows what
//! arrived: the token, the title and the comment, and nothing anywhere
//! else. A token GitHub does not know is never connected.

use ianua_scenarios::api::workflows;
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::workflows::{
    Edge, Execution, Graph, NewAccount, Node, Publication, Step, Trigger,
};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{
    Action, account_at, action, drafted, ended, published, read, started, written,
};

/// The token the team's GitHub account holds: a sentence, so no scanner
/// takes it for a key.
const TOKEN: &str = "acme github token for workflows";

/// Where GitHub says whose a token is.
const WHO: &str = "/user";

/// Where the issue is opened.
const ISSUES: &str = "/repos/acme/web/issues";

/// Where the comment goes: the issue GitHub numbered 42.
const COMMENTS: &str = "/repos/acme/web/issues/42/comments";

/// Tess connects the team's GitHub token, and GitHub is asked whose it is
/// before it is kept. Ann publishes a workflow that opens an issue in
/// acme/web and then comments on issue 42. Tess runs it: GitHub receives
/// the issue and the comment, each carrying the token and asking for
/// GitHub's own format, and the run succeeds with GitHub's answer as the
/// step's output. The token is nowhere in the trail.
#[tokio::test]
async fn a_run_opens_an_issue_and_comments_through_the_teams_token() {
    let github = CannedApp::start([
        (WHO, Canned::json(&json!({ "login": "acme-bot" }))),
        (ISSUES, Canned::json(&json!({ "number": 42 }))),
        (COMMENTS, Canned::json(&json!({ "id": 7 }))),
    ])
    .await
    .expect("the GitHub stand-in starts");
    let profile = Profile::standard().with("GITHUB_API_URL", &github.url());
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "github", TOKEN).await;
    check_token_probe(&github);
    let draft = drafted(&world, Trigger::Manual, issue_graph(&account)).await;
    let workflow = published(&world, &draft).await;
    let decided = started(&world, &workflow).await;
    let run = ended(&world, &decided.execution_id, "succeeded").await;
    check_issue_delivery(&github);
    check_issue_output(&run);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[TOKEN]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Connecting the account makes exactly one authenticated identity probe.
fn check_token_probe(github: &CannedApp) {
    let asked = github.received();
    assert_eq!(asked.len(), 1, "GitHub was asked about the token once");
    assert_eq!(
        (asked[0].method.as_str(), asked[0].path.as_str()),
        ("GET", WHO)
    );
    assert_eq!(
        asked[0].header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
}

/// The workflow opens an issue and comments on the number returned by GitHub.
fn issue_graph(account: &str) -> Graph {
    let open = opening_step(account);
    let comment = action(
        Action {
            integration: "github",
            operation: "comment-on-issue",
        },
        account,
        "communicate",
        vec![
            ("repository", written("acme/web")),
            ("issue", read("github-create-issue.json.number")),
            ("body", written("Rolled back; looking into it.")),
        ],
    );
    Graph {
        edges: vec![Edge {
            from: open.key.clone(),
            to: comment.key.clone(),
        }],
        nodes: vec![open, comment],
    }
}

/// The first step files the failed-build issue in the team's repository.
fn opening_step(account: &str) -> Node {
    action(
        Action {
            integration: "github",
            operation: "create-issue",
        },
        account,
        "write",
        vec![
            ("repository", written("acme/web")),
            ("title", written("Nightly build failed")),
            (
                "body",
                written("The deploy job stopped at the database step."),
            ),
        ],
    )
}

/// GitHub receives one authenticated issue and one comment on that issue with the expected bodies.
fn check_issue_delivery(github: &CannedApp) {
    let received: Vec<_> = github
        .received()
        .into_iter()
        .filter(|call| call.path != WHO)
        .collect();
    assert_eq!(received.len(), 2, "GitHub was called once per step");
    let (issue, note) = (&received[0], &received[1]);
    assert_eq!(
        (issue.method.as_str(), issue.path.as_str()),
        ("POST", ISSUES)
    );
    assert_eq!(
        note.path, COMMENTS,
        "the comment went to the issue the first step opened, read from its output"
    );
    for call in &received {
        assert_eq!(
            call.header("authorization"),
            Some(format!("Bearer {TOKEN}").as_str())
        );
        assert_eq!(call.header("accept"), Some("application/vnd.github+json"));
    }
    assert_eq!(issue.json()["title"], "Nightly build failed");
    assert_eq!(
        note.json(),
        json!({ "body": "Rolled back; looking into it." })
    );
}

/// The issue step exposes GitHub's assigned issue number to subsequent steps.
fn check_issue_output(run: &Execution) {
    let output = run
        .steps
        .iter()
        .find(|step| step.key == "github-create-issue")
        .and_then(|step| step.output.clone())
        .expect("the issue step's output is readable");
    assert_eq!(
        output["json"]["number"], 42,
        "GitHub's answer is the output"
    );
}

/// Ann cannot publish Tess's branch-deletion workflow without an approval
/// step. With an approval for deletes right before the deletion, the workflow is
/// published.
#[tokio::test]
async fn a_github_delete_must_wait_for_an_approval() {
    let github = CannedApp::start([(WHO, Canned::json(&json!({ "login": "acme-bot" })))])
        .await
        .expect("the GitHub stand-in starts");
    let profile = Profile::standard().with("GITHUB_API_URL", &github.url());
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "github", TOKEN).await;
    let delete = delete_step(&account);
    refuse_unguarded_delete(&world, &delete).await;
    let draft = drafted(&world, Trigger::Manual, guarded_delete(delete)).await;
    published(&world, &draft).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// The destructive operation names the branch that publication must protect.
fn delete_step(account: &str) -> Node {
    action(
        Action {
            integration: "github",
            operation: "delete-branch",
        },
        account,
        "delete",
        vec![
            ("repository", written("acme/web")),
            ("branch", written("feature/login")),
        ],
    )
}

/// Publication refuses the branch deletion when the graph lacks an approval.
async fn refuse_unguarded_delete(world: &World<'_>, delete: &Node) {
    let unguarded = Graph {
        nodes: vec![delete.clone()],
        edges: vec![],
    };

    let draft = drafted(world, Trigger::Manual, unguarded).await;
    workflows::publish(
        world.tenant(),
        &draft.id,
        &Publication {
            revision: draft.revision.clone(),
        },
    )
    .send(world.owner().client())
    .await
    .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
}

/// An approval of the delete effect immediately precedes branch deletion.
fn guarded_delete(delete: Node) -> Graph {
    let approval = Node {
        key: "approve-delete".to_owned(),
        name: "Approve deleting the branch".to_owned(),
        step: Step::Approval {
            summary: "Delete feature/login in acme/web".to_owned(),
            action_class: "delete".to_owned(),
            window_seconds: 120,
        },
    };
    Graph {
        edges: vec![Edge {
            from: approval.key.clone(),
            to: delete.key.clone(),
        }],
        nodes: vec![approval, delete],
    }
}

/// GitHub rejects Tess's token, so connecting the account fails without
/// adding an account-connected audit record. Max lacks permission to connect
/// accounts and is refused before any request reaches GitHub.
#[tokio::test]
async fn a_token_github_refuses_is_never_connected() {
    let github = CannedApp::start([(WHO, Canned::refusing(401))])
        .await
        .expect("the GitHub stand-in starts");
    let profile = Profile::standard().with("GITHUB_API_URL", &github.url());
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let before = world.trail().count("workflows.account_connected").await;
    let account = NewAccount {
        integration: "github".to_owned(),
        name: "Mistyped GitHub account".to_owned(),
        credential: "a mistyped github token".to_owned(),
        sharing: "tenant".to_owned(),
    };

    refuse_account(&world, &github, &account).await;
    assert_eq!(
        world.trail().count("workflows.account_connected").await,
        before,
        "no account was connected"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max's attempt never reaches GitHub, while Tess's attempt is refused by its token probe.
async fn refuse_account(world: &World<'_>, github: &CannedApp, account: &NewAccount) {
    workflows::connect_account(world.tenant(), account)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    assert!(
        github.received().is_empty(),
        "Max's attempt never reached GitHub"
    );
    workflows::connect_account(world.tenant(), account)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    assert_eq!(github.asked_for(WHO), 1, "GitHub was asked once, for Tess");
}
