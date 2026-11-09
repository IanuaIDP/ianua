//! Linear as a workflow step: Tess connects the team's API key, which
//! Linear is asked about first with a query sent as a `GET`, and Ann
//! publishes a workflow that creates an issue and comments on it. Linear's
//! API is GraphQL alone, so a stand-in for it shows each step posted to
//! `graphql`: the key with nothing before it, the step's fixed document,
//! and its inputs among the variables. Linear refuses with success and an
//! `errors` list, which fails the run; a key Linear does not know is never
//! connected.

use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp, Received};
use ianua_scenarios::wire::workflows::Graph;
use ianua_scenarios::world::World;
use serde_json::json;

use crate::integrations::calls::{
    Offered, chain, failed_step, never_connected, only_call, output_of, ran,
};
use crate::support::{Action, account_at, action, read, written};

/// The team's API key: a sentence, so no scanner takes it for a key.
const KEY: &str = "acme linear key for workflows";

/// Where every Linear call goes.
const GRAPHQL: &str = "/graphql";

/// Tess connects the key, which Linear vouches for when asked who it
/// belongs to. Ann publishes a workflow creating an issue in the
/// engineering team and commenting on it, the comment naming the issue by
/// the identifier Linear gave it. Tess runs it: Linear receives two
/// mutations, each with the key alone in `Authorization`, and the run
/// succeeds. The key is nowhere in the trail.
#[tokio::test]
async fn a_run_creates_an_issue_and_comments_on_it() {
    let linear = linear_answering(Canned::json(&json!({
        "data": {
            "issueCreate": { "success": true, "issue": { "id": "issue-1", "identifier": "ENG-42" } },
            "commentCreate": { "success": true, "comment": { "id": "comment-1" } }
        }
    })))
    .await;
    let stack = Stack::start(profile(&linear))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "linear", KEY).await;
    check_probe(&linear);
    let run = ran(&world, issue_graph(&account), "succeeded").await;
    check_mutations(&linear);
    let created = output_of(&run, "linear-create-issue");
    assert_eq!(
        created["json"]["data"]["issueCreate"]["issue"]["identifier"],
        "ENG-42"
    );
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[KEY]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Linear answers the issue with success but an `errors` list naming a team
/// it does not have, as GraphQL refuses. The issue step and the run fail
/// after one request, and no comment is posted.
#[tokio::test]
async fn an_errors_list_linear_answers_with_success_fails_the_run() {
    let linear = linear_answering(Canned::json(&json!({
        "errors": [{ "message": "Entity not found: Team" }]
    })))
    .await;
    let stack = Stack::start(profile(&linear))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "linear", KEY).await;

    let run = ran(&world, issue_graph(&account), "failed").await;

    failed_step(&run, "linear-create-issue");
    assert_eq!(posted(&linear).len(), 1, "only the issue was asked for");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Linear does not know Tess's mistyped key: its query answers 401, and no
/// account is connected.
#[tokio::test]
async fn a_key_linear_refuses_is_never_connected() {
    let linear = CannedApp::start([(GRAPHQL, Canned::refusing(401))])
        .await
        .expect("the Linear stand-in starts");
    let stack = Stack::start(profile(&linear))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let offered = Offered {
        integration: "linear",
        credential: "a mistyped linear key",
    };

    never_connected(&world, offered).await;

    assert_eq!(
        linear.asked_for(GRAPHQL),
        1,
        "Linear was asked about the key"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Linear was asked once, by a `GET` query for the key's own person, with
/// the key alone in `Authorization`.
fn check_probe(linear: &CannedApp) {
    let asked = only_call(linear, "GET", GRAPHQL);
    assert_eq!(asked.header("authorization"), Some(KEY));
    assert!(
        asked
            .query_pairs()
            .iter()
            .any(|(name, value)| name == "query" && value.contains("viewer")),
        "the probe asks who the key belongs to: {:?}",
        asked.query
    );
}

/// The workflow creates an issue in the engineering team and comments on
/// it by the identifier Linear gave back.
fn issue_graph(account: &str) -> Graph {
    let create = action(
        Action {
            integration: "linear",
            operation: "create-issue",
        },
        account,
        "write",
        vec![
            ("team", written("team-eng")),
            ("title", written("Login fails on Safari")),
            ("description", written("Seen since the release.")),
        ],
    );
    let comment = action(
        Action {
            integration: "linear",
            operation: "comment-on-issue",
        },
        account,
        "communicate",
        vec![
            (
                "issue",
                read("linear-create-issue.json.data.issueCreate.issue.identifier"),
            ),
            ("body", written("Rolled back; looking into it.")),
        ],
    );
    chain(vec![create, comment])
}

/// Linear received the issue's mutation and then the comment's, each with
/// the key, Linear's preflight header and the inputs as variables.
fn check_mutations(linear: &CannedApp) {
    let posted = posted(linear);
    assert_eq!(posted.len(), 2, "one mutation per step");
    let (issue, comment) = (posted[0].json(), posted[1].json());
    for call in &posted {
        assert_eq!(call.header("authorization"), Some(KEY));
        assert_eq!(call.header("apollo-require-preflight"), Some("true"));
    }
    assert!(
        issue["query"]
            .as_str()
            .is_some_and(|text| text.starts_with("mutation IssueCreate"))
    );
    assert_eq!(
        issue["variables"],
        json!({ "input": {
            "teamId": "team-eng",
            "title": "Login fails on Safari",
            "description": "Seen since the release."
        } })
    );
    assert!(
        comment["query"]
            .as_str()
            .is_some_and(|text| text.starts_with("mutation CommentCreate"))
    );
    assert_eq!(
        comment["variables"],
        json!({ "input": { "issueId": "ENG-42", "body": "Rolled back; looking into it." } })
    );
}

/// Every mutation posted to Linear, oldest first.
fn posted(linear: &CannedApp) -> Vec<Received> {
    linear
        .received()
        .into_iter()
        .filter(|call| call.method == "POST" && call.path == GRAPHQL)
        .collect()
}

/// A Linear stand-in that tells the key's person to the probe and answers
/// every mutation with `answer`.
async fn linear_answering(answer: Canned) -> CannedApp {
    CannedApp::start([
        (
            "GET /graphql",
            Canned::json(&json!({ "data": { "viewer": { "id": "tess" } } })),
        ),
        ("POST /graphql", answer),
    ])
    .await
    .expect("the Linear stand-in starts")
}

/// The standard deployment, its Linear steps calling `linear`.
fn profile(linear: &CannedApp) -> Profile {
    Profile::standard().with("LINEAR_API_URL", &linear.url())
}
