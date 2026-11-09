//! Suggesting keep or remove in an access review: Pat's workflow opens a
//! review of Support and puts a suggestion beside Lee, which Bea, the
//! reviewer, reads beside his name; nothing is decided for her.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{people, policies, workflows};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::policies::{NewGroup, NewGroupMember};
use ianua_scenarios::wire::workflows::{
    Edge, Execution, Graph, MappedField, Node, StartExecution, Step, Trigger,
};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{drafted, ended, invited, published, read, written};

/// The key of the step opening the review.
const OPEN_STEP: &str = "open";

/// The key of the step suggesting beside Lee.
const SUGGEST_STEP: &str = "suggest";

/// Why Pat's workflow suggests removing Lee.
const REASON: &str = "no Support app opened since June";

/// What Pat may do by hand: run workflows, find people, and read and
/// assign roles, which runs reviews.
const RUNS_REVIEWS: &[(&str, &str)] = &[
    ("Workflows", "View"),
    ("Workflows", "Run"),
    ("Users", "View"),
    ("Roles", "View"),
    ("Roles", "Assign"),
];

/// One company step `operation`, a write, given `inputs`.
fn company_step(key: &str, operation: &str, inputs: Vec<MappedField>) -> Node {
    Node {
        key: key.to_owned(),
        name: operation.to_owned(),
        step: Step::Action {
            integration: "ianua".to_owned(),
            operation: operation.to_owned(),
            account_id: None,
            effect: "write".to_owned(),
            ceiling: "internal".to_owned(),
            inputs,
        },
    }
}

/// A graph opening a review of the group `group_id` by the reviewer at
/// `reviewer`, then suggesting removing the person at `holder`.
fn reviewing(group_id: &str, reviewer: &str, holder: &str) -> Graph {
    let field = |field: &str, source| MappedField {
        field: field.to_owned(),
        source,
    };
    Graph {
        nodes: vec![
            company_step(
                OPEN_STEP,
                "open-review",
                vec![
                    field("group", written(group_id)),
                    field("reviewers", written(json!([reviewer]))),
                ],
            ),
            suggestion_step(holder),
        ],
        edges: vec![Edge {
            from: OPEN_STEP.to_owned(),
            to: SUGGEST_STEP.to_owned(),
        }],
    }
}

/// The suggestion names Lee in the review opened by the preceding step.
fn suggestion_step(holder: &str) -> Node {
    company_step(
        SUGGEST_STEP,
        "suggest-review",
        vec![
            MappedField {
                field: "review".to_owned(),
                source: read(&format!("{OPEN_STEP}.review_id")),
            },
            MappedField {
                field: "suggestions".to_owned(),
                source: written(json!([
                    {"person": holder, "suggest": "remove", "reason": REASON}
                ])),
            },
        ],
    )
}

/// Pat may run reviews. Her workflow opens a review of Support, where Lee
/// is a member, with Bea reviewing, and suggests removing Lee. Bea reads
/// the suggestion and its reason beside Lee's name, and Lee is still
/// undecided.
#[tokio::test]
async fn a_run_suggests_removing_lee_beside_his_name_in_bea_s_review() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), RUNS_REVIEWS).await;
    let lee = invited(&world, ("lee", "Lee Lost"), &[("Workflows", "View")]).await;
    let bea = invited(&world, ("bea", "Bea Reviewer"), &[("Workflows", "View")]).await;
    let lee_id = people::me(world.tenant()).send(lee.client()).await.ok().id;
    let support_id = create_support(&world, &lee_id).await;
    let graph = reviewing(&support_id, bea.email(), lee.email());
    let draft = drafted(&world, Trigger::Manual, graph).await;
    let workflow = published(&world, &draft).await;
    let start = StartExecution {
        input: json!({}),
        exposure: "internal".to_owned(),
    };
    let started = pat
        .send(workflows::start(world.tenant(), &workflow.id, &start))
        .await
        .ok();
    let run = ended(&world, &started.execution_id, "succeeded").await;
    check_suggestion(&world, &bea, &lee_id, &run).await;
}

/// Tess creates Support and adds Lee as the review's subject.
async fn create_support(world: &World<'_>, lee_id: &str) -> String {
    let support = policies::create_group(
        world.tenant(),
        &NewGroup {
            name: "Support".to_owned(),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    policies::add_member(
        world.tenant(),
        &support.id,
        &NewGroupMember {
            kind: "user".to_owned(),
            id: lee_id.to_owned(),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    support.id
}

/// The run suggests removing Lee with its reason while leaving Bea's decision unset.
async fn check_suggestion(world: &World<'_>, bea: &Person, lee_id: &str, run: &Execution) {
    let step = |key: &str| {
        run.steps
            .iter()
            .find(|step| step.key == key)
            .and_then(|step| step.output.clone())
            .expect("the step answered")
    };
    assert_eq!(step(SUGGEST_STEP)["suggested"].as_f64(), Some(1.0));
    let review_id = step(OPEN_STEP)["review_id"]
        .as_str()
        .expect("the review has an id")
        .to_owned();
    check_review_item(world, bea, lee_id, &review_id).await;
}

/// Bea reads the suggestion beside Lee and has not yet chosen what to do.
async fn check_review_item(world: &World<'_>, bea: &Person, lee_id: &str, review_id: &str) {
    let items = policies::review_items(world.tenant(), review_id)
        .send(bea.client())
        .await
        .ok();
    let lee_item = items
        .items
        .iter()
        .find(|item| item.holder.id == lee_id)
        .expect("the review lists Lee");
    let suggestion = lee_item
        .suggestion
        .as_ref()
        .expect("a suggestion sits beside Lee");
    assert_eq!(suggestion.choice, "remove");
    assert_eq!(suggestion.reason, REASON);
    assert_eq!(lee_item.choice, None, "nothing is decided for Bea");
}
