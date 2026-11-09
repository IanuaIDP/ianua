//! Evaluations: Tess saves sample cases for her draft that delivers an
//! order to the outside service, each with checks of what the run hands
//! on, and evaluates the draft before anyone publishes it. Each case runs
//! as a test of the draft, so the outside service shows the reads it
//! really made while the workflow's live runs stay empty. A case the
//! draft satisfies passes; one expecting what the draft does not hand on
//! fails, saying which check and what it found. With the gate on, Ann may
//! publish only once the latest evaluation of the draft passed.

use ianua_scenarios::api::workflows;
use ianua_scenarios::expect::eventually;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::workflows::{
    CaseCheck, Evaluation, EvaluationCase, NewEvaluationSet, Publication, Trigger, Workflow,
};
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;
use serde_json::{Value, json};

use crate::service::Service;
use crate::support::{connected_account, delivery_graph, drafted};

/// Where the service's answer is read in the delivery step's output.
const DELIVERED_AT: &str = "deliver.json.delivered";

/// What the outside service answers every delivery with.
const DELIVERED: &str = "real outside service";

/// The gate holding publishing back until the last evaluation passed.
const MUST_PASS: &str = "must_pass";

/// A check that the value at `at` is exactly `value`.
fn equals(at: &str, value: Value) -> CaseCheck {
    CaseCheck {
        kind: "equals".to_owned(),
        at: at.to_owned(),
        value: Some(value),
        text: None,
        pattern: None,
    }
}

/// A check that the text at `at` contains `text`.
fn contains(at: &str, text: &str) -> CaseCheck {
    CaseCheck {
        kind: "contains".to_owned(),
        at: at.to_owned(),
        value: None,
        text: Some(text.to_owned()),
        pattern: None,
    }
}

/// A check that the whole text at `at` matches `pattern`.
fn matches(at: &str, pattern: &str) -> CaseCheck {
    CaseCheck {
        kind: "matches".to_owned(),
        at: at.to_owned(),
        value: None,
        text: None,
        pattern: Some(pattern.to_owned()),
    }
}

/// The case `name`, starting from Tess's usual order, held to `checks`.
fn case(name: &str, checks: Vec<CaseCheck>) -> EvaluationCase {
    EvaluationCase {
        name: name.to_owned(),
        input: json!({"order": "visible-order"}),
        exposure: "internal".to_owned(),
        checks,
    }
}

/// A case the draft passes: the order it started with, and the service's
/// answer read three ways.
fn delivered_case() -> EvaluationCase {
    case(
        "Order delivered",
        vec![
            equals("trigger.order", json!("visible-order")),
            contains(DELIVERED_AT, "outside"),
            matches(DELIVERED_AT, "real*serv?ce"),
        ],
    )
}

/// A case expecting a partner's service, which the draft never reaches.
fn partner_case() -> EvaluationCase {
    case(
        "Order reaches the partner",
        vec![equals(DELIVERED_AT, json!("partner service"))],
    )
}

/// Tess connects the service's account and drafts the delivery; the
/// draft, never published.
async fn delivery_draft(world: &World<'_>, service: &Service) -> Workflow {
    let account = connected_account(world, service).await;
    drafted(world, Trigger::Manual, delivery_graph(service, &account)).await
}

/// Tess saves `cases` as the draft's set, with `gate` when one is named.
async fn save_cases(
    world: &World<'_>,
    draft: &Workflow,
    cases: Vec<EvaluationCase>,
    gate: Option<&str>,
) {
    let set = NewEvaluationSet {
        cases,
        publish_gate: gate.map(str::to_owned),
    };
    workflows::save_evaluation_set(world.tenant(), &draft.id, &set)
        .send(world.admin().client())
        .await
        .ok();
}

/// Tess evaluates the draft; the evaluation once every case is decided.
async fn evaluated(world: &World<'_>, draft: &Workflow) -> Evaluation {
    let started = workflows::start_evaluation(world.tenant(), &draft.id)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(started.status, "running", "it answers at once");
    eventually("the evaluation to end", || async {
        let evaluation = workflows::evaluation(world.tenant(), &draft.id, &started.id)
            .send(world.admin().client())
            .await
            .ok();
        (evaluation.status != "running").then_some(evaluation)
    })
    .await
}

/// Ann publishes the revision of `draft` she reviewed, as the gate lets
/// her or not.
async fn publish(world: &World<'_>, draft: &Workflow) -> Answer<Workflow> {
    let publication = Publication {
        revision: draft.revision.clone(),
    };
    workflows::publish(world.tenant(), &draft.id, &publication)
        .send(world.owner().client())
        .await
}

/// Tess saves one case for her unpublished draft, checking the order with
/// `equals` and the service's answer with `contains` and `matches`, and
/// evaluates the draft. It passes, its one case passed in a test run of
/// its own, and the service was read once for it. The workflow has no
/// live run, one test, and the trail records the set saved, the
/// evaluation started and its end.
#[tokio::test]
async fn an_evaluation_of_the_draft_passes_every_case() {
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let draft = delivery_draft(&world, &service).await;
    save_cases(&world, &draft, vec![delivered_case()], None).await;

    let evaluation = evaluated(&world, &draft).await;

    assert_eq!(evaluation.status, "passed", "{evaluation:?}");
    assert_eq!(evaluation.version, draft.version, "it tried the draft");
    assert_eq!(evaluation.cases[0].outcome, "passed");
    assert!(
        evaluation.cases[0].execution_id.is_some(),
        "it ran as a test"
    );
    assert_eq!(service.calls(), 1, "the test really read the service");
    check_kept_apart(&world, &draft).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// The case's run is a test, never a live run, and the trail records the
/// evaluation from its set to its end.
async fn check_kept_apart(world: &World<'_>, draft: &Workflow) {
    let live = workflows::executions(world.tenant(), &draft.id)
        .send(world.admin().client())
        .await
        .ok()
        .items;
    let tests = workflows::tests(world.tenant(), &draft.id)
        .send(world.admin().client())
        .await
        .ok()
        .items;
    assert!(live.is_empty(), "no live run: {live:?}");
    assert_eq!(tests.len(), 1, "one test for the one case");
    let trail = world.trail();
    assert_eq!(trail.count("workflows.evaluation_set_saved").await, 1);
    assert_eq!(trail.count("workflows.evaluation_started").await, 1);
    assert_eq!(trail.count("workflows.evaluation_ended").await, 1);
}

/// Tess saves the passing case and one expecting the partner's service,
/// which her draft never reaches. The evaluation fails: the first case
/// passed, the second failed, naming its first check and showing that
/// the real outside service was found there instead.
#[tokio::test]
async fn a_case_expecting_what_the_draft_does_not_hand_on_fails_with_what_differed() {
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let draft = delivery_draft(&world, &service).await;
    save_cases(&world, &draft, vec![delivered_case(), partner_case()], None).await;

    let evaluation = evaluated(&world, &draft).await;

    assert_eq!(evaluation.status, "failed");
    assert_eq!(evaluation.cases[0].outcome, "passed");
    let failed = &evaluation.cases[1];
    assert_eq!(failed.outcome, "failed");
    let differences = failed.differences.clone().expect("what differed");
    assert_eq!(differences.len(), 1, "{differences:?}");
    assert_eq!(differences[0].kind, "check");
    assert_eq!(differences[0].check, Some(0));
    let found = differences[0].found.clone().unwrap_or_default();
    assert!(found.contains(DELIVERED), "it found {found}");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess turns the gate on with only the partner case. Ann's publication is
/// refused: the draft was never evaluated. Tess evaluates it and it
/// fails, so Ann is still refused. Tess replaces the case with the
/// passing one: Ann is still refused, since the latest evaluation failed.
/// Tess evaluates again and it passes: Ann publishes the draft.
#[tokio::test]
async fn publishing_waits_for_a_passing_evaluation_when_the_gate_must_pass() {
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let draft = delivery_draft(&world, &service).await;
    save_cases(&world, &draft, vec![partner_case()], Some(MUST_PASS)).await;
    publish(&world, &draft)
        .await
        .refused(Status::CONFLICT, "conflict");

    assert_eq!(evaluated(&world, &draft).await.status, "failed");
    publish(&world, &draft)
        .await
        .refused(Status::CONFLICT, "conflict");
    save_cases(&world, &draft, vec![delivered_case()], Some(MUST_PASS)).await;
    publish(&world, &draft)
        .await
        .refused(Status::CONFLICT, "conflict");
    assert_eq!(evaluated(&world, &draft).await.status, "passed");

    let workflow = publish(&world, &draft).await.ok();
    assert_eq!(workflow.status, "published");
    stack.stop().await.expect("the stack stops cleanly");
}
