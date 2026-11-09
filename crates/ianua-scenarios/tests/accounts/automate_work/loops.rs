//! A loop runs its steps once for each issue, each pass a run of its own:
//! the outside service shows how many passes really called it. Every pass
//! of a three-issue loop delivers once and the loop gives back three
//! answers; a refused pass fails the loop and stops the pass still
//! waiting, so nothing is delivered.

use ianua_scenarios::api::workflows;
use ianua_scenarios::expect::eventually;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::workflows::{Execution, PassRun, Trigger};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::service::Service;
use crate::support::{
    APPROVAL_STEP, LOOP_STEP, approved_delivery_graph, connected_account, delivery_graph, drafted,
    each_issue, ended, published, run, started_with,
};

/// The passes of the run `execution_id`, as Tess reads them.
async fn passes(world: &World<'_>, execution_id: &str) -> Vec<PassRun> {
    workflows::passes(world.tenant(), execution_id)
        .send(world.admin().client())
        .await
        .ok()
        .items
}

/// Waits until `count` passes of the run `execution_id` are held at their
/// approval step, and gives them back.
async fn held_at_their_approvals(
    world: &World<'_>,
    execution_id: &str,
    count: usize,
) -> Vec<PassRun> {
    eventually("every pass to wait for its approval", || async {
        let started = passes(world, execution_id).await;
        if started.len() != count {
            return None;
        }
        for pass in &started {
            let steps = run(world, &pass.id).await.steps;
            let held = steps
                .iter()
                .any(|step| step.key == APPROVAL_STEP && step.phase == "running");
            if !held {
                return None;
            }
        }
        Some(started)
    })
    .await
}

/// Tess loops over three issues, two at a time, calling the service for
/// each. Ann publishes it and Tess starts it. The run succeeds, the
/// service is called and delivers three times, the loop gives back three
/// answers, and three passes name Tess's run and their items. The
/// workflow's list of runs shows the one run, and the trail records one
/// run start and three pass starts.
#[tokio::test]
async fn each_issue_reaches_the_service_once() {
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connected_account(&world, &service).await;
    let draft = drafted(
        &world,
        Trigger::Manual,
        each_issue(delivery_graph(&service, &account), 2),
    )
    .await;
    let workflow = published(&world, &draft).await;

    let started = started_with(
        &world,
        &workflow,
        json!({"issues": ["login fails", "slow search", "typo on pricing"]}),
    )
    .await;
    let execution = ended(&world, &started.execution_id, "succeeded").await;
    check_loop_answers(&world, &service, &workflow.id, &execution).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Each successful pass belongs to this loop and names its issue index.
async fn successful_items(world: &World<'_>, execution_id: &str) -> Vec<u32> {
    let mut items: Vec<u32> = passes(world, execution_id)
        .await
        .iter()
        .inspect(|pass| {
            assert_eq!(pass.status, "succeeded", "every pass succeeded");
            assert_eq!(pass.pass.execution_id, execution_id);
            assert_eq!(pass.pass.step, LOOP_STEP);
        })
        .map(|pass| pass.pass.index)
        .collect();
    items.sort_unstable();
    items
}

/// The loop returns one answer and delivery per issue while listing and auditing its parent separately.
async fn check_loop_answers(
    world: &World<'_>,
    service: &Service,
    workflow_id: &str,
    execution: &Execution,
) {
    let answers = execution
        .steps
        .iter()
        .find(|step| step.key == LOOP_STEP)
        .and_then(|step| step.output.as_ref())
        .and_then(|output| output.as_array())
        .map(Vec::len);
    let items = successful_items(world, &execution.id).await;
    let runs = workflows::executions(world.tenant(), workflow_id)
        .send(world.admin().client())
        .await
        .ok()
        .items;
    assert_eq!(service.calls(), 3, "the service was called once per issue");
    assert_eq!(service.delivered(), 3, "every issue was delivered");
    assert_eq!(answers, Some(3), "the loop gave back one answer per issue");
    assert_eq!(items, [0, 1, 2], "one pass ran for each issue");
    assert_eq!(runs.len(), 1, "the list shows the run, not its passes");
    assert_eq!(world.trail().count("workflows.execution_started").await, 1);
    assert_eq!(world.trail().count("workflows.pass_started").await, 3);
}

/// Tess loops over two issues at once, each pass waiting for Ann's
/// approval before calling the service. Ann refuses the first issue. The
/// loop and the run fail, the second pass, still waiting, is stopped as
/// its loop ended, and the service is never called.
#[tokio::test]
async fn a_refused_pass_fails_the_loop_and_stops_the_other() {
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connected_account(&world, &service).await;
    let draft = drafted(
        &world,
        Trigger::Manual,
        each_issue(approved_delivery_graph(&service, &account), 2),
    )
    .await;
    let workflow = published(&world, &draft).await;
    let started = started_with(
        &world,
        &workflow,
        json!({"issues": ["refund order 1", "refund order 2"]}),
    )
    .await;
    let held = held_at_their_approvals(&world, &started.execution_id, 2).await;
    deny_first_pass(&world, &started.execution_id, &held).await;
    assert_eq!(service.calls(), 0, "nothing reached the service");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Denying the first approval fails the parent loop and stops its other waiting pass.
async fn deny_first_pass(world: &World<'_>, execution_id: &str, held: &[PassRun]) {
    let first = held
        .iter()
        .find(|pass| pass.pass.index == 0)
        .expect("a pass for the first issue");
    let second = held
        .iter()
        .find(|pass| pass.pass.index == 1)
        .expect("a pass for the second issue");

    workflows::deny(world.tenant(), &first.id, APPROVAL_STEP)
        .send(world.owner().client())
        .await
        .ok();

    let execution = ended(world, execution_id, "failed").await;
    let stopped = ended(world, &second.id, "loop_ended").await;
    let loop_phase = execution
        .steps
        .iter()
        .find(|step| step.key == LOOP_STEP)
        .map(|step| step.phase.clone());
    assert_eq!(loop_phase.as_deref(), Some("failed"), "the loop failed");
    assert_eq!(stopped.status, "loop_ended", "the waiting pass was stopped");
}
