//! Mallory races a run against itself: the same approval sent ten times at
//! once, and a cancel sent at the very moment the approval lands. However
//! the requests interleave, a run decides once: the service is called at
//! most once, and what the run says happened is what did.

use futures_util::future::join_all;
use ianua_scenarios::api::workflows;
use ianua_scenarios::expect::eventually;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::workflows::{Approve, Trigger};
use ianua_scenarios::world::World;
use serde_json::Value;

use crate::service::Service;
use crate::support::{
    APPROVAL_STEP, approved_delivery_graph, connected_account, drafted, published, run, started,
};

/// How many copies of the approval go out at once.
const COPIES: usize = 10;

/// Ann's approval of exactly what she was shown goes out ten times at
/// once. One is taken; the run succeeds and the service is called once.
#[tokio::test]
async fn ten_copies_of_one_approval_deliver_once() {
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let execution_id = held_run(&world, &service).await;
    let approval = Approve {
        shown: shown(&world, &execution_id).await,
        mfa_code: None,
    };

    let answers = join_all((0..COPIES).map(|_| {
        workflows::approve(world.tenant(), &execution_id, APPROVAL_STEP, &approval)
            .send(world.owner().client())
    }))
    .await;
    let ended = ended_either_way(&world, &execution_id).await;

    let taken = answers
        .iter()
        .filter(|answer| answer.status().is_success())
        .count();
    assert!(
        answers
            .iter()
            .all(|answer| !answer.status().is_server_error()),
        "no copy broke the platform"
    );
    assert!(taken >= 1, "the approval was taken");
    assert_eq!(ended, "succeeded");
    assert_eq!(service.calls(), 1, "one delivery, however many copies");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann approves while Tess cancels, both at the same moment. Whichever
/// wins, the run agrees with the service: cancelled and never called, or
/// succeeded and called once.
#[tokio::test]
async fn a_cancel_racing_an_approval_leaves_one_true_story() {
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let execution_id = held_run(&world, &service).await;
    let approval = Approve {
        shown: shown(&world, &execution_id).await,
        mfa_code: None,
    };

    let (approved, cancelled) = tokio::join!(
        workflows::approve(world.tenant(), &execution_id, APPROVAL_STEP, &approval)
            .send(world.owner().client()),
        workflows::cancel(world.tenant(), &execution_id).send(world.admin().client()),
    );
    let ended = ended_either_way(&world, &execution_id).await;

    for answer in [&approved.status(), &cancelled.status()] {
        assert!(!answer.is_server_error(), "no request broke the platform");
    }
    match ended.as_str() {
        "cancelled" => assert_eq!(service.calls(), 0, "a cancelled run called nothing"),
        "succeeded" => assert_eq!(service.calls(), 1, "an approved run called once"),
        other => panic!("the run ended {other}"),
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess's run of a published workflow, held at Ann's approval.
async fn held_run(world: &World<'_>, service: &Service) -> String {
    let account = connected_account(world, service).await;
    let graph = approved_delivery_graph(service, &account);
    let workflow = published(world, &drafted(world, Trigger::Manual, graph).await).await;
    let execution_id = started(world, &workflow).await.execution_id;
    eventually("the run to wait for its approval", || async {
        let execution = run(world, &execution_id).await;
        let held = execution
            .steps
            .iter()
            .any(|step| step.key == APPROVAL_STEP && step.phase == "running");
        (execution.status == "running" && held).then_some(())
    })
    .await;
    execution_id
}

/// What Ann is shown at the run's approval.
async fn shown(world: &World<'_>, execution_id: &str) -> Value {
    workflows::approval(world.tenant(), execution_id, APPROVAL_STEP)
        .send(world.owner().client())
        .await
        .ok()
        .shown
}

/// How the run `execution_id` ended, once it did.
async fn ended_either_way(world: &World<'_>, execution_id: &str) -> String {
    eventually("the run to end", || async {
        let status = run(world, execution_id).await.status;
        (status != "running").then_some(status)
    })
    .await
}
