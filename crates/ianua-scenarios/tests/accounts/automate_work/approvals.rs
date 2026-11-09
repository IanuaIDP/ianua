//! An approval step holds a run before it calls the outside service:
//! whether the service was called proves what the approval did. Max
//! cannot approve, Ann cannot approve data other than what she was shown,
//! and her approval of exactly that releases one delivery. Her denial
//! ends the run for good, even across a restart.

use ianua_scenarios::api::workflows;
use ianua_scenarios::expect::eventually;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::workflows::{Approve, Trigger};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::service::Service;
use crate::support::{
    APPROVAL_STEP, approved_delivery_graph, connected_account, drafted, ended, published, run,
    started,
};

/// Waits until the run `execution_id` is held at its approval step.
async fn held_at_the_approval(world: &World<'_>, execution_id: &str) {
    eventually("the run to wait for its approval", || async {
        let execution = run(world, execution_id).await;
        let held = execution
            .steps
            .iter()
            .any(|step| step.key == APPROVAL_STEP && step.phase == "running");
        (execution.status == "running" && held).then_some(())
    })
    .await;
}

/// Connects the service and starts a published run, waiting until its approval step is active.
async fn start_held_run(world: &World<'_>, service: &Service) -> String {
    let account = connected_account(world, service).await;
    let draft = drafted(
        world,
        Trigger::Manual,
        approved_delivery_graph(service, &account),
    )
    .await;
    let workflow = published(world, &draft).await;
    let first = started(world, &workflow).await;
    held_at_the_approval(world, &first.execution_id).await;
    first.execution_id
}

/// Tess starts a run that waits for an approval before calling the
/// service; nothing is called yet. Max may not approve. Ann approves data
/// other than what she was shown: refused, and still nothing is called.
/// Ann approves exactly what she was shown: the run succeeds and the
/// service is called once.
#[tokio::test]
async fn only_anns_approval_of_what_she_was_shown_releases_the_delivery() {
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let execution_id = start_held_run(&world, &service).await;
    assert_eq!(service.calls(), 0, "nothing is called before the approval");

    let as_shown = refused_approvals(&world, &execution_id).await;
    assert_eq!(service.calls(), 0, "a refused approval releases nothing");
    workflows::approve(world.tenant(), &execution_id, APPROVAL_STEP, &as_shown)
        .send(world.owner().client())
        .await
        .ok();
    ended(&world, &execution_id, "succeeded").await;
    assert_eq!(service.delivered(), 1, "the approval released one delivery");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max cannot approve the shown data, and Ann cannot approve different data.
async fn refused_approvals(world: &World<'_>, execution_id: &str) -> Approve {
    let shown = workflows::approval(world.tenant(), execution_id, APPROVAL_STEP)
        .send(world.owner().client())
        .await
        .ok();
    let as_shown = Approve {
        shown: shown.shown,
        mfa_code: None,
    };
    workflows::approve(world.tenant(), execution_id, APPROVAL_STEP, &as_shown)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    refuse_other_data(world, execution_id).await;
    as_shown
}

/// Approval binds Ann to the data that the running step showed her.
async fn refuse_other_data(world: &World<'_>, execution_id: &str) {
    let other_data = Approve {
        shown: json!({"different": "data"}),
        mfa_code: None,
    };
    workflows::approve(world.tenant(), execution_id, APPROVAL_STEP, &other_data)
        .send(world.owner().client())
        .await
        .refused(Status::CONFLICT, "conflict");
}

/// Ann denies the approval a run waits for: the run ends, in neither
/// success nor running, and stays so across a restart. Approving what she
/// was shown afterwards is refused, and the service is never called.
#[tokio::test]
async fn anns_denial_ends_the_run_for_good() {
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let execution_id = start_held_run(&world, &service).await;
    let shown = workflows::approval(world.tenant(), &execution_id, APPROVAL_STEP)
        .send(world.owner().client())
        .await
        .ok();

    deny_and_restart(&world, &execution_id).await;
    let as_shown = Approve {
        shown: shown.shown,
        mfa_code: None,
    };
    workflows::approve(world.tenant(), &execution_id, APPROVAL_STEP, &as_shown)
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    assert_eq!(service.calls(), 0, "the service was never called");

    stack.stop().await.expect("the stack stops cleanly");
}

/// A denial fails the run and its failed status survives a platform restart.
async fn deny_and_restart(world: &World<'_>, execution_id: &str) {
    workflows::deny(world.tenant(), execution_id, APPROVAL_STEP)
        .send(world.owner().client())
        .await
        .ok();
    let denied = run(world, execution_id).await;
    assert_eq!(
        denied.status, "failed",
        "a denied run is over, and no success"
    );

    world.stack().restart().await.expect("the stack restarts");
    assert_eq!(
        run(world, execution_id).await.status,
        denied.status,
        "the denied run is as it was after the restart"
    );
}
