//! Stopping and repeating runs. A run Tess cancels while it waits for an
//! approval ends for good: the approval can no longer release it, nothing
//! reaches the service, and a restart does not bring it back. A failed run
//! can be retried, which runs only the steps that did not finish, or
//! rerun, which runs every step again; only a failed run is rerun, and
//! only by the person it acted for.

use ianua_scenarios::api::workflows;
use ianua_scenarios::expect::{Matrix, eventually};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::workflows::{Approve, Edge, Graph, MappedField, Node, Step, Trigger};
use ianua_scenarios::world::World;

use crate::service::Service;
use crate::support::{
    APPROVAL_STEP, approved_delivery_graph, connected_account, drafted, ended, published, run,
    started, written,
};

/// The key of the step that calls the first service.
const FIRST_STEP: &str = "record";

/// The key of the step that calls the second service.
const SECOND_STEP: &str = "notify";

/// Tess starts a run that waits for Ann's approval before calling the
/// service. Max, Sam and nobody signed in cannot cancel it; Max, in the
/// tenant but neither its person nor in full control of workflows, is
/// told there is no such run, so a run's id tells him nothing. Tess cancels
/// it: it ends cancelled, Ann can no longer approve it, and cancelling it
/// again is refused as already ended. The platform restarts, and the run
/// is still cancelled with the service never called.
#[tokio::test]
async fn a_cancelled_run_ends_for_good_and_reaches_nothing() {
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connected_account(&world, &service).await;
    let graph = approved_delivery_graph(&service, &account);
    let workflow = published(&world, &drafted(&world, Trigger::Manual, graph).await).await;
    let execution_id = started(&world, &workflow).await.execution_id;
    held_at_the_approval(&world, &execution_id).await;
    let shown = workflows::approval(world.tenant(), &execution_id, APPROVAL_STEP)
        .send(world.owner().client())
        .await
        .ok()
        .shown;

    Matrix::new(
        "cancelling Tess's run",
        workflows::cancel(world.tenant(), &execution_id).call(),
    )
    .refused(world.member().client(), Status::NOT_FOUND, "not_found")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
    let cancelled = workflows::cancel(world.tenant(), &execution_id)
        .send(world.admin().client())
        .await
        .ok();
    let approval = Approve {
        shown,
        mfa_code: None,
    };
    let late = workflows::approve(world.tenant(), &execution_id, APPROVAL_STEP, &approval)
        .send(world.owner().client())
        .await;
    workflows::cancel(world.tenant(), &execution_id)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    stack.restart().await.expect("the stack restarts");

    assert_eq!(cancelled.status, "cancelled");
    assert!(
        late.status().is_client_error(),
        "Ann's late approval is refused: {}",
        late.summary()
    );
    assert_eq!(run(&world, &execution_id).await.status, "cancelled");
    assert_eq!(service.calls(), 0, "the service was never called");
    stack.stop().await.expect("the stack stops cleanly");
}

/// A run records with the first service, then notifies the second, which
/// refuses: the run fails after one call to each. Max cannot rerun it. The
/// second service recovers. Tess retries the failed run: only the
/// notification runs again, so the first service is not called again.
/// Tess then reruns the same failed run: every step runs again, so both
/// services are called once more. The rerun succeeded, and rerunning it
/// is refused because it did not fail.
#[tokio::test]
async fn a_retry_runs_what_did_not_finish_and_a_rerun_runs_every_step() {
    let first = Service::start().await;
    let second = Service::start().await;
    second.fail();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let graph = record_then_notify(&world, &first, &second).await;
    let workflow = published(&world, &drafted(&world, Trigger::Manual, graph).await).await;
    let failed = started(&world, &workflow).await.execution_id;
    ended(&world, &failed, "failed").await;
    assert_eq!((first.calls(), second.calls()), (1, 1), "one call to each");

    workflows::rerun(world.tenant(), &failed)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    second.recover();
    let retried = workflows::retry(world.tenant(), &failed)
        .send(world.admin().client())
        .await
        .ok()
        .execution_id;
    ended(&world, &retried, "succeeded").await;
    assert_eq!(
        (first.calls(), second.calls()),
        (1, 2),
        "the retry notified only"
    );
    let rerun = workflows::rerun(world.tenant(), &failed)
        .send(world.admin().client())
        .await
        .ok()
        .execution_id;
    ended(&world, &rerun, "succeeded").await;
    workflows::rerun(world.tenant(), &rerun)
        .send(world.admin().client())
        .await
        .refused(Status::CONFLICT, "conflict");

    assert_eq!(
        (first.calls(), second.calls()),
        (2, 3),
        "the rerun ran both"
    );
    assert_ne!(retried, failed, "a retry is a run of its own");
    assert_ne!(rerun, failed, "a rerun is a run of its own");
    assert_eq!(
        run(&world, &failed).await.status,
        "failed",
        "it stays failed"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

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

/// Two steps: one calling `first` through an account of its own, then one
/// calling `second` through another.
async fn record_then_notify(world: &World<'_>, first: &Service, second: &Service) -> Graph {
    let first_account = connected_account(world, first).await;
    let second_account = connected_account(world, second).await;
    Graph {
        nodes: vec![
            calling(FIRST_STEP, first, &first_account),
            calling(SECOND_STEP, second, &second_account),
        ],
        edges: vec![Edge {
            from: FIRST_STEP.to_owned(),
            to: SECOND_STEP.to_owned(),
        }],
    }
}

/// A step keyed `key` reading from `service` through `account_id`.
fn calling(key: &str, service: &Service, account_id: &str) -> Node {
    Node {
        key: key.to_owned(),
        name: format!("Call for {key}"),
        step: Step::Action {
            integration: "http".to_owned(),
            operation: "get-with-account".to_owned(),
            account_id: Some(account_id.to_owned()),
            effect: "read".to_owned(),
            ceiling: "internal".to_owned(),
            inputs: vec![MappedField {
                field: "url".to_owned(),
                source: written(service.url()),
            }],
        },
    }
}
