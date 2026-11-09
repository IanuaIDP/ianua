//! Runs of a published workflow against the outside service: one run
//! delivers once however often the platform restarts; a delivery the
//! service refuses leaves the run failed until Tess retries it on purpose,
//! and the first run stays failed; Max, Sam, nobody signed in and a record
//! that cannot be written start no run and reach the service not at all.

use ianua_scenarios::api::workflows;
use ianua_scenarios::expect::{Matrix, no_secret_leaked};
use ianua_scenarios::stack::{AuditWrites, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::workflows::{StartExecution, Trigger};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::service::{CREDENTIAL, Service};
use crate::support::{
    DELIVERY_STEP, connected_account, delivery_graph, drafted, ended, published, run, started,
};

/// Tess drafts a workflow calling the outside service through the
/// connected account, Ann publishes it, Tess starts a run, and the
/// platform restarts while it is queued. The run ends in success with the
/// delivery step's output, which shows the account's credential nowhere;
/// the service was called once. Another restart changes neither the run
/// nor the one call, and one start is recorded.
#[tokio::test]
async fn a_published_workflow_delivers_once_however_often_the_platform_restarts() {
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connected_account(&world, &service).await;
    let draft = drafted(&world, Trigger::Manual, delivery_graph(&service, &account)).await;
    let workflow = published(&world, &draft).await;
    assert_eq!(workflow.status, "published", "Ann put the draft in service");

    let first = started(&world, &workflow).await;
    stack.restart().await.expect("the stack restarts");
    check_delivery_output(&world, &first.execution_id).await;
    assert_eq!(service.delivered(), 1, "the service was called once");
    check_restart_keeps_delivery(&world, &service, &first.execution_id).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The completed run has a successful delivery output without the account credential.
async fn check_delivery_output(world: &World<'_>, execution_id: &str) {
    let completed = ended(world, execution_id, "succeeded").await;
    assert_eq!(
        completed.id, execution_id,
        "the run read is the one started"
    );
    assert!(
        completed.steps.iter().any(|step| step.key == DELIVERY_STEP
            && step.phase == "succeeded"
            && step.output.is_some()),
        "the delivery step succeeded with an output"
    );
    for step in completed.steps {
        no_secret_leaked(&step.output.unwrap_or_default().to_string(), &[CREDENTIAL]);
    }
}

/// Restarting a completed run neither repeats its delivery nor records another start.
async fn check_restart_keeps_delivery(world: &World<'_>, service: &Service, execution_id: &str) {
    world
        .stack()
        .restart()
        .await
        .expect("the stack restarts again");
    assert_eq!(
        run(world, execution_id).await.status,
        "succeeded",
        "the run is still a success"
    );
    assert_eq!(service.delivered(), 1, "the restart repeated no delivery");
    assert_eq!(
        world.trail().count("workflows.execution_started").await,
        1,
        "one start is recorded"
    );
}

/// The outside service refuses what reaches it: the run fails after one
/// call and nothing was delivered. The service recovers, and Tess retries
/// the failed run on purpose: a new run succeeds with one more call, the
/// first run stays failed, and two starts are recorded.
#[tokio::test]
async fn a_retry_on_purpose_recovers_a_failed_delivery_and_leaves_the_first_run_failed() {
    let service = Service::start().await;
    service.fail();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connected_account(&world, &service).await;
    let draft = drafted(&world, Trigger::Manual, delivery_graph(&service, &account)).await;
    let workflow = published(&world, &draft).await;

    let first = started(&world, &workflow).await;
    ended(&world, &first.execution_id, "failed").await;
    assert_eq!(service.calls(), 1, "the service was called once");
    assert_eq!(service.delivered(), 0, "nothing was delivered");

    service.recover();
    retry_failed_delivery(&world, &service, &first.execution_id).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// An explicit retry succeeds in its own run and leaves the failed original intact.
async fn retry_failed_delivery(world: &World<'_>, service: &Service, execution_id: &str) {
    let retry = workflows::retry(world.tenant(), execution_id)
        .send(world.admin().client())
        .await
        .ok();
    assert_ne!(
        retry.execution_id, execution_id,
        "a retry is a run of its own"
    );
    ended(world, &retry.execution_id, "succeeded").await;
    assert_eq!(service.calls(), 2, "the retry called the service once more");
    assert_eq!(service.delivered(), 1, "the retry delivered");
    assert_eq!(
        run(world, execution_id).await.status,
        "failed",
        "the first run stays failed"
    );
    assert_eq!(
        world.trail().count("workflows.execution_started").await,
        2,
        "two starts are recorded"
    );
}

/// Max, Sam and an anonymous visitor cannot start the published workflow.
/// Tess's start also fails while its audit record cannot be written.
/// None of these requests calls the service or records a start. Once audit
/// writes recover, Tess starts a successful run that delivers once.
#[tokio::test]
async fn nobody_without_the_right_and_no_unrecorded_start_reaches_the_service() {
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connected_account(&world, &service).await;
    let draft = drafted(&world, Trigger::Manual, delivery_graph(&service, &account)).await;
    let workflow = published(&world, &draft).await;
    refuse_start_without_authority(&world, &workflow.id).await;
    refuse_unrecorded_start(&world, &workflow.id).await;
    assert_eq!(service.calls(), 0, "the service was not called");
    assert_eq!(
        world.trail().count("workflows.execution_started").await,
        0,
        "no start is recorded"
    );

    let first = started(&world, &workflow).await;
    ended(&world, &first.execution_id, "succeeded").await;
    assert_eq!(service.delivered(), 1, "Tess's start delivered");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Members, strangers and anonymous visitors cannot start the published workflow.
async fn refuse_start_without_authority(world: &World<'_>, workflow_id: &str) {
    let start = StartExecution {
        input: json!({}),
        exposure: "internal".to_owned(),
    };

    Matrix::new(
        "starting the workflow",
        workflows::start(world.tenant(), workflow_id, &start).call(),
    )
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
}

/// A failed audit write refuses Tess's start before audit storage is restored.
async fn refuse_unrecorded_start(world: &World<'_>, workflow_id: &str) {
    let start = StartExecution {
        input: json!({}),
        exposure: "internal".to_owned(),
    };
    world.stack().audit_writes(AuditWrites::Refuse).await;
    let failed = workflows::start(world.tenant(), workflow_id, &start)
        .send(world.admin().client())
        .await;
    assert_eq!(
        failed.status(),
        Status::INTERNAL_SERVER_ERROR,
        "a start whose record cannot be written fails: {}",
        failed.summary()
    );
    world.stack().audit_writes(AuditWrites::Allow).await;
}
