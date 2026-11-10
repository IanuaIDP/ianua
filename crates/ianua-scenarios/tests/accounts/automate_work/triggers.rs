//! What starts a workflow from outside: a webhook, called with the secret
//! Ann issued and no other, whose rotation kills the old secret and whose
//! archived version answers nobody; and a schedule that fires once a
//! minute, not again when the workers restart mid-minute, and not at all
//! once the version is archived.

use std::time::{Duration, Instant};

use ianua_scenarios::api::{Request, workflows};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::eventually;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::workflows::{Trigger, TriggerSecret, WebhookStarted, Workflow};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::service::Service;
use crate::support::{connected_account, delivery_graph, drafted, ended, published};

/// How long the platform is watched for a firing that must not come:
/// three of the worker's one-second sweeps, so a late second firing has
/// every chance to show.
const QUIET: Duration = Duration::from_secs(3);

/// Waits out `duration` on the real clock, the worker sweeping meanwhile.
async fn watched_for(duration: Duration) {
    let since = Instant::now();
    eventually("the watch for a firing that must not come", || async {
        (since.elapsed() > duration).then_some(())
    })
    .await;
}

/// An outside caller's webhook call with `secret`, sending an order.
fn webhook_call(world: &World<'_>, secret: &TriggerSecret) -> Request<WebhookStarted> {
    workflows::call_webhook(world.tenant(), secret, &json!({"order": "webhook-order"}))
}

/// Ann archives the version `workflow` is, taking it out of service.
async fn archived(world: &World<'_>, workflow: &Workflow) {
    let version = workflows::archive_version(world.tenant(), &workflow.id, workflow.version)
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(version.status, "archived", "the version is archived");
}

/// Ann issues the webhook's secret. Mallory's guessed secret starts
/// nothing; the issued one starts a run that delivers. Ann rotates the
/// secret: the old one starts nothing, the new one delivers again. Ann
/// archives the version: the new secret starts nothing either, no more is
/// delivered, and two starts are recorded.
#[tokio::test]
async fn a_rotated_webhook_secret_and_an_archived_version_stop_outside_callers() {
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connected_account(&world, &service).await;
    let draft = drafted(&world, Trigger::Webhook, delivery_graph(&service, &account)).await;
    let workflow = published(&world, &draft).await;
    let issued = workflows::issue_trigger_secret(world.tenant(), &workflow.id)
        .send(world.owner().client())
        .await
        .ok();
    refuse_guessed_secret(&world, &issued).await;
    assert_eq!(service.calls(), 0, "a guessed secret starts nothing");
    start_issued_webhook(&world, &issued).await;
    let rotated = rotate_webhook(&world, &workflow, &issued).await;
    assert_eq!(service.delivered(), 2, "each admitted call delivered once");
    check_archived_webhook(&world, &workflow, &rotated, &service).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// A guessed secret cannot start this trigger.
async fn refuse_guessed_secret(world: &World<'_>, issued: &TriggerSecret) {
    let guessed = TriggerSecret {
        trigger_id: issued.trigger_id.clone(),
        secret: "a secret never issued to anyone 4917".to_owned(),
    };
    webhook_call(world, &guessed)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// The issued webhook secret starts a run that finishes successfully.
async fn start_issued_webhook(world: &World<'_>, issued: &TriggerSecret) {
    let admitted = webhook_call(world, issued)
        .send(world.anonymous().client())
        .await
        .ok();
    assert_eq!(admitted.status, "started", "the issued secret starts a run");
    let execution_id = admitted
        .execution_id
        .as_deref()
        .expect("the webhook started a run");
    ended(world, execution_id, "succeeded").await;
}

/// Rotation refuses the old secret and allows one completed run with its replacement.
async fn rotate_webhook(
    world: &World<'_>,
    workflow: &Workflow,
    issued: &TriggerSecret,
) -> TriggerSecret {
    let rotated = workflows::rotate_trigger_secret(world.tenant(), &workflow.id)
        .send(world.owner().client())
        .await
        .ok();
    webhook_call(world, issued)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let again = webhook_call(world, &rotated)
        .send(world.anonymous().client())
        .await
        .ok();
    let execution_id = again
        .execution_id
        .as_deref()
        .expect("the rotated secret started a run");
    ended(world, execution_id, "succeeded").await;
    rotated
}

/// Archiving the version refuses its current secret and leaves the two deliveries and starts intact.
async fn check_archived_webhook(
    world: &World<'_>,
    workflow: &Workflow,
    rotated: &TriggerSecret,
    service: &Service,
) {
    archived(world, workflow).await;
    webhook_call(world, rotated)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_eq!(
        service.delivered(),
        2,
        "an archived version delivers nothing"
    );
    assert_eq!(
        world.trail().count("workflows.execution_started").await,
        2,
        "two starts are recorded"
    );
}

/// A workflow on an every-minute schedule is published. The clock moves
/// past the next minute: the service is called once. The workers restart
/// in that minute and are watched for three sweeps: still once, with one
/// start recorded. The clock moves past the minute after: called twice.
/// Ann archives the version, the clock moves on, the platform restarts
/// and is watched again: still twice, two starts.
#[tokio::test]
async fn a_schedule_fires_once_a_minute_across_a_restart_and_stops_when_archived() {
    let clock = Clock::controlled();
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard().with("WORKER_SWEEP_TICK_SECONDS", "1"))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connected_account(&world, &service).await;
    let every_minute = Trigger::Schedule {
        cron: "* * * * *".to_owned(),
    };
    let draft = drafted(&world, every_minute, delivery_graph(&service, &account)).await;
    let workflow = published(&world, &draft).await;

    clock.advance_into_next_minute();
    eventually("the first scheduled delivery", || async {
        (service.delivered() == 1).then_some(())
    })
    .await;

    check_minute_restart(&world, &service).await;
    clock.advance_into_next_minute();
    eventually("the next minute's delivery", || async {
        (service.delivered() == 2).then_some(())
    })
    .await;
    archived(&world, &workflow).await;
    clock.advance_into_next_minute();
    check_archived_schedule(&world, &service).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Restarting within a minute neither repeats delivery nor records another scheduled start.
async fn check_minute_restart(world: &World<'_>, service: &Service) {
    world.stack().restart().await.expect("the stack restarts");
    eventually("the restarted platform to read its trail", || async {
        let starts = world.trail().count("workflows.execution_started").await;
        (starts == 1).then_some(())
    })
    .await;
    watched_for(QUIET).await;
    assert_eq!(
        service.delivered(),
        1,
        "the restart fired the minute no second time"
    );
    assert_eq!(
        world.trail().count("workflows.execution_started").await,
        1,
        "the restart recorded no second start"
    );
}

/// After the archived schedule's next minute, restarting and waiting produces no further work.
async fn check_archived_schedule(world: &World<'_>, service: &Service) {
    world
        .stack()
        .restart()
        .await
        .expect("the stack restarts again");
    watched_for(QUIET).await;
    assert_eq!(
        world.trail().count("workflows.execution_started").await,
        2,
        "the archived schedule started nothing more"
    );
    assert_eq!(
        service.delivered(),
        2,
        "the archived schedule delivered nothing more"
    );
}
