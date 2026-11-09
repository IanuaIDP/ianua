//! Tess keeping a stream: what status a receiver reads, a new endpoint
//! having to prove itself again, pausing, resuming and disabling, and
//! deleting only what is already disabled.

use ianua_scenarios::api::signals;
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::signals::StreamChange;
use ianua_scenarios::world::World;

use crate::support::{
    EventSource, VERIFICATION, awaited, prove_endpoint, published, register, stream,
};

/// The endpoint Acme moves its receiver to.
const MOVED: &str = "https://signals-new.acme.invalid/events";

/// Tess pauses a stream: its status reads paused, and it cannot be paused
/// twice. She resumes it, again only once, and it reads enabled. She moves
/// its endpoint: it must prove itself anew, a fresh challenge arriving at
/// the new address, the trail noting the change without the key. She
/// disables it for good: it cannot be disabled twice nor resumed, its
/// status reads disabled. While it was active it could not be deleted;
/// disabled, she deletes it and it is gone.
#[tokio::test]
async fn tess_runs_a_stream_through_its_lifecycle() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let (_, keys) = published(&world).await;
    let receiver = register(&world, &stream("Poll", "ALL"), "Acme's receiver").await;
    prove_endpoint(&world, &receiver, &keys).await;
    let id = receiver.id.as_str();
    let trail_before = world.trail().ids().await;

    let status = signals::status(tenant, id).send(tess).await.ok();
    assert_eq!(status.status, "enabled", "a new stream runs");
    signals::delete(tenant, id)
        .send(tess)
        .await
        .refused(Status::CONFLICT, "conflict");

    signals::pause(tenant, id).send(tess).await.ok();
    let paused = signals::status(tenant, id).send(tess).await.ok();
    assert_eq!(paused.status, "paused", "the stream is paused");
    signals::pause(tenant, id)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    signals::resume(tenant, id).send(tess).await.ok();
    let running = signals::status(tenant, id).send(tess).await.ok();
    assert_eq!(running.status, "enabled", "the stream runs again");
    signals::resume(tenant, id)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    let moved = StreamChange {
        endpoint: Some(MOVED.to_owned()),
    };
    signals::change(tenant, id, &moved).send(tess).await.ok();
    let shown = signals::get(tenant, id).send(tess).await.ok();
    assert_eq!(shown.endpoint, MOVED, "the endpoint changed");
    assert_eq!(
        shown.verification, "Pending",
        "the new endpoint must prove itself"
    );
    let source = EventSource {
        tenant,
        receiver: &receiver,
        keys: &keys,
    };
    let (_, claims, _) = awaited(&source, VERIFICATION, |event| event["state"].is_string()).await;
    assert_eq!(
        claims["aud"], MOVED,
        "the challenge is addressed to the new endpoint"
    );
    let record = world
        .trail()
        .recorded_after(&trail_before, "signals.stream_updated")
        .await;
    no_secret_leaked(&record.details.to_string(), &[&receiver.key]);

    signals::disable(tenant, id).send(tess).await.ok();
    let disabled = signals::status(tenant, id).send(tess).await.ok();
    assert_eq!(disabled.status, "disabled", "the stream is off");
    signals::disable(tenant, id)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    signals::resume(tenant, id)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    signals::delete(tenant, id).send(tess).await.ok();
    signals::get(tenant, id)
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");

    for event in [
        "signals.stream_paused",
        "signals.stream_resumed",
        "signals.stream_disabled",
        "signals.stream_deleted",
    ] {
        world.trail().recorded_after(&trail_before, event).await;
    }

    stack.stop().await.expect("the stack stops cleanly");
}
