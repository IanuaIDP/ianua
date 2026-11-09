//! Tess registers a partner's program as a consumer of the tenant: its
//! key is shown once and never again, she renames it, gives it an hourly
//! allowance and a clearance, rotates its key with an overlap and ends the
//! overlap early, switches it off and on, and deletes it once it is off.
//! Uma, Max, Sam and nobody signed in do none of it, and nothing is
//! recorded for them.

use std::collections::HashSet;

use ianua_scenarios::api::consumers;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::consumers::{
    ClearanceChange, ConsumerMade, ConsumerName, NewConsumer, Quota, QuotaChange, Rotation,
};
use ianua_scenarios::world::World;

use crate::support::person;

/// The record a new consumer leaves.
const CREATED: &str = "consumers.consumer_created";

/// The record a rename leaves.
const RENAMED: &str = "consumers.consumer_renamed";

/// The record a changed allowance leaves.
const QUOTA_CHANGED: &str = "consumers.quota_changed";

/// The record a changed clearance leaves.
const CLEARANCE_CHANGED: &str = "consumers.clearance_changed";

/// The record a rotated key leaves.
const ROTATED: &str = "consumers.credential_rotated";

/// The record an overlap ended early leaves.
const OVERLAP_ENDED: &str = "consumers.credential_overlap_ended";

/// The record a consumer switched off leaves.
const DISABLED: &str = "consumers.consumer_disabled";

/// The record a consumer switched back on leaves.
const ENABLED: &str = "consumers.consumer_enabled";

/// The record a deleted consumer leaves.
const DELETED: &str = "consumers.consumer_deleted";

/// The partner's program, signing in with a key the platform makes.
fn partner_program() -> NewConsumer {
    NewConsumer {
        name: "Orders partner".to_owned(),
        description: Some("Reads order status for the courier".to_owned()),
        credential_kind: "api_key".to_owned(),
    }
}

/// Tess registers the partner's program.
async fn registered(world: &World<'_>) -> ConsumerMade {
    consumers::create(world.tenant(), &partner_program())
        .send(world.admin().client())
        .await
        .ok()
}

/// Every record of `event_types` the trail holds after `seen`.
async fn all_recorded(world: &World<'_>, seen: &HashSet<String>, event_types: &[&str]) {
    for event_type in event_types {
        world.trail().recorded_after(seen, event_type).await;
    }
}

/// Tess registers the partner's program: it starts active, cleared for
/// internal data, its key shown once and only a hint of it kept. The
/// tenant's list shows it with that hint. She renames it, gives it a
/// hundred requests an hour and clears it for confidential data, and
/// reads each back. She switches it off and on, and once it is off
/// again deletes it; it is gone from the list. Every step is on record.
#[tokio::test]
async fn tess_registers_a_partner_program_and_runs_it_to_its_end() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let seen = world.trail().ids().await;

    let made = registered(&world).await;
    let key = made.api_key.expect("the key is shown once");
    let read = consumers::get(world.tenant(), &made.id)
        .send(tess)
        .await
        .ok();
    assert_eq!(read.status, "Active");
    assert_eq!(read.clearance, "Internal", "internal data by default");
    assert!(
        !read.credential_hint.contains(&key),
        "only a hint of the key is kept"
    );
    let listed = consumers::list(world.tenant()).send(tess).await.ok();
    let shown = listed.items.iter().find(|consumer| consumer.id == made.id);
    assert!(
        shown.is_some_and(|consumer| consumer.credential_hint == read.credential_hint),
        "the list shows it by its hint"
    );

    let name = ConsumerName {
        name: "Courier partner".to_owned(),
    };
    consumers::rename(world.tenant(), &made.id, &name)
        .send(tess)
        .await
        .ok();
    let hourly = Quota {
        requests: 100,
        per: "hour".to_owned(),
    };
    let limited = consumers::change_quota(
        world.tenant(),
        &made.id,
        &QuotaChange {
            quota: Some(hourly.clone()),
        },
    )
    .send(tess)
    .await
    .ok();
    assert_eq!(limited.quota, Some(hourly));
    let cleared = consumers::change_clearance(
        world.tenant(),
        &made.id,
        &ClearanceChange {
            clearance: "Confidential".to_owned(),
        },
    )
    .send(tess)
    .await
    .ok();
    assert_eq!(cleared.clearance, "Confidential");
    assert_eq!(cleared.name, "Courier partner");

    consumers::disable(world.tenant(), &made.id)
        .send(tess)
        .await
        .ok();
    consumers::enable(world.tenant(), &made.id)
        .send(tess)
        .await
        .ok();
    let back = consumers::get(world.tenant(), &made.id)
        .send(tess)
        .await
        .ok();
    assert_eq!(back.status, "Active");
    consumers::disable(world.tenant(), &made.id)
        .send(tess)
        .await
        .ok();
    consumers::delete(world.tenant(), &made.id)
        .send(tess)
        .await
        .ok();
    consumers::get(world.tenant(), &made.id)
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");

    all_recorded(
        &world,
        &seen,
        &[
            CREATED,
            RENAMED,
            QUOTA_CHANGED,
            CLEARANCE_CHANGED,
            DISABLED,
            ENABLED,
            DELETED,
        ],
    )
    .await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess rotates the program's key with an hour's overlap: a new key is
/// shown once, different from the first, and the consumer names the old
/// key's hint and until when it still works. She ends the overlap early:
/// no old key is named any more, and ending it again is refused. An
/// active consumer cannot be deleted. Each step is on record.
#[tokio::test]
async fn tess_rotates_the_partner_s_key_and_ends_the_overlap_early() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let made = registered(&world).await;
    let first_key = made.api_key.expect("the key is shown once");
    let before = consumers::get(world.tenant(), &made.id)
        .send(tess)
        .await
        .ok();
    let seen = world.trail().ids().await;

    let rotation = Rotation {
        credential_kind: "api_key".to_owned(),
        overlap_seconds: Some(3600),
    };
    let rotated = consumers::rotate(world.tenant(), &made.id, &rotation)
        .send(tess)
        .await
        .ok();
    let second_key = rotated.api_key.expect("the new key is shown once");
    assert_ne!(second_key, first_key, "the new key is a new one");
    let overlapping = consumers::get(world.tenant(), &made.id)
        .send(tess)
        .await
        .ok();
    let previous = overlapping
        .previous_credential
        .expect("the old key still works for a while");
    assert_eq!(previous.credential_hint, before.credential_hint);
    assert!(!previous.until.is_empty());
    assert_ne!(overlapping.credential_hint, before.credential_hint);

    consumers::end_overlap(world.tenant(), &made.id)
        .send(tess)
        .await
        .ok();
    let ended = consumers::get(world.tenant(), &made.id)
        .send(tess)
        .await
        .ok();
    assert!(ended.previous_credential.is_none(), "the old key is dead");
    consumers::end_overlap(world.tenant(), &made.id)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    consumers::delete(world.tenant(), &made.id)
        .send(tess)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    all_recorded(&world, &seen, &[ROTATED, OVERLAP_ENDED]).await;
    world.trail().nothing_after(&seen, DELETED).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma, an ordinary user of the tenant, Max, a member with no
/// administrator's rights, Sam from the other company and nobody signed
/// in may not register, read, rename, rotate, switch off or delete the
/// partner's program. It stays as Tess left it and nothing is recorded.
#[tokio::test]
async fn nobody_without_the_right_touches_the_partner_s_program() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = person(&world, "uma").await;
    let made = registered(&world).await;
    let seen = world.trail().ids().await;
    let name = ConsumerName {
        name: "Taken over".to_owned(),
    };
    let rotation = Rotation {
        credential_kind: "api_key".to_owned(),
        overlap_seconds: None,
    };

    for request in [
        consumers::create(world.tenant(), &partner_program()).call(),
        consumers::get(world.tenant(), &made.id).call(),
        consumers::rename(world.tenant(), &made.id, &name).call(),
        consumers::rotate(world.tenant(), &made.id, &rotation).call(),
        consumers::disable(world.tenant(), &made.id).call(),
        consumers::delete(world.tenant(), &made.id).call(),
    ] {
        Matrix::new("managing the partner's program", request)
            .refused(uma.client(), Status::FORBIDDEN, "forbidden")
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

    let kept = consumers::get(world.tenant(), &made.id)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(kept.name, "Orders partner");
    assert_eq!(kept.status, "Active");
    for event_type in [CREATED, RENAMED, ROTATED, DISABLED, DELETED] {
        world.trail().nothing_after(&seen, event_type).await;
    }

    stack.stop().await.expect("the stack stops cleanly");
}
