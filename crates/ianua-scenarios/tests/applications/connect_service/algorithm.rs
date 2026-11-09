//! Tess moves the tenant's token signing from RSA to elliptic-curve keys
//! without breaking anyone: she plans the move, starts it so both keys
//! are published, promotes the new key and completes the move, and the
//! old key leaves the published set. A plan can be cancelled before it
//! starts and a started move rolled back. Uma, Max, Sam and nobody signed
//! in plan nothing.

use std::collections::HashSet;

use ianua_scenarios::api::crypto;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::crypto::{PlanMigration, RollBack};
use ianua_scenarios::world::World;

use crate::support::person;

/// The record a planned move leaves.
const PLANNED: &str = "crypto.migration_planned";

/// The record a started move leaves.
const STARTED: &str = "crypto.migration_started";

/// The record a promoted key leaves.
const PROMOTED: &str = "crypto.migration_promoted";

/// The record a completed move leaves.
const COMPLETED: &str = "crypto.migration_completed";

/// The record a cancelled plan leaves.
const CANCELLED: &str = "crypto.migration_cancelled";

/// The record a rolled-back move leaves.
const ROLLED_BACK: &str = "crypto.migration_rolled_back";

/// A move to elliptic-curve keys.
fn to_elliptic_curve() -> PlanMigration {
    PlanMigration {
        target_algorithm: "ES256".to_owned(),
    }
}

/// The ids of the keys the tenant publishes now, read as any relying
/// party reads them.
async fn published(world: &World<'_>) -> HashSet<String> {
    let keys = crypto::published(world.tenant())
        .send(world.anonymous().client())
        .await
        .ok();
    keys.keys.into_iter().map(|key| key.kid).collect()
}

/// The status of the key `kid` among the tenant's signing keys.
async fn key_status(world: &World<'_>, kid: &str) -> Option<String> {
    let keys = crypto::keys(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    keys.keys
        .into_iter()
        .find(|key| key.kid == kid)
        .map(|key| key.status)
}

/// Tess plans a move from the RSA key to an elliptic-curve one, on
/// record; a second plan beside it is refused. She starts it: a new key
/// is made and published beside the old one. She promotes the new key,
/// and then completes the move: the new key alone is active and
/// published, the old one revoked and gone from the published set. Every
/// step is on record.
#[tokio::test]
async fn tess_moves_the_tenant_s_signing_to_elliptic_curve_keys() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let seen = world.trail().ids().await;

    crypto::plan_migration(world.tenant(), &to_elliptic_curve())
        .send(tess)
        .await
        .ok();
    let planned = crypto::migration(world.tenant()).send(tess).await.ok();
    assert_eq!(planned.status, "Planned");
    assert_eq!(planned.source_algorithm, "RS256");
    assert_eq!(planned.target_algorithm, "ES256");
    assert_eq!(planned.target_key_id, None, "no key is made at the plan");
    let old_key = planned.source_key_id;
    crypto::plan_migration(world.tenant(), &to_elliptic_curve())
        .send(tess)
        .await
        .refused(Status::CONFLICT, "conflict");

    let new_key = crypto::start_migration(world.tenant())
        .send(tess)
        .await
        .ok()
        .key_id;
    let both = published(&world).await;
    assert!(both.contains(&old_key) && both.contains(&new_key));
    let started = crypto::migration(world.tenant()).send(tess).await.ok();
    assert_eq!(started.status, "InProgress");

    crypto::promote_migration(world.tenant())
        .send(tess)
        .await
        .ok();
    let validating = crypto::migration(world.tenant()).send(tess).await.ok();
    assert_eq!(validating.status, "Validating");
    crypto::complete_migration(world.tenant())
        .send(tess)
        .await
        .ok();
    let after = published(&world).await;
    assert!(after.contains(&new_key), "the new key is published");
    assert!(!after.contains(&old_key), "the old key is gone");
    assert_eq!(
        key_status(&world, &new_key).await.as_deref(),
        Some("Active")
    );
    assert_eq!(
        key_status(&world, &old_key).await.as_deref(),
        Some("Revoked")
    );

    for event_type in [PLANNED, STARTED, PROMOTED, COMPLETED] {
        world.trail().recorded_after(&seen, event_type).await;
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess plans a move and cancels it before it starts, on record. She
/// plans again and starts, then rolls back with a reason, on record: the
/// new key is revoked and leaves the published set, and the RSA key
/// still signs.
#[tokio::test]
async fn tess_cancels_one_move_and_rolls_another_back() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let seen = world.trail().ids().await;

    crypto::plan_migration(world.tenant(), &to_elliptic_curve())
        .send(tess)
        .await
        .ok();
    let old_key = crypto::migration(world.tenant())
        .send(tess)
        .await
        .ok()
        .source_key_id;
    crypto::cancel_migration(world.tenant())
        .send(tess)
        .await
        .ok();
    world.trail().recorded_after(&seen, CANCELLED).await;

    crypto::plan_migration(world.tenant(), &to_elliptic_curve())
        .send(tess)
        .await
        .ok();
    let new_key = crypto::start_migration(world.tenant())
        .send(tess)
        .await
        .ok()
        .key_id;
    crypto::cancel_migration(world.tenant())
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let reason = RollBack {
        reason: "A relying party cannot read elliptic-curve keys yet".to_owned(),
    };
    crypto::roll_back_migration(world.tenant(), &reason)
        .send(tess)
        .await
        .ok();
    world.trail().recorded_after(&seen, ROLLED_BACK).await;
    let after = published(&world).await;
    assert!(!after.contains(&new_key), "the new key is gone");
    assert!(after.contains(&old_key), "the RSA key is still published");
    assert_eq!(
        key_status(&world, &old_key).await.as_deref(),
        Some("Active")
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma, an ordinary user of the tenant, Max, a member with no
/// administrator's rights, Sam from the other company and nobody signed
/// in may not plan a move. No move is under way afterwards and nothing is
/// recorded.
#[tokio::test]
async fn nobody_without_the_right_moves_the_tenant_s_signing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = person(&world, "uma").await;
    let seen = world.trail().ids().await;

    Matrix::new(
        "planning a move of the tenant's signing",
        crypto::plan_migration(world.tenant(), &to_elliptic_curve()).call(),
    )
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

    crypto::migration(world.tenant())
        .send(world.admin().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    world.trail().nothing_after(&seen, PLANNED).await;

    stack.stop().await.expect("the stack stops cleanly");
}
