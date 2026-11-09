//! Tess replacing her tenant's signing key: the new key signs, the old
//! one stays published until she revokes it, and then it is gone from
//! what anyone can read. The last key that signs cannot be revoked, and
//! Max may not touch the keys at all.

use ianua_scenarios::api::crypto;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::crypto::RotateKey;
use ianua_scenarios::world::World;

/// The algorithm Tess rotates to.
const ALGORITHM: &str = "ES256";

/// The old and replacement key identifiers retained through the rotation checks.
struct RotationKeys {
    new: String,
    old: String,
}

/// Tess replaces the tenant's signing key. The new key is the one that
/// signs, the old one is kept as rotated, and both are published, so
/// tokens the old key signed still check. She revokes the old key: it
/// leaves the published keys at once. She cannot revoke the only remaining
/// signing key, and Max cannot replace it. The new key stays published.
#[tokio::test]
async fn tess_replaces_the_signing_key_and_retires_the_old_one() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let rotation = RotateKey {
        algorithm: ALGORITHM.to_owned(),
    };

    crypto::rotate(world.tenant(), &rotation)
        .send(world.admin().client())
        .await
        .ok();
    let keys = assert_rotated_keys(&world).await;
    assert_both_published(&world, &keys).await;
    crypto::revoke(world.tenant(), &keys.old)
        .send(world.admin().client())
        .await
        .ok();
    let published = published_kids(&world).await;
    assert!(
        !published.contains(&keys.old),
        "a revoked key leaves the published keys at once"
    );
    assert_last_key_protected(&world, &rotation, &keys).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Rotation leaves exactly one active signer and retains the old rotated key.
async fn assert_rotated_keys(world: &World<'_>) -> RotationKeys {
    let keys = crypto::keys(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let active: Vec<_> = keys
        .keys
        .iter()
        .filter(|key| key.status == "Active")
        .collect();
    let rotated: Vec<_> = keys
        .keys
        .iter()
        .filter(|key| key.status == "Rotated")
        .collect();
    assert_eq!(active.len(), 1, "one key signs after the rotation");
    assert!(!rotated.is_empty(), "the old key is kept as rotated");
    let new = active[0].kid.clone();
    let old = rotated[0].kid.clone();
    RotationKeys { new, old }
}

/// Both generations remain published while the old key has not been revoked.
async fn assert_both_published(world: &World<'_>, keys: &RotationKeys) {
    let published = published_kids(world).await;
    assert!(published.contains(&keys.new), "the new key is published");
    assert!(
        published.contains(&keys.old),
        "the old key stays published, so its tokens still check"
    );
}

/// The last signer cannot be revoked and members cannot replace it.
async fn assert_last_key_protected(world: &World<'_>, rotation: &RotateKey, keys: &RotationKeys) {
    crypto::revoke(world.tenant(), &keys.new)
        .send(world.admin().client())
        .await
        .refused(Status::CONFLICT, "conflict");
    crypto::rotate(world.tenant(), rotation)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    assert!(
        published_kids(world).await.contains(&keys.new),
        "the new key still signs"
    );
}

/// The ids of the keys the tenant publishes, as anyone reads them.
async fn published_kids(world: &World<'_>) -> Vec<String> {
    crypto::published(world.tenant())
        .send(world.anonymous().client())
        .await
        .ok()
        .keys
        .into_iter()
        .map(|key| key.kid)
        .collect()
}
