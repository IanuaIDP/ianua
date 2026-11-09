//! Ann hands her company to Uma while the audit trail cannot be written:
//! nothing changes and both keep their sessions; with the trail back the
//! same handover succeeds once, whole.

use ianua_scenarios::actors::Member;
use ianua_scenarios::api::members;
use ianua_scenarios::expect::Trail;
use ianua_scenarios::stack::{AuditWrites, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::OrgRole;
use ianua_scenarios::world::World;

/// Failure to record Ann's handover rolls back its role and session
/// changes. Neither Ann nor Uma keeps half a change: Ann is still
/// the owner and Uma a member, both on the sessions they hold, and
/// nothing is recorded. With the trail back the handover goes through
/// once: both sessions end, Uma signs in again as the owner, and the
/// trail holds one handover and two role changes. Sam is still in.
#[tokio::test]
async fn failed_handover_audit_rolls_back_roles_and_sessions_before_a_successful_retry() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut uma = world.colleague("uma", "Uma Heir", OrgRole::Member).await;
    uma.sign_in(&stack).await;
    fail_handover(&world, &uma).await;
    check_unchanged_handover(&world, &uma).await;
    retry_handover(&world, &mut uma).await;
    check_retry_records(&world, &uma).await;
    members::me(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// An unwritable trail makes Ann's ownership transfer fail.
async fn fail_handover(world: &World<'_>, uma: &Member) {
    world.stack().audit_writes(AuditWrites::Refuse).await;
    let failed = members::transfer_ownership(world.org(), uma.id())
        .send(world.owner().client())
        .await;
    assert_eq!(
        failed.status(),
        Status::INTERNAL_SERVER_ERROR,
        "a handover the trail cannot record fails: {}",
        failed.summary()
    );
    world.stack().audit_writes(AuditWrites::Allow).await;
}

/// Both original sessions retain their roles and the failed handover records no changes.
async fn check_unchanged_handover(world: &World<'_>, uma: &Member) {
    let ann = members::me(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        ann.role,
        Some(OrgRole::Owner),
        "Ann is still the owner on the session she holds"
    );
    let own = members::me(world.org()).send(uma.client()).await.ok();
    assert_eq!(
        own.role,
        Some(OrgRole::Member),
        "Uma is still a member on the session she holds"
    );
    let trail = world.trail();
    assert_eq!(
        trail.count("organization.ownership_transferred").await,
        0,
        "the failed handover is not recorded"
    );
    assert_eq!(
        trail.count("organization.org_user_role_changed").await,
        0,
        "the failed handover records no role change"
    );
}

/// The retry invalidates both original sessions and lets Uma sign in as owner.
async fn retry_handover(world: &World<'_>, uma: &mut Member) {
    members::transfer_ownership(world.org(), uma.id())
        .send(world.owner().client())
        .await
        .ok();
    members::me(world.org())
        .send(world.owner().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    members::me(world.org())
        .send(uma.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    uma.sign_in(world.stack()).await;
    let own = members::me(world.org()).send(uma.client()).await.ok();
    assert_eq!(own.role, Some(OrgRole::Owner), "Uma owns the company now");
}

/// The successful retry produces one handover and both role-change records.
async fn check_retry_records(world: &World<'_>, uma: &Member) {
    let trail = Trail::of_organization(uma.client(), world.org().slug());
    assert_eq!(
        trail.count("organization.ownership_transferred").await,
        1,
        "the retried handover is recorded once"
    );
    assert_eq!(
        trail.count("organization.org_user_role_changed").await,
        2,
        "the retried handover records both role changes"
    );
}
