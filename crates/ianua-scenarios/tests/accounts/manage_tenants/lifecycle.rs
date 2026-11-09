//! Ann moves her tenant through its life while Pat is signed in to it: a
//! suspension and an archive sign Pat out until a fresh sign-in after the
//! tenant is back; nobody but Ann moves it; a record that cannot be
//! written changes nothing; and once the archive grace has passed the
//! tenant is deleted, freeing the organization's room, and torn down
//! once.

use std::time::Duration;

use ianua_scenarios::actors::{Member, Person};
use ianua_scenarios::api::{members, organizations, people, tenants};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Matrix, Trail};
use ianua_scenarios::stack::{AuditWrites, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::tenants::TenantStatus;
use ianua_scenarios::world::World;

use crate::support::{Move, ann_signed_in_again, moved, pat_in_the_tenant};

/// A day past the thirty-day grace an archived tenant may be restored in.
const PAST_THE_ARCHIVE_GRACE: Duration = Duration::from_secs(31 * 24 * 3600);

/// Every move of a tenant's life, for the people who may make none.
const EVERY_MOVE: [Move; 5] = [
    Move::Suspend,
    Move::Reactivate,
    Move::Archive,
    Move::Restore,
    Move::Delete,
];

/// Ann suspends the tenant Pat is signed in to: Pat reads nothing. Ann
/// reactivates it: Pat's old session is still dead, and a fresh sign-in
/// lets her in. Ann still administers her organization, Sam's twin tenant
/// is untouched, and the two moves are recorded once each.
#[tokio::test]
async fn a_suspended_tenant_comes_back_only_for_a_fresh_sign_in() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = pat_in_the_tenant(&world).await;
    let before = world.trail().count("tenant.status_changed").await;
    suspend_tenant(&world, &pat).await;
    reactivate_tenant(&world, &mut pat).await;
    check_other_access(&world, before).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Suspending the tenant changes its state and blocks Pat's current session.
async fn suspend_tenant(world: &World<'_>, pat: &Person) {
    moved(world.tenant(), Move::Suspend)
        .send(world.owner().client())
        .await
        .ok();
    let suspended = tenants::get(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        suspended.status,
        TenantStatus::Suspended,
        "the tenant is suspended"
    );
    let shut_out = people::me(world.tenant()).send(pat.client()).await;
    assert!(
        !shut_out.status().is_success(),
        "Pat reads nothing in a suspended tenant: {}",
        shut_out.summary()
    );
}

/// Reactivation requires Pat to sign in again before she can read her own record.
async fn reactivate_tenant(world: &World<'_>, pat: &mut Person) {
    moved(world.tenant(), Move::Reactivate)
        .send(world.owner().client())
        .await
        .ok();
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    pat.sign_in(world.stack()).await;
    let me = people::me(world.tenant()).send(pat.client()).await.ok();
    assert_eq!(me.id, pat.id(), "a fresh sign-in lets Pat in");
}

/// Ann's organization and Sam's tenant stay accessible and both lifecycle changes are recorded.
async fn check_other_access(world: &World<'_>, before: usize) {
    members::me(world.org())
        .send(world.owner().client())
        .await
        .ok();
    tenants::get(world.twin())
        .send(world.stranger().client())
        .await
        .ok();
    assert_eq!(
        world.trail().count("tenant.status_changed").await,
        before + 2,
        "the suspension and the reactivation are recorded once each"
    );
}

/// Ann archives the tenant Pat is signed in to. Deleting it during its
/// grace is refused. Ann restores it: Pat's record is still there, her old
/// session is dead, and a fresh sign-in lets her in. Nothing recorded a
/// deletion.
#[tokio::test]
async fn an_archived_tenant_keeps_its_people_and_restoring_it_needs_a_fresh_sign_in() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = pat_in_the_tenant(&world).await;
    archive_during_grace(&world).await;
    restore_tenant(&world, &mut pat).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// An archived tenant cannot be deleted while its restoration grace remains.
async fn archive_during_grace(world: &World<'_>) {
    moved(world.tenant(), Move::Archive)
        .send(world.owner().client())
        .await
        .ok();
    let archived = tenants::get(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        archived.status,
        TenantStatus::Archived,
        "the tenant is archived"
    );
    moved(world.tenant(), Move::Delete)
        .send(world.owner().client())
        .await
        .refused(Status::CONFLICT, "conflict");
}

/// Restoration retains Pat's record but requires a fresh session and records no deletion.
async fn restore_tenant(world: &World<'_>, pat: &mut Person) {
    moved(world.tenant(), Move::Restore)
        .send(world.owner().client())
        .await
        .ok();
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    pat.sign_in(world.stack()).await;
    let me = people::me(world.tenant()).send(pat.client()).await.ok();
    assert_eq!(me.id, pat.id(), "Pat's record survived the archive");
    assert_eq!(
        world.trail().count("tenant.deleted").await,
        0,
        "nothing recorded a deletion"
    );
}

/// Tess, Max, Sam and an anonymous caller are refused every tenant
/// lifecycle action. The tenant is still active, Pat still signed
/// in, and no move was recorded.
#[tokio::test]
async fn only_the_owner_moves_a_tenant_through_its_life() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat_in_the_tenant(&world).await;
    let before = world.trail().count("tenant.status_changed").await;
    refuse_lifecycle_callers(&world).await;

    people::me(world.tenant()).send(pat.client()).await.ok();
    let untouched = tenants::get(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        untouched.status,
        TenantStatus::Active,
        "the tenant is still active"
    );
    assert_eq!(
        world.trail().count("tenant.status_changed").await,
        before,
        "a refused move records nothing"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Every lifecycle operation refuses tenant admins, members, strangers and anonymous callers.
async fn refuse_lifecycle_callers(world: &World<'_>) {
    for change in EVERY_MOVE {
        Matrix::new(change.what(), moved(world.tenant(), change).call())
            .refused(world.admin().client(), Status::FORBIDDEN, "forbidden")
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
}

/// Failure to record Ann's suspension rolls the change back: the tenant
/// stays active, Pat still reads her account, and no status change is recorded.
/// Once records can be written, the same suspension ends Pat's session
/// and is recorded once.
#[tokio::test]
async fn a_suspension_whose_record_cannot_be_written_changes_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat_in_the_tenant(&world).await;
    let before = world.trail().count("tenant.status_changed").await;
    fail_suspension(&world).await;
    check_failed_suspension(&world, &pat, before).await;
    retry_suspension(&world, &pat, before).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Suspension fails when its audit record cannot be written.
async fn fail_suspension(world: &World<'_>) {
    world.stack().audit_writes(AuditWrites::Refuse).await;
    let failed = moved(world.tenant(), Move::Suspend)
        .send(world.owner().client())
        .await;
    assert_eq!(
        failed.status(),
        Status::INTERNAL_SERVER_ERROR,
        "a suspension whose record cannot be written fails: {}",
        failed.summary()
    );
    world.stack().audit_writes(AuditWrites::Allow).await;
}

/// The failed suspension preserves the active tenant, Pat's session and its audit count.
async fn check_failed_suspension(world: &World<'_>, pat: &Person, before: usize) {
    let untouched = tenants::get(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        untouched.status,
        TenantStatus::Active,
        "the tenant is still active"
    );
    people::me(world.tenant()).send(pat.client()).await.ok();
    assert_eq!(
        world.trail().count("tenant.status_changed").await,
        before,
        "a failed suspension records nothing"
    );
}

/// Retrying after audit recovery blocks Pat and records exactly one suspension.
async fn retry_suspension(world: &World<'_>, pat: &Person, before: usize) {
    moved(world.tenant(), Move::Suspend)
        .send(world.owner().client())
        .await
        .ok();
    let shut_out = people::me(world.tenant()).send(pat.client()).await;
    assert!(
        !shut_out.status().is_success(),
        "Pat reads nothing once the tenant is suspended: {}",
        shut_out.summary()
    );
    assert_eq!(
        world.trail().count("tenant.status_changed").await,
        before + 1,
        "the suspension is recorded once"
    );
}

/// Ann archives the tenant, and the clock moves past the archive grace.
/// Signed in again, she deletes it: her organization has room for a
/// tenant again, the deleted tenant can neither be restored nor deleted
/// twice, one deletion is recorded, and its teardown runs once, even
/// across a restart.
#[tokio::test]
async fn an_archived_tenant_is_deleted_once_its_grace_has_passed() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().with("WORKER_SWEEP_TICK_SECONDS", "60"))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    moved(world.tenant(), Move::Archive)
        .send(world.owner().client())
        .await
        .ok();
    clock.advance(PAST_THE_ARCHIVE_GRACE);
    let ann = ann_signed_in_again(&world).await;
    delete_after_grace(&world, &ann).await;

    let trail = Trail::of_organization(ann.client(), world.org().slug());
    assert_eq!(
        trail.count("tenant.deleted").await,
        1,
        "one deletion record"
    );
    trail.recorded("tenant.torn_down").await;
    stack.restart().await.expect("the stack restarts");
    assert_eq!(
        trail.count("tenant.torn_down").await,
        1,
        "the teardown ran once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Deletion releases the tenant count and refuses both restoration and a second deletion.
async fn delete_after_grace(world: &World<'_>, ann: &Member) {
    moved(world.tenant(), Move::Delete)
        .send(ann.client())
        .await
        .ok();
    let organization = organizations::get(world.org())
        .send(ann.client())
        .await
        .ok();
    assert_eq!(
        organization.tenant_count, 0,
        "the deleted tenant no longer counts"
    );
    moved(world.tenant(), Move::Restore)
        .send(ann.client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    moved(world.tenant(), Move::Delete)
        .send(ann.client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
}
