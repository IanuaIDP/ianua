//! Tess renames Pat, locks her, lets her back in and removes her, and
//! Pat feels each at once on the session she holds while Uma, untouched,
//! works on. Uma, Max, Sam and nobody signed in change nothing about Pat,
//! and a lock the trail cannot record leaves her active and signed in.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{members, people, sessions};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{AuditWrites, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::people::{ChangeUserStatus, UserChange};
use ianua_scenarios::wire::tenant_sign_in::TenantPasswordSignIn;
use ianua_scenarios::world::World;

use crate::support::person;

/// The audit record a changed standing leaves.
const STATUS_CHANGED: &str = "identity.user_status_changed";

/// The audit record a removed user leaves.
const DELETED: &str = "identity.user_deleted";

/// The standing `status`, to move a user to.
fn standing(status: &str) -> ChangeUserStatus {
    ChangeUserStatus {
        status: status.to_owned(),
    }
}

/// Tess renames Pat, who sees the new name on her own record, her
/// address and its proof unchanged. Tess locks her: Pat's session is
/// dead at once, and letting her back in does not revive it; signed in
/// afresh she is in, and both changes are recorded. Tess removes her:
/// that session is dead too and her password opens none, while Uma
/// works on. The removal is recorded once.
#[tokio::test]
async fn renaming_locking_releasing_and_removing_pat_each_show_at_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    rename_pat(&world, &pat).await;
    lock_and_release(&world, &mut pat).await;
    remove_pat(&world, &pat, &uma).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A rename changes Pat's displayed name while preserving her proved address.
async fn rename_pat(world: &World<'_>, pat: &Person) {
    people::change(
        world.tenant(),
        pat.id(),
        &UserChange {
            display_name: Some("Pat Updated".to_owned()),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    let own = people::me(world.tenant()).send(pat.client()).await.ok();
    assert_eq!(own.display_name, "Pat Updated", "Pat sees her new name");
    assert_eq!(own.email, pat.email(), "Pat's address is unchanged");
    assert!(own.email_verified, "Pat's address is still proved");
}

/// Locking ends Pat's session; releasing requires a fresh sign-in and records both changes.
async fn lock_and_release(world: &World<'_>, pat: &mut Person) {
    let before = world.trail().count(STATUS_CHANGED).await;
    people::change_status(world.tenant(), pat.id(), &standing("Locked"))
        .send(world.admin().client())
        .await
        .ok();
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    people::change_status(world.tenant(), pat.id(), &standing("Active"))
        .send(world.admin().client())
        .await
        .ok();
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    pat.sign_in(world.stack()).await;
    people::me(world.tenant()).send(pat.client()).await.ok();
    assert_eq!(
        world.trail().count(STATUS_CHANGED).await,
        before + 2,
        "the lock and the release are each recorded"
    );
}

/// Removing Pat ends her new session and password access while Uma remains signed in.
async fn remove_pat(world: &World<'_>, pat: &Person, uma: &Person) {
    people::remove(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let sign_in = TenantPasswordSignIn {
        email: pat.email().to_owned(),
        password: pat.password().to_owned(),
        fingerprint_hash: None,
    };
    sessions::sign_in(world.tenant(), &sign_in)
        .send(pat.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    people::me(world.tenant()).send(uma.client()).await.ok();
    assert_eq!(
        world.trail().count(DELETED).await,
        1,
        "the removal is recorded once"
    );
}

/// Uma, Max, Sam and an anonymous caller cannot rename, lock or remove Pat.
/// Her current session still reads her unchanged name, no status change or
/// deletion is recorded, and Sam remains signed in to his own company.
#[tokio::test]
async fn nobody_without_the_right_renames_locks_or_removes_pat() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let before = world.trail().count(STATUS_CHANGED).await;
    refuse_changes(&world, &pat, &uma).await;
    check_unchanged(&world, &pat, before).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Every unprivileged actor is refused each rename, lock and removal request.
async fn refuse_changes(world: &World<'_>, pat: &Person, uma: &Person) {
    for request in [
        people::change(
            world.tenant(),
            pat.id(),
            &UserChange {
                display_name: Some("Forbidden rename".to_owned()),
            },
        ),
        people::change_status(world.tenant(), pat.id(), &standing("Locked")),
        people::remove(world.tenant(), pat.id()),
    ] {
        Matrix::new("changing someone's record or standing", request.call())
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
}

/// Refused changes preserve Pat's name, both audit counts and the stranger's own session.
async fn check_unchanged(world: &World<'_>, pat: &Person, before: usize) {
    let own = people::me(world.tenant()).send(pat.client()).await.ok();
    assert_eq!(
        own.display_name,
        pat.account().display_name,
        "Pat still has her name"
    );
    assert_eq!(
        world.trail().count(STATUS_CHANGED).await,
        before,
        "no refused change of standing is recorded"
    );
    assert_eq!(
        world.trail().count(DELETED).await,
        0,
        "no refused removal is recorded"
    );
    members::me(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();
}

/// Tess's attempt to lock Pat fails when audit writes fail. Pat remains
/// active on her current session and no lock is recorded; with the
/// trail back the retry locks her, that same session is dead at once,
/// and the lock is recorded once.
#[tokio::test]
async fn a_lock_the_trail_cannot_record_leaves_pat_active_and_signed_in() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let before = world.trail().count(STATUS_CHANGED).await;
    people::me(world.tenant()).send(pat.client()).await.ok();
    fail_lock(&world, &pat, before).await;
    retry_lock(&world, &pat, before).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// An unwritable audit trail leaves Pat active on her original session.
async fn fail_lock(world: &World<'_>, pat: &Person, before: usize) {
    world.stack().audit_writes(AuditWrites::Refuse).await;
    let failed = people::change_status(world.tenant(), pat.id(), &standing("Locked"))
        .send(world.admin().client())
        .await;
    assert_eq!(
        failed.status(),
        Status::INTERNAL_SERVER_ERROR,
        "a lock the trail cannot record fails: {}",
        failed.summary()
    );
    world.stack().audit_writes(AuditWrites::Allow).await;
    let own = people::me(world.tenant()).send(pat.client()).await.ok();
    assert_eq!(own.status, "Active", "Pat is still active");
    assert_eq!(
        world.trail().count(STATUS_CHANGED).await,
        before,
        "the failed lock is not recorded"
    );
}

/// A successful retry ends Pat's original session and records one lock.
async fn retry_lock(world: &World<'_>, pat: &Person, before: usize) {
    people::change_status(world.tenant(), pat.id(), &standing("Locked"))
        .send(world.admin().client())
        .await
        .ok();
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_eq!(
        world.trail().count(STATUS_CHANGED).await,
        before + 1,
        "the retried lock is recorded once"
    );
}
