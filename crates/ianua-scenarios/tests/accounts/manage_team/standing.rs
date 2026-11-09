//! Ann locks, lets back in and removes colleagues, and what each of them
//! can still do follows at once on every browser they hold. Max, Sam and
//! nobody signed in change nobody's standing; a standing nobody can be
//! moved to changes nothing; a removed colleague's password opens no
//! session and a stranger is not Ann's to remove; an administrator never
//! locks or removes an owner, and an owner never removes herself.

use ianua_scenarios::actors::Member;
use ianua_scenarios::api::{members, sessions};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::{ChangeMemberStatus, OrgRole};
use ianua_scenarios::wire::sign_in::PasswordSignIn;
use ianua_scenarios::world::World;

use crate::support::{another, listed, recorded};

/// The audit record a changed standing leaves.
const STATUS_CHANGED: &str = "organization.org_user_status_changed";

/// The audit record a removed member leaves.
const DELETED: &str = "organization.org_user_deleted";

/// The standing `status`, to move a member to.
fn standing(status: &str) -> ChangeMemberStatus {
    ChangeMemberStatus {
        status: status.to_owned(),
    }
}

/// Max, Sam and an anonymous caller cannot lock, deactivate or remove
/// Tess. She stays in on the session she
/// holds, stays active, and neither a change of standing nor a removal
/// is recorded.
#[tokio::test]
async fn nobody_without_the_right_changes_a_members_standing_or_removes_them() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let statuses_before = world.trail().count(STATUS_CHANGED).await;
    let deleted_before = world.trail().count(DELETED).await;
    refuse_standing_callers(&world).await;
    assert_eq!(
        listed(&world, world.admin().id()).await.status,
        "Active",
        "Tess is still active"
    );
    assert_eq!(
        world.trail().count(STATUS_CHANGED).await,
        statuses_before,
        "no refused change of standing is recorded"
    );
    assert_eq!(
        world.trail().count(DELETED).await,
        deleted_before,
        "no refused removal is recorded"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Each forbidden status change leaves Tess's existing session usable.
async fn refuse_standing_callers(world: &World<'_>) {
    for call in [
        members::change_status(world.org(), world.admin().id(), &standing("Locked")).call(),
        members::change_status(world.org(), world.admin().id(), &standing("Deactivated")).call(),
        members::remove(world.org(), world.admin().id()).call(),
    ] {
        Matrix::new("changing a colleague's standing", call)
            .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
            .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
            .refused(
                world.anonymous().client(),
                Status::UNAUTHORIZED,
                "unauthenticated",
            )
            .run()
            .await;
        members::me(world.org())
            .send(world.admin().client())
            .await
            .ok();
    }
}

/// Uma is signed in on two browsers, the second having replaced the
/// first. Ann moves her to active, which she is, to invited, which she
/// is past, and to a standing nobody has: each is refused and Uma's
/// second browser goes on working. Ann locks her: both browsers are out
/// at once, and the lock is recorded once under Ann. Let back in, Uma
/// signs in afresh; the browser locked out stays out.
#[tokio::test]
async fn a_lock_ends_every_session_and_an_impossible_standing_changes_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut uma = world
        .colleague("uma", "Uma Colleague", OrgRole::Member)
        .await;
    uma.sign_in(&stack).await;
    let second = another(&world, &uma).await;
    let before = world.trail().count(STATUS_CHANGED).await;
    refuse_impossible_standing(&world, &uma, &second, before).await;
    lock_both_browsers(&world, &uma, &second).await;
    check_recorded_lock(&world, &uma).await;
    release_uma(&world, &mut uma, &second).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Impossible status changes preserve Uma's current browser and leave no audit event.
async fn refuse_impossible_standing(
    world: &World<'_>,
    uma: &Member,
    second: &Member,
    before: usize,
) {
    for status in ["Active", "Invited", "Unknown"] {
        members::change_status(world.org(), uma.id(), &standing(status))
            .send(world.owner().client())
            .await
            .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
        members::me(world.org()).send(second.client()).await.ok();
    }
    assert_eq!(
        world.trail().count(STATUS_CHANGED).await,
        before,
        "no refused change of standing is recorded"
    );
}

/// Locking Uma blocks both the replaced browser and the currently active browser.
async fn lock_both_browsers(world: &World<'_>, uma: &Member, second: &Member) {
    members::change_status(world.org(), uma.id(), &standing("Locked"))
        .send(world.owner().client())
        .await
        .ok();
    for browser in [uma.client(), second.client()] {
        members::me(world.org())
            .send(browser)
            .await
            .refused(Status::UNAUTHORIZED, "unauthenticated");
    }
}

/// Exactly one lock event names Uma and attributes the action to Ann.
async fn check_recorded_lock(world: &World<'_>, uma: &Member) {
    let locks: Vec<_> = world
        .trail()
        .entries(STATUS_CHANGED)
        .await
        .into_iter()
        .filter(|entry| {
            entry.details["org_user"]["id"] == uma.id()
                && entry.details["status"]["change"]["to"] == "Locked"
        })
        .collect();
    let [lock] = locks.as_slice() else {
        panic!("Uma's lock is recorded once, not {} times", locks.len());
    };
    assert!(
        lock.actor.contains(world.owner().email()),
        "the lock is recorded under Ann"
    );
}

/// Release allows a new Uma sign-in without reviving the browser invalidated by the lock.
async fn release_uma(world: &World<'_>, uma: &mut Member, second: &Member) {
    members::change_status(world.org(), uma.id(), &standing("Active"))
        .send(world.owner().client())
        .await
        .ok();
    uma.sign_in(world.stack()).await;
    members::me(world.org()).send(uma.client()).await.ok();
    members::me(world.org())
        .send(second.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Max is signed in on two browsers. Ann is refused removing Sam, who is
/// not hers to remove, then removes Max: both his browsers are out at
/// once, his password opens no session, he is off the team list, and
/// removing him again finds nobody. The removal is recorded once under
/// Ann; Tess and Sam are still in.
#[tokio::test]
async fn a_removed_member_is_cut_off_at_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let second = another(&world, world.member()).await;
    members::me(world.org()).send(second.client()).await.ok();

    members::remove(world.org(), world.stranger().id())
        .send(world.owner().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    remove_max(&world, &second).await;
    check_max_absent(&world).await;
    recorded(&world, DELETED, world.member().id(), world.owner().email()).await;

    members::me(world.org())
        .send(world.admin().client())
        .await
        .ok();
    members::me(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Removing Max blocks both browsers and prevents his password from starting a session.
async fn remove_max(world: &World<'_>, second: &Member) {
    members::remove(world.org(), world.member().id())
        .send(world.owner().client())
        .await
        .ok();
    for browser in [world.member().client(), second.client()] {
        members::me(world.org())
            .send(browser)
            .await
            .refused(Status::UNAUTHORIZED, "unauthenticated");
    }
    let sign_in = PasswordSignIn {
        organization: Some(world.org().slug().to_owned()),
        ..PasswordSignIn::of(world.member().email(), world.member().password())
    };
    sessions::member_sign_in(&sign_in)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// Max is absent from the team list and a second removal finds no account.
async fn check_max_absent(world: &World<'_>) {
    let found = members::list(world.org(), Some(world.member().email()))
        .send(world.owner().client())
        .await
        .ok();
    assert!(found.items.is_empty(), "Max is off the team list");
    members::remove(world.org(), world.member().id())
        .send(world.owner().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// Uma's administrator role cannot lock, deactivate or remove owner Ann;
/// Ann cannot remove herself even with a second owner available.
/// Every attempt is refused, both owners stay in, and neither a
/// removal nor a change of standing is recorded.
#[tokio::test]
async fn an_administrator_cannot_lock_or_remove_an_owner_nor_can_an_owner_remove_herself() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut uma = world
        .colleague("uma", "Uma Administrator", OrgRole::Admin)
        .await;
    uma.sign_in(&stack).await;
    let mut coowner = world
        .colleague("coowner", "Other Owner", OrgRole::Owner)
        .await;
    coowner.sign_in(&stack).await;
    let statuses_before = world.trail().count(STATUS_CHANGED).await;
    refuse_owner_changes(&world, &uma).await;
    members::me(world.org())
        .send(world.owner().client())
        .await
        .ok();
    members::me(world.org()).send(coowner.client()).await.ok();
    assert_eq!(
        world.trail().count(DELETED).await,
        0,
        "no refused removal is recorded"
    );
    assert_eq!(
        world.trail().count(STATUS_CHANGED).await,
        statuses_before,
        "no refused change of standing is recorded"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// An administrator cannot disable or remove Ann, and Ann cannot remove herself.
async fn refuse_owner_changes(world: &World<'_>, uma: &Member) {
    for status in ["Locked", "Deactivated"] {
        members::change_status(world.org(), world.owner().id(), &standing(status))
            .send(uma.client())
            .await
            .refused(Status::FORBIDDEN, "forbidden");
    }
    members::remove(world.org(), world.owner().id())
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    members::remove(world.org(), world.owner().id())
        .send(world.owner().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}
