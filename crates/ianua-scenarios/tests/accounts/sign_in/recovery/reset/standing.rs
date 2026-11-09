//! A reset changes Max's password, never his standing: a link mailed
//! before Ann locked or deactivated him sets a new password, but neither
//! that nor his old one signs him in until Ann sets him active again,
//! and the reset and the standing changes are recorded apart.

use ianua_scenarios::api::{members, sessions};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::ChangeMemberStatus;
use ianua_scenarios::wire::sign_in::PasswordSignIn;
use ianua_scenarios::world::World;

use crate::recovery::reset::support::{access_after_reset, reset, reset_link, single_change};
use crate::support::settled_sign_in;

/// The password Max sets with the link: a sentence, so no scanner takes
/// it for a key.
const NEW_PASSWORD: &str = "Scenario restored orchard lantern 7194";

/// The record a change of a member's standing leaves.
const STATUS_CHANGED: &str = "organization.org_user_status_changed";

/// Ann locks Max after a reset link was mailed to him. The reset sets his
/// new password without unlocking him; neither
/// password signs him in and his old session is dead. Once Ann sets him
/// active again, the new password signs him in and the spent link sets
/// nothing more. The reset and the two standing changes are recorded.
#[tokio::test]
async fn a_password_reset_does_not_unlock_a_locked_member() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let trail = world.trail();
    let before = trail.count(STATUS_CHANGED).await;
    let token = reset_link(&world).await;

    change_standing(&world, "Locked").await;
    assert_eq!(
        trail.count(STATUS_CHANGED).await,
        before + 1,
        "the lock is recorded as a change of standing"
    );
    let unchanged = "the reset leaves Max locked";
    reset_preserving_standing(&world, &token, "Locked", unchanged).await;
    assert_eq!(
        trail.count(STATUS_CHANGED).await,
        before + 1,
        "the reset is not recorded as a change of standing"
    );
    reject_passwords_while_inactive(&world).await;
    reactivate_and_recover(&world, token).await;
    assert_eq!(
        trail.count(STATUS_CHANGED).await,
        before + 2,
        "the lock and the reactivation are the two changes of standing"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann deactivates Max after a reset link was mailed to him. The reset sets
/// his new password without reactivating him; neither password signs him in,
/// and his old session is dead. Once Ann sets him active again, the new password signs him in
/// and the spent link sets nothing more. The reset and the two standing
/// changes are recorded.
#[tokio::test]
async fn a_password_reset_does_not_reactivate_a_deactivated_member() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let trail = world.trail();
    let before = trail.count(STATUS_CHANGED).await;
    let token = reset_link(&world).await;

    change_standing(&world, "Deactivated").await;
    assert_eq!(
        trail.count(STATUS_CHANGED).await,
        before + 1,
        "the deactivation is recorded as a change of standing"
    );
    let unchanged = "the reset leaves Max deactivated";
    reset_preserving_standing(&world, &token, "Deactivated", unchanged).await;
    assert_eq!(
        trail.count(STATUS_CHANGED).await,
        before + 1,
        "the reset is not recorded as a change of standing"
    );
    reject_passwords_while_inactive(&world).await;
    reactivate_and_recover(&world, token).await;
    assert_eq!(
        trail.count(STATUS_CHANGED).await,
        before + 2,
        "the deactivation and the reactivation are the two changes of standing"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The reset replaces the password while retaining the administrator's chosen standing.
async fn reset_preserving_standing(world: &World<'_>, token: &str, expected: &str, reason: &str) {
    access_after_reset(world).await;
    sessions::confirm_member_password_reset(&reset(token, NEW_PASSWORD))
        .send(world.anonymous().client())
        .await
        .ok();
    assert_eq!(standing(world).await, expected, "{reason}");
}

/// Neither password authenticates an inactive member, and existing access remains ended.
async fn reject_passwords_while_inactive(world: &World<'_>) {
    for password in [world.member().password(), NEW_PASSWORD] {
        sessions::member_sign_in(&PasswordSignIn::of(world.member().email(), password))
            .send(world.anonymous().client())
            .await
            .refused(Status::NOT_FOUND, "not_found");
    }
    access_after_reset(world).await;
}

/// Reactivation permits the new password without reviving the old session or reset link.
async fn reactivate_and_recover(world: &World<'_>, token: String) {
    change_standing(world, "Active").await;
    members::me(world.org())
        .send(world.member().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let mut browser = Client::new(world.stack(), "Max, set active again").expect("a client");
    let sign_in = PasswordSignIn::of(world.member().email(), NEW_PASSWORD);
    let session = settled_sign_in(world.stack(), &browser, &sign_in).await;
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(world.org()).send(&browser).await.ok().email,
        world.member().email(),
        "the new password signs Max in once he is active again"
    );
    sessions::confirm_member_password_reset(&reset(&token, NEW_PASSWORD))
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    members::me(world.org()).send(&browser).await.ok();
    let mut secrets = world.cast_secrets();
    secrets.extend([token, NEW_PASSWORD.to_owned(), session.refresh_token]);
    single_change(world, &secrets).await;
}

/// Max's standing, as Ann lists him.
async fn standing(world: &World<'_>) -> String {
    let listed = members::list(world.org(), Some(world.member().email()))
        .send(world.owner().client())
        .await
        .ok();
    let [max] = listed.items.as_slice() else {
        panic!(
            "Max's address matches one member, not {}",
            listed.items.len()
        );
    };
    max.status.clone()
}

/// Ann sets Max's standing to `status`, `Active`, `Locked` or
/// `Deactivated`.
async fn change_standing(world: &World<'_>, status: &str) {
    let change = ChangeMemberStatus {
        status: status.to_owned(),
    };
    members::change_status(world.org(), world.member().id(), &change)
        .send(world.owner().client())
        .await
        .ok();
}
