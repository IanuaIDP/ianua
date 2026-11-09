//! Max's password changed by Max, or reset by Ann: the old access stops
//! and the replacement signs him in, while a refused change leaves his
//! session and his reset link as they were, and nobody but Ann resets
//! another member's password.

use ianua_scenarios::api::{members, sessions};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::{ChangeMemberPassword, ResetMemberPassword};
use ianua_scenarios::wire::sign_in::ResetLinkToken;
use ianua_scenarios::world::World;

use crate::credentials::{REPLACEMENT, password_replaced, recorded_once, unspent_reset_token};
use crate::factors::member::others_keep_access;
use crate::support::WRONG_GUESS;

/// Max, with a reset link still unspent in his mailbox, changes his
/// password with his current one. The session he held and his old
/// password stop working, the reset link is worth nothing, the new
/// password signs him in and his colleagues keep their access. One change
/// is recorded in Max's name, with no password or token in it.
#[tokio::test]
async fn changing_a_password_ends_old_access_and_invalidates_outstanding_reset() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let token = unspent_reset_token(&world).await;

    members::change_password(
        world.org(),
        &ChangeMemberPassword {
            old_password: world.member().password().to_owned(),
            new_password: REPLACEMENT.to_owned(),
        },
    )
    .send(world.member().client())
    .await
    .ok();
    password_replaced(&world, REPLACEMENT, &token).await;

    recorded_once(
        &world,
        "organization.org_user_password_changed",
        world.member().email(),
        &[world.member().password(), REPLACEMENT, &token],
    )
    .await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory, on Max's signed-in session, tries to change his password
/// without knowing the current one, and Max himself tries a replacement
/// too weak to be allowed. Neither is accepted: the session still reads,
/// the reset link in his mailbox is still worth something, nothing is
/// recorded and his colleagues keep their access. With his current
/// password and a good replacement Max then changes it, through and
/// through.
#[tokio::test]
async fn a_refused_password_change_keeps_the_session_and_the_reset_link() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let token = unspent_reset_token(&world).await;

    assert_invalid_changes(&world).await;
    assert_password_unchanged(&world, &token).await;
    others_keep_access(&world).await;

    members::change_password(
        world.org(),
        &ChangeMemberPassword {
            old_password: world.member().password().to_owned(),
            new_password: REPLACEMENT.to_owned(),
        },
    )
    .send(world.member().client())
    .await
    .ok();
    password_replaced(&world, REPLACEMENT, &token).await;
    recorded_once(
        &world,
        "organization.org_user_password_changed",
        world.member().email(),
        &[REPLACEMENT, &token],
    )
    .await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A wrong current password and a weak replacement are refused for their distinct reasons.
async fn assert_invalid_changes(world: &World<'_>) {
    members::change_password(
        world.org(),
        &ChangeMemberPassword {
            old_password: WRONG_GUESS.to_owned(),
            new_password: REPLACEMENT.to_owned(),
        },
    )
    .send(world.member().client())
    .await
    .refused(Status::FORBIDDEN, "forbidden");
    members::change_password(
        world.org(),
        &ChangeMemberPassword {
            old_password: world.member().password().to_owned(),
            new_password: "x".to_owned(),
        },
    )
    .send(world.member().client())
    .await
    .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
}

/// Refused changes preserve Max's existing session and reset proof without recording a change.
async fn assert_password_unchanged(world: &World<'_>, token: &str) {
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    let link = sessions::member_reset_link_status(&ResetLinkToken {
        token: token.to_owned(),
    })
    .send(world.anonymous().client())
    .await
    .ok();
    assert_eq!(
        link.status, "Valid",
        "the reset link is still worth something after the refusals"
    );
    assert_eq!(
        world
            .trail()
            .count("organization.org_user_password_changed")
            .await,
        0,
        "a refused change records nothing"
    );
}

/// Max, Tess, Sam and nobody signed in each try to reset Max's password,
/// and Ann tries to reset her own, skipping the proof of her current one:
/// all are refused, Max's session still reads and nothing is recorded.
/// Ann resets Max's: the replacement shown to her signs him in, his old
/// access and reset link stop, and one reset is recorded in Ann's name.
#[tokio::test]
async fn only_an_owner_resets_another_members_password_and_never_her_own() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let token = unspent_reset_token(&world).await;
    let reset = ResetMemberPassword {
        password: Some(REPLACEMENT.to_owned()),
    };
    let resets_before = world
        .trail()
        .count("organization.org_user_password_reset")
        .await;

    assert_unauthorized_resets(&world, &reset).await;
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    assert_eq!(
        world
            .trail()
            .count("organization.org_user_password_reset")
            .await,
        resets_before,
        "a refused reset records nothing"
    );
    reset_as_owner(&world, &reset, &token).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Only an owner may reset another member; even the owner cannot skip her own current-password proof.
async fn assert_unauthorized_resets(world: &World<'_>, reset: &ResetMemberPassword) {
    Matrix::new(
        "resetting Max's password",
        members::reset_password(world.org(), world.member().id(), reset).call(),
    )
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.admin().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
    members::reset_password(world.org(), world.owner().id(), reset)
        .send(world.owner().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Ann's authorized reset returns the requested replacement and records it once in her name.
async fn reset_as_owner(world: &World<'_>, reset: &ResetMemberPassword, token: &str) {
    let shown = members::reset_password(world.org(), world.member().id(), reset)
        .send(world.owner().client())
        .await
        .ok();
    assert!(
        shown.new_password == REPLACEMENT,
        "the password Ann asked for is the one shown to her"
    );
    password_replaced(world, &shown.new_password, token).await;
    recorded_once(
        world,
        "organization.org_user_password_reset",
        world.owner().email(),
        &[REPLACEMENT, token],
    )
    .await;
}

/// Ann resets Max's password letting the platform choose one. The
/// password shown to her once signs Max in, his old password, session and
/// reset link stop, and one reset is recorded in Ann's name with no
/// password in it.
#[tokio::test]
async fn a_generated_replacement_password_really_signs_the_member_in() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let token = unspent_reset_token(&world).await;

    let shown = members::reset_password(
        world.org(),
        world.member().id(),
        &ResetMemberPassword { password: None },
    )
    .send(world.owner().client())
    .await
    .ok();
    assert!(
        !shown.new_password.is_empty(),
        "a generated password is shown to Ann"
    );
    password_replaced(&world, &shown.new_password, &token).await;

    recorded_once(
        &world,
        "organization.org_user_password_reset",
        world.owner().email(),
        &[&shown.new_password, &token],
    )
    .await;

    stack.stop().await.expect("the stack stops cleanly");
}
