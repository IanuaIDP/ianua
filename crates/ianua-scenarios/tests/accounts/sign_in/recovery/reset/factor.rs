//! Max set up an authenticator app, and a reset link is mailed to him.
//! Mallory, holding the link, resets nothing without the phone's fresh
//! code: no code, a wrong code and a code Max already typed are each
//! refused and leave his password, his session and the link as they
//! were. With a fresh code the password is set, and the new password
//! still owes the phone at sign-in.

use ianua_scenarios::api::{members, sessions};
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sign_in::{
    ConfirmMemberPasswordReset, PasswordSignIn, ResetLinkToken, Session,
};
use ianua_scenarios::world::World;

use crate::factors::member::{answered, enrolled, others_keep_access, waiting};
use crate::recovery::reset::support::{CHANGED, access_after_reset, reset_link, single_change};

/// The password the link would set: a sentence that must not become
/// Max's before the phone is answered.
const NEW_PASSWORD: &str = "Scenario protected orchard meadow 5194";

/// Sessions opened before and after the successful reset, retained for secret checks.
struct ResetSessions {
    old: Session,
    new: Session,
}

/// Mallory holds Max's reset link but not his phone. A missing, wrong or
/// already used code cannot reset his password. Each refusal leaves his
/// session, his old password and the link as they were, with no change
/// recorded. With a fresh code the password is set: Max's session ends,
/// the new password owes the phone at sign-in, the spent link and the old
/// password open nothing, and one change is recorded without a secret.
#[tokio::test]
async fn a_reset_needs_the_phones_fresh_code_and_the_new_password_still_owes_the_phone() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut factor = enrolled(&world).await;
    let token = reset_link(&world).await;
    let mallory = Client::new(&stack, "Mallory, with Max's reset link").expect("a client");

    let no_code = ConfirmMemberPasswordReset {
        token: token.clone(),
        password: NEW_PASSWORD.to_owned(),
        mfa_code: None,
    };
    reject_missing_or_stale_codes(&world, &mallory, &factor.phone, &no_code).await;
    let sessions = reset_with_fresh_code(&world, &mallory, &mut factor.phone, no_code).await;

    let mut secrets = world.cast_secrets();
    secrets.extend([
        token,
        NEW_PASSWORD.to_owned(),
        factor.phone.secret().to_owned(),
        sessions.old.refresh_token,
        sessions.new.refresh_token,
    ]);
    secrets.extend(factor.codes.all().iter().cloned());
    single_change(&world, &secrets).await;
    others_keep_access(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Missing, wrong, and already typed codes each leave the reset link and access unchanged.
async fn reject_missing_or_stale_codes(
    world: &World<'_>,
    mallory: &Client,
    phone: &TotpApp,
    no_code: &ConfirmMemberPasswordReset,
) {
    sessions::confirm_member_password_reset(no_code)
        .send(mallory)
        .await
        .refused(Status::FORBIDDEN, "step_up_required");
    unchanged(world, mallory, &no_code.token).await;

    let wrong_code = ConfirmMemberPasswordReset {
        mfa_code: Some("0000000".to_owned()),
        ..no_code.clone()
    };
    sessions::confirm_member_password_reset(&wrong_code)
        .send(mallory)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    unchanged(world, mallory, &no_code.token).await;

    let typed_code = ConfirmMemberPasswordReset {
        mfa_code: Some(phone.last_code_again()),
        ..no_code.clone()
    };
    sessions::confirm_member_password_reset(&typed_code)
        .send(mallory)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    unchanged(world, mallory, &no_code.token).await;
}

/// A fresh phone proof resets the password, ends the old session, and still requires the phone.
async fn reset_with_fresh_code(
    world: &World<'_>,
    mallory: &Client,
    phone: &mut TotpApp,
    no_code: ConfirmMemberPasswordReset,
) -> ResetSessions {
    let mut browser = Client::new(world.stack(), "Max, with his old password").expect("a client");
    let old = waiting(world, &mut browser, world.member().password()).await;
    answered(world, &browser, phone).await;
    let fresh_code = ConfirmMemberPasswordReset {
        mfa_code: Some(phone.code().await),
        ..no_code
    };
    sessions::confirm_member_password_reset(&fresh_code)
        .send(mallory)
        .await
        .ok();
    members::me(world.org())
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    access_after_reset(world).await;

    let new = waiting(world, &mut browser, NEW_PASSWORD).await;
    answered(world, &browser, phone).await;
    reject_spent_link_and_old_password(world, mallory, &browser, &fresh_code).await;
    ResetSessions { old, new }
}

/// The spent reset and old password fail without ending the newly completed session.
async fn reject_spent_link_and_old_password(
    world: &World<'_>,
    mallory: &Client,
    browser: &Client,
    fresh_code: &ConfirmMemberPasswordReset,
) {
    sessions::confirm_member_password_reset(fresh_code)
        .send(mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let old_sign_in = PasswordSignIn::of(world.member().email(), world.member().password());
    sessions::member_sign_in(&old_sign_in)
        .send(mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    members::me(world.org()).send(browser).await.ok();
}

/// After a refused reset: the password it tried signs nobody in, Mallory
/// reads nothing, Max's session goes on, the link `token` still reads as
/// valid, no change is recorded, and the others keep their access.
async fn unchanged(world: &World<'_>, mallory: &Client, token: &str) {
    let attempted = PasswordSignIn::of(world.member().email(), NEW_PASSWORD);
    sessions::member_sign_in(&attempted)
        .send(mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    members::me(world.org())
        .send(mallory)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    let asked = ResetLinkToken {
        token: token.to_owned(),
    };
    let worth = sessions::member_reset_link_status(&asked)
        .send(mallory)
        .await
        .ok();
    assert_eq!(worth.status, "Valid", "the link is still worth a reset");
    assert_eq!(
        world.trail().count(CHANGED).await,
        0,
        "the refused reset recorded no password change"
    );
    others_keep_access(world).await;
}
