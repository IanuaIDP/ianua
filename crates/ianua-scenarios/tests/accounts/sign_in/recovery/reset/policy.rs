//! A reset link obeys the account and the password rules in force when
//! it is followed, not when it was sent: Max's link recreates no account
//! after Ann removed him, and sets no password that met the old minimum
//! after Ann raised it, while a sentence meeting the new rules resets
//! once.

use ianua_scenarios::api::{members, organizations, sessions};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::ReplaceOrgSignInSettings;
use ianua_scenarios::wire::sign_in::{MemberProof, PasswordSignIn, ResetLinkToken};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::factors::member::others_keep_access;
use crate::recovery::reset::support::{
    CHANGED, access_after_reset, reset, reset_link, single_change,
};
use crate::support::settled_sign_in;

/// The least characters a password may have once Ann tightens the rule.
const RAISED_MINIMUM: usize = 40;

/// A sentence longer than the raised minimum.
const LONG_PASSWORD: &str = "Scenario orchard harbour mountain lantern meadow 5194";

/// A sentence that met the old minimum and falls short of the raised one.
const SHORT_PASSWORD: &str = "Scenario orchard meadow 5194";

/// Ann removes Max from Acme after a reset link was mailed to him. The
/// link cannot recreate his account: it sets nothing and reads as invalid,
/// neither password signs him in, he is not listed, no change is recorded
/// and the removal is; Ann, Tess and Sam keep their access.
#[tokio::test]
async fn a_removed_members_reset_link_cannot_recreate_the_account() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let token = reset_link(&world).await;

    members::remove(world.org(), world.member().id())
        .send(world.owner().client())
        .await
        .ok();
    reject_removed_members_link(&world, token).await;
    let listed = members::list(world.org(), Some(world.member().email()))
        .send(world.owner().client())
        .await
        .ok();
    assert!(listed.items.is_empty(), "the removed member is not listed");
    access_after_reset(&world).await;

    let trail = world.trail();
    assert_eq!(
        trail.count(CHANGED).await,
        0,
        "the refused reset recorded no password change"
    );
    trail.recorded("organization.org_user_deleted").await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A removed member's link is invalid, and neither password opens an account.
async fn reject_removed_members_link(world: &World<'_>, token: String) {
    let visitor = world.anonymous().client();
    sessions::confirm_member_password_reset(&reset(&token, LONG_PASSWORD))
        .send(visitor)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let worth = sessions::member_reset_link_status(&ResetLinkToken { token })
        .send(visitor)
        .await
        .ok();
    assert_eq!(
        worth.status, "Invalid",
        "a removed member's link reads as invalid"
    );
    for password in [world.member().password(), LONG_PASSWORD] {
        sessions::member_sign_in(&PasswordSignIn::of(world.member().email(), password))
            .send(visitor)
            .await
            .refused(Status::NOT_FOUND, "not_found");
    }
}

/// Ann raises Acme's password minimum after a reset link was mailed to
/// Max. The link cannot set a password below the new minimum. Max's
/// session and the link survive the refusal and nothing is recorded; a
/// sentence meeting the new rule resets once, ends his old session and
/// signs him in.
#[tokio::test]
async fn an_outstanding_reset_obeys_the_current_password_policy() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let token = reset_link(&world).await;
    raise_minimum(&world).await;
    reject_short_password(&world, &token).await;
    accept_long_password(&world, token).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The current minimum refuses a short password without spending the link or ending access.
async fn reject_short_password(world: &World<'_>, token: &str) {
    sessions::confirm_member_password_reset(&reset(token, SHORT_PASSWORD))
        .send(world.anonymous().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    let asked = ResetLinkToken {
        token: token.to_owned(),
    };
    let worth = sessions::member_reset_link_status(&asked)
        .send(world.anonymous().client())
        .await
        .ok();
    assert_eq!(worth.status, "Valid", "the link is still worth a reset");
    let trail = world.trail();
    assert_eq!(
        trail.count(CHANGED).await,
        0,
        "the refused reset recorded no password change"
    );
    sessions::member_sign_in(&PasswordSignIn::of(world.member().email(), SHORT_PASSWORD))
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    others_keep_access(world).await;
}

/// A qualifying password resets once, ends old access, and opens Max's account.
async fn accept_long_password(world: &World<'_>, token: String) {
    sessions::confirm_member_password_reset(&reset(&token, LONG_PASSWORD))
        .send(world.anonymous().client())
        .await
        .ok();
    access_after_reset(world).await;
    let mut browser =
        Client::new(world.stack(), "Max, with a long enough password").expect("a client");
    let sign_in = PasswordSignIn::of(world.member().email(), LONG_PASSWORD);
    let session = settled_sign_in(world.stack(), &browser, &sign_in).await;
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(world.org()).send(&browser).await.ok().email,
        world.member().email(),
        "the new password signs Max in"
    );
    let mut secrets = world.cast_secrets();
    secrets.extend([token, LONG_PASSWORD.to_owned(), session.refresh_token]);
    single_change(world, &secrets).await;
}

/// Ann raises Acme's password minimum to forty characters and changes
/// nothing else, with her password typed again.
async fn raise_minimum(world: &World<'_>) {
    let mut settings = organizations::sign_in_settings(world.org())
        .send(world.owner().client())
        .await
        .ok();
    settings
        .rest
        .get_mut("password_policy")
        .expect("password policy")["min_length"] = json!(RAISED_MINIMUM);
    let replace = ReplaceOrgSignInSettings {
        settings,
        proof: MemberProof {
            password: world.owner().password().to_owned(),
            code: None,
        },
    };
    organizations::replace_sign_in_settings(world.org(), &replace)
        .send(world.owner().client())
        .await
        .ok();
}
