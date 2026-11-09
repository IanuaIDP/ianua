//! A mailed proof keeps the purpose it was sent for, with both mailbox
//! sign-in and reset switched on: Max's sign-in link sets no password at
//! the reset endpoint and still signs him in, once; his reset link opens
//! no session at the sign-in endpoint and still resets his password.

use ianua_scenarios::api::{members, organizations, sessions};
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::ReplaceOrgSignInSettings;
use ianua_scenarios::wire::sign_in::{
    MagicLinkRequest, MagicLinkSignIn, MemberProof, Owed, PasswordSignIn, ResetLinkToken, Session,
    SignedIn,
};
use ianua_scenarios::world::World;

use crate::factors::member::others_keep_access;
use crate::recovery::reset::support::{
    CHANGED, access_after_reset, reset, reset_link, single_change,
};
use crate::support::{mail_linking_to, settled_sign_in};

/// The password a proof of the wrong purpose would set if it were taken.
const NEW_PASSWORD: &str = "Scenario separate orchard purpose 7194";

/// The record a sign-in leaves.
const SIGNED_IN: &str = "organization.org_login_succeeded";

/// Max's mailed sign-in link cannot reset his password.
/// It sets nothing, his session and password go on and no change is
/// recorded; the same link then signs him in, once, owing nothing, and
/// his password still signs him in. The sign-in records show no secret.
#[tokio::test]
async fn a_sign_in_link_resets_no_password_and_still_signs_in() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    allow_mailed_sign_in(&world).await;
    let token = sign_in_link(&world).await;
    reject_sign_in_link_as_reset(&world, &token).await;
    let mut browser = Client::new(&stack, "Max, following his sign-in link").expect("a client");
    let session = use_sign_in_link(&world, &mut browser, &token).await;

    let password_sign_in = PasswordSignIn::of(world.member().email(), world.member().password());
    let old = settled_sign_in(&stack, &browser, &password_sign_in).await;
    browser.authorize(&old.refresh_token);
    members::me(world.org()).send(&browser).await.ok();
    assert_sign_in_trail(
        &world,
        &[
            &token,
            NEW_PASSWORD,
            &session.refresh_token,
            &old.refresh_token,
        ],
    )
    .await;
    others_keep_access(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Requests Max's mailbox sign-in link from an anonymous client.
async fn sign_in_link(world: &World<'_>) -> String {
    let for_max = MagicLinkRequest {
        email: world.member().email().to_owned(),
    };
    sessions::request_magic_link(&for_max)
        .send(world.anonymous().client())
        .await
        .ok();
    let mail = mail_linking_to(world.stack(), world.member().email(), "/magic-link").await;
    mail.token_in("/magic-link")
}

/// A sign-in link cannot set a password or end existing access.
async fn reject_sign_in_link_as_reset(world: &World<'_>, token: &str) {
    sessions::confirm_member_password_reset(&reset(token, NEW_PASSWORD))
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    sessions::member_sign_in(&PasswordSignIn::of(world.member().email(), NEW_PASSWORD))
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let trail = world.trail();
    assert_eq!(
        trail.count(CHANGED).await,
        0,
        "a sign-in link changes no password"
    );
    others_keep_access(world).await;
}

/// The same link opens Max's session once, owing nothing, and replay leaves that session usable.
async fn use_sign_in_link(world: &World<'_>, browser: &mut Client, token: &str) -> Session {
    let sign_in = MagicLinkSignIn {
        token: token.to_owned(),
        tenant_slug: None,
    };
    let answer = sessions::sign_in_by_magic_link(&sign_in)
        .send(browser)
        .await
        .ok();
    let SignedIn::Authenticated(session) = answer else {
        panic!("the link names Max alone, so no choice is offered");
    };
    assert_eq!(
        session.owed(),
        Owed::Nothing,
        "the sign-in link opens a session owing nothing"
    );
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(world.org()).send(browser).await.ok().email,
        world.member().email(),
        "the sign-in link signs Max in"
    );
    sessions::sign_in_by_magic_link(&sign_in)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    members::me(world.org()).send(browser).await.ok();
    session
}

/// Max's sign-in is recorded without exposing secrets or recording a password change.
async fn assert_sign_in_trail(world: &World<'_>, secrets: &[&str]) {
    let trail = world.trail();
    assert_eq!(
        trail.count(CHANGED).await,
        0,
        "no password was changed along the way"
    );
    let records = trail.entries(SIGNED_IN).await;
    assert!(
        records
            .iter()
            .any(|record| record.actor.contains(world.member().email())),
        "Max's sign-in is recorded"
    );
    no_secret_leaked(&format!("{records:?}"), secrets);
}

/// Max's reset link cannot open a session even while mailbox sign-in is on.
/// Sent to the sign-in endpoint, it opens nothing and
/// records nothing; it still reads as valid, resets his password, ends
/// his old session, and the new password signs him in.
#[tokio::test]
async fn a_reset_link_signs_nobody_in_and_still_resets() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    allow_mailed_sign_in(&world).await;
    let token = reset_link(&world).await;
    let mut browser = Client::new(&stack, "Max, at the wrong endpoint").expect("a client");
    let trail = world.trail();
    let before = trail.count(SIGNED_IN).await;
    reject_reset_as_sign_in(&world, &browser, &token, before).await;
    reset_and_sign_in(&world, &mut browser, token).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A reset token cannot authenticate a browser or change the sign-in and password trails.
async fn reject_reset_as_sign_in(world: &World<'_>, browser: &Client, token: &str, before: usize) {
    let as_a_sign_in = MagicLinkSignIn {
        token: token.to_owned(),
        tenant_slug: None,
    };
    sessions::sign_in_by_magic_link(&as_a_sign_in)
        .send(browser)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    assert_eq!(
        world.trail().count(SIGNED_IN).await,
        before,
        "the reset link signed nobody in"
    );
    assert_eq!(
        world.trail().count(CHANGED).await,
        0,
        "the refused sign-in changed no password"
    );
    assert_link_still_valid(browser, token).await;
    others_keep_access(world).await;
}

/// The refusal at the wrong endpoint leaves the reset token valid.
async fn assert_link_still_valid(browser: &Client, token: &str) {
    let asked = ResetLinkToken {
        token: token.to_owned(),
    };
    let worth = sessions::member_reset_link_status(&asked)
        .send(browser)
        .await
        .ok();
    assert_eq!(worth.status, "Valid", "the link is still worth a reset");
}

/// The reset token performs its own purpose and the replacement password opens Max's account.
async fn reset_and_sign_in(world: &World<'_>, browser: &mut Client, token: String) {
    sessions::confirm_member_password_reset(&reset(&token, NEW_PASSWORD))
        .send(browser)
        .await
        .ok();
    access_after_reset(world).await;
    let sign_in = PasswordSignIn::of(world.member().email(), NEW_PASSWORD);
    let session = settled_sign_in(world.stack(), browser, &sign_in).await;
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(world.org()).send(browser).await.ok().email,
        world.member().email(),
        "the new password signs Max in"
    );
    let mut secrets = world.cast_secrets();
    secrets.extend([token, NEW_PASSWORD.to_owned(), session.refresh_token]);
    single_change(world, &secrets).await;
}

/// Ann switches mailbox sign-in on for Acme, so a refusal cannot be put
/// down to the method being off.
async fn allow_mailed_sign_in(world: &World<'_>) {
    let mut settings = organizations::sign_in_settings(world.org())
        .send(world.owner().client())
        .await
        .ok();
    settings.enabled_methods.push("MagicLink".to_owned());
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
