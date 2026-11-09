//! Max's reset link and its deadline: Mallory, holding a link Max let
//! expire, changes nothing with it, and a fresh link still resets Max's
//! password; a link spent one second before its deadline works, while
//! one at the deadline or one second after it is refused and leaves his
//! password and access as they were. Application time is controlled, so
//! each boundary is exact.

use std::time::Duration;

use ianua_scenarios::api::{members, sessions};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sign_in::{PasswordSignIn, ResetLinkToken};
use ianua_scenarios::world::World;

use crate::recovery::reset::support::{
    CHANGED, access_after_reset, reset, reset_link, single_change,
};
use crate::support::{past_lifetime, settled_sign_in};

/// How long a reset link lives in these stacks: short enough that the
/// controlled application clock steps past it at once.
const LIFETIME: Duration = Duration::from_secs(10);

/// How long the platform waits before mailing the same address again in
/// the fresh-link scenario: short, so the fresh link can be asked for on
/// the real clock.
const MAIL_COOLDOWN: Duration = Duration::from_secs(1);

/// The password Max sets with a fresh link after the first expired.
const NEW_PASSWORD: &str = "Scenario renewed orchard harbour 3917";

/// The password Mallory tries to set with the expired link: it must never
/// become Max's, before or after he recovers.
const ATTEMPTED_PASSWORD: &str = "Scenario expired meadow lantern 6284";

/// Max lets his reset link expire. Mallory cannot set a password with it
/// or end his session; no change is recorded. Max asks for a fresh
/// link, still signs in with his old password, resets with the fresh link
/// and signs in with the new one. Neither the expired link nor the spent
/// one undoes that; Ann, Tess and Sam keep their access, and one change
/// is recorded.
#[tokio::test]
async fn an_expired_password_reset_changes_nothing_and_a_fresh_link_still_works() {
    let clock = Clock::controlled();
    let profile = Profile::standard()
        .with(
            "EMAIL_PASSWORD_RESET_TTL_SECONDS",
            &LIFETIME.as_secs().to_string(),
        )
        .with(
            "MAIL_COOLDOWN_SECONDS",
            &MAIL_COOLDOWN.as_secs().to_string(),
        );
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let expired = reset_link(&world).await;

    clock.advance(LIFETIME + Duration::from_secs(1));
    past_lifetime(MAIL_COOLDOWN).await;
    expired_attempt(&world, &expired).await;
    recover_after_expiry(&world, &expired).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// A fresh link replaces the password, and neither expired nor spent links undo that change.
async fn recover_after_expiry(world: &World<'_>, expired: &str) {
    let fresh = reset_link(world).await;
    assert_ne!(fresh, expired, "the fresh link carries a new token");
    let mut browser = Client::new(world.stack(), "Max, with a fresh reset link").expect("a client");
    let mut secrets = world.cast_secrets();
    secrets.extend([
        expired.to_owned(),
        fresh.clone(),
        NEW_PASSWORD.to_owned(),
        ATTEMPTED_PASSWORD.to_owned(),
    ]);
    secrets.push(replace_password(world, &mut browser, &fresh).await);
    access_after_reset(world).await;
    let changed = single_change(world, &secrets).await;

    let old_sign_in = PasswordSignIn::of(world.member().email(), world.member().password());
    sessions::member_sign_in(&old_sign_in)
        .send(&browser)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    secrets.push(signed_in(world, &mut browser, NEW_PASSWORD).await);

    for token in [expired, fresh.as_str()] {
        refused_replay(world, &browser, token).await;
        access_after_reset(world).await;
        assert_eq!(
            single_change(world, &secrets).await,
            changed,
            "the replayed links changed nothing more"
        );
    }
}

/// Max spends his reset link one second before its deadline: it reads as
/// valid, the new password is set, the session he held is dead, one
/// change is recorded, and the new password signs him in.
#[tokio::test]
async fn a_reset_link_works_one_second_before_its_expiry() {
    let profile = Profile::standard().with(
        "EMAIL_PASSWORD_RESET_TTL_SECONDS",
        &LIFETIME.as_secs().to_string(),
    );
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let clock = Clock::fixed();
    let token = reset_link(&world).await;

    clock.advance(LIFETIME - Duration::from_secs(1));
    assert_eq!(
        link_status(&world, &token).await,
        "Valid",
        "a second before its deadline the link reads as valid"
    );
    accept_unexpired_link(&world, &token).await;

    clock.advance(Duration::from_secs(1));
    let mut browser = Client::new(&stack, "Max, after the deadline").expect("a client");
    signed_in(&world, &mut browser, NEW_PASSWORD).await;
    members::me(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// An unexpired reset ends the member's session and records exactly one password change.
async fn accept_unexpired_link(world: &World<'_>, token: &str) {
    sessions::confirm_member_password_reset(&reset(token, NEW_PASSWORD))
        .send(world.anonymous().client())
        .await
        .ok();
    members::me(world.org())
        .send(world.member().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_eq!(
        world.trail().count(CHANGED).await,
        1,
        "the reset recorded one password change"
    );
}

/// At Max's reset link deadline, the link reads as expired and the reset
/// is refused. His session survives, no password change is recorded, and
/// his old password still signs him in.
#[tokio::test]
async fn a_reset_link_is_expired_at_its_exact_deadline() {
    let profile = Profile::standard().with(
        "EMAIL_PASSWORD_RESET_TTL_SECONDS",
        &LIFETIME.as_secs().to_string(),
    );
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let clock = Clock::fixed();
    let token = reset_link(&world).await;

    clock.advance(LIFETIME);
    assert_eq!(
        link_status(&world, &token).await,
        "Expired",
        "at its deadline the link reads as expired"
    );
    reject_expired_link(&world, &token).await;

    clock.advance(Duration::from_secs(1));
    let mut browser = Client::new(&stack, "Max, after the deadline").expect("a client");
    signed_in(&world, &mut browser, world.member().password()).await;
    members::me(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// One second past Max's reset link deadline, the link reads as expired
/// and the reset is refused. His session survives, no password change is
/// recorded, and his old password still signs him in.
#[tokio::test]
async fn a_reset_link_is_expired_one_second_after_its_deadline() {
    let profile = Profile::standard().with(
        "EMAIL_PASSWORD_RESET_TTL_SECONDS",
        &LIFETIME.as_secs().to_string(),
    );
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let clock = Clock::fixed();
    let token = reset_link(&world).await;

    clock.advance(LIFETIME + Duration::from_secs(1));
    assert_eq!(
        link_status(&world, &token).await,
        "Expired",
        "a second after its deadline the link reads as expired"
    );
    reject_expired_link(&world, &token).await;

    clock.advance(Duration::from_secs(1));
    let mut browser = Client::new(&stack, "Max, after the deadline").expect("a client");
    signed_in(&world, &mut browser, world.member().password()).await;
    members::me(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Expiry refuses the reset while preserving the member's session and unchanged trail.
async fn reject_expired_link(world: &World<'_>, token: &str) {
    sessions::confirm_member_password_reset(&reset(token, NEW_PASSWORD))
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    assert_eq!(
        world.trail().count(CHANGED).await,
        0,
        "the refused reset recorded no password change"
    );
}

/// What the link `token` is worth now, asked by nobody signed in.
async fn link_status(world: &World<'_>, token: &str) -> String {
    let asked = ResetLinkToken {
        token: token.to_owned(),
    };
    sessions::member_reset_link_status(&asked)
        .send(world.anonymous().client())
        .await
        .ok()
        .status
}

/// Mallory holds Max's expired link `token`: it reads as expired, sets no
/// password, the password she tried signs nobody in, everyone's access is
/// as it was, and no change is recorded.
async fn expired_attempt(world: &World<'_>, token: &str) {
    let mallory =
        Client::new(world.stack(), "Mallory, holding Max's expired link").expect("a client");
    assert_eq!(
        link_status(world, token).await,
        "Expired",
        "the link Max let expire reads as expired"
    );
    sessions::confirm_member_password_reset(&reset(token, ATTEMPTED_PASSWORD))
        .send(&mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let attempted = PasswordSignIn::of(world.member().email(), ATTEMPTED_PASSWORD);
    sessions::member_sign_in(&attempted)
        .send(&mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert_access_after_expiry(world, &mallory).await;
    assert_eq!(
        world.trail().count(CHANGED).await,
        0,
        "an expired link changes no password"
    );
}

/// The expired-link attempt leaves all existing members' access intact and Mallory signed out.
async fn assert_access_after_expiry(world: &World<'_>, mallory: &Client) {
    Matrix::new(
        "reading one's own account after an expired reset",
        members::me(world.org()).call(),
    )
    .allowed(world.member().client())
    .allowed(world.owner().client())
    .allowed(world.admin().client())
    .refused(mallory, Status::UNAUTHORIZED, "unauthenticated")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
    members::me(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();
}

/// Max, whose old password still signs him in through `browser`, resets
/// it with the fresh link `token`: the session just opened is dead and
/// the link reads as used. The dead session's token, for the leak checks.
async fn replace_password(world: &World<'_>, browser: &mut Client, token: &str) -> String {
    let previous = signed_in(world, browser, world.member().password()).await;
    sessions::confirm_member_password_reset(&reset(token, NEW_PASSWORD))
        .send(world.anonymous().client())
        .await
        .ok();
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_eq!(
        link_status(world, token).await,
        "AlreadyUsed",
        "the spent link reads as used"
    );
    previous
}

/// Max signs in through `browser` with `password` and his mailbox, and
/// reads his own account. The session's token, for the leak checks.
async fn signed_in(world: &World<'_>, browser: &mut Client, password: &str) -> String {
    let sign_in = PasswordSignIn::of(world.member().email(), password);
    let session = settled_sign_in(world.stack(), browser, &sign_in).await;
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(world.org()).send(browser).await.ok().email,
        world.member().email(),
        "the sign-in reads Max's own account"
    );
    session.refresh_token
}

/// Mallory replays the old link `token` after Max recovered: it sets
/// nothing, the password she tried signs nobody in, she reads nothing,
/// and Max's fresh session, on `browser`, reads his own company only.
async fn refused_replay(world: &World<'_>, browser: &Client, token: &str) {
    let mallory =
        Client::new(world.stack(), "Mallory, replaying an old reset link").expect("a client");
    sessions::confirm_member_password_reset(&reset(token, ATTEMPTED_PASSWORD))
        .send(&mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let attempted = PasswordSignIn::of(world.member().email(), ATTEMPTED_PASSWORD);
    sessions::member_sign_in(&attempted)
        .send(&mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    Matrix::new(
        "reading one's own account after a replayed reset link",
        members::me(world.org()).call(),
    )
    .allowed(browser)
    .refused(&mallory, Status::UNAUTHORIZED, "unauthenticated")
    .run()
    .await;
    members::me(world.stranger().org())
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}
