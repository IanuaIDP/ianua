//! Max asks for his reset link again. Right away he is told to wait,
//! and no mail goes out; once the cooldown has passed a replacement
//! arrives, which works, while the old link is dead. Mallory, pressing
//! resend with the old link, floods nobody's mailbox and resets nothing.

use std::time::Duration;

use ianua_scenarios::api::{members, sessions};
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sign_in::{PasswordSignIn, ResetLinkToken};
use ianua_scenarios::world::World;

use crate::factors::member::others_keep_access;
use crate::recovery::reset::support::{
    CHANGED, access_after_reset, reset, reset_link, single_change,
};
use crate::support::{QUIET, mail_linking_to, settled_sign_in};

/// How long the platform waits before mailing the same address again, and
/// before taking another resend: short, so the wait is real but brief.
const COOLDOWN: Duration = Duration::from_secs(2);

/// The password Max sets with the replacement link.
const NEW_PASSWORD: &str = "Scenario resent orchard lantern 4158";

/// The record a reset request leaves, once per link mailed.
const REQUESTED: &str = "organization.org_user_password_reset_requested";

/// Max asks for a reset link. Mallory, with that link, presses resend at
/// once and is told to wait; nothing is mailed. After the cooldown a
/// replacement arrives for Max, and the old link is throttled again and
/// mails nothing. Mallory cannot reset with the old link: no password change
/// is recorded and Max's session goes on. The replacement resets Max's
/// password, ending his session, and one change is recorded. Ann, Tess
/// and Sam keep their access, and no record shows a token or password.
#[tokio::test]
async fn a_resent_reset_link_waits_for_the_cooldown_and_replaces_the_old_one() {
    let profile = Profile::standard()
        .with("MAIL_COOLDOWN_SECONDS", &COOLDOWN.as_secs().to_string())
        .with(
            "MAIL_RESEND_COOLDOWN_SECONDS",
            &COOLDOWN.as_secs().to_string(),
        );
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let original = reset_link(&world).await;
    let mallory = Client::new(&stack, "Mallory, pressing resend").expect("a client");
    let fresh = resend_after_cooldown(&world, &mallory, &original).await;
    reject_superseded_link(&world, &mallory, &original).await;

    let mut secrets = world.cast_secrets();
    secrets.extend([original, fresh.clone(), NEW_PASSWORD.to_owned()]);
    secrets.push(recovered(&world, &fresh).await);
    single_change(&world, &secrets).await;
    let borrowed: Vec<&str> = secrets.iter().map(String::as_str).collect();
    no_secret_leaked(
        &format!("{:?}", world.trail().entries(REQUESTED).await),
        &borrowed,
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The cooldown suppresses immediate mail, then permits one replacement and throttles again.
async fn resend_after_cooldown(world: &World<'_>, mallory: &Client, original: &str) -> String {
    throttled(world, mallory, original).await;
    world
        .stack()
        .mailbox()
        .nothing_for(world.member().email(), COOLDOWN)
        .await;
    requested(world, 1).await;

    let fresh = replacement(world, original).await;
    assert_ne!(fresh, original, "the replacement carries a new token");
    throttled(world, mallory, original).await;
    world
        .stack()
        .mailbox()
        .nothing_for(world.member().email(), QUIET)
        .await;
    requested(world, 2).await;
    fresh
}

/// The superseded link changes no password and leaves the member's existing session usable.
async fn reject_superseded_link(world: &World<'_>, mallory: &Client, original: &str) {
    sessions::confirm_member_password_reset(&reset(original, NEW_PASSWORD))
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
    others_keep_access(world).await;
    let trail = world.trail();
    assert_eq!(
        trail.count(CHANGED).await,
        0,
        "the old link changed no password"
    );
}

/// A resend of `token` from `client` is told to wait, naming how many
/// seconds, within the cooldown; Max's session goes on.
async fn throttled(world: &World<'_>, client: &Client, token: &str) {
    let asked = ResetLinkToken {
        token: token.to_owned(),
    };
    let problem = sessions::resend_member_password_reset(&asked)
        .send(client)
        .await
        .refused(Status::TOO_MANY_REQUESTS, "rate_limit_exceeded");
    let seconds = problem
        .message()
        .split_whitespace()
        .find_map(|word| word.parse::<u64>().ok());
    assert!(
        seconds.is_some_and(|left| (1..=COOLDOWN.as_secs()).contains(&left)),
        "the refusal says how long to wait, within the cooldown"
    );
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
}

/// The token of the replacement link mailed to Max when `token` is resent
/// by nobody signed in: the resend names the cooldown, the link reaches
/// Max's address and reads as valid.
async fn replacement(world: &World<'_>, token: &str) -> String {
    let asked = ResetLinkToken {
        token: token.to_owned(),
    };
    let resent = sessions::resend_member_password_reset(&asked)
        .send(world.anonymous().client())
        .await
        .ok();
    assert_eq!(
        resent.retry_after_seconds,
        COOLDOWN.as_secs(),
        "the resend names the cooldown before the next one"
    );
    let mail = mail_linking_to(world.stack(), world.member().email(), "/reset-password").await;
    assert_eq!(
        mail.recipient(),
        world.member().email(),
        "the replacement reaches Max's address alone"
    );
    let fresh = mail.token_in("/reset-password");
    let asked = ResetLinkToken {
        token: fresh.clone(),
    };
    let worth = sessions::member_reset_link_status(&asked)
        .send(world.anonymous().client())
        .await
        .ok();
    assert_eq!(worth.status, "Valid", "the replacement reads as valid");
    fresh
}

/// The trail holds `expected` reset requests, every one for Max rather
/// than whoever asked.
async fn requested(world: &World<'_>, expected: usize) {
    let entries = world.trail().entries(REQUESTED).await;
    assert_eq!(
        entries.len(),
        expected,
        "the trail holds one request per link mailed"
    );
    assert!(
        entries
            .iter()
            .all(|entry| entry.actor.contains(world.member().email())),
        "every request names Max"
    );
}

/// Max resets his password with the replacement `token`: his old session
/// is dead, his old password signs nobody in, the new one signs him in to
/// his own company only, and the spent link sets nothing more without
/// ending the new session. The session's token, for the leak checks.
async fn recovered(world: &World<'_>, token: &str) -> String {
    let mut browser =
        Client::new(world.stack(), "Max, following the replacement").expect("a client");
    sessions::confirm_member_password_reset(&reset(token, NEW_PASSWORD))
        .send(&browser)
        .await
        .ok();
    access_after_reset(world).await;
    let old_sign_in = PasswordSignIn::of(world.member().email(), world.member().password());
    sessions::member_sign_in(&old_sign_in)
        .send(&browser)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let sign_in = PasswordSignIn::of(world.member().email(), NEW_PASSWORD);
    let session = settled_sign_in(world.stack(), &browser, &sign_in).await;
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(world.org()).send(&browser).await.ok().email,
        world.member().email(),
        "the new password signs Max in"
    );
    reject_replay_without_ending_session(world, &browser, token).await;
    session.refresh_token
}

/// A replay changes nothing, the new session stays usable only in Acme, and old access stays ended.
async fn reject_replay_without_ending_session(world: &World<'_>, browser: &Client, token: &str) {
    sessions::confirm_member_password_reset(&reset(token, NEW_PASSWORD))
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    members::me(world.org()).send(browser).await.ok();
    members::me(world.stranger().org())
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    access_after_reset(world).await;
}
