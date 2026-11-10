//! Pat's reset link as the page it opens reads it before she types
//! anything: valid with the rules her new password must meet, spent once
//! used, expired past its deadline, worthless in the other tenant. A
//! resend waits out its cooldown, retires the old link and reaches only
//! Pat; Mallory, pressing it or guessing, gets nothing done.

use std::time::Duration;

use ianua_scenarios::actors::{Person, SignedInWith};
use ianua_scenarios::api::sessions;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sign_in::ResetLinkToken;
use ianua_scenarios::wire::tenant_sign_in::{ConfirmPasswordReset, ResetLinkWorth};
use ianua_scenarios::world::World;

use crate::support::{QUIET, mail_linking_to, past_lifetime};
use crate::tenant::support::person;

/// The password Pat chooses with her reset link.
const NEW_PASSWORD: &str = "Scenario resetting orchard lantern 7213";

/// The password Mallory tries to set with a dead link.
const ATTEMPTED_PASSWORD: &str = "Scenario meddling harbour lantern 6204";

/// How long a resend waits after the newest link in these stacks.
const COOLDOWN: Duration = Duration::from_secs(5);

/// How long a reset link lives in the expiry scenario.
const LIFETIME: Duration = Duration::from_secs(10);

/// The record a mailed reset leaves.
const RESET_REQUESTED: &str = "authentication.password_reset_requested";

/// The record a finished reset leaves.
const RESET_COMPLETED: &str = "authentication.password_reset_completed";

/// `value` as the body of a reset-link request.
fn link(value: &str) -> ResetLinkToken {
    ResetLinkToken {
        token: value.to_owned(),
    }
}

/// What the link `token` reads as in `world`'s tenant, to nobody signed
/// in.
async fn worth_of(world: &World<'_>, token: &str) -> ResetLinkWorth {
    sessions::reset_link_status(world.tenant(), &link(token))
        .send(world.anonymous().client())
        .await
        .ok()
}

/// Pat asks for a reset link. Before she types, her page reads it as
/// valid and carrying the rules her new password must meet, and reading it
/// again spends nothing. The same token reads as nothing in Sam's tenant,
/// and a made-up token reads as invalid, neither with any rules. Pat
/// resets with it and signs in: the link now reads as already used,
/// without rules.
#[tokio::test]
async fn pat_s_reset_link_reads_valid_with_its_rules_and_spent_after_she_uses_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    let token = pat.reset_link(&stack).await;

    let worth = worth_of(&world, &token).await;
    assert_eq!(worth.status, "Valid", "the mailed link reads as valid");
    assert!(
        worth.password_policy.is_some(),
        "a valid link carries the rules the reset enforces"
    );
    let again = worth_of(&world, &token).await;
    assert_eq!(again.status, "Valid", "reading it spends nothing");
    let elsewhere = sessions::reset_link_status(world.twin(), &link(&token))
        .send(world.anonymous().client())
        .await
        .ok();
    assert_eq!(
        elsewhere.status, "Invalid",
        "Sam's tenant knows no such link"
    );
    assert!(
        elsewhere.password_policy.is_none(),
        "a worthless link carries no rules"
    );
    let forged = worth_of(&world, "mallory made this reset token up").await;
    assert_eq!(forged.status, "Invalid", "a made-up token reads as invalid");
    assert!(forged.password_policy.is_none());

    pat.confirm_reset(&token, NEW_PASSWORD).await.ok();
    let spent = worth_of(&world, &token).await;
    assert_eq!(spent.status, "AlreadyUsed", "the used link reads as spent");
    assert!(
        spent.password_policy.is_none(),
        "a spent link carries no rules"
    );
    assert_eq!(pat.sign_in(&stack).await, SignedInWith::Password);

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat lets her reset link expire: its page reads expired and it sets
/// no password. A resend from that dead link mails her a fresh one, which
/// reads as valid and resets her password, and she signs in with it.
#[tokio::test]
async fn an_expired_reset_link_reads_expired_and_a_resend_mails_a_fresh_one() {
    let clock = Clock::controlled();
    let profile = Profile::standard()
        .with(
            "EMAIL_PASSWORD_RESET_TTL_SECONDS",
            &LIFETIME.as_secs().to_string(),
        )
        .with("MAIL_COOLDOWN_SECONDS", "1")
        .with("MAIL_RESEND_COOLDOWN_SECONDS", "1");
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    let expired = pat.reset_link(&stack).await;

    clock.advance(LIFETIME + Duration::from_secs(1));
    past_lifetime(Duration::from_secs(1)).await;
    assert_eq!(worth_of(&world, &expired).await.status, "Expired");
    pat.confirm_reset(&expired, ATTEMPTED_PASSWORD)
        .await
        .refused(Status::NOT_FOUND, "not_found");

    let fresh = resend_to_pat(&world, &pat, &expired, 1).await;
    assert_ne!(fresh, expired, "the replacement carries a new token");
    assert_eq!(worth_of(&world, &fresh).await.status, "Valid");
    pat.confirm_reset(&fresh, NEW_PASSWORD).await.ok();
    assert_eq!(pat.sign_in(&stack).await, SignedInWith::Password);

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory, with Pat's mailed link, presses resend at once and is told
/// to wait, naming how long; nothing is mailed. A made-up token gets a
/// plain not-found. Past the cooldown a replacement reaches Pat alone
/// while the old link is dead and resets nothing. Pat uses the new link:
/// one change is recorded, once per link mailed, and no record holds a
/// token.
#[tokio::test]
async fn a_resend_waits_for_its_cooldown_and_retires_the_old_link() {
    let profile = Profile::standard()
        .with("MAIL_COOLDOWN_SECONDS", &COOLDOWN.as_secs().to_string())
        .with(
            "MAIL_RESEND_COOLDOWN_SECONDS",
            &COOLDOWN.as_secs().to_string(),
        );
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    let original = pat.reset_link(&stack).await;
    let mallory = Client::new(&stack, "Mallory, pressing resend").expect("a client");

    told_to_wait(&world, &mallory, &original).await;
    sessions::resend_reset_link(world.tenant(), &link("mallory made this reset token up"))
        .send(&mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    stack.mailbox().nothing_for(pat.email(), COOLDOWN).await;

    let fresh = resend_to_pat(&world, &pat, &original, COOLDOWN.as_secs()).await;
    retired_link_changes_nothing(&world, &mallory, &original).await;
    told_to_wait(&world, &mallory, &original).await;
    stack.mailbox().nothing_for(pat.email(), QUIET).await;

    pat.confirm_reset(&fresh, NEW_PASSWORD).await.ok();
    assert_eq!(pat.sign_in(&stack).await, SignedInWith::Password);
    records_hold_no_token(&world, &[&original, &fresh]).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A resend of `token` by nobody signed in names `cooldown` and mails a
/// replacement to Pat alone, reading as valid; answers its token.
async fn resend_to_pat(world: &World<'_>, pat: &Person, token: &str, cooldown: u64) -> String {
    let resent = sessions::resend_reset_link(world.tenant(), &link(token))
        .send(world.anonymous().client())
        .await
        .ok();
    assert_eq!(
        resent.retry_after_seconds, cooldown,
        "the resend names its cooldown"
    );
    let mail = mail_linking_to(world.stack(), pat.email(), "/reset-password").await;
    assert_eq!(mail.recipient(), pat.email(), "only Pat gets the new link");
    mail.token_in("/reset-password")
}

/// A resend of `token` from `client` is told to wait, naming how many
/// seconds within the cooldown.
async fn told_to_wait(world: &World<'_>, client: &Client, token: &str) {
    let problem = sessions::resend_reset_link(world.tenant(), &link(token))
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
}

/// The replaced link `token` sets nothing for Mallory: refused as dead,
/// no change recorded.
async fn retired_link_changes_nothing(world: &World<'_>, mallory: &Client, token: &str) {
    let confirm = ConfirmPasswordReset {
        token: token.to_owned(),
        new_password: ATTEMPTED_PASSWORD.to_owned(),
        mfa_code: None,
    };
    sessions::confirm_password_reset(world.tenant(), &confirm)
        .send(mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert_eq!(
        world.trail().count(RESET_COMPLETED).await,
        0,
        "the retired link changed no password"
    );
}

/// Two links were mailed for one reset completed, and no record of the
/// reset or its links holds any of `tokens`.
async fn records_hold_no_token(world: &World<'_>, tokens: &[&str]) {
    let trail = world.trail();
    assert_eq!(
        trail.count(RESET_REQUESTED).await,
        2,
        "each mailed link is recorded"
    );
    assert_eq!(
        trail.count(RESET_COMPLETED).await,
        1,
        "one change is recorded"
    );
    for event_type in [RESET_REQUESTED, RESET_COMPLETED] {
        let entries = trail.entries(event_type).await;
        no_secret_leaked(&format!("{entries:?}"), tokens);
    }
}
