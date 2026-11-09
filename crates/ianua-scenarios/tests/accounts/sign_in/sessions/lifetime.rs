//! How long Ann's session lives: idle for two minutes, and ten minutes in
//! all however busy she keeps it, each to the second. A sign-in still
//! waiting for her mailbox dies with its lifetime too, and its link then
//! finishes nothing. In every case a fresh sign-in opens her account.

use std::time::Duration;

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{OrgPath, members, organizations, sessions};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::Trail;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::ReplaceOrgSignInSettings;
use ianua_scenarios::wire::sign_in::{ConfirmSignIn, MemberProof, Owed, PasswordSignIn, SignedIn};
use serde_json::json;

use crate::support::{mail_linking_to, settled_sign_in};

/// How long Ann lets her company's sessions live in all: ten minutes,
/// short enough to step through minute by minute.
const LIFETIME_SECONDS: u64 = 600;

/// How long Ann lets a session sit idle: two minutes, well inside the
/// lifetime, so the two deadlines are told apart.
const IDLE_SECONDS: u64 = 120;

/// A write throttle longer than the idle window, so one read inside the
/// window renews nothing and the window ends when it was first set to.
const THROTTLE_BEYOND_IDLE_SECONDS: u64 = 600;

/// Ann's password is accepted and her sign-in waits for her mailbox, but
/// she follows the link only once the session's whole lifetime has
/// passed: the link finishes nothing, twice over, and her browser reads
/// nothing. A fresh sign-in with its own link opens her account.
#[tokio::test]
async fn an_expired_pending_session_cannot_be_revived_by_its_mailbox_proof() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let Account { ann, org } = configured(&stack).await;
    let mut browser = Client::new(&stack, "Ann, leaving a sign-in waiting").expect("a client");
    let stale = begin_pending_sign_in(&stack, &ann, &mut browser).await;

    clock.advance(Duration::from_secs(LIFETIME_SECONDS + 1));
    for _ in 0..2 {
        sessions::confirm_member_sign_in(&stale)
            .send(&browser)
            .await
            .refused(Status::NOT_FOUND, "not_found");
        members::me(&org)
            .send(&browser)
            .await
            .refused(Status::UNAUTHORIZED, "unauthenticated");
    }

    signed_in_afresh(&stack, &ann, &org, &mut browser).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann signs in and leaves her session idle past its two-minute window:
/// it reads nothing, and reading again revives nothing. A fresh sign-in
/// with its mailbox proof opens her account, with one new sign-in record.
#[tokio::test]
async fn an_idle_session_stays_expired_until_a_fresh_sign_in() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let Account { ann, org } = configured(&stack).await;
    let mut browser = Client::new(&stack, "Ann, leaving her session idle").expect("a client");
    signed_in_afresh(&stack, &ann, &org, &mut browser).await;
    let signed_in_before = Trail::of_organization(&browser, org.slug())
        .count("organization.org_login_succeeded")
        .await;

    clock.advance(Duration::from_secs(IDLE_SECONDS + 1));
    for _ in 0..2 {
        members::me(&org)
            .send(&browser)
            .await
            .refused(Status::UNAUTHORIZED, "unauthenticated");
    }

    signed_in_afresh(&stack, &ann, &org, &mut browser).await;
    assert_eq!(
        Trail::of_organization(&browser, org.slug())
            .count("organization.org_login_succeeded")
            .await,
        signed_in_before + 1,
        "the fresh sign-in is recorded once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann reads her record every minute, and each read keeps her session
/// alive past the two-minute idle window; but ten minutes after signing
/// in the session ends however busy she was, and a fresh sign-in is
/// needed, recorded once. Credential writes are unthrottled here: the
/// clock advanced is the application's, not the write throttle's.
#[tokio::test]
async fn activity_extends_idle_time_but_not_the_session_lifetime() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().with("CREDENTIAL_USE_INTERVAL_SECONDS", "0"))
        .await
        .expect("the stack starts");
    let Account { ann, org } = configured(&stack).await;
    let mut browser = Client::new(&stack, "Ann, busy on her session").expect("a client");
    signed_in_afresh(&stack, &ann, &org, &mut browser).await;
    let signed_in_before = Trail::of_organization(&browser, org.slug())
        .count("organization.org_login_succeeded")
        .await;

    for _ in 0..9 {
        clock.advance(Duration::from_secs(60));
        members::me(&org).send(&browser).await.ok();
    }
    clock.advance(Duration::from_secs(61));
    members::me(&org)
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    signed_in_afresh(&stack, &ann, &org, &mut browser).await;
    assert_eq!(
        Trail::of_organization(&browser, org.slug())
            .count("organization.org_login_succeeded")
            .await,
        signed_in_before + 1,
        "the fresh sign-in is recorded once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann signs in and reads her record one second before the idle window
/// ends, which works; at the deadline and a second past it the session
/// reads nothing. A fresh sign-in opens her account. The write throttle
/// is set beyond the window, so that one read does not renew it.
#[tokio::test]
async fn idle_access_ends_at_the_deadline_after_working_one_second_before_it() {
    let clock = Clock::fixed();
    let stack = Stack::start(Profile::standard().with(
        "CREDENTIAL_USE_INTERVAL_SECONDS",
        &THROTTLE_BEYOND_IDLE_SECONDS.to_string(),
    ))
    .await
    .expect("the stack starts");
    let Account { ann, org } = configured(&stack).await;
    let mut browser = Client::new(&stack, "Ann, at the idle deadline").expect("a client");
    signed_in_afresh(&stack, &ann, &org, &mut browser).await;

    clock.advance(Duration::from_secs(IDLE_SECONDS - 1));
    members::me(&org).send(&browser).await.ok();
    clock.advance(Duration::from_secs(1));
    members::me(&org)
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    clock.advance(Duration::from_secs(1));
    members::me(&org)
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    signed_in_afresh(&stack, &ann, &org, &mut browser).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann keeps her session busy every minute and reads one second before
/// its lifetime ends, which works; at the deadline and a second past it
/// the session reads nothing, however recent her last read. A fresh
/// sign-in opens her account.
#[tokio::test]
async fn absolute_access_ends_at_the_deadline_despite_recent_activity() {
    let clock = Clock::fixed();
    let stack = Stack::start(Profile::standard().with("CREDENTIAL_USE_INTERVAL_SECONDS", "0"))
        .await
        .expect("the stack starts");
    let Account { ann, org } = configured(&stack).await;
    let mut browser = Client::new(&stack, "Ann, at the lifetime's end").expect("a client");
    signed_in_afresh(&stack, &ann, &org, &mut browser).await;

    for _ in 0..9 {
        clock.advance(Duration::from_secs(60));
        members::me(&org).send(&browser).await.ok();
    }
    clock.advance(Duration::from_secs(59));
    members::me(&org).send(&browser).await.ok();
    for _ in 0..2 {
        clock.advance(Duration::from_secs(1));
        members::me(&org)
            .send(&browser)
            .await
            .refused(Status::UNAUTHORIZED, "unauthenticated");
    }

    signed_in_afresh(&stack, &ann, &org, &mut browser).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann's mailed link finishes her waiting sign-in one second before the
/// sign-in's lifetime ends: the session reads her record, and one
/// confirmation is recorded.
#[tokio::test]
async fn a_pending_sign_in_can_finish_one_second_before_its_deadline() {
    pending_sign_in_at(LIFETIME_SECONDS - 1, PendingAt::Live).await;
}

/// Ann's mailed link cannot finish her waiting sign-in at its exact
/// deadline. It opens nothing; a fresh sign-in does, and
/// its confirmation is the one recorded.
#[tokio::test]
async fn a_pending_sign_in_cannot_finish_at_its_exact_deadline() {
    pending_sign_in_at(LIFETIME_SECONDS, PendingAt::Expired).await;
}

/// Ann's mailed link cannot finish her waiting sign-in one second after
/// its deadline. It opens nothing; a fresh sign-in does, and
/// its confirmation is the one recorded.
#[tokio::test]
async fn a_pending_sign_in_cannot_finish_one_second_after_its_deadline() {
    pending_sign_in_at(LIFETIME_SECONDS + 1, PendingAt::Expired).await;
}

/// Ann and the organization whose session limits she set.
struct Account {
    /// Ann, signed in.
    ann: Founder,
    /// Her organization.
    org: OrgPath,
}

/// Whether a waiting sign-in still takes its own mailed link at a given
/// age.
#[derive(Clone, Copy)]
enum PendingAt {
    /// The link finishes it.
    Live,
    /// The link finishes nothing.
    Expired,
}

/// Ann's password is accepted and her sign-in waits for her mailbox; she
/// follows the link `age` seconds later, and `at` says whether that is
/// in time. Either way she reads her record in the end, after a fresh
/// sign-in when the link was too late, and one confirmation is recorded.
/// The idle window is as long as the lifetime, so only the lifetime ends
/// the sign-in.
async fn pending_sign_in_at(age: u64, at: PendingAt) {
    let clock = Clock::fixed();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let Account { ann, org } = configured_with_idle(&stack, LIFETIME_SECONDS).await;
    let confirmed_before = Trail::of_organization(ann.client(), org.slug())
        .count("organization.org_mfa_verified")
        .await;
    let mut browser =
        Client::new(&stack, "Ann, at the waiting sign-in's deadline").expect("a client");
    let proof = begin_pending_sign_in(&stack, &ann, &mut browser).await;

    clock.advance(Duration::from_secs(age));
    confirm_at_deadline(&org, &browser, &proof, at).await;
    if matches!(at, PendingAt::Expired) {
        signed_in_afresh(&stack, &ann, &org, &mut browser).await;
    }
    assert_eq!(
        Trail::of_organization(&browser, org.slug())
            .count("organization.org_mfa_verified")
            .await,
        confirmed_before + 1,
        "{age} seconds on, one confirmation is recorded"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann's password opens a pending session whose mailed proof can be held until
/// the deadline; the browser uses that pending session throughout the wait.
async fn begin_pending_sign_in(
    stack: &Stack,
    ann: &Founder,
    browser: &mut Client,
) -> ConfirmSignIn {
    let answer = sessions::member_sign_in(&PasswordSignIn::of(ann.email(), FOUNDER_PASSWORD))
        .send(browser)
        .await
        .ok();
    let SignedIn::Authenticated(waiting) = answer else {
        panic!("Ann is in one organization, so no choice is offered");
    };
    assert_eq!(
        waiting.owed(),
        Owed::MailedConfirmation,
        "a device Ann never remembered waits for her mailbox"
    );
    let mail = mail_linking_to(stack, ann.email(), "/confirm-sign-in").await;
    browser.authorize(&waiting.refresh_token);
    ConfirmSignIn {
        token: mail.token_in("/confirm-sign-in"),
        refresh_token: waiting.refresh_token,
    }
}

/// The pending proof either opens the account before expiry or leaves both
/// confirmation and authenticated access refused at the deadline.
async fn confirm_at_deadline(
    org: &OrgPath,
    browser: &Client,
    proof: &ConfirmSignIn,
    at: PendingAt,
) {
    let answer = sessions::confirm_member_sign_in(proof).send(browser).await;
    match at {
        PendingAt::Live => {
            answer.ok();
            members::me(org).send(browser).await.ok();
        }
        PendingAt::Expired => {
            answer.refused(Status::NOT_FOUND, "not_found");
            members::me(org)
                .send(browser)
                .await
                .refused(Status::UNAUTHORIZED, "unauthenticated");
        }
    }
}

/// Ann, signed in, with her company's sessions set to the ten-minute
/// lifetime and the two-minute idle window.
async fn configured(stack: &Stack) -> Account {
    configured_with_idle(stack, IDLE_SECONDS).await
}

/// Ann, signed in, with her company's sessions set to the ten-minute
/// lifetime and an idle window of `idle_seconds`, through the settings
/// as the dashboard changes them.
async fn configured_with_idle(stack: &Stack, idle_seconds: u64) -> Account {
    let mut ann = Founder::named(stack, "Ann");
    let founded = ann.founded(stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let session = ann.signed_in(stack).await;
    ann.client_mut().authorize(&session.refresh_token);
    save_session_limits(&ann, &org, idle_seconds).await;
    Account { ann, org }
}

/// Ann saves the absolute and idle deadlines with her password proof through
/// the same settings request used by an administrator.
async fn save_session_limits(ann: &Founder, org: &OrgPath, idle_seconds: u64) {
    let mut settings = organizations::sign_in_settings(org)
        .send(ann.client())
        .await
        .ok();
    settings
        .rest
        .insert("session_lifetime_secs".to_owned(), json!(LIFETIME_SECONDS));
    settings
        .rest
        .insert("idle_timeout_secs".to_owned(), json!(idle_seconds));
    organizations::replace_sign_in_settings(
        org,
        &ReplaceOrgSignInSettings {
            settings,
            proof: MemberProof {
                password: FOUNDER_PASSWORD.to_owned(),
                code: None,
            },
        },
    )
    .send(ann.client())
    .await
    .ok();
}

/// Ann signs in afresh through `browser`, settling the sign-in from her
/// mailbox, and the new session reads her own record.
async fn signed_in_afresh(stack: &Stack, ann: &Founder, org: &OrgPath, browser: &mut Client) {
    let session = settled_sign_in(
        stack,
        browser,
        &PasswordSignIn::of(ann.email(), FOUNDER_PASSWORD),
    )
    .await;
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(org).send(browser).await.ok().email,
        ann.email(),
        "the fresh session reads Ann's own record"
    );
}
