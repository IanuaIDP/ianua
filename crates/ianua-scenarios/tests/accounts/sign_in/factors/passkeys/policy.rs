//! A passkey challenge answers the policy and the clock in force when it
//! is answered: one issued before Ann switched passkeys off is refused and
//! spent, one issued before its lifetime passed is refused, and a fresh
//! one still signs her in. When Ann raises Acme's baseline to two
//! factors, her password alone leaves her waiting while her passkey lets
//! her in at once.

use std::time::Duration;

use ianua_scenarios::actors::Founder;
use ianua_scenarios::api::{OrgPath, member_factors, members, organizations};
use ianua_scenarios::expect::{Trail, no_secret_leaked};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::OrgSignInSettings;
use ianua_scenarios::wire::sign_in::Owed;
use serde_json::json;

use crate::factors::passkeys::{
    PasskeyHolder, answer, challenge, enrolled, replace_settings, signed_in,
};
use crate::support::past_lifetime;

/// How long a passkey challenge lives in the stack of the expiry
/// scenario: short enough to wait out on the real clock.
const CHALLENGE_LIFETIME: Duration = Duration::from_secs(5);

/// Disabling passkeys for Acme makes Ann's outstanding challenge fail
/// without granting access; switched back on, the same
/// challenge is spent and a fresh one signs her in. The failed sign-in is
/// recorded without her token.
#[tokio::test]
async fn a_passkey_challenge_obeys_a_method_disabled_after_it_was_issued() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let PasskeyHolder { ann, org, mut key } = enrolled(&stack).await;
    let mut browser = Client::new(&stack, "Ann, with an earlier challenge").expect("a client");
    let pending = answer(&mut key, challenge(&browser, ann.email()).await);

    let original = disable_passkeys(&ann, &org).await;
    member_factors::confirm_passkey_sign_in(&pending)
        .send(&browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    members::me(&org)
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    replace_settings(&ann, &org, original).await;
    member_factors::confirm_passkey_sign_in(&pending)
        .send(&browser)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let fresh = answer(&mut key, challenge(&browser, ann.email()).await);
    let session = signed_in(&browser, &fresh).await;
    browser.authorize(&session.refresh_token);
    members::me(&org).send(&browser).await.ok();

    let record = Trail::of_organization(&browser, org.slug())
        .recorded("organization.org_login_failed")
        .await;
    no_secret_leaked(&record.details.to_string(), &[&session.refresh_token]);

    stack.stop().await.expect("the stack stops cleanly");
}

/// An answer to Ann's expired passkey prompt is refused and reads nothing,
/// while the session she holds
/// goes on; a fresh challenge takes the same key.
#[tokio::test]
async fn an_expired_passkey_challenge_requires_a_fresh_ceremony() {
    let profile = Profile::standard().with(
        "AUTH_PASSKEY_CEREMONY_TTL_SECONDS",
        &CHALLENGE_LIFETIME.as_secs().to_string(),
    );
    let stack = Stack::start(profile).await.expect("the stack starts");
    let PasskeyHolder { ann, org, mut key } = enrolled(&stack).await;
    let mut browser = Client::new(&stack, "Ann, back at an old passkey prompt").expect("a client");

    let expired = answer(&mut key, challenge(&browser, ann.email()).await);
    past_lifetime(CHALLENGE_LIFETIME).await;
    member_factors::confirm_passkey_sign_in(&expired)
        .send(&browser)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    members::me(&org)
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    members::me(&org).send(ann.client()).await.ok();

    let fresh = answer(&mut key, challenge(&browser, ann.email()).await);
    let session = signed_in(&browser, &fresh).await;
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(&org).send(&browser).await.ok().email,
        ann.email(),
        "a fresh challenge takes the same key"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann raises Acme's baseline to two factors after adding her passkey.
/// Her password alone cannot open her account. The password sign-in
/// waits for a factor and reads nothing; her passkey's signature meets
/// the baseline with no code or mailbox step, and is recorded.
#[tokio::test]
async fn a_passkey_meets_a_two_factor_baseline_that_a_password_alone_does_not() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let PasskeyHolder { ann, org, mut key } = enrolled(&stack).await;
    let mut browser = Client::new(&stack, "Ann, under a two-factor baseline").expect("a client");
    require_factor_for_password(&ann, &org, &mut browser).await;

    let fresh = answer(&mut key, challenge(&browser, ann.email()).await);
    let session = signed_in(&browser, &fresh).await;
    assert_eq!(
        session.owed(),
        Owed::Nothing,
        "the passkey meets the two-factor baseline by itself"
    );
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(&org).send(&browser).await.ok().email,
        ann.email(),
        "the passkey session reads Ann's account"
    );
    Trail::of_organization(&browser, org.slug())
        .recorded("organization.org_login_succeeded")
        .await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Turn off passkeys while retaining the original settings for restoration.
async fn disable_passkeys(ann: &Founder, org: &OrgPath) -> OrgSignInSettings {
    let original = organizations::sign_in_settings(org)
        .send(ann.client())
        .await
        .ok();
    let mut disabled = original.clone();
    disabled
        .enabled_methods
        .retain(|method| method != "Passkey");
    replace_settings(ann, org, disabled).await;
    original
}

/// Raising the baseline leaves a password session owing a factor and unable
/// to read Ann's account.
async fn require_factor_for_password(ann: &Founder, org: &OrgPath, browser: &mut Client) {
    let mut settings = organizations::sign_in_settings(org)
        .send(ann.client())
        .await
        .ok();
    settings.rest.get_mut("step_up").expect("step-up policy")["baseline_aal"] = json!("Aal2");
    replace_settings(ann, org, settings).await;
    let waiting = ann.password_sign_in().await;
    assert_eq!(
        waiting.owed(),
        Owed::FactorCode,
        "a password alone leaves Ann owing a factor"
    );
    browser.authorize(&waiting.refresh_token);
    members::me(org)
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}
