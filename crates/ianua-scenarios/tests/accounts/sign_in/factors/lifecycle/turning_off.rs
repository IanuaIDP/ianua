//! Max gives a factor up or turns it off: a setup he abandons is started
//! over and its old secret confirms nothing; turning his phone off needs
//! a fresh code, after which his sign-ins owe no phone; and Mallory, with
//! a copied session, can do neither. When Acme requires the factor, even
//! a fresh code leaves it on.

use ianua_scenarios::api::{member_factors, members};
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::{ConfirmFactor, FactorCode};
use ianua_scenarios::wire::sign_in::{MemberFactorSetup, PasswordSignIn};
use ianua_scenarios::world::World;

use crate::factors::lifecycle::setup;
use crate::factors::member::{answered, enrolled, others_keep_access, require_factor, waiting};
use crate::support::{WRONG_GUESS, settled_sign_in};

/// Max begins setting up an authenticator and gives it up. Mallory, with
/// his session but a wrong password, cannot give it up for him; Max does,
/// and the app that scanned the abandoned link confirms nothing. He
/// starts over with a different secret, and only the new phone finishes
/// his next sign-in. The trail holds two setups begun and one confirmed.
#[tokio::test]
async fn an_abandoned_setup_is_started_over_and_its_old_secret_confirms_nothing() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    let proof = setup(world.member().password());
    let begun = member_factors::begin_totp(world.org(), &proof)
        .send(world.member().client())
        .await
        .ok();
    let mut old = TotpApp::scanning(&begun.otpauth_uri);
    assert_wrong_abandonment(&world).await;
    abandon_and_refuse_old(&world, &proof, &mut old).await;

    let mut replacement = enrolled(&world).await;
    assert_ne!(
        old.secret(),
        replacement.phone.secret(),
        "starting over scans a different secret"
    );
    let mut browser = Client::new(&stack, "Max, using the replacement phone").expect("a client");
    waiting(&world, &mut browser, world.member().password()).await;
    answered(&world, &browser, &mut replacement.phone).await;
    others_keep_access(&world).await;
    assert_replacement_enrollments(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory's wrong password cannot abandon Max's pending setup or add another setup record.
async fn assert_wrong_abandonment(world: &World<'_>) {
    member_factors::abandon_totp(world.org(), &setup(WRONG_GUESS))
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    assert_eq!(
        world
            .trail()
            .count("organization.org_mfa_enrollment_started")
            .await,
        1,
        "the refused abandonment leaves the one setup begun"
    );
}

/// Max's authorized abandonment makes the old phone's setup code unusable without an enrollment record.
async fn abandon_and_refuse_old(world: &World<'_>, proof: &MemberFactorSetup, old: &mut TotpApp) {
    member_factors::abandon_totp(world.org(), proof)
        .send(world.member().client())
        .await
        .ok();
    let confirm = ConfirmFactor {
        code: old.code().await,
        session_id: None,
    };
    member_factors::confirm_totp(world.org(), &confirm)
        .send(world.member().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert_eq!(
        world.trail().count("organization.org_mfa_enrolled").await,
        0,
        "the abandoned setup was never confirmed"
    );
}

/// Both setup attempts are recorded, but only the replacement has a completed enrollment.
async fn assert_replacement_enrollments(world: &World<'_>) {
    let trail = world.trail();
    assert_eq!(
        trail.count("organization.org_mfa_enrollment_started").await,
        2,
        "two setups were begun"
    );
    assert_eq!(
        trail.count("organization.org_mfa_enrolled").await,
        1,
        "one setup was confirmed"
    );
}

/// Mallory cannot turn Max's phone off with his session and a spent code.
/// His session survives and no removal is recorded. Max turns it off with a
/// fresh code: the session he did it from is ended, and a sign-in with
/// his password and mailbox owes no phone any more. The record names Max
/// and holds no secret.
#[tokio::test]
async fn turning_a_factor_off_needs_a_fresh_code_and_the_next_sign_in_owes_none() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut factor = enrolled(&world).await;

    let spent = FactorCode {
        code: factor.phone.last_code_again(),
    };
    assert_spent_disable(&world, &spent).await;

    let fresh = FactorCode {
        code: factor.phone.code().await,
    };
    member_factors::disable_totp(world.org(), &fresh)
        .send(world.member().client())
        .await
        .ok();
    members::me(world.org())
        .send(world.member().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    let mut browser = Client::new(&stack, "Max, after turning his phone off").expect("a client");
    let sign_in = PasswordSignIn::of(world.member().email(), world.member().password());
    let session = settled_sign_in(&stack, &browser, &sign_in).await;
    browser.authorize(&session.refresh_token);
    members::me(world.org()).send(&browser).await.ok();
    others_keep_access(&world).await;
    assert_disable_record(&world, factor.phone.secret(), &session.refresh_token).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A spent code cannot disable the authenticator or end the existing session.
async fn assert_spent_disable(world: &World<'_>, spent: &FactorCode) {
    member_factors::disable_totp(world.org(), spent)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    assert_eq!(
        world.trail().count("organization.org_mfa_unenrolled").await,
        0,
        "a spent code turns nothing off"
    );
}

/// Max's sole successful removal is attributed to him and reveals no factor or session secret.
async fn assert_disable_record(world: &World<'_>, phone_secret: &str, refresh_token: &str) {
    let trail = world.trail();
    let record = trail.recorded("organization.org_mfa_unenrolled").await;
    assert_eq!(
        trail.count("organization.org_mfa_unenrolled").await,
        1,
        "the factor was turned off once"
    );
    assert!(
        record.actor.contains(world.member().email()),
        "the record names Max as the one who turned it off"
    );
    no_secret_leaked(&format!("{record:?}"), &[phone_secret, refresh_token]);
}

/// Max cannot turn off Acme's required factor even with a fresh code.
/// Nothing is turned off and his session goes on; the same
/// unspent code finishes his next sign-in, so the refusal kept the factor
/// whole.
#[tokio::test]
async fn a_required_factor_stays_on_even_with_a_fresh_code() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut factor = enrolled(&world).await;
    require_factor(&world).await;

    let code = FactorCode {
        code: factor.phone.code().await,
    };
    assert_required_factor_kept(&world, &code).await;

    let mut browser = Client::new(&stack, "Max, whose factor stays required").expect("a client");
    waiting(&world, &mut browser, world.member().password()).await;
    member_factors::verify(world.org(), &code)
        .send(&browser)
        .await
        .ok();
    members::me(world.org()).send(&browser).await.ok();
    assert_eq!(
        world.trail().count("organization.org_mfa_unenrolled").await,
        0,
        "the required factor was never turned off"
    );
    others_keep_access(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Even a fresh code cannot remove the policy-required factor or disturb Max's current session.
async fn assert_required_factor_kept(world: &World<'_>, code: &FactorCode) {
    member_factors::disable_totp(world.org(), code)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
}
