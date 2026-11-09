//! Max loses his phone. Ann, the owner, resets his factor, which nobody
//! else may: his sessions end, his old printout is dead, and a new phone
//! set up after a password-and-mailbox sign-in gets him in. Under a
//! required factor, a printed recovery code proves him but opens nothing
//! until a new phone is confirmed on that same sign-in.

use std::time::Duration;

use ianua_scenarios::api::{member_factors, members};
use ianua_scenarios::authenticators::{RecoveryCodes, TotpApp};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::ConfirmFactor;
use ianua_scenarios::wire::sign_in::{MemberRecoveryCode, PasswordSignIn, Session};
use ianua_scenarios::world::World;

use crate::factors::lifecycle::setup;
use crate::factors::member::{answered, enrolled, others_keep_access, require_factor, waiting};
use crate::support::settled_sign_in;

/// One step of an authenticator app's clock: the next code is shown only
/// in the next step, and a controlled clock moves there at once.
const CODE_STEP: Duration = Duration::from_secs(30);

/// After Max loses his phone, neither he, Tess, Sam nor an anonymous caller
/// can reset his factor. His session survives and no reset is recorded.
/// Ann resets it: Max's session is ended and a code
/// from his old printout opens nothing. He signs in with his password
/// and mailbox, sets up a new phone, and his next sign-in refuses the old
/// printout and takes the new phone's code. The record names Ann.
#[tokio::test]
async fn a_reset_lost_factor_ends_access_and_a_new_phone_signs_in() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut factor = enrolled(&world).await;
    assert_unauthorized_resets(&world).await;
    reset_lost_factor(&world, &mut factor.codes).await;

    let mut browser = Client::new(&stack, "Max, after losing his phone").expect("a client");
    let mut replacement = enroll_after_reset(&world, &clock, &mut browser).await;
    waiting(&world, &mut browser, world.member().password()).await;
    let another_old_code = MemberRecoveryCode {
        code: factor.codes.take(),
    };
    member_factors::redeem_recovery_code(world.org(), &another_old_code)
        .send(&browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    answered(&world, &browser, &mut replacement).await;
    others_keep_access(&world).await;
    assert_reset_record(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Unauthorized reset attempts leave Max's session and factor reset count unchanged.
async fn assert_unauthorized_resets(world: &World<'_>) {
    Matrix::new(
        "resetting Max's lost factor",
        members::reset_factor(world.org(), world.member().id()).call(),
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
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    assert_eq!(
        world
            .trail()
            .count("organization.org_member_mfa_reset")
            .await,
        0,
        "the refused resets reset nothing"
    );
}

/// Ann's reset ends Max's old session, which cannot redeem its old recovery printout.
async fn reset_lost_factor(world: &World<'_>, codes: &mut RecoveryCodes) {
    members::reset_factor(world.org(), world.member().id())
        .send(world.owner().client())
        .await
        .ok();
    members::me(world.org())
        .send(world.member().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let old_code = MemberRecoveryCode { code: codes.take() };
    member_factors::redeem_recovery_code(world.org(), &old_code)
        .send(world.member().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Max signs in by password and mailbox before replacing his lost authenticator with a new phone.
async fn enroll_after_reset(world: &World<'_>, clock: &Clock, browser: &mut Client) -> TotpApp {
    let sign_in = PasswordSignIn::of(world.member().email(), world.member().password());
    let session = settled_sign_in(world.stack(), browser, &sign_in).await;
    browser.authorize(&session.refresh_token);
    let begun = member_factors::begin_totp(world.org(), &setup(world.member().password()))
        .send(browser)
        .await
        .ok();
    let mut replacement = TotpApp::scanning(&begun.otpauth_uri);
    clock.advance(CODE_STEP);
    let confirm = ConfirmFactor {
        code: replacement.code().await,
        session_id: None,
    };
    member_factors::confirm_totp(world.org(), &confirm)
        .send(browser)
        .await
        .ok();
    replacement
}

/// The sole successful reset is attributed to Ann in the organization's trail.
async fn assert_reset_record(world: &World<'_>) {
    let trail = world.trail();
    let record = trail.recorded("organization.org_member_mfa_reset").await;
    assert_eq!(
        trail.count("organization.org_member_mfa_reset").await,
        1,
        "the factor was reset once"
    );
    assert!(
        record.actor.contains(world.owner().email()),
        "the record names Ann as the one who reset it"
    );
}

/// Acme requires a factor and Max lost his phone. A printed recovery code
/// proves him, but the sign-in still owes a new factor and reads nothing,
/// before and after he begins the setup; the new phone's first code,
/// confirmed on that same sign-in, lets him in. His next sign-in takes the
/// new phone's code.
#[tokio::test]
async fn a_recovery_code_under_a_required_factor_opens_nothing_until_a_new_phone_is_confirmed() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut factor = enrolled(&world).await;
    require_factor(&world).await;
    let trail = world.trail();
    let before = trail.count("organization.org_mfa_verified").await;

    let mut browser = Client::new(&stack, "Max, replacing his lost phone").expect("a client");
    let session = waiting(&world, &mut browser, world.member().password()).await;
    let printed = MemberRecoveryCode {
        code: factor.codes.take(),
    };
    redeem_for_enrollment(&world, &browser, &printed).await;
    let mut replacement = enroll_required_replacement(&world, &clock, &browser, session).await;
    others_keep_access(&world).await;
    assert_recovery_records(&world, before).await;

    waiting(&world, &mut browser, world.member().password()).await;
    answered(&world, &browser, &mut replacement).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// With a required factor, the recovery code proves Max but leaves new enrollment owed.
async fn redeem_for_enrollment(world: &World<'_>, browser: &Client, printed: &MemberRecoveryCode) {
    let accepted = member_factors::redeem_recovery_code(world.org(), printed)
        .send(browser)
        .await
        .ok();
    assert!(
        accepted.mfa_enrollment_required,
        "under a required factor the recovery code leaves a new one owed"
    );
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Only confirming the new phone against the recovered session opens account access.
async fn enroll_required_replacement(
    world: &World<'_>,
    clock: &Clock,
    browser: &Client,
    session: Session,
) -> TotpApp {
    let begun = member_factors::begin_required_totp(world.org())
        .send(browser)
        .await
        .ok();
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let mut replacement = TotpApp::scanning(&begun.otpauth_uri);
    clock.advance(CODE_STEP);
    let confirm = ConfirmFactor {
        code: replacement.code().await,
        session_id: Some(session.session_id),
    };
    member_factors::confirm_totp(world.org(), &confirm)
        .send(browser)
        .await
        .ok();
    members::me(world.org()).send(browser).await.ok();
    replacement
}

/// Both phones have enrollment records and only the successful recovery adds a verified answer.
async fn assert_recovery_records(world: &World<'_>, before: usize) {
    let trail = world.trail();
    assert_eq!(
        trail.count("organization.org_mfa_enrolled").await,
        2,
        "the lost phone and its replacement were each confirmed once"
    );
    assert_eq!(
        trail.count("organization.org_mfa_verified").await,
        before + 1,
        "the recovery code is recorded as one answer"
    );
}
