//! Max's phone and his printout share one lock: Mallory, guessing codes
//! and recovery codes in turn, buys no extra guesses, and while the lock
//! holds even a real code is refused; it lifts in time. A printout Max
//! uses up leaves his phone required and working, and a sign-in still
//! owing its factor cannot replace the printout, even with real proof.

use std::time::Duration;

use ianua_scenarios::api::{member_factors, members};
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::FactorCode;
use ianua_scenarios::wire::sign_in::{MemberFactorSetup, MemberProof, MemberRecoveryCode};
use ianua_scenarios::world::World;

use crate::factors::member::{answered, enrolled, others_keep_access, waiting};
use crate::recovery::codes::support::{
    FactorTrail, VERIFIED, denied, factor_secrets, recovered_session, verified,
};

/// How long the factor stays locked in this stack: long enough that only
/// the application clock, not the wait itself, lifts it.
const LOCKOUT: Duration = Duration::from_secs(120);

/// A code that is on no phone: one digit too many to be a real one.
const WRONG_CODE: &str = "0000000";

/// Words that are on no printout.
const WRONG_RECOVERY_CODE: &str = "not a printed recovery code";

/// The record a new printout leaves, and a refused one must not.
const GENERATED: &str = "organization.org_recovery_codes_generated";

/// Mallory, with Max's password, guesses two codes and two recovery codes
/// in turn and one more code: five wrong guesses lock the factor, so a
/// real printed code and the phone's real code are both refused as
/// locked, and the sign-in reads nothing. Nothing was spent: once the
/// lock's time has passed, the same printed code lets Max in, and on his
/// next sign-in so does his phone.
#[tokio::test]
async fn guessing_codes_and_recovery_codes_share_one_lock_that_lifts_in_time() {
    let clock = Clock::controlled();
    let profile = Profile::standard().with("MFA_LOCKOUT_SECONDS", &LOCKOUT.as_secs().to_string());
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let mut factor = enrolled(&world).await;
    let secrets = factor_secrets(&world, &factor);
    let before = world.trail().count(VERIFIED).await;
    let mut browser = Client::new(&stack, "Mallory, guessing Max's codes").expect("a client");
    waiting(&world, &mut browser, world.member().password()).await;

    exhaust_guesses(&world, &browser).await;
    let printed = MemberRecoveryCode {
        code: factor.codes.take(),
    };
    reject_real_codes_while_locked(&world, &browser, &printed, &mut factor.phone).await;
    denied(&world, &browser, before, &secrets).await;

    clock.advance(LOCKOUT + Duration::from_secs(1));
    recovered_session(&browser, world.org(), &printed).await;
    verified(&world, before + 1, &secrets).await;

    waiting(&world, &mut browser, world.member().password()).await;
    answered(&world, &browser, &mut factor.phone).await;
    verified(&world, before + 2, &secrets).await;
    others_keep_access(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Alternating ordinary and printed-code guesses exhausts one shared five-guess budget.
async fn exhaust_guesses(world: &World<'_>, browser: &Client) {
    let wrong_code = FactorCode {
        code: WRONG_CODE.to_owned(),
    };
    let wrong_recovery_code = MemberRecoveryCode {
        code: WRONG_RECOVERY_CODE.to_owned(),
    };
    for _ in 0..2 {
        member_factors::verify(world.org(), &wrong_code)
            .send(browser)
            .await
            .refused(Status::FORBIDDEN, "forbidden");
        member_factors::redeem_recovery_code(world.org(), &wrong_recovery_code)
            .send(browser)
            .await
            .refused(Status::FORBIDDEN, "forbidden");
    }
    member_factors::verify(world.org(), &wrong_code)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Both the real printed code and the current phone code are refused by the lock.
async fn reject_real_codes_while_locked(
    world: &World<'_>,
    browser: &Client,
    printed: &MemberRecoveryCode,
    phone: &mut TotpApp,
) {
    member_factors::redeem_recovery_code(world.org(), printed)
        .send(browser)
        .await
        .refused(Status::TOO_MANY_REQUESTS, "account_locked");
    let real_code = FactorCode {
        code: phone.code().await,
    };
    member_factors::verify(world.org(), &real_code)
        .send(browser)
        .await
        .refused(Status::TOO_MANY_REQUESTS, "account_locked");
}

/// Max uses every code on his printout, one sign-in each. His next
/// sign-in still owes a factor: a used code opens nothing, his phone
/// still lets him in, and nothing records the factor as turned off.
#[tokio::test]
async fn a_used_up_printout_leaves_the_phone_required_and_working() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut factor = enrolled(&world).await;
    let evidence = FactorTrail::capture(&world, &factor).await;
    let mut browser = Client::new(&stack, "Max, using up his printout").expect("a client");

    use_printout(&world, &mut browser, factor.codes.all(), &evidence).await;

    waiting(&world, &mut browser, world.member().password()).await;
    let used = MemberRecoveryCode {
        code: factor.codes.all()[0].clone(),
    };
    member_factors::redeem_recovery_code(world.org(), &used)
        .send(&browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let used_up = evidence.before + factor.codes.all().len();
    denied(&world, &browser, used_up, &evidence.secrets).await;

    answered(&world, &browser, &mut factor.phone).await;
    verified(&world, used_up + 1, &evidence.secrets).await;
    assert_eq!(
        world.trail().count("organization.org_mfa_unenrolled").await,
        0,
        "a used-up printout turns the factor off for nobody"
    );
    others_keep_access(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Each printed code finishes its own waiting session and adds one accepted answer.
async fn use_printout(
    world: &World<'_>,
    browser: &mut Client,
    codes: &[String],
    evidence: &FactorTrail,
) {
    for (index, code) in codes.iter().enumerate() {
        waiting(world, browser, world.member().password()).await;
        let printed = MemberRecoveryCode { code: code.clone() };
        recovered_session(browser, world.org(), &printed).await;
        verified(world, evidence.before + index + 1, &evidence.secrets).await;
    }
}

/// Max's waiting sign-in cannot replace his recovery printout even with
/// his real password and a fresh code. It is refused before
/// the code is spent and nothing is recorded; the same code then finishes
/// the sign-in, and on his next sign-in an old printed code still works.
#[tokio::test]
async fn a_sign_in_still_owing_its_factor_cannot_replace_the_printout() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut factor = enrolled(&world).await;
    let evidence = FactorTrail::capture(&world, &factor).await;
    let mut browser = Client::new(&stack, "Max, still owing his factor").expect("a client");
    waiting(&world, &mut browser, world.member().password()).await;

    let code = factor.phone.code().await;
    reject_waiting_replacement(&world, &browser, &code, &evidence).await;
    finish_with_same_code(&world, &browser, code).await;

    waiting(&world, &mut browser, world.member().password()).await;
    let printed = MemberRecoveryCode {
        code: factor.codes.take(),
    };
    recovered_session(&browser, world.org(), &printed).await;
    verified(&world, evidence.before + 2, &evidence.secrets).await;
    assert_eq!(
        world.trail().count(GENERATED).await,
        0,
        "no printout was generated along the way"
    );
    others_keep_access(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A waiting session cannot replace its printout and leaves no generation record.
async fn reject_waiting_replacement(
    world: &World<'_>,
    browser: &Client,
    code: &str,
    evidence: &FactorTrail,
) {
    let proof = MemberFactorSetup {
        proof: MemberProof {
            password: world.member().password().to_owned(),
            code: Some(code.to_owned()),
        },
    };
    member_factors::regenerate_recovery_codes(world.org(), &proof)
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    denied(world, browser, evidence.before, &evidence.secrets).await;
    assert_eq!(
        world.trail().count(GENERATED).await,
        0,
        "the refused replacement generated no printout"
    );
}

/// The phone code refused for replacement still completes the waiting sign-in.
async fn finish_with_same_code(world: &World<'_>, browser: &Client, code: String) {
    member_factors::verify(world.org(), &FactorCode { code })
        .send(browser)
        .await
        .ok();
    members::me(world.org()).send(browser).await.ok();
}
