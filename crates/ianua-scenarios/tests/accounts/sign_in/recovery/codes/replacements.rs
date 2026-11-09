//! Max replaces his printout with his password and a fresh code from his
//! phone: every old code is dead and each new one works once. Mallory,
//! with a copy of Max's session, cannot replace it with a wrong password,
//! no code or a code already typed; every old code stays good until Max
//! replaces the printout himself. The trail counts each replacement once
//! and shows no code, password, phone secret or token.

use ianua_scenarios::api::{member_factors, members};
use ianua_scenarios::authenticators::{RecoveryCodes, TotpApp};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sign_in::{MemberFactorSetup, MemberProof, MemberRecoveryCode, Session};
use ianua_scenarios::world::World;

use crate::factors::member::{Enrolled, answered, enrolled, others_keep_access, waiting};
use crate::recovery::codes::support::{VERIFIED, recovered_session};
use crate::support::WRONG_GUESS;

/// The record a new printout leaves; setting the factor up leaves another.
const GENERATED: &str = "organization.org_recovery_codes_generated";

/// The copied session as held by Mallory and by the member whose access must survive.
struct CopiedSession<'a> {
    mallory: &'a Client,
    max: &'a Client,
}

/// Max replaces his printout with his password and a fresh code. The new
/// printout is as long as the old and shares no code with it. Each old
/// code is refused on a sign-in of his, which his phone then finishes, so
/// no lock from the refusals could hide an old code being taken; each
/// new code works once. One replacement is recorded, showing no secret.
#[tokio::test]
async fn a_new_printout_kills_every_old_code_and_each_new_one_works_once() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut factor = enrolled(&world).await;
    let mut secrets = world.cast_secrets();
    secrets.extend(factor.codes.all().iter().cloned());
    secrets.push(factor.phone.secret().to_owned());
    generations(&world, 0, &secrets).await;

    let mut fresh = replace(&world, world.member().client(), &mut factor.phone).await;
    assert_distinct_printout(&factor.codes, &fresh);
    secrets.extend(fresh.all().iter().cloned());
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    generations(&world, 1, &secrets).await;
    others_keep_access(&world).await;

    let mut browser = Client::new(&stack, "Max, trying his old printout").expect("a client");
    reject_old_printout(&world, &mut browser, &mut factor, &mut secrets).await;
    new_code_works_once(&world, &mut browser, &mut fresh, &mut secrets).await;
    generations(&world, 1, &secrets).await;
    others_keep_access(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A replacement has the same number of codes and no overlap with its predecessor.
fn assert_distinct_printout(old: &RecoveryCodes, fresh: &RecoveryCodes) {
    assert_eq!(
        fresh.all().len(),
        old.all().len(),
        "the new printout is as long as the old"
    );
    assert!(
        fresh.all().iter().all(|code| !old.all().contains(code)),
        "the new printout shares no code with the old"
    );
}

/// Every old code is refused, with a successful phone answer between attempts.
async fn reject_old_printout(
    world: &World<'_>,
    browser: &mut Client,
    factor: &mut Enrolled,
    secrets: &mut Vec<String>,
) {
    for code in factor.codes.all() {
        let session = waiting(world, browser, world.member().password()).await;
        secrets.push(session.refresh_token);
        refused_code(world, browser, code).await;
        answered(world, browser, &mut factor.phone).await;
    }
}

/// Mallory cannot replace Max's printout using his copied session with a
/// wrong password, no code or a spent code. Each attempt leaves Max's
/// session usable and records no replacement.
/// Every original code still signs Max in once; Max then replaces the
/// used-up printout himself and a new code works once. One replacement
/// is recorded, showing no secret.
#[tokio::test]
async fn a_refused_recovery_code_replacement_leaves_every_original_code_usable() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut factor = enrolled(&world).await;
    let mut browser = Client::new(&stack, "Max, keeping his printout").expect("a client");
    let session = waiting(&world, &mut browser, world.member().password()).await;
    answered(&world, &browser, &mut factor.phone).await;
    let mut mallory = Client::new(&stack, "Mallory, with Max's copied session").expect("a client");
    mallory.authorize(&session.refresh_token);
    let mut secrets = replacement_secrets(&world, &factor, &session);
    let copied = CopiedSession {
        mallory: &mallory,
        max: &browser,
    };
    reject_unproved_replacements(&world, &copied, &mut factor.phone, &secrets).await;
    spend_original_printout(&world, &mut browser, &factor.codes, &mut secrets).await;
    members::me(world.org())
        .send(&mallory)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    generations(&world, 0, &secrets).await;

    let mut fresh = replace(&world, &browser, &mut factor.phone).await;
    secrets.extend(fresh.all().iter().cloned());
    new_code_works_once(&world, &mut browser, &mut fresh, &mut secrets).await;
    generations(&world, 1, &secrets).await;
    others_keep_access(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Collects the copied token, phone secret, guessed password, and original printout.
fn replacement_secrets(world: &World<'_>, factor: &Enrolled, session: &Session) -> Vec<String> {
    let mut secrets = world.cast_secrets();
    secrets.extend([
        session.refresh_token.clone(),
        factor.phone.secret().to_owned(),
        WRONG_GUESS.to_owned(),
    ]);
    secrets.extend(factor.codes.all().iter().cloned());
    secrets
}

/// A wrong password, absent code, and spent code each leave the copied session and printout intact.
async fn reject_unproved_replacements(
    world: &World<'_>,
    copied: &CopiedSession<'_>,
    phone: &mut TotpApp,
    secrets: &[String],
) {
    let wrong_password = MemberProof {
        password: WRONG_GUESS.to_owned(),
        code: Some(phone.code().await),
    };
    refused_replacement(world, copied, wrong_password, "forbidden").await;
    generations(world, 0, secrets).await;
    others_keep_access(world).await;

    let no_code = MemberProof {
        password: world.member().password().to_owned(),
        code: None,
    };
    refused_replacement(world, copied, no_code, "step_up_required").await;
    generations(world, 0, secrets).await;
    others_keep_access(world).await;

    let typed_code = MemberProof {
        password: world.member().password().to_owned(),
        code: Some(phone.last_code_again()),
    };
    refused_replacement(world, copied, typed_code, "forbidden").await;
    generations(world, 0, secrets).await;
    others_keep_access(world).await;
}

/// Every original code still completes a new session after the refused replacements.
async fn spend_original_printout(
    world: &World<'_>,
    browser: &mut Client,
    codes: &RecoveryCodes,
    secrets: &mut Vec<String>,
) {
    for code in codes.all() {
        let session = waiting(world, browser, world.member().password()).await;
        secrets.push(session.refresh_token);
        let printed = MemberRecoveryCode { code: code.clone() };
        recovered_session(browser, world.org(), &printed).await;
    }
}

/// The new printout Max is shown when he replaces the old one through
/// `browser`, with his password and a fresh code from `phone`.
async fn replace(world: &World<'_>, browser: &Client, phone: &mut TotpApp) -> RecoveryCodes {
    let proof = MemberFactorSetup {
        proof: MemberProof {
            password: world.member().password().to_owned(),
            code: Some(phone.code().await),
        },
    };
    let shown = member_factors::regenerate_recovery_codes(world.org(), &proof)
        .send(browser)
        .await
        .ok();
    RecoveryCodes::printed(shown.recovery_codes)
}

/// Mallory's replacement with `proof`, sent from her copied session, is refused
/// for `reason`, and the session she copied goes on reading Max's account
/// from `max`, his own browser.
async fn refused_replacement(
    world: &World<'_>,
    copied: &CopiedSession<'_>,
    proof: MemberProof,
    reason: &str,
) {
    member_factors::regenerate_recovery_codes(world.org(), &MemberFactorSetup { proof })
        .send(copied.mallory)
        .await
        .refused(Status::FORBIDDEN, reason);
    members::me(world.org()).send(copied.max).await.ok();
}

/// `code` is refused on the sign-in `browser` carries, which still reads
/// nothing, and no answer is recorded for it.
async fn refused_code(world: &World<'_>, browser: &Client, code: &str) {
    let trail = world.trail();
    let before = trail.count(VERIFIED).await;
    let printed = MemberRecoveryCode {
        code: code.to_owned(),
    };
    member_factors::redeem_recovery_code(world.org(), &printed)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_eq!(
        trail.count(VERIFIED).await,
        before,
        "a refused code is not recorded as an answer"
    );
}

/// One code from `codes` finishes a sign-in of Max's; on his next it is
/// refused, and the next code finishes it. The session stays in Acme.
/// Every session token is added to `secrets`.
async fn new_code_works_once(
    world: &World<'_>,
    browser: &mut Client,
    codes: &mut RecoveryCodes,
    secrets: &mut Vec<String>,
) {
    let session = waiting(world, browser, world.member().password()).await;
    secrets.push(session.refresh_token);
    let used = MemberRecoveryCode { code: codes.take() };
    recovered_session(browser, world.org(), &used).await;
    let session = waiting(world, browser, world.member().password()).await;
    secrets.push(session.refresh_token);
    refused_code(world, browser, &used.code).await;
    let next = MemberRecoveryCode { code: codes.take() };
    recovered_session(browser, world.org(), &next).await;
    assert_eq!(
        members::me(world.org()).send(browser).await.ok().email,
        world.member().email(),
        "the next code finishes Max's own sign-in"
    );
    members::me(world.stranger().org())
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// The trail holds `expected` replacements, every one made by Max, and
/// neither they nor the factor answers show one of `secrets`.
async fn generations(world: &World<'_>, expected: usize, secrets: &[String]) {
    let trail = world.trail();
    let entries = trail.entries(GENERATED).await;
    assert_eq!(
        entries.len(),
        expected,
        "the trail holds the replacements made and no other"
    );
    assert!(
        entries
            .iter()
            .all(|entry| entry.actor.contains(world.member().email())),
        "every replacement names Max"
    );
    let borrowed: Vec<&str> = secrets.iter().map(String::as_str).collect();
    no_secret_leaked(&format!("{entries:?}"), &borrowed);
    no_secret_leaked(&format!("{:?}", trail.entries(VERIFIED).await), &borrowed);
}
