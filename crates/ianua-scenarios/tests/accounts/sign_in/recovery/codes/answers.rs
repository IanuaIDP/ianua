//! A code answers one live sign-in of its own company: Max's real code
//! sent to Sam's company's address is refused and not spent; a sign-in of
//! his that Ann ended is not revived by its code; and two sends of one
//! code at once finish the sign-in once. After each, the code or the next
//! one still gets Max in, and the trail counts each answer once.

use ianua_scenarios::api::{member_factors, members, sessions};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::Trail;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::factors::FactorCode;
use ianua_scenarios::wire::sign_in::Session;
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;

use crate::factors::member::{answered, enrolled, others_keep_access, waiting};
use crate::recovery::codes::support::{FactorTrail, VERIFIED, denied, factor_secrets, verified};

/// Max's real code is refused when his waiting sign-in sends it to Globex
/// instead of Acme. Neither company records a successful factor answer,
/// and the same code sent to Acme finishes his sign-in, which
/// reads his own account and nothing of Globex.
#[tokio::test]
async fn a_code_sent_to_another_companys_address_is_refused_and_kept() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut factor = enrolled(&world).await;
    let evidence = FactorTrail::capture(&world, &factor).await;
    let mut browser = Client::new(&stack, "Max, at Globex's address").expect("a client");
    waiting(&world, &mut browser, world.member().password()).await;

    let code = FactorCode {
        code: factor.phone.code().await,
    };
    reject_foreign_code(&world, &browser, &code, &evidence).await;
    accept_own_code(&world, &browser, &code).await;
    verified(&world, evidence.before + 1, &evidence.secrets).await;
    others_keep_access(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Globex refuses Max's code without an accepted answer in either company's trail.
async fn reject_foreign_code(
    world: &World<'_>,
    browser: &Client,
    code: &FactorCode,
    evidence: &FactorTrail,
) {
    let other_trail =
        Trail::of_organization(world.stranger().client(), world.stranger().org().slug());
    let other_before = other_trail.count(VERIFIED).await;
    member_factors::verify(world.stranger().org(), code)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    denied(world, browser, evidence.before, &evidence.secrets).await;
    assert_eq!(
        other_trail.count(VERIFIED).await,
        other_before,
        "Globex records no answer for Max's code"
    );
}

/// The same code opens Max's Acme account while leaving Globex inaccessible.
async fn accept_own_code(world: &World<'_>, browser: &Client, code: &FactorCode) {
    member_factors::verify(world.org(), code)
        .send(browser)
        .await
        .ok();
    assert_eq!(
        members::me(world.org()).send(browser).await.ok().email,
        world.member().email(),
        "the same code finishes Max's sign-in at Acme"
    );
    members::me(world.stranger().org())
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Ann ends Max's sign-in while it waits for his code. The code cannot
/// revive it or record a successful answer; Max signs in
/// again and the same, unspent code finishes the fresh sign-in, while the
/// ended one's token still reads nothing. The ending is recorded.
#[tokio::test]
async fn a_waiting_sign_in_ended_by_the_owner_is_not_revived_by_its_code() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut factor = enrolled(&world).await;
    let secrets = factor_secrets(&world, &factor);
    let before = world.trail().count(VERIFIED).await;
    let mut browser = Client::new(&stack, "Max, on a sign-in Ann ended").expect("a client");
    let ended = waiting(&world, &mut browser, world.member().password()).await;

    sessions::end_member_session(world.org(), &ended.session_id)
        .send(world.owner().client())
        .await
        .ok();
    let code = FactorCode {
        code: factor.phone.code().await,
    };
    member_factors::verify(world.org(), &code)
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    denied(&world, &browser, before, &secrets).await;

    recover_after_revocation(&world, &mut browser, &code, &ended).await;
    verified(&world, before + 1, &secrets).await;
    world
        .trail()
        .recorded("organization.org_session_revoked")
        .await;
    others_keep_access(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A new sign-in accepts the unspent code while the ended token remains unusable.
async fn recover_after_revocation(
    world: &World<'_>,
    browser: &mut Client,
    code: &FactorCode,
    ended: &Session,
) {
    let fresh = waiting(world, browser, world.member().password()).await;
    member_factors::verify(world.org(), code)
        .send(browser)
        .await
        .ok();
    members::me(world.org()).send(browser).await.ok();
    browser.authorize(&ended.refresh_token);
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    browser.authorize(&fresh.refresh_token);
    members::me(world.org()).send(browser).await.ok();
}

/// Two of Max's browsers send the same unused code at the same moment.
/// One is accepted and the sign-in reads his account; the other is
/// refused, and one answer is recorded. On his next sign-in that code is
/// spent and the phone's next one lets him in.
#[tokio::test]
async fn simultaneous_totp_answers_finish_the_session_only_once() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut factor = enrolled(&world).await;
    let secrets = factor_secrets(&world, &factor);
    let before = world.trail().count(VERIFIED).await;
    let mut browser = Client::new(&stack, "Max, sending his code twice").expect("a client");
    waiting(&world, &mut browser, world.member().password()).await;

    let code = FactorCode {
        code: factor.phone.code().await,
    };
    answer_twice(&world, &browser, &code).await;
    verified(&world, before + 1, &secrets).await;

    waiting(&world, &mut browser, world.member().password()).await;
    member_factors::verify(world.org(), &code)
        .send(&browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    denied(&world, &browser, before + 1, &secrets).await;
    answered(&world, &browser, &mut factor.phone).await;
    verified(&world, before + 2, &secrets).await;
    others_keep_access(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Two simultaneous uses accept one answer and leave the completed session usable.
async fn answer_twice(world: &World<'_>, browser: &Client, code: &FactorCode) {
    let first = member_factors::verify(world.org(), code);
    let second = member_factors::verify(world.org(), code);
    let (first, second) = tokio::join!(first.send(browser), second.send(browser));
    let mut answers = [first, second];
    answers.sort_by_key(Answer::status);
    let [accepted, rejected] = answers;
    accepted.ok();
    rejected.refused(Status::FORBIDDEN, "forbidden");
    members::me(world.org()).send(browser).await.ok();
}
