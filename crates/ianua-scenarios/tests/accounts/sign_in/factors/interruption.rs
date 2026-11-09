//! Max answers his sign-in's factor while the audit trail cannot be
//! written, and the platform restarts: the refused answer opened nothing
//! and spent nothing, and the same code or recovery code finishes the same
//! sign-in once the trail can record it, once.

use ianua_scenarios::api::{member_factors, members};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{AuditWrites, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::FactorCode;
use ianua_scenarios::wire::sign_in::MemberRecoveryCode;
use ianua_scenarios::world::World;

use crate::factors::member::{answered, enrolled, others_keep_access, waiting};

/// The record a factor answer leaves, and a refused one must not.
const VERIFIED: &str = "organization.org_mfa_verified";

/// Max types the code from his phone while audit writes fail: the answer
/// is a server error, his sign-in still reads nothing, and nothing is
/// recorded, before and after the API and worker restart. The same code
/// on the same sign-in then lets him in and is recorded once; Ann, Tess
/// and Sam notice nothing.
#[tokio::test]
async fn a_code_refused_by_a_failed_audit_is_still_good_after_a_restart() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut factor = enrolled(&world).await;
    let mut browser = Client::new(&stack, "Max, during an audit outage").expect("a client");
    waiting(&world, &mut browser, world.member().password()).await;
    let trail = world.trail();
    let before = trail.count(VERIFIED).await;

    let code = FactorCode {
        code: factor.phone.code().await,
    };
    fail_factor_audit(&world, &browser, &code).await;
    members::me(world.org())
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    restart_pending(&world, &browser, before).await;
    accept_preserved_code(&world, &browser, &code, before).await;
    others_keep_access(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The authenticator answer fails while its audit record cannot be persisted.
async fn fail_factor_audit(world: &World<'_>, browser: &Client, code: &FactorCode) {
    world.stack().audit_writes(AuditWrites::Refuse).await;
    let failed = member_factors::verify(world.org(), code)
        .send(browser)
        .await;
    assert_eq!(
        failed.status(),
        Status::INTERNAL_SERVER_ERROR,
        "a code that cannot be recorded is not accepted: {}",
        failed.summary()
    );
    world.stack().audit_writes(AuditWrites::Allow).await;
}

/// Restarting preserves the pending session and does not fabricate a verification record.
async fn restart_pending(world: &World<'_>, browser: &Client, before: usize) {
    world
        .stack()
        .restart()
        .await
        .expect("the API and worker restart");
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_eq!(
        world.trail().count(VERIFIED).await,
        before,
        "the refused answer recorded nothing"
    );
}

/// The identical authenticator code completes Max's original session and records one answer.
async fn accept_preserved_code(
    world: &World<'_>,
    browser: &Client,
    code: &FactorCode,
    before: usize,
) {
    member_factors::verify(world.org(), code)
        .send(browser)
        .await
        .ok();
    assert_eq!(
        members::me(world.org()).send(browser).await.ok().id,
        world.member().id(),
        "the same code finishes the same sign-in once it can be recorded"
    );
    assert_eq!(
        world.trail().count(VERIFIED).await,
        before + 1,
        "the accepted answer is recorded once"
    );
}

/// Max types a printed recovery code while audit writes fail, and the
/// platform restarts: the refused answer opened nothing, recorded nothing
/// and spent no code. The same code then finishes the same sign-in and is
/// recorded once; on his next sign-in it is spent, while his phone still
/// gets him in.
#[tokio::test]
async fn a_recovery_code_refused_by_a_failed_audit_is_spent_only_when_recorded() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut factor = enrolled(&world).await;
    let mut browser =
        Client::new(&stack, "Max, recovering during an audit outage").expect("a client");
    waiting(&world, &mut browser, world.member().password()).await;
    let trail = world.trail();
    let before = trail.count(VERIFIED).await;

    let code = MemberRecoveryCode {
        code: factor.codes.take(),
    };
    fail_recovery_audit(&world, &browser, &code).await;
    restart_pending(&world, &browser, before).await;
    accept_preserved_recovery(&world, &browser, &code, before).await;

    waiting(&world, &mut browser, world.member().password()).await;
    assert_recovery_spent(&world, &browser, &code).await;
    answered(&world, &browser, &mut factor.phone).await;
    assert_eq!(
        trail.count(VERIFIED).await,
        before + 2,
        "the phone's code is recorded as the second answer"
    );
    others_keep_access(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A printed code is refused when its redemption cannot be recorded.
async fn fail_recovery_audit(world: &World<'_>, browser: &Client, code: &MemberRecoveryCode) {
    world.stack().audit_writes(AuditWrites::Refuse).await;
    let failed = member_factors::redeem_recovery_code(world.org(), code)
        .send(browser)
        .await;
    assert_eq!(
        failed.status(),
        Status::INTERNAL_SERVER_ERROR,
        "a recovery code that cannot be recorded is not accepted: {}",
        failed.summary()
    );
    world.stack().audit_writes(AuditWrites::Allow).await;
}

/// The preserved recovery code admits the pending session once audit storage is writable.
async fn accept_preserved_recovery(
    world: &World<'_>,
    browser: &Client,
    code: &MemberRecoveryCode,
    before: usize,
) {
    member_factors::redeem_recovery_code(world.org(), code)
        .send(browser)
        .await
        .ok();
    members::me(world.org()).send(browser).await.ok();
    assert_eq!(
        world.trail().count(VERIFIED).await,
        before + 1,
        "the accepted recovery code is recorded once"
    );
}

/// Once accepted, the same printed code cannot finish Max's next waiting session.
async fn assert_recovery_spent(world: &World<'_>, browser: &Client, code: &MemberRecoveryCode) {
    member_factors::redeem_recovery_code(world.org(), code)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}
