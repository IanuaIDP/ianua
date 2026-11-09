//! Max signing in while a dependency is cut: the cache, the mail relay,
//! the audit trail's storage, the database or the message bus. None of
//! them turns an unfinished sign-in into access or spends a proof, and
//! once the dependency is mended Max signs in or finishes the sign-in he
//! had, while Ann and Sam are untouched.

use ianua_scenarios::api::{members, sessions};
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{AuditWrites, Part, Profile, Stack};
use ianua_scenarios::wire::sign_in::{
    ConfirmSignIn, ConfirmedSignIn, PasswordSignIn, Session, SignedIn,
};
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;

use crate::support::{QUIET, api_ready_again, mail_linking_to, settled_sign_in};

/// Max signs in while the shared cache is cut. With nothing to check his
/// sign-in's counters against, the platform refuses him and asks for a
/// puzzle rather than letting him through. Once the cache is mended and
/// the API ready again, his browser still reads nothing, and his password
/// and mailbox sign him in to his own account.
#[tokio::test]
async fn a_cache_outage_cannot_bypass_sign_in_security_checks() {
    let stack = Stack::start(Profile::standard().with_cuttable_parts())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut browser = Client::new(&stack, "Max, during a cache outage").expect("a client");
    let sign_in = PasswordSignIn::of(world.member().email(), world.member().password());

    stack.cut(Part::Cache);
    sessions::member_sign_in(&sign_in)
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "challenge_required");

    stack.mend(Part::Cache);
    api_ready_again(&stack).await;
    members::me(world.org())
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let session = settled_sign_in(&stack, &browser, &sign_in).await;
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(world.org()).send(&browser).await.ok().id,
        world.member().id(),
        "after the outage Max's password and mailbox sign him in to his own account"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max's password is accepted while the mail relay is cut: his sign-in
/// waits for his mailbox and reads nothing, and no mail comes while the
/// relay is down. Once it is mended the queued link arrives and finishes
/// that same sign-in, with no new password typed; Ann still reads the
/// members.
#[tokio::test]
async fn a_mail_outage_keeps_sign_in_pending_until_queued_delivery_recovers() {
    let stack = Stack::start(
        Profile::standard()
            .with_cuttable_parts()
            .with("EMAIL_SEND_TIMEOUT_SECONDS", "1")
            .with("JOB_RETRY_BACKOFF_SECONDS", "1,2,3"),
    )
    .await
    .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut browser = Client::new(&stack, "Max, awaiting a delayed mail").expect("a client");

    stack.cut(Part::Mail);
    let waiting = begin_pending_sign_in(&world, &browser).await;
    browser.authorize(&waiting.refresh_token);
    members::me(world.org())
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    stack
        .mailbox()
        .nothing_for(world.member().email(), QUIET)
        .await;

    stack.mend(Part::Mail);
    finish_queued_sign_in(&world, &browser, waiting).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max's password identifies one organization and opens the session awaiting its next proof.
async fn begin_pending_sign_in(world: &World<'_>, browser: &Client) -> Session {
    let answer = sessions::member_sign_in(&PasswordSignIn::of(
        world.member().email(),
        world.member().password(),
    ))
    .send(browser)
    .await
    .ok();
    let SignedIn::Authenticated(waiting) = answer else {
        panic!("Max is in one organization, so no choice is offered");
    };
    waiting
}

/// Restored delivery finishes Max's original session, and Ann's access remains usable.
async fn finish_queued_sign_in(world: &World<'_>, browser: &Client, waiting: Session) {
    let mail = mail_linking_to(world.stack(), world.member().email(), "/confirm-sign-in").await;
    sessions::confirm_member_sign_in(&ConfirmSignIn {
        token: mail.token_in("/confirm-sign-in"),
        refresh_token: waiting.refresh_token,
    })
    .send(browser)
    .await
    .ok();
    assert_eq!(
        members::me(world.org()).send(browser).await.ok().id,
        world.member().id(),
        "the queued link finishes the sign-in Max was waiting on"
    );
    members::me(world.org())
        .send(world.owner().client())
        .await
        .ok();
}

/// Max follows his mailed link while the audit trail refuses writes: the
/// confirmation fails with a server error, grants nothing, records
/// nothing and does not spend the link. With the trail writable again the
/// same browser and link finish once, leaving one verification record,
/// and the failed answer printed neither the link's token nor the
/// session's.
#[tokio::test]
async fn failed_confirmation_audit_preserves_the_pending_session_and_mailbox_proof() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut browser =
        Client::new(&stack, "Max, confirming during an audit failure").expect("a client");
    let waiting = begin_pending_sign_in(&world, &browser).await;
    let mail = mail_linking_to(&stack, world.member().email(), "/confirm-sign-in").await;
    browser.authorize(&waiting.refresh_token);
    let confirm = ConfirmSignIn {
        token: mail.token_in("/confirm-sign-in"),
        refresh_token: waiting.refresh_token,
    };
    let trail = world.trail();
    let verified_before = trail.count("organization.org_mfa_verified").await;

    let failed = fail_confirmation_audit(&world, &browser, &confirm, verified_before).await;
    finish_after_audit_recovery(&world, &browser, &confirm, verified_before).await;
    no_secret_leaked(
        failed.exchange().response_body(),
        &[&confirm.token, &confirm.refresh_token],
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Refused audit writes leave both the session and its verification count unchanged.
async fn fail_confirmation_audit(
    world: &World<'_>,
    browser: &Client,
    confirm: &ConfirmSignIn,
    verified_before: usize,
) -> Answer<ConfirmedSignIn> {
    world.stack().audit_writes(AuditWrites::Refuse).await;
    let failed = sessions::confirm_member_sign_in(confirm)
        .send(browser)
        .await;
    assert_eq!(
        failed.status(),
        Status::INTERNAL_SERVER_ERROR,
        "a confirmation the trail cannot record fails: {}",
        failed.summary()
    );

    world.stack().audit_writes(AuditWrites::Allow).await;
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_eq!(
        world.trail().count("organization.org_mfa_verified").await,
        verified_before,
        "the failed confirmation recorded nothing"
    );
    failed
}

/// Once audit writes recover, the same link admits Max and records one verification.
async fn finish_after_audit_recovery(
    world: &World<'_>,
    browser: &Client,
    confirm: &ConfirmSignIn,
    verified_before: usize,
) {
    sessions::confirm_member_sign_in(confirm)
        .send(browser)
        .await
        .ok();
    assert_eq!(
        members::me(world.org()).send(browser).await.ok().id,
        world.member().id(),
        "the same link finishes the same sign-in once the trail is back"
    );
    assert_eq!(
        world.trail().count("organization.org_mfa_verified").await,
        verified_before + 1,
        "the confirmation is recorded once"
    );
}

/// Max signs in while the database is cut: the answer is a server error
/// that opens nothing and does not print his password. Once the database
/// is mended and the API ready again, his browser reads nothing, a fresh
/// sign-in with its mailbox proof opens his account and leaves one new
/// sign-in record, and Sam in the other company still reads.
#[tokio::test]
async fn a_database_outage_grants_no_access_and_fresh_sign_in_recovers() {
    let stack = Stack::start(Profile::standard().with_cuttable_parts())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut browser = Client::new(&stack, "Max, during a database outage").expect("a client");
    let sign_in = PasswordSignIn::of(world.member().email(), world.member().password());

    stack.cut(Part::Database);
    let failed = sessions::member_sign_in(&sign_in).send(&browser).await;
    assert!(
        failed.status().is_server_error(),
        "a sign-in with no database fails, it does not open: {}",
        failed.summary()
    );
    no_secret_leaked(
        failed.exchange().response_body(),
        &[world.member().password()],
    );

    stack.mend(Part::Database);
    api_ready_again(&stack).await;
    recover_database_sign_in(&world, &mut browser, &sign_in).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A fresh sign-in after database recovery restores Max alone and adds one successful-login record.
async fn recover_database_sign_in(
    world: &World<'_>,
    browser: &mut Client,
    sign_in: &PasswordSignIn,
) {
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let trail = world.trail();
    let signed_in_before = trail.count("organization.org_login_succeeded").await;
    let session = settled_sign_in(world.stack(), browser, sign_in).await;
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(world.org()).send(browser).await.ok().id,
        world.member().id(),
        "after the outage a fresh sign-in opens Max's own account"
    );
    assert_eq!(
        trail.count("organization.org_login_succeeded").await,
        signed_in_before + 1,
        "the fresh sign-in is recorded once"
    );
    members::me(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();
}

/// Max signs in while the message bus is cut: the sign-in and its record
/// complete anyway, and he reads his account during the outage. Once the
/// bus is mended the same session still reads, one sign-in record was
/// written, and Sam in the other company still reads.
#[tokio::test]
async fn a_bus_outage_preserves_audited_sign_in_and_usable_access() {
    let stack = Stack::start(Profile::standard().with_cuttable_parts())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let trail = world.trail();
    let signed_in_before = trail.count("organization.org_login_succeeded").await;
    let mut browser = Client::new(&stack, "Max, during a bus outage").expect("a client");

    stack.cut(Part::Bus);
    let session = settled_sign_in(
        &stack,
        &browser,
        &PasswordSignIn::of(world.member().email(), world.member().password()),
    )
    .await;
    browser.authorize(&session.refresh_token);
    members::me(world.org()).send(&browser).await.ok();

    stack.mend(Part::Bus);
    members::me(world.org()).send(&browser).await.ok();
    assert_eq!(
        trail.count("organization.org_login_succeeded").await,
        signed_in_before + 1,
        "the sign-in made during the outage is recorded once"
    );
    members::me(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}
