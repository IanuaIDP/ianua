//! Max resets his password while the audit trail cannot be written, and
//! the platform restarts: the refused reset changed nothing, ended
//! nothing and spent nothing, the same link then resets once, and after
//! another restart the new password holds and the link is spent.

use ianua_scenarios::api::{members, sessions};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{AuditWrites, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sign_in::{ConfirmMemberPasswordReset, PasswordSignIn, ResetLinkToken};
use ianua_scenarios::world::World;

use crate::recovery::reset::support::{CHANGED, access_after_reset, reset, reset_link};
use crate::support::settled_sign_in;

/// The password Max sets: a sentence, so no scanner takes it for a key.
const NEW_PASSWORD: &str = "Scenario restored orchard lantern 7382";

/// Max follows his reset link while audit writes fail: the answer is a
/// server error. After the API and worker restart, his session goes on,
/// nothing is recorded, the link still reads as valid and the new
/// password signs nobody in. The same link then resets once, ending his
/// old access; after another restart the link is spent and the new
/// password signs him in, with one change recorded.
#[tokio::test]
async fn a_failed_reset_audit_preserves_access_and_its_link_across_restarts() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let token = reset_link(&world).await;
    let request = reset(&token, NEW_PASSWORD);
    reject_during_audit_failure(&world, &request).await;
    stack.restart().await.expect("the API and worker restart");
    assert_reset_unchanged(&world, token).await;

    sessions::confirm_member_password_reset(&request)
        .send(world.anonymous().client())
        .await
        .ok();
    access_after_reset(&world).await;
    assert_eq!(
        world.trail().count(CHANGED).await,
        1,
        "the accepted reset recorded one password change"
    );

    stack
        .restart()
        .await
        .expect("the API and worker restart again");
    assert_reset_persisted(&world, &request).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// A failed audit write refuses the reset before audit writes are restored.
async fn reject_during_audit_failure(world: &World<'_>, request: &ConfirmMemberPasswordReset) {
    world.stack().audit_writes(AuditWrites::Refuse).await;
    let failed = sessions::confirm_member_password_reset(request)
        .send(world.anonymous().client())
        .await;
    assert_eq!(
        failed.status(),
        Status::INTERNAL_SERVER_ERROR,
        "a reset that cannot be recorded is not accepted: {}",
        failed.summary()
    );
    world.stack().audit_writes(AuditWrites::Allow).await;
}

/// After restart, the old session and reset link survive, with no new password or change record.
async fn assert_reset_unchanged(world: &World<'_>, token: String) {
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    assert_eq!(
        world.trail().count(CHANGED).await,
        0,
        "the refused reset recorded no password change"
    );
    let asked = ResetLinkToken { token };
    let worth = sessions::member_reset_link_status(&asked)
        .send(world.anonymous().client())
        .await
        .ok();
    assert_eq!(worth.status, "Valid", "the link is still worth a reset");
    sessions::member_sign_in(&PasswordSignIn::of(world.member().email(), NEW_PASSWORD))
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// A second restart retains the new password and the single-use link's spent state.
async fn assert_reset_persisted(world: &World<'_>, request: &ConfirmMemberPasswordReset) {
    sessions::confirm_member_password_reset(request)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let mut browser =
        Client::new(world.stack(), "Max, after the second restart").expect("a client");
    let sign_in = PasswordSignIn::of(world.member().email(), NEW_PASSWORD);
    let session = settled_sign_in(world.stack(), &browser, &sign_in).await;
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(world.org()).send(&browser).await.ok().id,
        world.member().id(),
        "the new password signs Max in after the restart"
    );
    assert_eq!(
        world.trail().count(CHANGED).await,
        1,
        "the restart recorded no further change"
    );
}
