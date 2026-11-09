//! Pat moving to another mailbox in her tenant: the move takes effect
//! only when the new mailbox's link is followed, the old mailbox's link
//! calls it off, no other link and no other tenant confirms it, and an
//! expired link is renewed to the same mailbox.

use std::time::Duration;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{account, people, registration, sessions};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::people::LinkToken;
use ianua_scenarios::wire::tenant_sign_in::{ConfirmPasswordReset, TenantPasswordSignIn};
use ianua_scenarios::world::World;

use crate::email::signs_in_at_new_address;
use crate::support::{
    EmailProofs, email_change_requested, invited_and_signed_in, mail_linking_to, past_lifetime,
    still_signed_in, tenant_records,
};

/// How long a move's links live in this scenario, set short so the
/// expiry is reached while the stack runs.
const LINK_LIFETIME: Duration = Duration::from_secs(5);

/// A password nobody ever set, which a dead reset link would have set.
const UNUSED_PASSWORD: &str = "Different Orchard Lantern 7482!";

/// Pat, holding a reset link she asked for, asks to move to a new
/// mailbox: her address is unchanged until the new mailbox's link is
/// followed. Then her record carries the new address as proved, the old
/// reset link is dead, the old address signs in no more, the new one
/// signs in to the same account, and the spent link confirms nothing
/// again. The move is recorded once, with no link or password in it.
#[tokio::test]
async fn pat_moves_to_a_new_mailbox_and_the_old_address_signs_in_no_more() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited_and_signed_in(&world, "pat").await;
    let reset = pat.reset_link(&stack).await;
    let plane = account::Plane::Tenant(world.tenant());

    let move_to = email_change_requested(&world, &pat, "new-pat").await;
    confirm_pat_move(&world, &pat, &move_to).await;
    refuse_old_proofs(&world, &pat, &reset).await;
    signs_in_at_new_address(&world, &pat, &move_to.address).await;
    account::confirm_email(plane, &move_to.confirm)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let secrets = [
        move_to.confirm.token.as_str(),
        &move_to.cancel.token,
        &reset,
        pat.password(),
    ];
    assert_eq!(
        tenant_records(&world, "identity.email_changed", &secrets).await,
        1,
        "the move is recorded once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat's address changes only after confirmation, which marks the new mailbox proved.
async fn confirm_pat_move(world: &World<'_>, pat: &Person, move_to: &EmailProofs) {
    let before = people::me(world.tenant()).send(pat.client()).await.ok();
    assert_eq!(
        before.email,
        pat.email(),
        "asking to move changes no address yet"
    );

    account::confirm_email(account::Plane::Tenant(world.tenant()), &move_to.confirm)
        .send(world.anonymous().client())
        .await
        .ok();
    let after = people::me(world.tenant()).send(pat.client()).await.ok();
    assert_eq!(
        after.email, move_to.address,
        "the followed link moves the address"
    );
    assert!(after.email_verified, "the new mailbox counts as proved");
}

/// The moved account refuses both its old password-reset link and its old sign-in address.
async fn refuse_old_proofs(world: &World<'_>, pat: &Person, reset: &str) {
    let by_dead_link = ConfirmPasswordReset {
        token: reset.to_owned(),
        new_password: UNUSED_PASSWORD.to_owned(),
        mfa_code: None,
    };
    sessions::confirm_password_reset(world.tenant(), &by_dead_link)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let old_address = TenantPasswordSignIn {
        email: pat.email().to_owned(),
        password: pat.password().to_owned(),
        fingerprint_hash: None,
    };
    sessions::sign_in(world.tenant(), &old_address)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// Pat asks to move, but her old mailbox's link cannot cancel the move in
/// the twin tenant. Followed in her own, it calls the move
/// off: the new mailbox's link is dead, Pat signs in at her old address,
/// which her record still carries, and no move is recorded.
#[tokio::test]
async fn the_old_mailbox_calls_off_the_move_and_pat_keeps_her_address() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited_and_signed_in(&world, "pat").await;
    let pending = email_change_requested(&world, &pat, "new-pat").await;
    cancel_pat_move(&world, &pending).await;

    pat.sign_in(&stack).await;
    let own = people::me(world.tenant()).send(pat.client()).await.ok();
    assert_eq!(
        own.email,
        pat.email(),
        "a move called off leaves the address"
    );
    assert_eq!(
        tenant_records(
            &world,
            "identity.email_changed",
            &[&pending.confirm.token, &pending.cancel.token]
        )
        .await,
        0,
        "a move called off records no move"
    );
    still_signed_in(&world, &pat).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Only the original tenant accepts the cancellation link, which expires the confirmation.
async fn cancel_pat_move(world: &World<'_>, pending: &EmailProofs) {
    account::cancel_email(account::Plane::Tenant(world.twin()), &pending.cancel)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    account::cancel_email(account::Plane::Tenant(world.tenant()), &pending.cancel)
        .send(world.anonymous().client())
        .await
        .ok();
    account::confirm_email(account::Plane::Tenant(world.tenant()), &pending.confirm)
        .send(world.anonymous().client())
        .await
        .refused(Status::GONE, "link_expired");
}

/// Pat's move cannot be confirmed in the twin tenant, with the old mailbox's
/// cancellation link, or through signup verification. Each request is refused
/// and spends nothing: the link then confirms the move, Pat signs in at
/// the new address, and the move is recorded once with no link in it.
#[tokio::test]
async fn a_move_is_confirmed_only_by_its_own_link_in_its_own_tenant() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;
    let pending = email_change_requested(&world, &pat, "new-pat").await;

    account::confirm_email(account::Plane::Tenant(world.twin()), &pending.confirm)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    account::confirm_email(account::Plane::Tenant(world.tenant()), &pending.cancel)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    registration::verify(world.tenant(), &pending.confirm)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    account::confirm_email(account::Plane::Tenant(world.tenant()), &pending.confirm)
        .send(world.anonymous().client())
        .await
        .ok();
    signs_in_at_new_address(&world, &pat, &pending.address).await;
    assert_eq!(
        tenant_records(&world, "identity.email_changed", &[&pending.confirm.token]).await,
        1,
        "the move is recorded once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat asks to move and lets the link expire: it confirms nothing. She
/// asks for it again: a new link, not the old one, reaches the same
/// mailbox; the old link stays dead, the new one confirms the move, and
/// Pat signs in at the new address.
#[tokio::test]
async fn an_expired_move_is_renewed_to_the_same_mailbox() {
    let lifetime = LINK_LIFETIME.as_secs().to_string();
    let stack = Stack::start(Profile::standard().with("EMAIL_CHANGE_TTL_SECONDS", &lifetime))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;
    let plane = account::Plane::Tenant(world.tenant());
    let pending = email_change_requested(&world, &pat, "new-pat").await;

    past_lifetime(LINK_LIFETIME).await;
    account::confirm_email(plane, &pending.confirm)
        .send(world.anonymous().client())
        .await
        .refused(Status::GONE, "link_expired");
    renew_expired_move(&world, &pending).await;
    signs_in_at_new_address(&world, &pat, &pending.address).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Resending replaces the expired confirmation link while targeting the same new mailbox.
async fn renew_expired_move(world: &World<'_>, pending: &EmailProofs) {
    let plane = account::Plane::Tenant(world.tenant());
    account::resend_email(plane, &pending.confirm)
        .send(world.anonymous().client())
        .await
        .ok();
    let mail = mail_linking_to(world.stack(), &pending.address, "/confirm-email-change").await;
    let renewed = LinkToken {
        token: mail.token_in("/confirm-email-change"),
    };
    assert!(
        renewed.token != pending.confirm.token,
        "the renewal mails a new link"
    );
    account::confirm_email(plane, &pending.confirm)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    account::confirm_email(plane, &renewed)
        .send(world.anonymous().client())
        .await
        .ok();
}
