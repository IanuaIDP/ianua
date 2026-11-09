//! Max moving his organization account to another mailbox: he signs in
//! from the new mailbox as himself and no longer from the old, Ann's
//! address is untouched, and his old mailbox calls a move off, which no
//! link followed in the tenant could have confirmed.

use ianua_scenarios::api::{account, members, sessions};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::account::EmailChange;
use ianua_scenarios::wire::sign_in::{ConfirmSignIn, PasswordSignIn, SignedIn};
use ianua_scenarios::world::World;

use crate::support::{EmailProofs, device, email_change_proofs, mail_linking_to};

/// Max asks to move his mailbox and follows the new mailbox's link: his
/// account carries the new address. His old address signs in no more; on
/// a fresh browser the new address signs in, confirmed from the new
/// mailbox, as the same account. Ann's address is as it was.
#[tokio::test]
async fn max_moves_his_mailbox_and_signs_in_from_it_as_himself() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pending = request_max_move(&world).await;
    confirm_max_move(&world, &pending).await;
    sign_in_new_max_address(&world, &pending.address).await;

    let ann = members::me(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        ann.email,
        world.owner().email(),
        "Max's move leaves Ann's address alone"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max requests a mailbox move and receives the confirmation and cancellation links.
async fn request_max_move(world: &World<'_>) -> EmailProofs {
    let max = world.member();
    let plane = account::Plane::Member(world.org());

    let change = EmailChange {
        new_email: world.address("new-max"),
        password: max.password().to_owned(),
        code: None,
    };
    account::change_email(plane, &change)
        .send(max.client())
        .await
        .ok();
    email_change_proofs(world.stack(), max.email(), change.new_email).await
}

/// Confirmation changes Max's address and prevents sign-in using his old address.
async fn confirm_max_move(world: &World<'_>, pending: &EmailProofs) {
    let max = world.member();
    let plane = account::Plane::Member(world.org());
    account::confirm_email(plane, &pending.confirm)
        .send(world.anonymous().client())
        .await
        .ok();
    let own = members::me(world.org()).send(max.client()).await.ok();
    assert_eq!(
        own.email, pending.address,
        "the followed link moves the address"
    );

    sessions::member_sign_in(&PasswordSignIn::of(max.email(), max.password()))
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// The new mailbox confirms a fresh sign-in to Max's original account.
async fn sign_in_new_max_address(world: &World<'_>, address: &str) {
    let max = world.member();
    let mut browser = device(world.stack(), "Max at his new mailbox");
    let answer = sessions::member_sign_in(&PasswordSignIn::of(address, max.password()))
        .send(&browser)
        .await
        .ok();
    let SignedIn::Authenticated(session) = answer else {
        panic!("Max is in one organization, so no choice is offered");
    };
    browser.authorize(&session.refresh_token);
    let mail = mail_linking_to(world.stack(), address, "/confirm-sign-in").await;
    let confirm = ConfirmSignIn {
        token: mail.token_in("/confirm-sign-in"),
        refresh_token: session.refresh_token,
    };
    sessions::confirm_member_sign_in(&confirm)
        .send(&browser)
        .await
        .ok();
    let from_new_mailbox = members::me(world.org()).send(&browser).await.ok();
    assert_eq!(
        from_new_mailbox.id,
        max.id(),
        "the new address signs in to the same account"
    );
}

/// Max asks to move his mailbox, but the new mailbox's link cannot confirm
/// an organization account's move through the tenant. His old mailbox's link
/// calls the move off: the new mailbox's link is dead, and his account
/// still carries his old address.
#[tokio::test]
async fn max_calls_off_his_move_and_a_tenant_link_cannot_confirm_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let max = world.member();
    let plane = account::Plane::Member(world.org());
    let pending = request_max_move(&world).await;

    account::confirm_email(account::Plane::Tenant(world.tenant()), &pending.confirm)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    account::cancel_email(plane, &pending.cancel)
        .send(world.anonymous().client())
        .await
        .ok();
    account::confirm_email(plane, &pending.confirm)
        .send(world.anonymous().client())
        .await
        .refused(Status::GONE, "link_expired");
    let own = members::me(world.org()).send(max.client()).await.ok();
    assert_eq!(
        own.email,
        max.email(),
        "a move called off leaves the address"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
