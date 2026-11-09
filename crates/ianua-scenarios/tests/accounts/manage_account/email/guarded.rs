//! What guards a move to another mailbox: Pat's password typed again,
//! which a wrong guess fails and which an address Uma holds cannot pass;
//! a password change, which kills a pending move; and the authenticator
//! Pat holds, owed afresh with the password.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{account, people, sessions};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::account::EmailChange;
use ianua_scenarios::wire::tenant_sign_in::ChangePassword;
use ianua_scenarios::world::World;

use crate::support::{
    email_change_proofs, email_change_requested, invited_and_signed_in, still_signed_in,
    tenant_records,
};

/// The password Pat changes to: a sentence, so no scanner takes it for a
/// key.
const NEW_PASSWORD: &str = "Different Orchard Lantern 7482!";

/// A wrong guess at Pat's current password.
const WRONG_PASSWORD: &str = "Wrong quiet meadow 7439";

/// Pat cannot move to a new mailbox with a wrong password or to Uma's
/// address with the correct password. Both attempts
/// are refused, Pat and Uma go on as before, and no move is recorded.
#[tokio::test]
async fn a_wrong_password_or_umas_address_moves_nobody() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;
    let uma = invited_and_signed_in(&world, "uma").await;
    refuse_password_and_address(&world, &pat, &uma).await;
    still_signed_in(&world, &pat).await;
    still_signed_in(&world, &uma).await;
    assert_eq!(
        tenant_records(&world, "identity.email_changed", &[pat.password()]).await,
        0,
        "a refused move records nothing"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// A wrong password or an address already held by Uma refuses Pat's requested move.
async fn refuse_password_and_address(world: &World<'_>, pat: &Person, uma: &Person) {
    let plane = account::Plane::Tenant(world.tenant());

    let wrong = EmailChange {
        new_email: world.address("stolen"),
        password: WRONG_PASSWORD.to_owned(),
        code: None,
    };
    account::change_email(plane, &wrong)
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let taken = EmailChange {
        new_email: uma.email().to_owned(),
        password: pat.password().to_owned(),
        code: None,
    };
    account::change_email(plane, &taken)
        .send(pat.client())
        .await
        .refused(Status::CONFLICT, "conflict");
}

/// Pat asks to move, then changes her password. The new mailbox's earlier
/// confirmation link is now expired and cannot finish the move. Her record
/// still carries the old address and her session goes on.
#[tokio::test]
async fn a_password_change_kills_the_pending_move() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;
    let pending = email_change_requested(&world, &pat, "new-pat").await;

    let change = ChangePassword {
        old_password: pat.password().to_owned(),
        new_password: NEW_PASSWORD.to_owned(),
        mfa_code: None,
    };
    sessions::change_password(world.tenant(), &change)
        .send(pat.client())
        .await
        .ok();

    account::confirm_email(account::Plane::Tenant(world.tenant()), &pending.confirm)
        .send(world.anonymous().client())
        .await
        .refused(Status::GONE, "link_expired");
    let own = people::me(world.tenant()).send(pat.client()).await.ok();
    assert_eq!(
        own.email,
        pat.email(),
        "a move killed by a password change leaves the address"
    );
    still_signed_in(&world, &pat).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat, with her authenticator set up, asks to move with her password
/// alone: refused, a code is owed too. With a fresh code from her phone
/// the move is accepted, the new mailbox's link confirms it, and her
/// record carries the new address.
#[tokio::test]
async fn pat_with_an_authenticator_moves_only_with_a_fresh_code() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited_and_signed_in(&world, "pat").await;
    pat.set_up_authenticator().await;
    let plane = account::Plane::Tenant(world.tenant());

    let change = EmailChange {
        new_email: world.address("new-pat"),
        password: pat.password().to_owned(),
        code: None,
    };
    account::change_email(plane, &change)
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "step_up_required");
    move_with_phone(&world, &mut pat, change).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A fresh phone code authorizes the move and the new mailbox's link confirms it.
async fn move_with_phone(world: &World<'_>, pat: &mut Person, mut change: EmailChange) {
    let plane = account::Plane::Tenant(world.tenant());
    let mut phone = pat.lose_phone();
    change.code = Some(phone.code().await);
    account::change_email(plane, &change)
        .send(pat.client())
        .await
        .ok();
    let links = email_change_proofs(world.stack(), pat.email(), change.new_email).await;
    account::confirm_email(plane, &links.confirm)
        .send(world.anonymous().client())
        .await
        .ok();
    let own = people::me(world.tenant()).send(pat.client()).await.ok();
    assert_eq!(
        own.email, links.address,
        "the confirmed move carries the new address"
    );
}
