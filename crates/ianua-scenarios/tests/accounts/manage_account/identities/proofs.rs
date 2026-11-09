//! What a link between Pat's accounts takes: a live session at each end.
//! A shared mailbox, a made-up token or a token from an ended session
//! proves no second end, and an account that moved to another address
//! cannot join a group at the first.

use ianua_scenarios::api::{account, people, sessions};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::account::{EmailChange, LinkedSwitch};
use ianua_scenarios::world::World;

use crate::identities::{Accounts, accounts, linking_profile};
use crate::support::{
    EmailProofs, SignedDevice, email_change_proofs, signed_in_elsewhere, still_signed_in,
};

/// Pat opens a group from her first account. Her staging account cannot
/// join through a shared mailbox alone or a made-up token, and the first
/// account cannot open a group in the twin tenant. With
/// the first session's real token the staging account joins, and the
/// switch into it works.
#[tokio::test]
async fn a_shared_mailbox_or_a_made_up_token_links_nothing() {
    let stack = Stack::start(linking_profile())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let accounts = accounts(&world).await;
    let source = signed_in_elsewhere(&world, &accounts.source).await;
    account::link_accounts(world.tenant())
        .send(&source.client)
        .await
        .ok();
    refuse_missing_proofs(&world, &accounts, &source).await;
    account::join_linked_accounts(&accounts.target_tenant, &source.session.refresh_token)
        .send(accounts.target.client())
        .await
        .ok();
    let switch = LinkedSwitch {
        target_tenant_id: accounts.target_id.clone(),
    };
    account::switch_linked_account(world.tenant(), &switch)
        .send(&source.client)
        .await
        .ok();
    stack.stop().await.expect("the stack stops cleanly");
}

/// Shared mailboxes, fabricated tokens and foreign tenant access supply no linking proof.
async fn refuse_missing_proofs(world: &World<'_>, accounts: &Accounts, source: &SignedDevice) {
    account::link_accounts(&accounts.target_tenant)
        .send(accounts.target.client())
        .await
        .refused(Status::CONFLICT, "conflict");
    account::join_linked_accounts(&accounts.target_tenant, "made-up-session")
        .send(accounts.target.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    account::link_accounts(world.twin())
        .send(&source.client)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Pat opens a group from a session in her first account, then ends that
/// session. The ended session's token cannot link her staging account.
/// A fresh session in the first account lets the staging
/// account join, and the switch into it works.
#[tokio::test]
async fn a_token_from_an_ended_session_links_nothing() {
    let stack = Stack::start(linking_profile())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let accounts = accounts(&world).await;
    let ended = signed_in_elsewhere(&world, &accounts.source).await;
    account::link_accounts(world.tenant())
        .send(&ended.client)
        .await
        .ok();
    sessions::end_my_session(world.tenant(), &ended.session.session_id)
        .send(accounts.source.client())
        .await
        .ok();

    account::join_linked_accounts(&accounts.target_tenant, &ended.session.refresh_token)
        .send(accounts.target.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    join_with_fresh_session(&world, &accounts).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// A new live source session supplies the missing proof and switches into the staging account.
async fn join_with_fresh_session(world: &World<'_>, accounts: &Accounts) {
    let fresh = signed_in_elsewhere(world, &accounts.source).await;
    account::join_linked_accounts(&accounts.target_tenant, &fresh.session.refresh_token)
        .send(accounts.target.client())
        .await
        .ok();
    let switch = LinkedSwitch {
        target_tenant_id: accounts.target_id.clone(),
    };
    let moved = account::switch_linked_account(world.tenant(), &switch)
        .send(&fresh.client)
        .await
        .ok();
    assert_eq!(
        moved.user_id,
        accounts.target.id(),
        "the fresh session's link lets the switch land in staging"
    );
}

/// Pat opens a group from her first account, then moves her staging
/// account to another mailbox and confirms it. The staging account's
/// different address prevents it from joining the group, and switching
/// into it is also refused. Both accounts go on, the staging one at its
/// new address.
#[tokio::test]
async fn accounts_at_different_addresses_cannot_be_linked() {
    let stack = Stack::start(linking_profile())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let accounts = accounts(&world).await;
    let source = signed_in_elsewhere(&world, &accounts.source).await;
    account::link_accounts(world.tenant())
        .send(&source.client)
        .await
        .ok();
    let proofs = move_staging_address(&world, &accounts).await;
    refuse_different_address(&world, &accounts, &source).await;
    still_signed_in(&world, &accounts.source).await;
    let staging = people::me(&accounts.target_tenant)
        .send(accounts.target.client())
        .await
        .ok();
    assert_eq!(
        staging.email, proofs.address,
        "the staging account carries its new address"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Confirm a different mailbox for the staging account before trying to link it.
async fn move_staging_address(world: &World<'_>, accounts: &Accounts) -> EmailProofs {
    let plane = account::Plane::Tenant(&accounts.target_tenant);
    let change = EmailChange {
        new_email: world.address("different-holder"),
        password: accounts.target.password().to_owned(),
        code: None,
    };
    account::change_email(plane, &change)
        .send(accounts.target.client())
        .await
        .ok();
    let proofs =
        email_change_proofs(world.stack(), accounts.target.email(), change.new_email).await;
    account::confirm_email(plane, &proofs.confirm)
        .send(world.anonymous().client())
        .await
        .ok();
    proofs
}

/// The changed address prevents both joining the group and switching to its staging account.
async fn refuse_different_address(world: &World<'_>, accounts: &Accounts, source: &SignedDevice) {
    account::join_linked_accounts(&accounts.target_tenant, &source.session.refresh_token)
        .send(accounts.target.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let switch = LinkedSwitch {
        target_tenant_id: accounts.target_id.clone(),
    };
    account::switch_linked_account(world.tenant(), &switch)
        .send(&source.client)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}
