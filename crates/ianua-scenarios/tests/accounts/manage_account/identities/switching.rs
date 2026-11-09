//! Pat switching between her two linked accounts: a session in the first
//! tenant moves into her staging account and reaches only what that
//! account may; unlinking stops the switch while both passwords still
//! sign in; a deactivated staging account cannot be switched into until
//! Ann restores it.

use ianua_scenarios::api::{account, people, tenants};
use ianua_scenarios::expect::Trail;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::account::{LinkedSwitch, Unlink};
use ianua_scenarios::wire::people::ChangeUserStatus;
use ianua_scenarios::world::World;

use crate::identities::{Accounts, accounts, linked, linking_profile};
use crate::support::{SignedDevice, device, still_signed_in};

/// Pat, signed in to both her accounts, links them and switches from the
/// first into the staging one: the session she gets is her staging
/// account's, owing nothing, reading that account and no list of users,
/// and nothing in the first tenant. Her first account goes on as before.
/// Two linkings and one switch are recorded.
#[tokio::test]
async fn pat_links_her_two_accounts_and_switches_into_the_staging_one() {
    let stack = Stack::start(linking_profile())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let accounts = accounts(&world).await;
    let source = linked(&world, &accounts).await;
    let browser = switch_into_staging(&world, &accounts, &source).await;
    check_switched_access(&world, &accounts, &browser).await;
    still_signed_in(&world, &accounts.source).await;
    check_switch_records(&world, &accounts).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Switching issues a session for the staging account without an outstanding factor challenge.
async fn switch_into_staging(
    world: &World<'_>,
    accounts: &Accounts,
    source: &SignedDevice,
) -> Client {
    let switch = LinkedSwitch {
        target_tenant_id: accounts.target_id.clone(),
    };
    let moved = account::switch_linked_account(world.tenant(), &switch)
        .send(&source.client)
        .await
        .ok();
    assert_eq!(
        moved.user_id,
        accounts.target.id(),
        "the switch lands in Pat's staging account"
    );
    assert!(!moved.mfa_required, "the switched session owes nothing");

    let mut browser = device(world.stack(), "Pat, switched into staging");
    browser.authorize(&moved.refresh_token);
    browser
}

/// The switched browser reads only its staging account, without user administration rights.
async fn check_switched_access(world: &World<'_>, accounts: &Accounts, browser: &Client) {
    let own = people::me(&accounts.target_tenant).send(browser).await.ok();
    assert_eq!(
        own.id,
        accounts.target.id(),
        "the switched session reads the staging account"
    );
    people::list(&accounts.target_tenant, None)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    people::me(world.tenant())
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// The audit trail records both linked accounts and the single switch.
async fn check_switch_records(world: &World<'_>, accounts: &Accounts) {
    let trail = Trail::of_organization(accounts.administrator.client(), world.org().slug());
    assert_eq!(
        trail.count("organization.identity_linked").await,
        2,
        "each end's linking is recorded"
    );
    assert_eq!(
        trail.count("organization.tenant_switched").await,
        1,
        "the switch is recorded once"
    );
}

/// Pat, her accounts linked, takes the staging account out of the group:
/// the switch is refused, and taking it out again finds nothing. Both
/// accounts still sign in with their own passwords. She takes the first
/// account out too, which ends the group, and opens a fresh one.
#[tokio::test]
async fn unlinking_stops_the_switch_and_both_passwords_still_work() {
    let stack = Stack::start(linking_profile())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut accounts = accounts(&world).await;
    let source = linked(&world, &accounts).await;
    unlink_staging(&world, &accounts, &source).await;
    check_separate_passwords(&world, &mut accounts).await;
    reopen_group(&world, &accounts, &source).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Removing staging stops switching and makes a repeated unlink find nothing.
async fn unlink_staging(world: &World<'_>, accounts: &Accounts, source: &SignedDevice) {
    let staging_out = Unlink {
        email: accounts.source.email().to_owned(),
        tenant_id: accounts.target_id.clone(),
    };
    account::unlink_account(world.tenant(), &staging_out)
        .send(&source.client)
        .await
        .ok();
    let switch = LinkedSwitch {
        target_tenant_id: accounts.target_id.clone(),
    };
    account::switch_linked_account(world.tenant(), &switch)
        .send(&source.client)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    account::unlink_account(world.tenant(), &staging_out)
        .send(&source.client)
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// Both unlinked accounts still authenticate with their own passwords.
async fn check_separate_passwords(world: &World<'_>, accounts: &mut Accounts) {
    accounts.source.sign_in(world.stack()).await;
    accounts.target.sign_in(world.stack()).await;
    still_signed_in(world, &accounts.source).await;
    let staging = people::me(&accounts.target_tenant)
        .send(accounts.target.client())
        .await
        .ok();
    assert_eq!(
        staging.id,
        accounts.target.id(),
        "the staging password still signs in to its own account"
    );
}

/// Removing the final source account ends the group and permits a new one.
async fn reopen_group(world: &World<'_>, accounts: &Accounts, source: &SignedDevice) {
    let first = tenants::get(world.tenant())
        .send(accounts.administrator.client())
        .await
        .ok();
    let first_out = Unlink {
        email: accounts.source.email().to_owned(),
        tenant_id: first.id,
    };
    account::unlink_account(world.tenant(), &first_out)
        .send(&source.client)
        .await
        .ok();
    account::link_accounts(world.tenant())
        .send(&source.client)
        .await
        .ok();
}

/// Ann deactivates Pat's linked staging account. Pat cannot switch into
/// it, and the staging account's own session is out. Ann restores it,
/// and the switch lands in it again, the link
/// never having been touched.
#[tokio::test]
async fn a_deactivated_staging_account_cannot_be_switched_into_until_restored() {
    let stack = Stack::start(linking_profile())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let accounts = accounts(&world).await;
    let source = linked(&world, &accounts).await;
    let switch = LinkedSwitch {
        target_tenant_id: accounts.target_id.clone(),
    };
    deactivate_staging(&world, &accounts, &source, &switch).await;
    restore_staging(&world, &accounts, &source, &switch).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Deactivation refuses switching and immediately ends the staging account's own access.
async fn deactivate_staging(
    world: &World<'_>,
    accounts: &Accounts,
    source: &SignedDevice,
    switch: &LinkedSwitch,
) {
    let deactivated = ChangeUserStatus {
        status: "Deactivated".to_owned(),
    };
    people::change_status(&accounts.target_tenant, accounts.target.id(), &deactivated)
        .send(accounts.administrator.client())
        .await
        .ok();
    account::switch_linked_account(world.tenant(), switch)
        .send(&source.client)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    people::me(&accounts.target_tenant)
        .send(accounts.target.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Reactivation allows switching through the same untouched account link.
async fn restore_staging(
    world: &World<'_>,
    accounts: &Accounts,
    source: &SignedDevice,
    switch: &LinkedSwitch,
) {
    let active = ChangeUserStatus {
        status: "Active".to_owned(),
    };
    people::change_status(&accounts.target_tenant, accounts.target.id(), &active)
        .send(accounts.administrator.client())
        .await
        .ok();
    let moved = account::switch_linked_account(world.tenant(), switch)
        .send(&source.client)
        .await
        .ok();
    assert_eq!(
        moved.user_id,
        accounts.target.id(),
        "the restored account is switched into again"
    );
}
