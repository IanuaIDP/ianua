//! Ann's company suspended, let go on again and closed, and who may do
//! which: Tess, Max, Sam and nobody signed in may none of it; Uma, an
//! administrator, may suspend it, which ends her own session with
//! everyone's, but not close it; an active company is not let go on
//! again; a closed company is shut to every member at once and for good,
//! and to the organization keys made before it closed.

use ianua_scenarios::actors::Member;
use ianua_scenarios::api::{api_keys, members, organizations, sessions};
use ianua_scenarios::expect::{Matrix, Trail};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::{NewOrgApiKey, OrgRole};
use ianua_scenarios::wire::sign_in::PasswordSignIn;
use ianua_scenarios::world::World;

use crate::support::twin_usable;

/// The audit record a company's change of status leaves.
const STATUS_CHANGED: &str = "organization.status_changed";

/// Tess, Max, Sam and an anonymous caller cannot suspend, reactivate or
/// close Ann's company. It
/// is still active, Max is still in, Sam's company untouched, and
/// nothing is recorded.
#[tokio::test]
async fn nobody_without_the_right_suspends_reactivates_or_closes_the_company() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    refuse_status_changes(&world).await;

    let acme = organizations::get(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(acme.status, "Active", "Ann's company is still active");
    assert_eq!(
        world.trail().count(STATUS_CHANGED).await,
        0,
        "no refused change of status is recorded"
    );
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    twin_usable(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tenant administrators, members, strangers and anonymous callers cannot change company status.
async fn refuse_status_changes(world: &World<'_>) {
    for request in [
        organizations::suspend(world.org()),
        organizations::reactivate(world.org()),
        organizations::close(world.org()),
    ] {
        Matrix::new("changing the company's status", request.call())
            .refused(world.admin().client(), Status::FORBIDDEN, "forbidden")
            .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
            .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
            .refused(
                world.anonymous().client(),
                Status::UNAUTHORIZED,
                "unauthenticated",
            )
            .run()
            .await;
    }
}

/// Uma, an administrator of Ann's company, is refused closing it, with
/// nothing recorded, then suspends it: her own session ends with
/// everyone's. Ann signs in afresh to the company alone, finds it
/// suspended and lets it go on again; Uma's old session stays dead. Two
/// changes of status are recorded; Sam's company is untouched.
#[tokio::test]
async fn an_administrator_may_suspend_the_company_but_not_close_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut uma = world
        .colleague("uma", "Uma Administrator", OrgRole::Admin)
        .await;
    uma.sign_in(&stack).await;
    suspend_as_admin(&world, &uma).await;
    reactivate_as_owner(&world, &uma).await;
    twin_usable(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma cannot close the company, but suspending it ends her own session.
async fn suspend_as_admin(world: &World<'_>, uma: &Member) {
    organizations::close(world.org())
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    assert_eq!(
        world.trail().count(STATUS_CHANGED).await,
        0,
        "a refused closure is not recorded"
    );

    organizations::suspend(world.org())
        .send(uma.client())
        .await
        .ok();
    members::me(world.org())
        .send(uma.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Ann can reactivate from a new company session without reviving Uma's old session.
async fn reactivate_as_owner(world: &World<'_>, uma: &Member) {
    let mut ann = ann_on_the_company_alone(world);
    ann.sign_in(world.stack()).await;
    let acme = organizations::get(world.org())
        .send(ann.client())
        .await
        .ok();
    assert_eq!(acme.status, "Suspended", "Ann finds her company suspended");
    organizations::reactivate(world.org())
        .send(ann.client())
        .await
        .ok();
    members::me(world.org())
        .send(uma.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_eq!(
        Trail::of_organization(ann.client(), world.org().slug())
            .count(STATUS_CHANGED)
            .await,
        2,
        "the suspension and the reactivation are each recorded"
    );
}

/// Ann on a fresh browser, to sign in to her company alone, landing in
/// no tenant: the way in while the company is suspended.
fn ann_on_the_company_alone(world: &World<'_>) -> Member {
    let mut account = world.owner().account().clone();
    account.landing = None;
    Member::new(
        Client::new(world.stack(), "Ann, back to her suspended company").expect("a client"),
        account,
        world.owner().password(),
    )
}

/// Reactivating Ann's already active company is refused without a status
/// record or loss of her session;
/// she then suspends it for real, which ends her session.
#[tokio::test]
async fn reactivating_an_active_company_changes_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    organizations::reactivate(world.org())
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    assert_eq!(
        world.trail().count(STATUS_CHANGED).await,
        0,
        "a refused reactivation is not recorded"
    );
    members::me(world.org())
        .send(world.owner().client())
        .await
        .ok();

    organizations::suspend(world.org())
        .send(world.owner().client())
        .await
        .ok();
    members::me(world.org())
        .send(world.owner().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    twin_usable(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann, Tess and Max are each in. Ann closes the company: all three are
/// out at once, and none of their passwords opens a session there any
/// more. Ann's try to let it go on again finds her session dead too.
/// Sam's company is untouched.
#[tokio::test]
async fn a_closed_company_is_shut_to_every_member_at_once_and_for_good() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    for member in [world.owner(), world.admin(), world.member()] {
        members::me(world.org()).send(member.client()).await.ok();
    }

    organizations::close(world.org())
        .send(world.owner().client())
        .await
        .ok();
    refuse_closed_members(&world).await;

    organizations::reactivate(world.org())
        .send(world.owner().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    twin_usable(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Closure invalidates every original session and refuses fresh password sign-ins.
async fn refuse_closed_members(world: &World<'_>) {
    for member in [world.owner(), world.admin(), world.member()] {
        members::me(world.org())
            .send(member.client())
            .await
            .refused(Status::UNAUTHORIZED, "unauthenticated");
        let sign_in = PasswordSignIn {
            organization: Some(world.org().slug().to_owned()),
            ..PasswordSignIn::of(member.email(), member.password())
        };
        sessions::member_sign_in(&sign_in)
            .send(member.client())
            .await
            .refused(Status::FORBIDDEN, "forbidden");
    }
}

/// Ann makes an organization key for her automation, able to do anything,
/// and proves it reads her members. After she closes the company, that
/// key can neither read the members nor reactivate the company.
/// Both calls are refused, Acme stays closed to Ann's
/// password, and Sam's company is untouched.
#[tokio::test]
async fn a_key_made_before_closing_neither_reads_nor_reopens_the_company() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let automation = organization_automation(&world).await;

    organizations::close(world.org())
        .send(world.owner().client())
        .await
        .ok();
    refuse_closed_automation(&world, &automation).await;
    twin_usable(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann's unrestricted organization key can read members before closure.
async fn organization_automation(world: &World<'_>) -> Client {
    let made = api_keys::create_for_organization(
        world.org(),
        &NewOrgApiKey {
            name: "Ann's automation".to_owned(),
            scopes: vec!["org:*:*".to_owned()],
        },
    )
    .send(world.owner().client())
    .await
    .ok();
    let mut automation = Client::new(world.stack(), "Ann's automation").expect("a client");
    automation.authorize(&made.raw_key);
    members::list(world.org(), None)
        .send(&automation)
        .await
        .ok();
    automation
}

/// The old key cannot read or reopen the closed company, and Ann's password also stays refused.
async fn refuse_closed_automation(world: &World<'_>, automation: &Client) {
    members::list(world.org(), None)
        .send(automation)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    organizations::reactivate(world.org())
        .send(automation)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let sign_in = PasswordSignIn {
        organization: Some(world.org().slug().to_owned()),
        ..PasswordSignIn::of(world.owner().email(), world.owner().password())
    };
    sessions::member_sign_in(&sign_in)
        .send(world.anonymous().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}
