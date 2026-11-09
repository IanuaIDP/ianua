//! Ann grants, narrows and withdraws the tenant roles her colleagues hold,
//! and what Max and Tess reach changes at once on the session they already
//! hold. A tenant that does not exist, a role nobody defined, a colleague
//! whose organization role already decides their reach, and Sam from the
//! other company take no grant, and a refused grant leaves what was held.

use ianua_scenarios::api::{members, people};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::{OrgRole, Reach, TenantRoles};
use ianua_scenarios::world::World;

use crate::support::recorded;

/// The tenant roles named by `names`, to replace what a member holds.
fn roles_named(names: &[&str]) -> TenantRoles {
    TenantRoles {
        roles: names.iter().map(|name| (*name).to_owned()).collect(),
    }
}

/// Ann is giving a colleague access. From her company session she reads the
/// role names the tenant offers, without opening a session in it, and one
/// of them is accepted as a grant. Tess, who may not give access, is
/// refused the list, and a tenant that does not exist is not found.
#[tokio::test]
async fn ann_picks_from_the_roles_a_tenant_offers_without_opening_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tenant = world.tenant().slug();

    let offered = members::grantable_roles(world.org(), tenant)
        .send(world.owner().client())
        .await
        .ok();
    let names: Vec<String> = offered.items.into_iter().map(|role| role.name).collect();
    assert!(
        names.iter().any(|name| name == "Admin"),
        "the tenant's own roles are offered: {names:?}"
    );
    members::set_tenant_roles(
        world.org(),
        world.member().id(),
        tenant,
        &TenantRoles {
            roles: vec!["Admin".to_owned()],
        },
    )
    .send(world.owner().client())
    .await
    .ok();

    members::grantable_roles(world.org(), tenant)
        .send(world.admin().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    members::grantable_roles(world.org(), "absent-tenant")
        .send(world.owner().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann cannot grant Tess the Admin role in an absent tenant. Tess keeps
/// her existing grant and still administers her
/// tenant on the session she holds, Sam's session in the other company
/// still works, and no grant is recorded.
#[tokio::test]
async fn an_absent_tenant_cannot_receive_a_members_grant() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let granted = "organization.org_user_tenant_access_granted";
    let before = world.trail().count(granted).await;
    let held = members::access(world.org(), world.admin().id())
        .send(world.owner().client())
        .await
        .ok();
    refuse_absent_tenant(&world).await;
    check_retained_access(&world, &held).await;
    assert_eq!(
        world.trail().count(granted).await,
        before,
        "a grant refused for its tenant is not recorded"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann cannot grant Tess a role in a tenant that does not exist.
async fn refuse_absent_tenant(world: &World<'_>) {
    members::set_tenant_roles(
        world.org(),
        world.admin().id(),
        "absent-tenant",
        &roles_named(&["Admin"]),
    )
    .send(world.owner().client())
    .await
    .refused(Status::NOT_FOUND, "not_found");
}

/// Tess keeps her tenant grants and active tenant access, and Sam retains his own session.
async fn check_retained_access(world: &World<'_>, held: &Reach) {
    let remaining = members::access(world.org(), world.admin().id())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        remaining.tenants.len(),
        held.tenants.len(),
        "Tess reaches the tenants she reached before"
    );
    assert_eq!(
        remaining.tenants[0].roles, held.tenants[0].roles,
        "Tess holds the roles she held before"
    );
    people::list(world.tenant(), None)
        .send(world.admin().client())
        .await
        .ok();
    members::me(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();
}

/// Ann replaces Max's tenant roles four times over: Admin named twice
/// around Member, then Member alone, then nothing, then Admin again. On
/// the session he already holds Max administers the tenant exactly while
/// he holds Admin, is out of the tenant with no role at all, and stays a
/// member of the company throughout; the twin tenant never opens to him.
/// The withdrawal is recorded under Ann.
#[tokio::test]
async fn a_grant_replaced_narrowed_and_withdrawn_changes_what_max_reaches_at_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    for names in [
        vec!["Admin", "Member", "Admin"],
        vec!["Member"],
        vec![],
        vec!["Admin"],
    ] {
        replace_max_roles(&world, &names).await;
    }

    recorded(
        &world,
        "organization.org_user_tenant_access_revoked",
        world.member().id(),
        world.owner().email(),
    )
    .await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Replacing Max's grant changes tenant access immediately without changing company membership.
async fn replace_max_roles(world: &World<'_>, names: &[&str]) {
    members::set_tenant_roles(
        world.org(),
        world.member().id(),
        world.tenant().slug(),
        &roles_named(names),
    )
    .send(world.owner().client())
    .await
    .ok();
    let reach = members::access(world.org(), world.member().id())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        reach.tenants.len(),
        usize::from(!names.is_empty()),
        "Max reaches the tenant exactly when granted a role there: {names:?}"
    );
    tenant_opens_to_max(world, names, &reach).await;
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    people::list(world.twin(), None)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Max, granted `names` in the tenant, lists its users on the session he
/// holds exactly when the first role is Admin, holding each role once.
async fn tenant_opens_to_max(world: &World<'_>, names: &[&str], reach: &Reach) {
    let listing = people::list(world.tenant(), None)
        .send(world.member().client())
        .await;
    match names.first() {
        Some(&"Admin") => {
            listing.ok();
            assert_eq!(
                reach.tenants[0].roles.len(),
                names.len().min(2),
                "Max holds each granted role once: {names:?}"
            );
        }
        Some(_) | None => {
            listing.refused(Status::FORBIDDEN, "forbidden");
        }
    }
}

/// Unauthorized withdrawals and Ann's grant containing an undefined role
/// are refused without replacing Tess's roles. She still holds Admin and administers
/// the tenant on the session she holds, and neither a grant nor a
/// withdrawal is recorded.
#[tokio::test]
async fn a_refused_or_unknown_grant_leaves_tess_what_she_had() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let granted = "organization.org_user_tenant_access_granted";
    let revoked = "organization.org_user_tenant_access_revoked";
    let granted_before = world.trail().count(granted).await;
    let revoked_before = world.trail().count(revoked).await;
    people::list(world.tenant(), None)
        .send(world.admin().client())
        .await
        .ok();
    refuse_grant_callers(&world).await;
    refuse_undefined_role(&world).await;
    check_tess_admin(&world).await;
    assert_eq!(
        world.trail().count(granted).await,
        granted_before,
        "a refused grant is not recorded"
    );
    assert_eq!(
        world.trail().count(revoked).await,
        revoked_before,
        "a refused withdrawal is not recorded"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Only a company administrator can withdraw Tess's tenant roles.
async fn refuse_grant_callers(world: &World<'_>) {
    Matrix::new(
        "withdrawing a colleague's tenant roles",
        members::set_tenant_roles(
            world.org(),
            world.admin().id(),
            world.tenant().slug(),
            &roles_named(&[]),
        )
        .call(),
    )
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

/// One undefined role makes Ann's entire replacement grant invalid.
async fn refuse_undefined_role(world: &World<'_>) {
    members::set_tenant_roles(
        world.org(),
        world.admin().id(),
        world.tenant().slug(),
        &roles_named(&["Member", "Never Defined"]),
    )
    .send(world.owner().client())
    .await
    .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
}

/// The refused grants leave Tess holding only Admin, usable on her current session.
async fn check_tess_admin(world: &World<'_>) {
    let reach = members::access(world.org(), world.admin().id())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        reach.tenants[0].roles,
        ["Admin"],
        "Tess still holds Admin and nothing else"
    );
    people::list(world.tenant(), None)
        .send(world.admin().client())
        .await
        .ok();
}

/// Ann cannot grant tenant roles to an owner, administrator, viewer or
/// billing contact whose organization role already decides their reach.
/// Each grant is refused and each colleague
/// reaches what their role gives, the owner and administrator the tenant
/// whole, the others nothing. Sam, of the other company, is not found to
/// grant to; no grant is recorded and Sam's session still works.
#[tokio::test]
async fn owners_admins_viewers_billing_and_strangers_take_no_tenant_grant() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let granted = "organization.org_user_tenant_access_granted";
    let before = world.trail().count(granted).await;

    for role in [
        OrgRole::Owner,
        OrgRole::Admin,
        OrgRole::Viewer,
        OrgRole::Billing,
    ] {
        refuse_role_derived_grant(&world, role).await;
    }
    refuse_stranger_grant(&world).await;
    assert_eq!(
        world.trail().count(granted).await,
        before,
        "no refused grant is recorded"
    );
    members::me(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Organization roles with inherent reach refuse explicit tenant grants and retain that reach.
async fn refuse_role_derived_grant(world: &World<'_>, role: OrgRole) {
    let colleague = world
        .colleague(&format!("{role:?}"), "Separate Colleague", role)
        .await;
    members::set_tenant_roles(
        world.org(),
        colleague.id(),
        world.tenant().slug(),
        &roles_named(&["Admin"]),
    )
    .send(world.owner().client())
    .await
    .refused(Status::CONFLICT, "conflict");
    let reach = members::access(world.org(), colleague.id())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        reach.tenants.len(),
        usize::from(matches!(role, OrgRole::Owner | OrgRole::Admin)),
        "a colleague who is {role:?} reaches what that role gives"
    );
}

/// A member belonging to Sam's company cannot receive a tenant grant in Ann's company.
async fn refuse_stranger_grant(world: &World<'_>) {
    members::set_tenant_roles(
        world.org(),
        world.stranger().id(),
        world.tenant().slug(),
        &roles_named(&["Admin"]),
    )
    .send(world.owner().client())
    .await
    .refused(Status::NOT_FOUND, "not_found");
}
