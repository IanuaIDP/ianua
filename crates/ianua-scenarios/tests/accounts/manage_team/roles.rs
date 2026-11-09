//! Ann changes the organization role a colleague holds: each real change
//! ends Uma's session and her next sign-in shows the new role and the
//! tenant reach that comes with it; giving Max the role he already holds
//! changes nothing. Uma, as an administrator, promotes Max to
//! administrator but never makes or unmakes an owner or a billing
//! contact, and no lower role changes anyone.

use ianua_scenarios::actors::Member;
use ianua_scenarios::api::{members, people};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::{ChangeRole, OrgRole};
use ianua_scenarios::world::World;

use crate::support::{listed, recorded};

/// The audit record a changed organization role leaves.
const ROLE_CHANGED: &str = "organization.org_user_role_changed";

/// Ann moves Uma through viewer, billing contact, administrator, owner
/// and back to member. Each change ends the session Uma held; signed in
/// again she holds exactly the new role, reaches the tenant whole as an
/// owner or administrator and not at all otherwise, and the twin tenant
/// never opens to her. Five changes are recorded.
#[tokio::test]
async fn all_five_roles_take_effect_on_the_next_sign_in() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut uma = world
        .colleague("uma", "Uma Colleague", OrgRole::Member)
        .await;
    uma.sign_in(&stack).await;
    let before = world.trail().count(ROLE_CHANGED).await;

    for role in [
        OrgRole::Viewer,
        OrgRole::Billing,
        OrgRole::Admin,
        OrgRole::Owner,
        OrgRole::Member,
    ] {
        change_and_verify_role(&world, &mut uma, role).await;
    }
    assert_eq!(
        world.trail().count(ROLE_CHANGED).await,
        before + 5,
        "each of the five changes is recorded once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Each role change ends Uma's session and her next sign-in receives only that role's reach.
async fn change_and_verify_role(world: &World<'_>, uma: &mut Member, role: OrgRole) {
    members::me(world.org()).send(uma.client()).await.ok();
    members::change_role(world.org(), uma.id(), &ChangeRole { role })
        .send(world.owner().client())
        .await
        .ok();
    members::me(world.org())
        .send(uma.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    uma.sign_in(world.stack()).await;
    let own = members::me(world.org()).send(uma.client()).await.ok();
    assert_eq!(own.role, Some(role), "Uma signs in again as {role:?}");
    let reach = members::access(world.org(), uma.id())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(reach.role, role, "Ann reads Uma's role as {role:?}");
    assert_eq!(
        reach.tenants.len(),
        usize::from(matches!(role, OrgRole::Owner | OrgRole::Admin)),
        "Uma as {role:?} reaches the tenant exactly as that role does"
    );
    people::list(world.twin(), None)
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Ann gives Max the member role he already holds. His session goes on
/// working and no change is recorded.
#[tokio::test]
async fn repeating_the_role_a_member_holds_changes_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let before = world.trail().count(ROLE_CHANGED).await;
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();

    members::change_role(
        world.org(),
        world.member().id(),
        &ChangeRole {
            role: OrgRole::Member,
        },
    )
    .send(world.owner().client())
    .await
    .ok();

    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    assert_eq!(
        world.trail().count(ROLE_CHANGED).await,
        before,
        "a role given again is not recorded as a change"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma, an administrator, is refused making Max an owner or a billing
/// contact, making Ann a member, and changing the billing contact's role;
/// Max, Tess, Sam and nobody signed in are refused changing Uma's. Ann
/// and the billing contact keep their roles, Max keeps his session, and
/// nothing is recorded. Uma then makes Max an administrator: his session
/// ends, and the change is recorded under Uma.
#[tokio::test]
async fn an_administrator_promotes_a_member_but_never_touches_owners_or_billing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut uma = world
        .colleague("uma", "Uma Administrator", OrgRole::Admin)
        .await;
    uma.sign_in(&stack).await;
    let billing = world
        .colleague("billing", "Billing Colleague", OrgRole::Billing)
        .await;
    let before = world.trail().count(ROLE_CHANGED).await;
    refuse_protected_roles(&world, &uma, &billing).await;
    refuse_role_callers(&world, &uma).await;
    check_refused_changes(&world, &billing, before).await;
    promote_max(&world, &uma).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma cannot create owner or billing roles or change their existing holders.
async fn refuse_protected_roles(world: &World<'_>, uma: &Member, billing: &Member) {
    for (id, role) in [
        (world.member().id(), OrgRole::Owner),
        (world.member().id(), OrgRole::Billing),
        (world.owner().id(), OrgRole::Member),
        (billing.id(), OrgRole::Viewer),
    ] {
        members::change_role(world.org(), id, &ChangeRole { role })
            .send(uma.client())
            .await
            .refused(Status::FORBIDDEN, "forbidden");
    }
}

/// Members, tenant administrators, strangers and anonymous callers cannot change Uma's role.
async fn refuse_role_callers(world: &World<'_>, uma: &Member) {
    Matrix::new(
        "changing a colleague's role",
        members::change_role(
            world.org(),
            uma.id(),
            &ChangeRole {
                role: OrgRole::Viewer,
            },
        )
        .call(),
    )
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.admin().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
}

/// Refused changes leave protected roles, Max's session and the audit count intact.
async fn check_refused_changes(world: &World<'_>, billing: &Member, before: usize) {
    assert_eq!(
        world.trail().count(ROLE_CHANGED).await,
        before,
        "no refused change is recorded"
    );
    assert_eq!(
        listed(world, world.owner().id()).await.role,
        Some(OrgRole::Owner),
        "Ann is still the owner"
    );
    assert_eq!(
        listed(world, billing.id()).await.role,
        Some(OrgRole::Billing),
        "the billing contact still is one"
    );
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
}

/// Uma can promote Max to administrator, ending his old session and recording her as actor.
async fn promote_max(world: &World<'_>, uma: &Member) {
    members::change_role(
        world.org(),
        world.member().id(),
        &ChangeRole {
            role: OrgRole::Admin,
        },
    )
    .send(uma.client())
    .await
    .ok();
    members::me(world.org())
        .send(world.member().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    recorded(world, ROLE_CHANGED, world.member().id(), uma.email()).await;
}
