//! Tess gives Pat the reader role and takes it back, and what Pat reaches
//! on the session she holds follows at once; changing the role's
//! permissions reaches Pat the same way, and a role taken back while the
//! trail cannot be written stays with her. Pat herself, Max, Sam and
//! nobody signed in give her no role, and the twin tenant's role is not
//! found here.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{people, roles};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{AuditWrites, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::roles::{AssignRole, RoleChange, SystemPermission};
use ianua_scenarios::world::World;

use crate::support::{person, reader, reads_the_users, refused_the_users};

/// The audit record a role given leaves.
const ROLE_ASSIGNED: &str = "authorization.role_assigned";

/// The audit record a role taken back leaves.
const ROLE_REVOKED: &str = "authorization.role_revoked";

/// A role given to the user `user_id`.
fn given_to(user_id: &str) -> AssignRole {
    AssignRole {
        user_id: user_id.to_owned(),
    }
}

/// Pat, signed in and refused the users, reads them the moment Tess
/// gives her the reader role; given again, the role is recorded once.
/// Uma, without it, is still refused. Tess takes it back: Pat is
/// refused at once, the revocation is recorded once, and Pat still reads
/// her own record.
#[tokio::test]
async fn a_role_given_and_taken_back_changes_what_pat_reaches_at_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let role = reader(&world).await;
    let before = world.trail().count(ROLE_ASSIGNED).await;
    refused_the_users(&world, &pat).await;
    grant_twice(&world, &pat, &role, before).await;
    refused_the_users(&world, &uma).await;
    withdraw_reader(&world, &pat, &role).await;
    people::me(world.tenant()).send(pat.client()).await.ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Repeating the grant preserves Pat's read and produces only one grant event.
async fn grant_twice(world: &World<'_>, pat: &Person, role: &str, before: usize) {
    roles::assign(world.tenant(), role, &given_to(pat.id()))
        .send(world.admin().client())
        .await
        .ok();
    reads_the_users(world, pat).await;
    roles::assign(world.tenant(), role, &given_to(pat.id()))
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(
        world.trail().count(ROLE_ASSIGNED).await,
        before + 1,
        "a role given twice is recorded once"
    );
}

/// Withdrawing the reader role cuts off Pat's read and records the revocation.
async fn withdraw_reader(world: &World<'_>, pat: &Person, role: &str) {
    roles::unassign(world.tenant(), role, pat.id())
        .send(world.admin().client())
        .await
        .ok();
    refused_the_users(world, pat).await;
    assert_eq!(
        world.trail().count(ROLE_REVOKED).await,
        1,
        "the role taken back is recorded once"
    );
}

/// Pat holds the reader role and reads the users. Tess empties the
/// role's permissions: Pat is refused at once on the session she holds.
/// Tess puts the permission back: Pat reads again with no new sign-in,
/// still as herself. The permission taken away is recorded once.
#[tokio::test]
async fn changing_a_roles_permissions_changes_what_its_holders_reach_at_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let role = reader(&world).await;
    roles::assign(world.tenant(), &role, &given_to(pat.id()))
        .send(world.admin().client())
        .await
        .ok();
    reads_the_users(&world, &pat).await;

    change_permissions(&world, &role, vec![]).await;
    refused_the_users(&world, &pat).await;
    change_permissions(&world, &role, vec![SystemPermission::new("Users", "View")]).await;
    reads_the_users(&world, &pat).await;
    check_restored_reader(&world, &pat).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Replaces the role's permissions through Tess's administrative session.
async fn change_permissions(world: &World<'_>, role: &str, permissions: Vec<SystemPermission>) {
    roles::change(
        world.tenant(),
        role,
        &RoleChange {
            system_permissions: Some(permissions),
            ..Default::default()
        },
    )
    .send(world.admin().client())
    .await
    .ok();
}

/// Pat keeps her identity on the original session and the revoked permission is recorded once.
async fn check_restored_reader(world: &World<'_>, pat: &Person) {
    let own = people::me(world.tenant()).send(pat.client()).await.ok();
    assert_eq!(own.id, pat.id(), "Pat is still herself on the same session");
    assert_eq!(
        world
            .trail()
            .count("authorization.permission_revoked")
            .await,
        1,
        "the permission taken away is recorded once"
    );
}

/// Tess cannot revoke Pat's reader role while the audit trail is unwritable.
/// Pat still reads the users on the session she
/// holds and nothing is recorded; with the trail back the retry takes
/// the role, Pat is refused at once, and the revocation is recorded once.
#[tokio::test]
async fn a_role_taken_back_while_the_trail_is_down_stays_with_pat() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let role = reader(&world).await;
    roles::assign(world.tenant(), &role, &given_to(pat.id()))
        .send(world.admin().client())
        .await
        .ok();
    reads_the_users(&world, &pat).await;
    fail_revocation(&world, &pat, &role).await;
    retry_revocation(&world, &pat, &role).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// An unwritable trail prevents revocation and preserves Pat's reader access.
async fn fail_revocation(world: &World<'_>, pat: &Person, role: &str) {
    world.stack().audit_writes(AuditWrites::Refuse).await;
    let failed = roles::unassign(world.tenant(), role, pat.id())
        .send(world.admin().client())
        .await;
    assert_eq!(
        failed.status(),
        Status::INTERNAL_SERVER_ERROR,
        "a revocation the trail cannot record fails: {}",
        failed.summary()
    );
    world.stack().audit_writes(AuditWrites::Allow).await;
    reads_the_users(world, pat).await;
    assert_eq!(
        world.trail().count(ROLE_REVOKED).await,
        0,
        "the failed revocation is not recorded"
    );
}

/// Retrying after audit recovery removes the read and records one revocation.
async fn retry_revocation(world: &World<'_>, pat: &Person, role: &str) {
    roles::unassign(world.tenant(), role, pat.id())
        .send(world.admin().client())
        .await
        .ok();
    refused_the_users(world, pat).await;
    assert_eq!(
        world.trail().count(ROLE_REVOKED).await,
        1,
        "the retried revocation is recorded once"
    );
}

/// Pat, Max, Sam and an anonymous caller cannot grant Pat the Admin role;
/// Tess cannot grant the twin tenant's Admin role, which is not found here.
/// No role grant is recorded; Pat is still refused
/// the users and still reads her own record.
#[tokio::test]
async fn nobody_without_the_right_gives_pat_a_role_and_the_twins_role_is_not_found() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let admin_role = world.role_id("Admin").await;
    let before = world.trail().count(ROLE_ASSIGNED).await;
    refuse_role_grants(&world, &pat, &admin_role).await;
    refuse_foreign_role(&world, &pat).await;

    assert_eq!(
        world.trail().count(ROLE_ASSIGNED).await,
        before,
        "no refused grant is recorded"
    );
    refused_the_users(&world, &pat).await;
    people::me(world.tenant()).send(pat.client()).await.ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// All callers without role-management rights are refused the Admin grant.
async fn refuse_role_grants(world: &World<'_>, pat: &Person, admin_role: &str) {
    Matrix::new(
        "giving someone a role",
        roles::assign(world.tenant(), admin_role, &given_to(pat.id())).call(),
    )
    .refused(pat.client(), Status::FORBIDDEN, "forbidden")
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

/// Tess cannot assign the twin tenant's Admin role in this tenant.
async fn refuse_foreign_role(world: &World<'_>, pat: &Person) {
    let twins = roles::list(world.twin())
        .send(world.stranger().client())
        .await
        .ok();
    let Some(foreign) = twins.items.into_iter().find(|role| role.name == "Admin") else {
        panic!("the twin tenant has an Admin role");
    };
    roles::assign(world.tenant(), &foreign.id, &given_to(pat.id()))
        .send(world.admin().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
}
