//! Max reads what he reaches himself, the way his dashboard is built: the
//! tenant he works in, his roles there and what they let him do. Ann
//! makes him an administrator of the tenant and his own read shows it on
//! the session he already holds, then narrows him back. Sam and nobody
//! signed in read nothing of Acme's.

use ianua_scenarios::api::members;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::{Reach, TenantRoles};
use ianua_scenarios::world::World;

/// The record a grant of tenant roles leaves.
const GRANTED: &str = "organization.org_user_tenant_access_granted";

/// The tenant roles named by `names`.
fn roles_named(names: &[&str]) -> TenantRoles {
    TenantRoles {
        roles: names.iter().map(|name| (*name).to_owned()).collect(),
    }
}

/// The roles `reach` holds in the tenant `slug`, with what they allow.
fn held_in<'r>(reach: &'r Reach, slug: &str) -> (&'r [String], &'r [String]) {
    let Some(tenant) = reach.tenants.iter().find(|tenant| tenant.slug == slug) else {
        panic!("the reach names no tenant {slug}");
    };
    (tenant.roles.as_slice(), tenant.permissions.as_slice())
}

/// Max reads his reach: the tenant with its `Member` role. Ann makes him
/// the tenant's administrator, on record, and Max's next read on the same
/// session names the `Admin` role and allows more than before. Ann narrows
/// him back to `Member`, and his read shows that too.
#[tokio::test]
async fn max_reads_his_reach_and_sees_each_grant_at_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let max = world.member();
    let slug = world.tenant().slug();
    let seen = world.trail().ids().await;

    let before = members::my_access(world.org())
        .send(max.client())
        .await
        .ok();
    let (roles, allowed_before) = held_in(&before, slug);
    assert_eq!(roles, ["Member".to_owned()], "Max holds the Member role");
    let allowed_before = allowed_before.len();

    members::set_tenant_roles(world.org(), max.id(), slug, &roles_named(&["Admin"]))
        .send(world.owner().client())
        .await
        .ok();
    world.trail().recorded_after(&seen, GRANTED).await;
    let promoted = members::my_access(world.org())
        .send(max.client())
        .await
        .ok();
    let (roles, allowed) = held_in(&promoted, slug);
    assert_eq!(
        roles,
        ["Admin".to_owned()],
        "Max now administers the tenant"
    );
    assert!(allowed.len() > allowed_before, "the Admin role allows more");

    members::set_tenant_roles(world.org(), max.id(), slug, &roles_named(&["Member"]))
        .send(world.owner().client())
        .await
        .ok();
    let narrowed = members::my_access(world.org())
        .send(max.client())
        .await
        .ok();
    let (roles, allowed) = held_in(&narrowed, slug);
    assert_eq!(roles, ["Member".to_owned()]);
    assert_eq!(allowed.len(), allowed_before, "back to what he had");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Sam, who owns the other company, and nobody signed in may not read a
/// reach in Acme; Sam still reads his own in Globex.
#[tokio::test]
async fn nobody_outside_acme_reads_a_reach_there() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    Matrix::new(
        "reading a reach in Acme",
        members::my_access(world.org()).call(),
    )
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
    let own = members::my_access(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();
    assert!(
        own.tenants
            .iter()
            .any(|tenant| tenant.slug == world.twin().slug()),
        "Sam reaches his own tenant"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
