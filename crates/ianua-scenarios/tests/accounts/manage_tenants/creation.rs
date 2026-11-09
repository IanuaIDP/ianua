//! Ann makes a second tenant, `staging`: its setup finishes and survives
//! restarts, and she signs in to it. The plan, Tess, Max, Sam and nobody
//! signed in are all refused a tenant; an audit record that cannot be
//! written refuses it whole; a bus outage neither loses nor doubles its
//! setup.

use ianua_scenarios::actors::Member;
use ianua_scenarios::api::{TenantPath, members, organizations, roles, tenants};
use ianua_scenarios::expect::{Matrix, Trail};
use ianua_scenarios::stack::{AuditWrites, Part, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::world::World;

use crate::support::{ann_landing_in, new_tenant, once_set_up, room_for_another_tenant};

/// Ann makes `staging`, and the platform restarts while its setup runs.
/// The setup finishes anyway; she signs in to it and reads the roles its
/// setup seeded. After another restart the tenant is still there, counted
/// once in her organization, listed once, with one creation record.
#[tokio::test]
async fn a_new_tenant_finishes_its_setup_and_survives_restarts() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    room_for_another_tenant(&world).await;
    let before = world.trail().count("organization.tenant_created").await;

    let made = tenants::create(world.org(), &new_tenant(&world, "staging"))
        .send(world.owner().client())
        .await
        .ok();
    stack.restart().await.expect("the stack restarts");
    let staging = world.org().tenant("staging");
    once_set_up(&world, &staging, &made.id).await;

    let ann = ann_landing_in(&world, "staging").await;
    check_seeded_roles(&staging, &ann).await;

    stack.restart().await.expect("the stack restarts again");
    check_persisted_tenant(&world, &ann, &made.id).await;
    check_creation_record(&world, &ann, before).await;
    check_listed_once(&world, &ann, &made.id).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann can read both built-in roles after staging finishes setup.
async fn check_seeded_roles(staging: &TenantPath, ann: &Member) {
    let seeded = roles::list(staging).send(ann.client()).await.ok();
    assert!(
        seeded.items.iter().any(|role| role.name == "Admin"),
        "the setup seeded the Admin role"
    );
    assert!(
        seeded.items.iter().any(|role| role.name == "Member"),
        "the setup seeded the Member role"
    );
}

/// Restart preserves staging and its contribution to the organization's tenant count.
async fn check_persisted_tenant(world: &World<'_>, ann: &Member, id: &str) {
    let staging = world.org().tenant("staging");
    assert_eq!(
        tenants::get(&staging).send(ann.client()).await.ok().id,
        id,
        "the tenant is still there after the restart"
    );
    let organization = organizations::get(world.org())
        .send(ann.client())
        .await
        .ok();
    assert_eq!(
        organization.tenant_count, 2,
        "the organization counts its first tenant and staging"
    );
}

/// Ann's replacement session reads exactly one additional creation record.
async fn check_creation_record(world: &World<'_>, ann: &Member, before: usize) {
    let trail = Trail::of_organization(ann.client(), world.org().slug());
    assert_eq!(
        trail.count("organization.tenant_created").await,
        before + 1,
        "one creation record, read by Ann's session in staging since the move ended her first"
    );
}

/// The organization lists the newly created tenant exactly once after restart.
async fn check_listed_once(world: &World<'_>, ann: &Member, id: &str) {
    let listed = tenants::list(world.org()).send(ann.client()).await.ok();
    assert_eq!(
        listed.items.iter().filter(|tenant| tenant.id == id).count(),
        1,
        "staging is listed once"
    );
}

/// Ann cannot create a second tenant on a plan allowing one. The refusal
/// names the limit, creates no tenant and records no creation. Once she
/// moves to a plan with room, the same form makes `staging`, and the first
/// tenant is untouched.
#[tokio::test]
async fn a_tenant_over_the_plan_is_refused_whole_and_made_once_there_is_room() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let before = world.trail().count("organization.tenant_created").await;
    refuse_over_plan(&world, before).await;

    room_for_another_tenant(&world).await;
    let made = tenants::create(world.org(), &new_tenant(&world, "staging"))
        .send(world.owner().client())
        .await
        .ok();
    once_set_up(&world, &world.org().tenant("staging"), &made.id).await;
    tenants::get(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        world.trail().count("organization.tenant_created").await,
        before + 1,
        "one creation record once staging is made"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The plan refusal names its limit and leaves only the first tenant and its records.
async fn refuse_over_plan(world: &World<'_>, before: usize) {
    let refused = tenants::create(world.org(), &new_tenant(world, "staging"))
        .send(world.owner().client())
        .await
        .refused(Status::CONFLICT, "conflict");
    assert!(
        refused.message().contains("plan allows at most 1 tenants"),
        "the refusal names the plan's limit: {}",
        refused.message()
    );
    let listed = tenants::list(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(listed.items.len(), 1, "only the first tenant exists");
    assert_eq!(
        world.trail().count("organization.tenant_created").await,
        before,
        "a refused tenant records nothing"
    );
}

/// Tess, Max, Sam and an anonymous caller cannot create `staging` in Ann's
/// organization, and none leaves a creation record. Ann then
/// makes it with the same slug, so the refusals claimed nothing, and Sam
/// still reads his own organization.
#[tokio::test]
async fn only_the_owner_makes_a_tenant() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    room_for_another_tenant(&world).await;
    let before = world.trail().count("organization.tenant_created").await;
    refuse_nonowners(&world).await;
    assert_eq!(
        world.trail().count("organization.tenant_created").await,
        before,
        "a refused tenant records nothing"
    );

    let made = tenants::create(world.org(), &new_tenant(&world, "staging"))
        .send(world.owner().client())
        .await
        .ok();
    once_set_up(&world, &world.org().tenant("staging"), &made.id).await;
    members::me(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Only Ann's ownership authorizes creating a tenant in her organization.
async fn refuse_nonowners(world: &World<'_>) {
    Matrix::new(
        "making a tenant",
        tenants::create(world.org(), &new_tenant(world, "staging")).call(),
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

/// Failure to write the new tenant's audit record rolls creation back.
/// Ann's organization still has one tenant and no new creation record. Once
/// records can be written again, the same form makes `staging` and
/// records it once.
#[tokio::test]
async fn a_tenant_whose_record_cannot_be_written_is_not_made() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    room_for_another_tenant(&world).await;
    let before = world.trail().count("organization.tenant_created").await;
    fail_creation(&world, before).await;

    let made = tenants::create(world.org(), &new_tenant(&world, "staging"))
        .send(world.owner().client())
        .await
        .ok();
    once_set_up(&world, &world.org().tenant("staging"), &made.id).await;
    assert_eq!(
        world.trail().count("organization.tenant_created").await,
        before + 1,
        "one creation record once staging is made"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Audit failure rolls tenant creation back, including the organization's count.
async fn fail_creation(world: &World<'_>, before: usize) {
    world.stack().audit_writes(AuditWrites::Refuse).await;
    let failed = tenants::create(world.org(), &new_tenant(world, "staging"))
        .send(world.owner().client())
        .await;
    assert_eq!(
        failed.status(),
        Status::INTERNAL_SERVER_ERROR,
        "a tenant whose record cannot be written fails: {}",
        failed.summary()
    );
    world.stack().audit_writes(AuditWrites::Allow).await;
    let organization = organizations::get(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        organization.tenant_count, 1,
        "the organization still has its one tenant"
    );
    assert_eq!(
        world.trail().count("organization.tenant_created").await,
        before,
        "a failed creation records nothing"
    );
}

/// The bus is cut while Ann makes `staging`. The setup is queued durably
/// and finishes once the bus is back; a restart neither loses the tenant
/// nor records its creation twice.
#[tokio::test]
async fn a_bus_outage_does_not_lose_or_duplicate_tenant_setup() {
    let stack = Stack::start(Profile::standard().with_cuttable_parts())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    room_for_another_tenant(&world).await;
    let before = world.trail().count("organization.tenant_created").await;

    stack.cut(Part::Bus);
    let made = tenants::create(world.org(), &new_tenant(&world, "staging"))
        .send(world.owner().client())
        .await
        .ok();
    stack.mend(Part::Bus);
    once_set_up(&world, &world.org().tenant("staging"), &made.id).await;

    stack.restart().await.expect("the stack restarts");
    assert_eq!(
        world.trail().count("organization.tenant_created").await,
        before + 1,
        "one creation record after the outage and the restart"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
