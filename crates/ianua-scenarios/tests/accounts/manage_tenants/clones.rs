//! Ann copies the roles of her first tenant into `staging`: the copy
//! survives a restart, finishes once, brings the custom role and none of
//! the people. Max, nobody signed in, Sam's tenant as a target and a
//! tenant copied into itself start no copy at all.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{people, roles, tenants};
use ianua_scenarios::expect::{Matrix, eventually};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::roles::{NewRole, SystemPermission};
use ianua_scenarios::wire::tenants::{CloneProgress, CloneSetup};
use ianua_scenarios::world::World;

use crate::support::{
    ann_landing_in, new_tenant, once_set_up, pat_in_the_tenant, room_for_another_tenant,
};

/// Tess adds a custom role to the first tenant, where Pat is signed in.
/// Ann makes `staging` and copies the roles and policies into it; the
/// platform restarts while the copy runs. The copy finishes once, naming
/// both tenants and what it copied. Signed in to staging, Ann reads the
/// custom role there; Pat is not among staging's people and cannot read
/// it, and is still signed in to the first tenant.
#[tokio::test]
async fn a_clone_copies_the_roles_and_none_of_the_people() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat_in_the_tenant(&world).await;
    create_source_role(&world).await;
    let setup = prepare_copy(&world).await;
    let copy = tenants::start_clone(world.org(), &setup)
        .send(world.owner().client())
        .await
        .ok();
    stack.restart().await.expect("the stack restarts");
    let completed = wait_for_copy(&world, &copy.id).await;
    check_completed_copy(&world, &setup, &completed).await;
    check_copied_access(&world, &pat).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess gives the source tenant a custom role to distinguish copied roles from seeded ones.
async fn create_source_role(world: &World<'_>) {
    roles::create(
        world.tenant(),
        &NewRole {
            name: "Source Reader".to_owned(),
            system_permissions: vec![SystemPermission::new("Users", "View")],
        },
    )
    .send(world.admin().client())
    .await
    .ok();
}

/// Creates an empty staging tenant and selects only roles and policies for copying.
async fn prepare_copy(world: &World<'_>) -> CloneSetup {
    room_for_another_tenant(world).await;
    let target = tenants::create(world.org(), &new_tenant(world, "staging"))
        .send(world.owner().client())
        .await
        .ok();
    let staging = world.org().tenant("staging");
    once_set_up(world, &staging, &target.id).await;
    let source = tenants::get(world.tenant())
        .send(world.owner().client())
        .await
        .ok();

    CloneSetup {
        source_tenant_id: source.id,
        target_tenant_id: target.id,
        parts: vec!["roles_and_policies".to_owned()],
    }
}

/// Waits for completion while failing immediately if the copy reports a failure.
async fn wait_for_copy(world: &World<'_>, copy: &str) -> CloneProgress {
    eventually("the copy to finish", || async {
        let progress = tenants::clone_progress(world.org(), copy)
            .send(world.owner().client())
            .await
            .ok();
        assert!(
            progress.failure.is_none(),
            "the copy did not fail: {:?}",
            progress.failure
        );
        (progress.state == "completed").then_some(progress)
    })
    .await
}

/// The completed copy names both tenants, copies only the requested parts and records once.
async fn check_completed_copy(world: &World<'_>, setup: &CloneSetup, completed: &CloneProgress) {
    assert_eq!(
        completed.source_tenant_id, setup.source_tenant_id,
        "the copy names its source"
    );
    assert_eq!(
        completed.target_tenant_id, setup.target_tenant_id,
        "the copy names its target"
    );
    assert_eq!(
        completed.copied,
        ["roles_and_policies"],
        "the copy copied what was asked"
    );
    assert_eq!(
        world.trail().count("tenant.clone_completed").await,
        1,
        "the copy finished once"
    );
}

/// Ann finds the copied role in staging while Pat remains confined to the source tenant.
async fn check_copied_access(world: &World<'_>, pat: &Person) {
    people::me(world.tenant()).send(pat.client()).await.ok();
    let ann = ann_landing_in(world, "staging").await;
    let staging = world.org().tenant("staging");
    let copied = roles::list(&staging).send(ann.client()).await.ok();
    assert!(
        copied.items.iter().any(|role| role.name == "Source Reader"),
        "the custom role reached staging"
    );
    let people_in_staging = people::list(&staging, Some(pat.email()))
        .send(ann.client())
        .await
        .ok();
    assert!(
        people_in_staging.items.is_empty(),
        "Pat was not copied into staging"
    );
    people::me(&staging)
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Max and an anonymous caller cannot start a copy; Ann cannot copy into
/// Sam's tenant or into the source itself. No copy-start record is written,
/// and each owner can still read their own tenant.
#[tokio::test]
async fn nobody_but_the_owner_starts_a_clone_and_a_wrong_target_starts_none() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let source = tenants::get(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    let twin = tenants::get(world.twin())
        .send(world.stranger().client())
        .await
        .ok();
    let setup = CloneSetup {
        source_tenant_id: source.id.clone(),
        target_tenant_id: source.id.clone(),
        parts: vec!["settings".to_owned()],
    };
    refuse_copy_callers(&world, &setup).await;
    refuse_copy_targets(&world, setup, &twin.id).await;
    check_no_copy(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Neither a member nor an anonymous caller can start a tenant copy.
async fn refuse_copy_callers(world: &World<'_>, setup: &CloneSetup) {
    Matrix::new(
        "starting a copy",
        tenants::start_clone(world.org(), setup).call(),
    )
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
}

/// Ann cannot target another organization or copy a tenant into itself.
async fn refuse_copy_targets(world: &World<'_>, mut setup: CloneSetup, twin: &str) {
    setup.target_tenant_id = twin.to_owned();
    tenants::start_clone(world.org(), &setup)
        .send(world.owner().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    setup.target_tenant_id = setup.source_tenant_id.clone();
    tenants::start_clone(world.org(), &setup)
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
}

/// Refused copies leave no start record and preserve each owner's tenant read.
async fn check_no_copy(world: &World<'_>) {
    assert_eq!(
        world.trail().count("tenant.clone_started").await,
        0,
        "no copy was started"
    );
    tenants::get(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    tenants::get(world.twin())
        .send(world.stranger().client())
        .await
        .ok();
}
