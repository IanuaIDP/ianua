//! Tess labels the tenant as the staging stage of Acme's product, and the
//! label shows with the tenant; a stage that is not one is refused. Max,
//! Sam and nobody signed in change no label, and nothing is recorded for
//! them.

use ianua_scenarios::api::tenants;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::tenants::EnvironmentChange;
use ianua_scenarios::world::World;

/// The record a changed label leaves.
const CHANGED: &str = "tenant.environment_changed";

/// The stage `name`.
fn stage(name: &str) -> EnvironmentChange {
    EnvironmentChange {
        environment: name.to_owned(),
    }
}

/// Tess labels the tenant `staging`, on record, and the tenant reads that
/// way to her and to Ann. Labelled `production` again, it reads so. A
/// stage called `qa` is refused and the label stays.
#[tokio::test]
async fn tess_labels_the_tenant_as_staging_and_back() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let seen = world.trail().ids().await;

    tenants::change_environment(world.tenant(), &stage("staging"))
        .send(tess)
        .await
        .ok();
    world.trail().recorded_after(&seen, CHANGED).await;
    for reader in [tess, world.owner().client()] {
        let read = tenants::get(world.tenant()).send(reader).await.ok();
        assert_eq!(read.environment, "staging");
    }

    tenants::change_environment(world.tenant(), &stage("production"))
        .send(tess)
        .await
        .ok();
    tenants::change_environment(world.tenant(), &stage("qa"))
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let read = tenants::get(world.tenant()).send(tess).await.ok();
    assert_eq!(
        read.environment, "production",
        "the refused stage changed nothing"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max, a member with no administrator's rights, Sam from the other
/// company and nobody signed in may not relabel the tenant; its label
/// stays and nothing is recorded.
#[tokio::test]
async fn nobody_without_the_right_relabels_the_tenant() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let before = tenants::get(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let seen = world.trail().ids().await;

    Matrix::new(
        "relabelling the tenant",
        tenants::change_environment(world.tenant(), &stage("development")).call(),
    )
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;

    let after = tenants::get(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(after.environment, before.environment);
    world.trail().nothing_after(&seen, CHANGED).await;

    stack.stop().await.expect("the stack stops cleanly");
}
