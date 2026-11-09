//! Ann changes her company's profile and closes the company while the
//! audit trail cannot be written: neither change happens in part, the
//! profile, the tenant and every session are as they were, and with the
//! trail back the change goes through whole.

use ianua_scenarios::api::{members, organizations, tenants};
use ianua_scenarios::stack::{AuditWrites, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::Organization;
use ianua_scenarios::wire::tenants::TenantStatus;
use ianua_scenarios::world::World;

use crate::support::{change, twin_usable};

/// The audit record a renamed company leaves.
const RENAMED: &str = "organization.renamed";

/// The audit record a company's change of status leaves.
const STATUS_CHANGED: &str = "organization.status_changed";

/// Ann's profile update fails when the audit trail cannot be written.
/// The profile is unchanged and none of its changes is recorded; with
/// the trail back the same form goes through, and the rename is
/// recorded once. Sam's company is untouched.
#[tokio::test]
async fn a_profile_change_the_trail_cannot_record_changes_nothing_and_succeeds_retried() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let before = organizations::get(world.org())
        .send(world.owner().client())
        .await
        .ok();
    fail_profile_change(&world).await;
    check_unchanged_profile(&world, &before).await;

    organizations::change(world.org(), &change(&world))
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        world.trail().count(RENAMED).await,
        1,
        "the retried change's rename is recorded once"
    );
    twin_usable(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The profile write fails when its audit event cannot be persisted.
async fn fail_profile_change(world: &World<'_>) {
    world.stack().audit_writes(AuditWrites::Refuse).await;
    let failed = organizations::change(world.org(), &change(world))
        .send(world.owner().client())
        .await;
    assert_eq!(
        failed.status(),
        Status::INTERNAL_SERVER_ERROR,
        "a change the trail cannot record fails: {}",
        failed.summary()
    );
    world.stack().audit_writes(AuditWrites::Allow).await;
}

/// The failed update leaves the entire profile and every profile-event count unchanged.
async fn check_unchanged_profile(world: &World<'_>, before: &Organization) {
    let unchanged = organizations::get(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(&unchanged, before, "the failed change changed nothing");
    for event in [
        RENAMED,
        "organization.contact_email_changed",
        "organization.display_name_changed",
    ] {
        assert_eq!(
            world.trail().count(event).await,
            0,
            "the failed change is not recorded as {event}"
        );
    }
}

/// Ann's attempt to close the company fails when audit writes fail. The
/// company is still active, its tenant still active, Max and Tess still
/// in on the sessions they hold, and nothing is recorded. Ann then
/// suspends it for real, and Max is out. Sam's company is untouched.
#[tokio::test]
async fn a_closure_the_trail_cannot_record_leaves_the_company_open_whole() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    fail_closure(&world).await;
    check_open_company(&world).await;

    organizations::suspend(world.org())
        .send(world.owner().client())
        .await
        .ok();
    members::me(world.org())
        .send(world.member().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    twin_usable(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Closing the company fails when the audit trail is unwritable.
async fn fail_closure(world: &World<'_>) {
    world.stack().audit_writes(AuditWrites::Refuse).await;
    let failed = organizations::close(world.org())
        .send(world.owner().client())
        .await;
    assert_eq!(
        failed.status(),
        Status::INTERNAL_SERVER_ERROR,
        "a closure the trail cannot record fails: {}",
        failed.summary()
    );
    world.stack().audit_writes(AuditWrites::Allow).await;
}

/// Company and tenant remain active, both sessions survive, and no status event is recorded.
async fn check_open_company(world: &World<'_>) {
    let acme = organizations::get(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(acme.status, "Active", "the company is still active");
    let tenant = tenants::get(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        tenant.status,
        TenantStatus::Active,
        "the tenant is still active"
    );
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    members::me(world.org())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(
        world.trail().count(STATUS_CHANGED).await,
        0,
        "the failed closure is not recorded"
    );
}
