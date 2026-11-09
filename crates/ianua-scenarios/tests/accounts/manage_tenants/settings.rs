//! Tess changes her tenant's profile: the name, contact address, time
//! zone and locale change together, a later change of the name alone
//! leaves the rest, a bad time zone refuses the whole change, and Max, Sam
//! and nobody signed in change nothing.

use ianua_scenarios::api::tenants;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::tenants::{Tenant, TenantChange};
use ianua_scenarios::world::World;

/// Tess replaces the tenant's name, contact address, time zone and
/// locale, and reads them back on the same session; its id, organization
/// and slug are as before. She then changes the name alone: the contact
/// address, time zone and locale stay. Two renames are recorded, and Sam
/// still reads his own tenant.
#[tokio::test]
async fn tess_changes_the_tenants_profile_and_what_she_leaves_out_stays() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let before = tenants::get(world.tenant())
        .send(world.admin().client())
        .await
        .ok();

    let contact = change_whole_profile(&world, &before).await;
    rename_only(&world, &contact).await;
    tenants::get(world.twin())
        .send(world.stranger().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Changes all profile fields together while retaining tenant identity and ownership.
async fn change_whole_profile(world: &World<'_>, before: &Tenant) -> String {
    let contact = world.address("new-tenant-contact");
    let whole = TenantChange {
        display_name: Some("Changed tenant".to_owned()),
        contact_email: Some(contact.clone()),
        timezone: Some("Europe/Paris".to_owned()),
        locale: Some("fr-FR".to_owned()),
        ..Default::default()
    };
    tenants::change(world.tenant(), &whole)
        .send(world.admin().client())
        .await
        .ok();
    let after = tenants::get(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(after.id, before.id, "the tenant keeps its id");
    assert_eq!(
        after.organization_id, before.organization_id,
        "the tenant keeps its organization"
    );
    assert_eq!(after.slug, before.slug, "the tenant keeps its slug");
    assert_eq!(after.contact_email, contact, "the contact address changed");
    assert_eq!(after.timezone, "Europe/Paris", "the time zone changed");
    assert_eq!(after.locale, "fr-FR", "the locale changed");
    contact
}

/// A later rename retains omitted fields and records the second rename.
async fn rename_only(world: &World<'_>, contact: &str) {
    let name_alone = TenantChange {
        display_name: Some("Final tenant name".to_owned()),
        ..Default::default()
    };
    tenants::change(world.tenant(), &name_alone)
        .send(world.admin().client())
        .await
        .ok();
    let renamed = tenants::get(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(
        renamed.contact_email, contact,
        "the contact address left out stays"
    );
    assert_eq!(
        renamed.timezone, "Europe/Paris",
        "the time zone left out stays"
    );
    assert_eq!(renamed.locale, "fr-FR", "the locale left out stays");
    assert_eq!(
        world.trail().count("tenant.renamed").await,
        2,
        "two renames are recorded"
    );
}

/// An invalid time zone makes Tess's whole update fail, including its
/// valid new name. The name and
/// the time zone are as before, no rename is recorded, and she still
/// reads the tenant on the same session.
#[tokio::test]
async fn a_bad_time_zone_refuses_the_whole_change() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let before = tenants::get(world.tenant())
        .send(world.admin().client())
        .await
        .ok();

    refuse_bad_timezone(&world).await;

    let after = tenants::get(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(
        after.display_name, before.display_name,
        "the name is as before"
    );
    assert_eq!(
        after.timezone, before.timezone,
        "the time zone is as before"
    );
    assert_eq!(
        world.trail().count("tenant.renamed").await,
        0,
        "a refused change records no rename"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// An invalid time zone refuses a request even when its new display name is valid.
async fn refuse_bad_timezone(world: &World<'_>) {
    let half_bad = TenantChange {
        display_name: Some("Must not persist".to_owned()),
        timezone: Some("Not/A-Timezone".to_owned()),
        ..Default::default()
    };
    tenants::change(world.tenant(), &half_bad)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
}

/// Max, Sam and an anonymous caller cannot rename Ann's tenant, while
/// Tess, its administrator, can. One rename is recorded, and Sam's own
/// tenant keeps its name.
#[tokio::test]
async fn only_the_tenants_administrator_changes_its_profile() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let twin = tenants::get(world.twin())
        .send(world.stranger().client())
        .await
        .ok();

    check_profile_callers(&world).await;

    assert_eq!(
        world.trail().count("tenant.renamed").await,
        1,
        "one rename is recorded"
    );
    let twin_after = tenants::get(world.twin())
        .send(world.stranger().client())
        .await
        .ok();
    assert_eq!(
        twin_after.display_name, twin.display_name,
        "Sam's tenant keeps its name"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Only Tess's tenant-administrator session can apply the rename.
async fn check_profile_callers(world: &World<'_>) {
    let rename = TenantChange {
        display_name: Some("Authorized name".to_owned()),
        ..Default::default()
    };
    Matrix::new(
        "renaming the tenant",
        tenants::change(world.tenant(), &rename).call(),
    )
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .allowed(world.admin().client())
    .run()
    .await;
}
