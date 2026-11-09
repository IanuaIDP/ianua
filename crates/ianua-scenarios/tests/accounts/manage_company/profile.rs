//! Ann changes her company's profile, and the company stays the same
//! company: its address, its tenants and its members' proved addresses
//! are untouched. A field left out keeps its value, an unchanged form
//! records nothing, one bad field refuses the whole form, and Tess, Max,
//! Sam and nobody signed in change nothing.

use ianua_scenarios::actors::Member;
use ianua_scenarios::api::{members, organizations, tenants};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::{OrgRole, Organization, OrganizationChange};
use ianua_scenarios::world::World;

use crate::support::{change, twin_usable};

/// The audit record a renamed company leaves.
const RENAMED: &str = "organization.renamed";

/// The audit record a changed display name leaves.
const DISPLAY_NAME_CHANGED: &str = "organization.display_name_changed";

/// The audit records a change to every field of the profile leaves.
const EVERY_FIELD_CHANGED: [&str; 3] = [
    RENAMED,
    "organization.contact_email_changed",
    DISPLAY_NAME_CHANGED,
];

/// Ann changes every field of the profile, then saves the same form
/// again. Max reads the new name, contact mailbox and display name on
/// the company whose id, address and tenants are as they were; each
/// field's change is recorded once, under Ann, and the unchanged form
/// records nothing. Max's own address is still proved, the tenant still
/// belongs to the company, and Sam's company is untouched.
#[tokio::test]
async fn ann_changes_the_company_profile_and_the_company_stays_the_same_company() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let before = organizations::get(world.org())
        .send(world.member().client())
        .await
        .ok();

    let replacement = change(&world);
    replace_profile(&world, &before, &replacement).await;
    repeat_profile_change(&world, &replacement).await;
    check_related_records(&world, &before).await;
    twin_usable(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max sees all replacement fields while the company's identity and tenant count stay fixed.
async fn replace_profile(
    world: &World<'_>,
    before: &Organization,
    replacement: &OrganizationChange,
) {
    organizations::change(world.org(), replacement)
        .send(world.owner().client())
        .await
        .ok();
    let after = organizations::get(world.org())
        .send(world.member().client())
        .await
        .ok();
    assert_eq!(after.id, before.id, "the company keeps its id");
    assert_eq!(after.slug, before.slug, "the company keeps its address");
    assert_eq!(
        after.tenant_count, before.tenant_count,
        "the company keeps its tenants"
    );
    assert_eq!(Some(after.name), replacement.name, "Max reads the new name");
    assert_eq!(
        Some(after.contact_email),
        replacement.contact_email,
        "Max reads the new contact mailbox"
    );
    assert_eq!(
        Some(after.display_name),
        replacement.display_name,
        "Max reads the new display name"
    );
}

/// Saving the same form again leaves one event per changed field, all attributed to Ann.
async fn repeat_profile_change(world: &World<'_>, replacement: &OrganizationChange) {
    organizations::change(world.org(), replacement)
        .send(world.owner().client())
        .await
        .ok();
    for event in EVERY_FIELD_CHANGED {
        let records = world.trail().entries(event).await;
        let [record] = records.as_slice() else {
            panic!("one {event} is recorded, not {}", records.len());
        };
        assert!(
            record.actor.contains(world.owner().email()),
            "the {event} is recorded under Ann"
        );
    }
}

/// The profile update preserves Max's proved address and the tenant's company relationship.
async fn check_related_records(world: &World<'_>, before: &Organization) {
    let max = members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    assert_eq!(max.email, world.member().email(), "Max keeps his address");
    assert!(max.email_verified, "Max's address is still proved");
    let tenant = tenants::get(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        tenant.organization_id, before.id,
        "the tenant still belongs to the company"
    );
}

/// Uma, an administrator, changes only the display name, then saves an
/// empty form. The name and contact mailbox keep their values, the
/// display name is the new one, and only that one change is recorded.
#[tokio::test]
async fn a_field_left_out_keeps_its_value_and_an_empty_form_changes_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut uma = world
        .colleague("uma", "Uma Administrator", OrgRole::Admin)
        .await;
    uma.sign_in(&stack).await;
    let before = organizations::get(world.org())
        .send(world.owner().client())
        .await
        .ok();
    change_display_only(&world, &uma).await;
    check_partial_update(&world, &before).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma changes only the display name, then submits an empty form on the same session.
async fn change_display_only(world: &World<'_>, uma: &Member) {
    organizations::change(
        world.org(),
        &OrganizationChange {
            display_name: Some("New company display".to_owned()),
            ..OrganizationChange::default()
        },
    )
    .send(uma.client())
    .await
    .ok();
    organizations::change(world.org(), &OrganizationChange::default())
        .send(uma.client())
        .await
        .ok();
}

/// Omitted values stay fixed and the display-name event is the only recorded change.
async fn check_partial_update(world: &World<'_>, before: &Organization) {
    let after = organizations::get(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(after.name, before.name, "the name left out keeps its value");
    assert_eq!(
        after.contact_email, before.contact_email,
        "the contact mailbox left out keeps its value"
    );
    assert_eq!(
        after.display_name, "New company display",
        "the display name is the new one"
    );
    assert_eq!(
        world.trail().count(DISPLAY_NAME_CHANGED).await,
        1,
        "the display name change is recorded once"
    );
    assert_eq!(
        world.trail().count(RENAMED).await,
        0,
        "no rename is recorded"
    );
}

/// An invalid contact mailbox makes Ann's whole profile update fail,
/// leaving the profile unchanged and recording no rename. With the
/// mailbox corrected the same session
/// saves the form, and the rename is recorded once.
#[tokio::test]
async fn an_invalid_field_refuses_the_whole_profile_update() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let before = organizations::get(world.org())
        .send(world.owner().client())
        .await
        .ok();
    refuse_invalid_profile(&world, &before).await;

    organizations::change(world.org(), &change(&world))
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        world.trail().count(RENAMED).await,
        1,
        "the corrected form's rename is recorded once"
    );
    twin_usable(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// An invalid mailbox refuses the entire profile form without recording a rename.
async fn refuse_invalid_profile(world: &World<'_>, before: &Organization) {
    let invalid = OrganizationChange {
        contact_email: Some("not a mailbox".to_owned()),
        ..change(world)
    };
    organizations::change(world.org(), &invalid)
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let unchanged = organizations::get(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(&unchanged, before, "the refused form changed nothing");
    assert_eq!(
        world.trail().count(RENAMED).await,
        0,
        "the refused form is not recorded as a rename"
    );
}

/// Tess, Max, Sam and an anonymous caller cannot change the company
/// profile. No rename is recorded; Ann changes the display name afterward, and
/// the name and contact mailbox are as they were. Sam's company is
/// untouched.
#[tokio::test]
async fn nobody_without_the_right_changes_the_company_profile() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let before = organizations::get(world.org())
        .send(world.owner().client())
        .await
        .ok();
    refuse_profile_callers(&world).await;
    change_after_refusals(&world, &before).await;
    twin_usable(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Every caller lacking company-administration rights is refused the whole profile change.
async fn refuse_profile_callers(world: &World<'_>) {
    Matrix::new(
        "changing the company's profile",
        organizations::change(world.org(), &change(world)).call(),
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

/// Ann still changes the display name while the refused name and mailbox changes remain absent.
async fn change_after_refusals(world: &World<'_>, before: &Organization) {
    organizations::change(
        world.org(),
        &OrganizationChange {
            display_name: Some("Still the owner".to_owned()),
            ..OrganizationChange::default()
        },
    )
    .send(world.owner().client())
    .await
    .ok();
    let after = organizations::get(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(after.name, before.name, "the name is as it was");
    assert_eq!(
        after.contact_email, before.contact_email,
        "the contact mailbox is as it was"
    );
    assert_eq!(
        world.trail().count(RENAMED).await,
        0,
        "no refused rename is recorded"
    );
}
