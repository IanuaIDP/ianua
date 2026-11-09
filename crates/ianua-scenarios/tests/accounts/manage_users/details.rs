//! Pat's details and the company's records about her: Pat keeps her own
//! name and number from her session, Tess keeps her department, manager
//! and staff numbers, and each is replaced as a whole, a field left out
//! being cleared. Pat changes nothing of the records, and Uma nothing of
//! either.

use ianua_scenarios::api::people;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::people::{UserDetails, UserProfile, UserRecords};
use ianua_scenarios::world::World;

use crate::support::person;

/// The record a changed profile leaves.
const PROFILE_UPDATED: &str = "identity.user_profile_updated";

/// A phone number set aside for testing, which no carrier serves.
const PHONE_NUMBER: &str = "+15005550009";

/// An id no user of the tenant has.
const NOBODY: &str = "00000000-0000-7000-8000-00000000abcd";

/// The name Pat goes by.
const GOES_BY: &str = "pat.l";

/// Pat replaces her own details and reads them back; left out next time,
/// they are cleared. Tess sets the records about her: department,
/// another system's id, a manager who is Uma, and a staff number. Pat
/// reads them, a later set with the department left out clears that alone,
/// and each change is recorded once, without what it says.
#[tokio::test]
async fn pat_keeps_her_details_and_tess_keeps_the_records_about_her() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let before = world.trail().count(PROFILE_UPDATED).await;

    let details = UserDetails {
        given_name: Some("Pat".to_owned()),
        family_name: Some("Lovelace".to_owned()),
        preferred_username: Some(GOES_BY.to_owned()),
        phone_number: Some(PHONE_NUMBER.to_owned()),
    };
    people::change_details(world.tenant(), pat.id(), &details)
        .send(pat.client())
        .await
        .ok();
    let profile = profile_of(&world, pat.id()).await;
    assert_eq!(profile.given_name.as_deref(), Some("Pat"));
    assert_eq!(profile.preferred_username.as_deref(), Some(GOES_BY));
    assert_eq!(profile.phone_number.as_deref(), Some(PHONE_NUMBER));

    let shorter = UserDetails {
        given_name: Some("Patricia".to_owned()),
        ..UserDetails::default()
    };
    people::change_details(world.tenant(), pat.id(), &shorter)
        .send(pat.client())
        .await
        .ok();
    let profile = profile_of(&world, pat.id()).await;
    assert_eq!(profile.given_name.as_deref(), Some("Patricia"));
    assert_eq!(profile.family_name, None, "a field left out is cleared");

    let records = UserRecords {
        external_id: Some("ext-pat".to_owned()),
        department: Some("Finance".to_owned()),
        manager_id: Some(uma.id().to_owned()),
        employee_number: Some("EMP-7".to_owned()),
    };
    people::change_records(world.tenant(), pat.id(), &records)
        .send(world.admin().client())
        .await
        .ok();
    let profile = profile_of(&world, pat.id()).await;
    assert_eq!(profile.department.as_deref(), Some("Finance"));
    assert_eq!(profile.manager_id.as_deref(), Some(uma.id()));
    assert_eq!(profile.employee_number.as_deref(), Some("EMP-7"));

    let without_department = UserRecords {
        department: None,
        ..records
    };
    people::change_records(world.tenant(), pat.id(), &without_department)
        .send(world.admin().client())
        .await
        .ok();
    let profile = profile_of(&world, pat.id()).await;
    assert_eq!(profile.department, None, "the department was left out");
    assert_eq!(profile.external_id.as_deref(), Some("ext-pat"));

    assert_eq!(
        world.trail().count(PROFILE_UPDATED).await,
        before + 4,
        "each of the four changes is recorded once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat cannot change the records about her. Uma cannot change Pat's
/// details or records, nor can nobody signed in. Tess names a manager the
/// tenant does not have, or Pat as her own manager, and is refused. A
/// malformed phone number is refused. Nothing changed.
#[tokio::test]
async fn pat_cannot_write_her_records_and_a_bad_manager_is_refused() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let details = UserDetails {
        given_name: Some("Patricia".to_owned()),
        ..UserDetails::default()
    };
    let records = UserRecords {
        department: Some("Finance".to_owned()),
        ..UserRecords::default()
    };

    people::change_records(world.tenant(), pat.id(), &records)
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    people::change_details(world.tenant(), pat.id(), &details)
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    people::change_records(world.tenant(), pat.id(), &records)
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    people::change_details(world.tenant(), pat.id(), &details)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    let bad_number = UserDetails {
        phone_number: Some("not a number".to_owned()),
        ..UserDetails::default()
    };
    people::change_details(world.tenant(), pat.id(), &bad_number)
        .send(pat.client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let unknown_manager = UserRecords {
        manager_id: Some(NOBODY.to_owned()),
        ..UserRecords::default()
    };
    people::change_records(world.tenant(), pat.id(), &unknown_manager)
        .send(world.admin().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let own_manager = UserRecords {
        manager_id: Some(pat.id().to_owned()),
        ..UserRecords::default()
    };
    people::change_records(world.tenant(), pat.id(), &own_manager)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    let profile = profile_of(&world, pat.id()).await;
    assert_eq!(profile.given_name, None, "no refused change landed");
    assert_eq!(profile.department, None);

    stack.stop().await.expect("the stack stops cleanly");
}

/// The profile `user_id` holds, as Tess reads it.
async fn profile_of(world: &World<'_>, user_id: &str) -> UserProfile {
    let record = people::get(world.tenant(), user_id)
        .send(world.admin().client())
        .await
        .ok();
    let Some(profile) = record.profile else {
        panic!("the user's record holds a profile");
    };
    profile
}
