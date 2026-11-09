//! A person's whole record as the directory sends it and reads it back,
//! the version it holds answered "not modified", a replaced record keeping
//! only what was sent, and records the endpoint cannot keep refused before
//! any account is opened.

use ianua_scenarios::api::{directory, people};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::directory::{
    DirectoryEmail, DirectoryEnterprise, DirectoryName, DirectoryRecord, DirectoryResource,
    ManagerReference,
};
use ianua_scenarios::world::World;

use super::{ENTERPRISE, read};
use crate::support::{OnRemove, linked_directory, made};

/// The audit record an account the directory opens leaves.
const USER_REGISTERED: &str = "identity.user_registered";

/// The audit record a switched-off account leaves.
const STATUS_CHANGED: &str = "identity.user_status_changed";

/// Uma's record comes first, so Pat's can name her as manager. The
/// directory sends Pat's whole record: her name's parts, its own id for
/// her, her department and employee number, and Uma as her manager. Each
/// part reads back as sent, the enterprise extension named among the
/// record's schemas and her address as her one work address. Tess reads
/// Pat active with her mailbox unproved. The directory asks again with
/// the version it holds and is told nothing changed. The opening is
/// recorded as the platform's own doing, naming Pat.
#[tokio::test]
async fn the_directory_reads_back_pats_whole_record_as_it_sent_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let uma = made(&world, &linked, "uma").await;
    let pat = world.newcomer("pat", "Pat Holder");
    let enterprise = DirectoryEnterprise {
        department: Some("Finance".to_owned()),
        employee_number: Some("E-1042".to_owned()),
        manager: Some(ManagerReference {
            value: uma.id().to_owned(),
        }),
    };
    let record = DirectoryRecord {
        user_name: pat.email().to_owned(),
        display_name: Some("Pat Holder".to_owned()),
        name: Some(DirectoryName {
            formatted: None,
            given_name: Some("Pat".to_owned()),
            family_name: Some("Holder".to_owned()),
        }),
        external_id: Some("okta-pat-1042".to_owned()),
        enterprise: Some(enterprise.clone()),
        ..DirectoryRecord::default()
    };

    let created = directory::create_record(world.tenant(), &record)
        .send(&linked)
        .await;
    assert_eq!(
        created.status(),
        Status::CREATED,
        "the directory's record opens an account: {}",
        created.summary()
    );
    let pat_id = created.ok().id;

    let kept = read(&world, &linked, &pat_id).await;
    assert_eq!(kept.user_name, pat.email());
    assert_eq!(kept.display_name, "Pat Holder");
    assert!(kept.active, "Pat may sign in at once");
    assert_eq!(kept.external_id.as_deref(), Some("okta-pat-1042"));
    let name = kept.name.expect("Pat's name is kept");
    assert_eq!(name.given_name.as_deref(), Some("Pat"));
    assert_eq!(name.family_name.as_deref(), Some("Holder"));
    assert_eq!(kept.enterprise, Some(enterprise));
    assert!(
        kept.schemas.iter().any(|schema| schema == ENTERPRISE),
        "the record names the enterprise extension it carries"
    );
    assert_eq!(
        kept.emails,
        [DirectoryEmail {
            value: pat.email().to_owned(),
            primary: true,
            kind: Some("work".to_owned()),
        }]
    );
    assert_eq!(
        kept.meta.map(|meta| meta.resource_type).as_deref(),
        Some("User")
    );

    let seen_by_tess = people::get(world.tenant(), &pat_id)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(seen_by_tess.status, "Active");
    assert!(
        !seen_by_tess.email_verified,
        "the directory's word proves no mailbox"
    );

    let first = directory::get_user(world.tenant(), &pat_id)
        .send(&linked)
        .await;
    let version = first
        .header("etag")
        .expect("the record is sent with its version")
        .to_owned();
    let again = directory::get_user(world.tenant(), &pat_id)
        .header("if-none-match", &version)
        .send(&linked)
        .await;
    assert_eq!(
        again.status(),
        Status::NOT_MODIFIED,
        "the version the directory holds is current: {}",
        again.summary()
    );

    let opened = world.trail().entries(USER_REGISTERED).await;
    let recorded = opened
        .iter()
        .find(|entry| entry.details["email"] == pat.email())
        .expect("Pat's opening is recorded");
    assert!(
        recorded.actor.to_ascii_lowercase().contains("system"),
        "the directory acts as the platform, not as a person: {}",
        recorded.actor
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The directory makes Pat with her whole record and Uma as her manager,
/// then sends Pat's record again with only her address, a new display
/// name, a family name and her account switched off. Pat keeps only what
/// was sent: her given name, the directory's id for her and the whole
/// enterprise extension are cleared, the record no longer names that
/// extension, and her version changes. Tess reads her locked, and the
/// lock is recorded.
#[tokio::test]
async fn a_replaced_record_keeps_only_what_the_directory_sent() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let uma = made(&world, &linked, "uma").await;
    let pat = world.newcomer("pat", "Pat Holder");
    let whole = DirectoryRecord {
        user_name: pat.email().to_owned(),
        display_name: Some("Pat Holder".to_owned()),
        name: Some(DirectoryName {
            formatted: None,
            given_name: Some("Pat".to_owned()),
            family_name: Some("Holder".to_owned()),
        }),
        external_id: Some("okta-pat-2001".to_owned()),
        enterprise: Some(DirectoryEnterprise {
            department: Some("Finance".to_owned()),
            employee_number: Some("E-2001".to_owned()),
            manager: Some(ManagerReference {
                value: uma.id().to_owned(),
            }),
        }),
        ..DirectoryRecord::default()
    };
    let pat_id = directory::create_record(world.tenant(), &whole)
        .send(&linked)
        .await
        .ok()
        .id;
    let before = read(&world, &linked, &pat_id).await;
    let locks_before = world.trail().count(STATUS_CHANGED).await;

    let slimmer = DirectoryRecord {
        user_name: pat.email().to_owned(),
        display_name: Some("Pat Married".to_owned()),
        name: Some(DirectoryName {
            formatted: None,
            given_name: None,
            family_name: Some("Married".to_owned()),
        }),
        active: Some(false),
        ..DirectoryRecord::default()
    };
    let replaced = directory::replace_user(world.tenant(), &pat_id, &slimmer)
        .send(&linked)
        .await
        .ok();

    assert_eq!(replaced.display_name, "Pat Married");
    assert!(!replaced.active, "the record switched Pat off");
    assert_eq!(replaced.external_id, None, "the directory's id is cleared");
    assert_eq!(
        replaced.enterprise, None,
        "the enterprise fields are cleared"
    );
    assert!(
        replaced.schemas.iter().all(|schema| schema != ENTERPRISE),
        "the record names no extension it no longer carries"
    );
    let name = replaced.name.as_ref().expect("Pat's name is kept");
    assert_eq!(name.given_name, None, "her given name is cleared");
    assert_eq!(name.family_name.as_deref(), Some("Married"));
    let version =
        |record: &DirectoryResource| record.meta.as_ref().map(|meta| meta.version.clone());
    assert_ne!(
        version(&replaced),
        version(&before),
        "a changed record has a new version"
    );

    let seen_by_tess = people::get(world.tenant(), &pat_id)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(seen_by_tess.status, "Locked", "the directory locked Pat");
    assert_eq!(seen_by_tess.display_name, "Pat Married");
    assert!(
        world.trail().count(STATUS_CHANGED).await > locks_before,
        "the lock is recorded"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The directory sends records the endpoint cannot keep: a user name that
/// is no address with no address among its emails, a manager that is no
/// user id, a manager who is nobody in the tenant, and a body that is not
/// JSON at all. Each is refused in SCIM's own terms, no account is opened
/// at Pat's address and no opening is recorded. Then it sends Pat as Okta
/// may, her employee number as the user name and her address as the
/// primary email, and Pat is made at her address.
#[tokio::test]
async fn records_the_endpoint_cannot_keep_open_no_account() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let pat = world.newcomer("pat", "Pat Holder");
    let opened_before = world.trail().count(USER_REGISTERED).await;
    let pats = |user_name: &str, manager: Option<String>| DirectoryRecord {
        user_name: user_name.to_owned(),
        display_name: Some("Pat Holder".to_owned()),
        enterprise: manager.map(|value| DirectoryEnterprise {
            manager: Some(ManagerReference { value }),
            ..DirectoryEnterprise::default()
        }),
        ..DirectoryRecord::default()
    };

    directory::create_record(world.tenant(), &pats("E-1042", None))
        .send(&linked)
        .await
        .refused(Status::BAD_REQUEST, "invalidValue");
    directory::create_record(
        world.tenant(),
        &pats(pat.email(), Some("the-manager".to_owned())),
    )
    .send(&linked)
    .await
    .refused(Status::BAD_REQUEST, "invalidValue");
    let nobody = uuid::Uuid::now_v7().to_string();
    let unknown_manager =
        directory::create_record(world.tenant(), &pats(pat.email(), Some(nobody)))
            .send(&linked)
            .await;
    assert_eq!(
        unknown_manager.status(),
        Status::NOT_FOUND,
        "a manager who is nobody here is not found: {}",
        unknown_manager.summary()
    );
    directory::create_user_raw(
        world.tenant(),
        "application/scim+json",
        "userName=pat&active=true",
    )
    .send(&linked)
    .await
    .refused(Status::BAD_REQUEST, "invalidValue");

    let nobody_there =
        directory::find_users(world.tenant(), &format!("userName eq \"{}\"", pat.email()))
            .send(&linked)
            .await
            .ok();
    assert_eq!(nobody_there.total_results, 0, "no account was opened");
    assert_eq!(
        world.trail().count(USER_REGISTERED).await,
        opened_before,
        "a refused record records no opening"
    );

    let by_number = DirectoryRecord {
        emails: vec![DirectoryEmail {
            value: pat.email().to_owned(),
            primary: true,
            kind: Some("work".to_owned()),
        }],
        ..pats("E-1042", None)
    };
    let created = directory::create_record(world.tenant(), &by_number)
        .send(&linked)
        .await
        .ok();
    assert_eq!(
        created.user_name,
        pat.email(),
        "the primary email names the account"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
