//! Every way a directory may change part of a person's record: by short
//! or fully qualified path, by a pathless object as Okta sends it, with
//! Entra ID's booleans spelled as text, through an `emails` path, and with
//! attributes the endpoint does not keep; and `remove`, which clears
//! profile fields and leaves the sign-in address, name and switch alone.

use ianua_scenarios::api::{directory, people};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::directory::{
    DirectoryEnterprise, DirectoryName, DirectoryOperation, DirectoryPatch, DirectoryRecord,
    ManagerReference,
};
use ianua_scenarios::world::World;
use serde_json::{Value, json};

use super::{ENTERPRISE, read};
use crate::support::{OnRemove, linked_directory, made};

/// The audit record a moved sign-in address leaves.
const EMAIL_CHANGED: &str = "identity.email_changed";

/// The directory makes Pat and Uma. In one request it sets Pat's family
/// name by the core schema's full path, her department by the enterprise
/// extension's full path, its own new id for her, and a job title the
/// endpoint does not keep; each kept part changes and the title is passed
/// over. A pathless change, as Okta sends it, sets her given name and,
/// inside the enterprise object, her employee number and Uma as her
/// manager, leaving her department as it was. Entra ID switches her off
/// with `"False"` and back on with `"True"`. Last, the directory moves her
/// to a new address through her work email's path: Tess reads the new
/// address, unproved, and the move is recorded.
#[tokio::test]
async fn the_directory_changes_pat_by_every_patch_form_it_may_send() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let uma = made(&world, &linked, "uma").await;
    let pat = made(&world, &linked, "pat").await;
    let change = |patch: DirectoryPatch| directory::patch_user(world.tenant(), pat.id(), &patch);

    let by_path = DirectoryPatch::of(vec![
        DirectoryOperation::at(
            "replace",
            "urn:ietf:params:scim:schemas:core:2.0:User:name.familyName",
            Value::from("Holder"),
        ),
        DirectoryOperation::at(
            "Add",
            &format!("{ENTERPRISE}:department"),
            Value::from("Research"),
        ),
        DirectoryOperation::at("replace", "externalId", Value::from("entra-pat-7")),
        DirectoryOperation::at("replace", "title", Value::from("Engineer")),
    ]);
    change(by_path).send(&linked).await.ok();
    let after_paths = read(&world, &linked, pat.id()).await;
    assert_eq!(
        after_paths
            .name
            .and_then(|name| name.family_name)
            .as_deref(),
        Some("Holder")
    );
    assert_eq!(after_paths.external_id.as_deref(), Some("entra-pat-7"));
    assert_eq!(
        after_paths
            .enterprise
            .and_then(|enterprise| enterprise.department)
            .as_deref(),
        Some("Research")
    );

    let pathless = DirectoryPatch::of(vec![DirectoryOperation::pathless(
        "replace",
        json!({
            "name.givenName": "Patricia",
            ENTERPRISE: {
                "employeeNumber": "701",
                "manager": { "value": uma.id() }
            }
        }),
    )]);
    change(pathless).send(&linked).await.ok();
    let after_object = read(&world, &linked, pat.id()).await;
    assert_eq!(
        after_object
            .name
            .and_then(|name| name.given_name)
            .as_deref(),
        Some("Patricia")
    );
    assert_eq!(
        after_object.enterprise,
        Some(DirectoryEnterprise {
            department: Some("Research".to_owned()),
            employee_number: Some("701".to_owned()),
            manager: Some(ManagerReference {
                value: uma.id().to_owned(),
            }),
        }),
        "the object changed only the fields it named"
    );

    let off = change(DirectoryPatch::one(
        "Replace",
        "active",
        Value::from("False"),
    ))
    .send(&linked)
    .await
    .ok();
    assert!(!off.active, "Entra's \"False\" switches Pat off");
    let on = change(DirectoryPatch::one(
        "Replace",
        "active",
        Value::from("True"),
    ))
    .send(&linked)
    .await
    .ok();
    assert!(on.active, "Entra's \"True\" lets Pat back in");

    let moved_to = world.address("pat.work");
    let seen = world.trail().ids().await;
    change(DirectoryPatch::one(
        "replace",
        "emails[type eq \"work\"].value",
        Value::from(moved_to.as_str()),
    ))
    .send(&linked)
    .await
    .ok();
    let seen_by_tess = people::get(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(seen_by_tess.email, moved_to);
    assert!(
        !seen_by_tess.email_verified,
        "the directory's word proves no new mailbox"
    );
    let moved = world.trail().recorded_after(&seen, EMAIL_CHANGED).await;
    assert_eq!(moved.details["user"]["id"], pat.id());

    stack.stop().await.expect("the stack stops cleanly");
}

/// The directory makes Pat with her whole record and Uma as her manager.
/// In one request it removes her own id, her given name, her department,
/// her manager, and also her user name, display name and switch. The
/// profile fields are cleared and her employee number stays; her address,
/// display name and account are untouched, since those cannot be removed.
/// A switch sent as "maybe" and a pathless change that is no object are
/// refused as values the endpoint cannot read, and a change to someone the
/// tenant does not hold is not found.
#[tokio::test]
async fn removing_a_field_clears_it_while_the_sign_in_address_stays() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let uma = made(&world, &linked, "uma").await;
    let pat = world.newcomer("pat", "Pat Holder");
    let record = DirectoryRecord {
        user_name: pat.email().to_owned(),
        display_name: Some("Pat Holder".to_owned()),
        name: Some(DirectoryName {
            formatted: None,
            given_name: Some("Pat".to_owned()),
            family_name: Some("Holder".to_owned()),
        }),
        external_id: Some("okta-pat-3003".to_owned()),
        enterprise: Some(DirectoryEnterprise {
            department: Some("Finance".to_owned()),
            employee_number: Some("E-3003".to_owned()),
            manager: Some(ManagerReference {
                value: uma.id().to_owned(),
            }),
        }),
        ..DirectoryRecord::default()
    };
    let pat_id = directory::create_record(world.tenant(), &record)
        .send(&linked)
        .await
        .ok()
        .id;

    let department = format!("{ENTERPRISE}:department");
    let manager = format!("{ENTERPRISE}:manager");
    let removals = DirectoryPatch::of(
        [
            "externalId",
            "name.givenName",
            department.as_str(),
            manager.as_str(),
            "userName",
            "displayName",
            "active",
        ]
        .into_iter()
        .map(|path| DirectoryOperation::at("remove", path, Value::Null))
        .collect(),
    );
    directory::patch_user(world.tenant(), &pat_id, &removals)
        .send(&linked)
        .await
        .ok();

    let kept = read(&world, &linked, &pat_id).await;
    assert_eq!(kept.external_id, None, "the directory's id is cleared");
    let name = kept.name.expect("Pat's name is kept");
    assert_eq!(name.given_name, None, "her given name is cleared");
    assert_eq!(name.family_name.as_deref(), Some("Holder"));
    assert_eq!(
        kept.enterprise,
        Some(DirectoryEnterprise {
            employee_number: Some("E-3003".to_owned()),
            ..DirectoryEnterprise::default()
        }),
        "only the fields removed are cleared"
    );
    assert_eq!(kept.user_name, pat.email(), "her address cannot be removed");
    assert_eq!(kept.display_name, "Pat Holder");
    assert!(kept.active, "her account cannot be removed by a patch");

    directory::patch_user(
        world.tenant(),
        &pat_id,
        &DirectoryPatch::one("replace", "active", Value::from("maybe")),
    )
    .send(&linked)
    .await
    .refused(Status::BAD_REQUEST, "invalidValue");
    directory::patch_user(
        world.tenant(),
        &pat_id,
        &DirectoryPatch::of(vec![DirectoryOperation::pathless(
            "replace",
            Value::from("Pat"),
        )]),
    )
    .send(&linked)
    .await
    .refused(Status::BAD_REQUEST, "invalidValue");
    let stranger = uuid::Uuid::now_v7().to_string();
    let missing = directory::patch_user(world.tenant(), &stranger, &DirectoryPatch::deactivation())
        .send(&linked)
        .await;
    assert_eq!(
        missing.status(),
        Status::NOT_FOUND,
        "nobody the tenant holds is changed: {}",
        missing.summary()
    );

    stack.stop().await.expect("the stack stops cleanly");
}
