//! What a tenant's messages look like: Tess registers an order-created
//! schema, adds a compatible version, and finds both on record. A version
//! that would break the schema's promise, a definition that is not JSON
//! and a second schema of the same name are refused and change nothing.
//! Only someone with the right touches a schema, and Sam reaches Acme's
//! schemas neither from outside nor from his own tenant.

use ianua_scenarios::api::messaging;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::messaging::{NewSchema, NewSchemaVersion};
use ianua_scenarios::world::World;

use crate::bus::refused_to_the_cast;
use crate::support::person;

/// The record a registered schema leaves.
const REGISTERED: &str = "messaging.schema_registered";

/// The record a new version leaves.
const EVOLVED: &str = "messaging.schema_evolved";

/// The record a deleted schema leaves.
const DELETED: &str = "messaging.schema_deleted";

/// What an order-created message must carry to begin with.
const FIRST_VERSION: &str =
    r#"{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}"#;

/// The same, adding an optional note: old messages still fit.
const OPTIONAL_NOTE: &str = concat!(
    r#"{"type":"object","properties":{"id":{"type":"string"},"#,
    r#""note":{"type":"string"}},"required":["id"]}"#
);

/// The same, no longer requiring `id`: a backward compatible schema keeps
/// every field it required.
const DROPS_REQUIRED_ID: &str =
    r#"{"type":"object","properties":{"id":{"type":"string"}},"required":[]}"#;

/// A schema held to backward compatibility, in JSON Schema form.
fn order_created() -> NewSchema {
    NewSchema {
        name: "Order created".to_owned(),
        schema_name: "order-created".to_owned(),
        format: "JsonSchema".to_owned(),
        compatibility: "Backward".to_owned(),
        definition: FIRST_VERSION.to_owned(),
    }
}

/// A new version with `definition`.
fn version(definition: &str) -> NewSchemaVersion {
    NewSchemaVersion {
        definition: definition.to_owned(),
    }
}

/// Tess registers the order-created schema, on record: version 1 is there
/// in the list and on its own page. She adds an optional note: version 2,
/// on record, and both are kept in order. A version no longer requiring
/// `id` is refused for dropping a required field, a definition that is
/// not JSON is no definition, and a second schema called order-created is
/// a conflict; none changes the versions. She deletes the schema, on
/// record, and it is gone from both places.
#[tokio::test]
async fn tess_registers_a_schema_and_adds_only_compatible_versions() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let seen = world.trail().ids().await;

    let schema_id = messaging::register_schema(world.tenant(), &order_created())
        .send(tess)
        .await
        .ok()
        .id;
    world.trail().recorded_after(&seen, REGISTERED).await;
    let listed = messaging::schemas(world.tenant()).send(tess).await.ok();
    let found = listed
        .items
        .iter()
        .find(|schema| schema.id == schema_id)
        .expect("the schema is among the tenant's");
    assert_eq!(found.schema_name, "order-created");
    assert_eq!(found.versions.len(), 1, "one version to begin with");

    let evolved = messaging::evolve_schema(world.tenant(), &schema_id, &version(OPTIONAL_NOTE))
        .send(tess)
        .await
        .ok();
    assert_eq!(evolved.version, 2);
    world.trail().recorded_after(&seen, EVOLVED).await;
    let read = messaging::schema(world.tenant(), &schema_id)
        .send(tess)
        .await
        .ok();
    assert_eq!(read.versions[0].version, 1, "oldest first");
    assert_eq!(read.versions[0].definition, FIRST_VERSION);
    assert_eq!(read.versions[1].version, 2);
    assert_eq!(read.versions[1].definition, OPTIONAL_NOTE);

    messaging::evolve_schema(world.tenant(), &schema_id, &version(DROPS_REQUIRED_ID))
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    messaging::evolve_schema(world.tenant(), &schema_id, &version("not json at all"))
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    messaging::register_schema(world.tenant(), &order_created())
        .send(tess)
        .await
        .refused(Status::CONFLICT, "conflict");
    let unchanged = messaging::schema(world.tenant(), &schema_id)
        .send(tess)
        .await
        .ok();
    assert_eq!(unchanged.versions.len(), 2, "the refusals added nothing");

    messaging::delete_schema(world.tenant(), &schema_id)
        .send(tess)
        .await
        .ok();
    world.trail().recorded_after(&seen, DELETED).await;
    messaging::schema(world.tenant(), &schema_id)
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let remaining = messaging::schemas(world.tenant()).send(tess).await.ok();
    assert!(
        remaining.items.iter().all(|schema| schema.id != schema_id),
        "the deleted schema is gone from the list"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma, an ordinary user of the tenant, Max, a member with no
/// administrator's rights, Sam from the other company and nobody signed
/// in cannot read the schemas, register one, add a version or delete it.
/// In his own tenant Sam still finds no schema at Tess's id: it is not
/// his, and an id tells him nothing. Nothing they tried is on record, and
/// Tess's schema keeps its one version.
#[tokio::test]
async fn nobody_without_the_right_touches_a_schema() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let uma = person(&world, "uma").await;
    let schema_id = messaging::register_schema(world.tenant(), &order_created())
        .send(tess)
        .await
        .ok()
        .id;
    let seen = world.trail().ids().await;

    for call in [
        messaging::schemas(world.tenant()).call(),
        messaging::schema(world.tenant(), &schema_id).call(),
        messaging::register_schema(world.tenant(), &order_created()).call(),
        messaging::evolve_schema(world.tenant(), &schema_id, &version(OPTIONAL_NOTE)).call(),
        messaging::delete_schema(world.tenant(), &schema_id).call(),
    ] {
        refused_to_the_cast(&world, &uma, "managing the order-created schema", call).await;
    }

    for call in [
        messaging::schema(world.twin(), &schema_id).call(),
        messaging::evolve_schema(world.twin(), &schema_id, &version(OPTIONAL_NOTE)).call(),
        messaging::delete_schema(world.twin(), &schema_id).call(),
    ] {
        Matrix::new("reaching Acme's schema from the other tenant", call)
            .refused(world.stranger().client(), Status::NOT_FOUND, "not_found")
            .run()
            .await;
    }

    let read = messaging::schema(world.tenant(), &schema_id)
        .send(tess)
        .await
        .ok();
    assert_eq!(read.versions.len(), 1, "no version was added");
    world.trail().nothing_after(&seen, EVOLVED).await;
    world.trail().nothing_after(&seen, DELETED).await;

    stack.stop().await.expect("the stack stops cleanly");
}
