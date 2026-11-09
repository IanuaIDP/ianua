//! What a company's directory reads before it provisions anyone: the
//! endpoint's abilities, the kinds of record it keeps and their
//! attributes, all public, and `/Me`, which a directory token cannot
//! answer.

use ianua_scenarios::api::{directory, people};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::directory::DirectoryUser;
use ianua_scenarios::world::World;

use crate::support::{OnRemove, linked_directory};

/// The schema a user record follows.
const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";

/// The schema a group record follows.
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

/// The schema of the abilities document itself.
const ABILITIES_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";

/// The media type every SCIM answer carries.
const SCIM_JSON: &str = "application/scim+json";

/// Before Tess hands over any token, the directory's setup reads what the
/// endpoint offers, as anyone may: changes sent as patches and filtered
/// searches, but no bulk requests and no password changes; the tenant's
/// bearer token as the one way in; and a limit on members per group
/// write. It reads that users live at `/Users` and groups at `/Groups`,
/// and that a user must carry a `userName` and a group a `displayName`.
/// Linked, the directory makes Pat where it was pointed, and Tess finds
/// her among the tenant's users.
#[tokio::test]
async fn the_directory_reads_what_the_endpoint_offers_then_provisions_pat() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let setup = world.anonymous().client();

    let offered = directory::abilities(world.tenant()).send(setup).await.ok();
    assert!(
        offered
            .schemas
            .iter()
            .any(|schema| schema == ABILITIES_SCHEMA)
    );
    assert!(offered.patch.supported, "changes may be sent as patches");
    assert!(offered.filter.supported, "people may be found by a filter");
    assert!(!offered.bulk.supported, "bulk requests are not offered");
    assert!(
        !offered.change_password.supported,
        "no password is set through the directory"
    );
    assert!(
        offered
            .authentication_schemes
            .iter()
            .any(|scheme| scheme.kind == "oauthbearertoken" && scheme.primary),
        "the tenant's bearer token is the way in"
    );
    assert!(offered.limits.max_members_per_operation >= 1);

    let kinds = directory::resource_types(world.tenant())
        .send(setup)
        .await
        .ok();
    assert_eq!(kinds.total_results, 2, "users and groups");
    let users = kinds.resources.iter().find(|kind| kind.name == "User");
    assert!(users.is_some_and(|kind| kind.endpoint == "/Users" && kind.schema == USER_SCHEMA));
    let groups = kinds.resources.iter().find(|kind| kind.name == "Group");
    assert!(groups.is_some_and(|kind| kind.endpoint == "/Groups" && kind.schema == GROUP_SCHEMA));

    let schemas = directory::schemas(world.tenant()).send(setup).await.ok();
    let required = |id: &str, attribute: &str| {
        schemas
            .resources
            .iter()
            .find(|schema| schema.id == id)
            .and_then(|schema| schema.attributes.iter().find(|a| a.name == attribute))
            .is_some_and(|a| a.required)
    };
    assert!(required(USER_SCHEMA, "userName"), "a user needs a userName");
    assert!(
        required(GROUP_SCHEMA, "displayName"),
        "a group needs a displayName"
    );

    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let pat = world.newcomer("pat", "Pat Discovered");
    let user = DirectoryUser {
        user_name: pat.email().to_owned(),
        display_name: pat.account().display_name.clone(),
        active: true,
        external_id: "external-pat-discovered".to_owned(),
    };
    directory::create_user(world.tenant(), &user)
        .send(&linked)
        .await
        .ok();
    let found = people::list(world.tenant(), Some(pat.email()))
        .send(world.admin().client())
        .await
        .ok();
    assert!(
        found.items.iter().any(|person| person.email == pat.email()),
        "Tess finds Pat among the tenant's users"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The linked directory asks `/Me` who it is and is told, in SCIM's own
/// error format, that the endpoint does not offer it: its token names the
/// directory, not a person. Nobody signed in is told the same.
#[tokio::test]
async fn me_is_not_offered_to_the_directory_or_anyone() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;

    for asker in [&linked, world.anonymous().client()] {
        let answer = directory::me(world.tenant()).send(asker).await;
        assert_eq!(
            answer.status(),
            Status::NOT_IMPLEMENTED,
            "/Me is not offered: {}",
            answer.summary()
        );
        assert!(
            answer
                .header("content-type")
                .is_some_and(|kind| kind.starts_with(SCIM_JSON)),
            "the refusal is in SCIM's format"
        );
    }

    stack.stop().await.expect("the stack stops cleanly");
}
