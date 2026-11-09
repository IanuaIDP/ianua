//! The group writes a directory cannot make: each is refused in SCIM's
//! own terms and changes nothing.

use ianua_scenarios::api::directory;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::directory::{
    DirectoryGroup, DirectoryMember, DirectoryPatch, DirectorySearch,
};
use ianua_scenarios::world::World;
use serde_json::{Value, json};

use crate::support::{OnRemove, linked_directory};

/// A group named `name` holding `members`.
fn group(name: &str, members: Vec<DirectoryMember>) -> DirectoryGroup {
    DirectoryGroup {
        display_name: name.to_owned(),
        members,
    }
}

/// A member reference for an id.
fn member(value: String) -> DirectoryMember {
    DirectoryMember { value }
}

/// The directory makes Finance. A second Finance is refused as a taken
/// name; a group with no name, a member that is no user id and a member
/// who is nobody in the tenant are refused as values it cannot keep; and
/// so is one more member than the endpoint's own published limit, as too
/// many. Asking groups in an order is refused, since they are listed in
/// one. Finance's own patch refuses a name that is no text and a member
/// path that is not `value eq`. A group the tenant does not hold is not
/// found for reading, patching, replacing or deleting.
#[tokio::test]
async fn group_writes_the_directory_cannot_make_are_refused() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let finance = directory::create_group(world.tenant(), &group("Finance", vec![]))
        .send(&linked)
        .await
        .ok();
    let create = |body: DirectoryGroup| directory::create_group(world.tenant(), &body);

    create(group("Finance", vec![]))
        .send(&linked)
        .await
        .refused(Status::CONFLICT, "uniqueness");
    create(group("   ", vec![]))
        .send(&linked)
        .await
        .refused(Status::BAD_REQUEST, "invalidValue");
    create(group("Ghosts", vec![member("not-a-user-id".to_owned())]))
        .send(&linked)
        .await
        .refused(Status::BAD_REQUEST, "invalidValue");
    create(group(
        "Ghosts",
        vec![member(uuid::Uuid::now_v7().to_string())],
    ))
    .send(&linked)
    .await
    .refused(Status::BAD_REQUEST, "invalidValue");

    let most = directory::abilities(world.tenant())
        .send(&linked)
        .await
        .ok()
        .limits
        .max_members_per_operation;
    let crowd = (0..=most)
        .map(|_| member(uuid::Uuid::now_v7().to_string()))
        .collect();
    create(group("Crowd", crowd))
        .send(&linked)
        .await
        .refused(Status::BAD_REQUEST, "tooMany");

    let ordered = DirectorySearch {
        sort_by: Some("displayName".to_owned()),
        ..DirectorySearch::default()
    };
    directory::search_groups(world.tenant(), &ordered)
        .send(&linked)
        .await
        .refused(Status::BAD_REQUEST, "invalidValue");

    directory::patch_group(
        world.tenant(),
        &finance.id,
        &DirectoryPatch::one("replace", "displayName", json!(["Treasury"])),
    )
    .send(&linked)
    .await
    .refused(Status::BAD_REQUEST, "invalidValue");
    directory::patch_group(
        world.tenant(),
        &finance.id,
        &DirectoryPatch::one("remove", "members[value gt \"a\"]", Value::Null),
    )
    .send(&linked)
    .await
    .refused(Status::BAD_REQUEST, "invalidFilter");

    let nothing = uuid::Uuid::now_v7().to_string();
    let read = directory::get_group(world.tenant(), &nothing)
        .send(&linked)
        .await;
    assert_eq!(read.status(), Status::NOT_FOUND, "{}", read.summary());
    let patched = directory::patch_group(
        world.tenant(),
        &nothing,
        &DirectoryPatch::one("replace", "displayName", Value::from("Nope")),
    )
    .send(&linked)
    .await;
    assert_eq!(patched.status(), Status::NOT_FOUND, "{}", patched.summary());
    let replaced = directory::replace_group(world.tenant(), &nothing, &group("Nope", vec![]))
        .send(&linked)
        .await;
    assert_eq!(
        replaced.status(),
        Status::NOT_FOUND,
        "{}",
        replaced.summary()
    );
    let deleted = directory::delete_group(world.tenant(), &nothing)
        .send(&linked)
        .await;
    assert_eq!(deleted.status(), Status::NOT_FOUND, "{}", deleted.summary());

    stack.stop().await.expect("the stack stops cleanly");
}
