//! The life of one group the directory keeps: what it writes, what it
//! reads back, how it finds the group, and the record each change leaves.

use ianua_scenarios::api::directory;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::directory::{
    DirectoryGroup, DirectoryMember, DirectoryOperation, DirectoryPatch, DirectorySearch,
};
use ianua_scenarios::world::World;
use serde_json::{Value, json};

use crate::support::{OnRemove, linked_directory, made};

/// The directory's reference to the member `id`.
fn member(id: &str) -> DirectoryMember {
    DirectoryMember {
        value: id.to_owned(),
    }
}

/// The ids in the group `group_id`, sorted, as the directory reads them.
async fn members_of(world: &World<'_>, linked: &Client, group_id: &str) -> Vec<String> {
    let group = directory::get_group(world.tenant(), group_id)
        .send(linked)
        .await
        .ok();
    let mut ids: Vec<String> = group.members.into_iter().map(|one| one.value).collect();
    ids.sort();
    ids
}

/// How many groups `filter` finds.
async fn matching(world: &World<'_>, linked: &Client, filter: &str) -> u64 {
    let search = DirectorySearch {
        filter: Some(filter.to_owned()),
        ..DirectorySearch::default()
    };
    directory::search_groups(world.tenant(), &search)
        .send(linked)
        .await
        .ok()
        .total_results
}

/// The directory makes Finance with Pat in it and reads it back, told its
/// version is current when it holds it. It finds the group by the whole
/// name and by a start of it; a comparison on an attribute groups do not
/// have finds nothing. It adds Uma, and the version it held is stale. It
/// renames the group Treasury, and the old name finds nobody. It replaces
/// the members with Uma alone, removes Uma, and at last replaces the whole
/// group with its old name and Pat. Then it deletes it: reading it is not
/// found. The trail holds the group's making, its renaming, each member's
/// joining and leaving, and its deletion.
#[tokio::test]
async fn the_directory_keeps_finance_through_its_whole_life() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let pat = made(&world, &linked, "pat").await;
    let uma = made(&world, &linked, "uma").await;

    let created = directory::create_group(
        world.tenant(),
        &DirectoryGroup {
            display_name: "Finance".to_owned(),
            members: vec![member(pat.id())],
        },
    )
    .send(&linked)
    .await;
    assert_eq!(created.status(), Status::CREATED, "{}", created.summary());
    let finance = created.ok();
    assert_eq!(finance.display_name, "Finance");
    assert_eq!(finance.members, [member(pat.id())]);
    assert_eq!(
        finance.meta.map(|meta| meta.resource_type).as_deref(),
        Some("Group")
    );
    let read = directory::get_group(world.tenant(), &finance.id)
        .send(&linked)
        .await;
    let version = read
        .header("etag")
        .expect("the group is sent with its version")
        .to_owned();
    let unchanged = directory::get_group(world.tenant(), &finance.id)
        .header("if-none-match", &version)
        .send(&linked)
        .await;
    assert_eq!(unchanged.status(), Status::NOT_MODIFIED);

    assert_eq!(
        matching(&world, &linked, "displayName eq \"finance\"").await,
        1,
        "a name compares without its letter case"
    );
    assert_eq!(matching(&world, &linked, "displayName sw \"Fin\"").await, 1);
    assert_eq!(
        matching(&world, &linked, "owner eq \"Tess\"").await,
        0,
        "an attribute groups do not have finds nothing"
    );

    let add_uma = DirectoryPatch::one("add", "members", json!([{ "value": uma.id() }]));
    directory::patch_group(world.tenant(), &finance.id, &add_uma)
        .send(&linked)
        .await
        .ok();
    let stale = directory::get_group(world.tenant(), &finance.id)
        .header("if-none-match", &version)
        .send(&linked)
        .await;
    assert_eq!(stale.status(), Status::OK, "a new member is a new version");
    let mut both = [pat.id().to_owned(), uma.id().to_owned()];
    both.sort();
    assert_eq!(members_of(&world, &linked, &finance.id).await, both);

    directory::patch_group(
        world.tenant(),
        &finance.id,
        &DirectoryPatch::one("replace", "displayName", Value::from("Treasury")),
    )
    .send(&linked)
    .await
    .ok();
    assert_eq!(
        matching(&world, &linked, "displayName eq \"Finance\"").await,
        0
    );
    assert_eq!(
        matching(&world, &linked, "displayName eq \"Treasury\"").await,
        1
    );

    let only_uma = DirectoryPatch::of(vec![DirectoryOperation::at(
        "replace",
        "members",
        json!([{ "value": uma.id() }]),
    )]);
    directory::patch_group(world.tenant(), &finance.id, &only_uma)
        .send(&linked)
        .await
        .ok();
    assert_eq!(
        members_of(&world, &linked, &finance.id).await,
        [uma.id()],
        "replace keeps only the members it names"
    );

    let without_uma = DirectoryPatch::one("remove", "members", json!([{ "value": uma.id() }]));
    directory::patch_group(world.tenant(), &finance.id, &without_uma)
        .send(&linked)
        .await
        .ok();
    assert!(
        members_of(&world, &linked, &finance.id).await.is_empty(),
        "the group is empty"
    );

    let whole = directory::replace_group(
        world.tenant(),
        &finance.id,
        &DirectoryGroup {
            display_name: "Finance".to_owned(),
            members: vec![member(pat.id())],
        },
    )
    .send(&linked)
    .await
    .ok();
    assert_eq!(whole.display_name, "Finance");
    assert_eq!(whole.members, [member(pat.id())]);

    directory::delete_group(world.tenant(), &finance.id)
        .send(&linked)
        .await
        .ok();
    let gone = directory::get_group(world.tenant(), &finance.id)
        .send(&linked)
        .await;
    assert_eq!(gone.status(), Status::NOT_FOUND, "{}", gone.summary());

    for event in [
        "authorization.group_created",
        "authorization.group_renamed",
        "authorization.group_member_added",
        "authorization.group_member_removed",
        "authorization.group_deleted",
    ] {
        world.trail().recorded(event).await;
    }

    stack.stop().await.expect("the stack stops cleanly");
}
