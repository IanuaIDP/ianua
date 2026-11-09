//! The groups a person keeps in the dashboard are not the directory's:
//! it does not see them, cannot change them, and cannot take their names.

use ianua_scenarios::api::{directory, policies};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::directory::{DirectoryGroup, DirectoryPatch, DirectorySearch};
use ianua_scenarios::wire::policies::NewGroup;
use ianua_scenarios::world::World;
use serde_json::Value;

use crate::support::{OnRemove, linked_directory};

/// Tess keeps Project Atlas in the dashboard. The directory's listing
/// does not show it, and reading, patching, replacing or deleting it by
/// its id is not found, so a leaked token cannot rewrite who is in it.
/// The directory cannot make a group of the same name, and Tess still
/// reads hers.
#[tokio::test]
async fn the_directory_cannot_see_or_touch_a_group_tess_keeps() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let atlas = policies::create_group(
        world.tenant(),
        &NewGroup {
            name: "Project Atlas".to_owned(),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    let same_name = DirectoryGroup {
        display_name: "Project Atlas".to_owned(),
        members: vec![],
    };

    let listing = directory::search_groups(world.tenant(), &DirectorySearch::default())
        .send(&linked)
        .await
        .ok();
    assert!(
        listing.resources.iter().all(|group| group.id != atlas.id),
        "the directory lists only what it keeps"
    );
    let read = directory::get_group(world.tenant(), &atlas.id)
        .send(&linked)
        .await;
    assert_eq!(read.status(), Status::NOT_FOUND, "{}", read.summary());
    let patched = directory::patch_group(
        world.tenant(),
        &atlas.id,
        &DirectoryPatch::one("replace", "displayName", Value::from("Atlas Renamed")),
    )
    .send(&linked)
    .await;
    assert_eq!(patched.status(), Status::NOT_FOUND, "{}", patched.summary());
    let replaced = directory::replace_group(world.tenant(), &atlas.id, &same_name)
        .send(&linked)
        .await;
    assert_eq!(
        replaced.status(),
        Status::NOT_FOUND,
        "{}",
        replaced.summary()
    );
    let deleted = directory::delete_group(world.tenant(), &atlas.id)
        .send(&linked)
        .await;
    assert_eq!(deleted.status(), Status::NOT_FOUND, "{}", deleted.summary());

    directory::create_group(world.tenant(), &same_name)
        .send(&linked)
        .await
        .refused(Status::CONFLICT, "uniqueness");
    policies::members(world.tenant(), &atlas.id)
        .send(world.admin().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}
