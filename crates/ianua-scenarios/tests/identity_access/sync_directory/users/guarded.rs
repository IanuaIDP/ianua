//! The accounts a directory may never move: someone who holds the
//! tenant's built-in permissions stays at their address and is not let
//! back in by the directory's word, and when the directory removes them
//! they are switched off, never deleted, so a leaked token cannot erase
//! the tenant's administrators.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{directory, people, roles};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::directory::{DirectoryPatch, DirectoryRecord};
use ianua_scenarios::wire::roles::AssignRole;
use ianua_scenarios::world::{ADMIN_ROLE, World};
use serde_json::Value;

use super::read;
use crate::support::{OnRemove, linked_directory, made, removals_set};

/// Someone the directory made, then given the `Admin` role by Tess.
async fn made_administrator(world: &World<'_>, linked: &Client, name: &str) -> Person {
    let person = made(world, linked, name).await;
    let admin = world.role_id(ADMIN_ROLE).await;
    roles::assign(
        world.tenant(),
        &admin,
        &AssignRole {
            user_id: person.id().to_owned(),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    person
}

/// The directory makes Pat, Uma and Quinn, and Tess gives each the Admin
/// role, so the tenant has administrators to spare. Mallory holds the
/// directory's leaked token: moving Pat to her own mailbox is refused, by
/// a patch and by a replaced record, so no reset link can reach her. The
/// directory may switch Pat off, and does, but may not let her back in.
/// Tess has removed people deleted; the directory removes Uma all the
/// same, and Tess still reads her, deactivated, for someone to put right.
#[tokio::test]
async fn the_directory_never_moves_an_administrator_or_lets_one_back_in() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let pat = made_administrator(&world, &linked, "pat").await;
    let uma = made_administrator(&world, &linked, "uma").await;
    made_administrator(&world, &linked, "quinn").await;
    let mallorys_mailbox = world.address("mallory");

    let by_patch = directory::patch_user(
        world.tenant(),
        pat.id(),
        &DirectoryPatch::one(
            "replace",
            "userName",
            Value::from(mallorys_mailbox.as_str()),
        ),
    )
    .send(&linked)
    .await;
    assert_eq!(
        by_patch.status(),
        Status::FORBIDDEN,
        "an administrator is not moved by a patch: {}",
        by_patch.summary()
    );
    let by_record = directory::replace_user(
        world.tenant(),
        pat.id(),
        &DirectoryRecord {
            user_name: mallorys_mailbox.clone(),
            ..DirectoryRecord::default()
        },
    )
    .send(&linked)
    .await;
    assert_eq!(
        by_record.status(),
        Status::FORBIDDEN,
        "an administrator is not moved by a replaced record: {}",
        by_record.summary()
    );
    assert_eq!(
        read(&world, &linked, pat.id()).await.user_name,
        pat.email(),
        "Pat stays at her own address"
    );

    directory::patch_user(world.tenant(), pat.id(), &DirectoryPatch::deactivation())
        .send(&linked)
        .await
        .ok();
    let let_in = directory::patch_user(world.tenant(), pat.id(), &DirectoryPatch::reactivation())
        .send(&linked)
        .await;
    assert_eq!(
        let_in.status(),
        Status::FORBIDDEN,
        "only a person lets an administrator back in: {}",
        let_in.summary()
    );
    let pat_now = people::get(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(pat_now.status, "Locked", "Pat stays switched off");

    removals_set(&world, OnRemove::Delete).await;
    directory::delete_user(world.tenant(), uma.id())
        .send(&linked)
        .await
        .ok();
    let uma_now = people::get(world.tenant(), uma.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(
        uma_now.status, "Deactivated",
        "an administrator removed is switched off, never deleted"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
