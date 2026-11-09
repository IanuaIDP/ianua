//! The people a directory keeps in the tenant: their records follow its
//! changes, a new address is never taken as proved, its search finds them,
//! and its deactivation, reactivation and removal decide who signs in.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{directory, people, sessions};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::directory::{DirectoryPatch, DirectoryUser};
use ianua_scenarios::wire::tenant_sign_in::TenantPasswordSignIn;
use ianua_scenarios::world::World;
use serde_json::Value;

use crate::support::{
    OWN_PASSWORD, OnRemove, linked_directory, made, proved_mailbox, removals_set, settled_in,
};

/// The directory makes Pat, who proves her mailbox. It renames her, and
/// Tess reads the new name. It moves her to a new address: Tess reads the
/// new address, no longer proved, since the directory's word proves no
/// mailbox. The directory's search finds her by the new address and
/// nobody by the old one, and it may not make a second person at her
/// address.
#[tokio::test]
async fn the_directory_renames_and_readdresses_pat_without_proving_her_new_mailbox() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let pat = made(&world, &linked, "pat").await;
    proved_mailbox(&world, pat.email()).await;
    rename_pat(&world, &linked, &pat).await;
    let moved_to = world.address("pat.moved");
    move_pat(&world, &linked, &pat, &moved_to).await;
    assert_directory_search(&world, &linked, &pat, &moved_to).await;
    refuse_duplicate_person(&world, &linked, &moved_to).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Renaming Pat preserves the proof of her existing mailbox.
async fn rename_pat(world: &World<'_>, linked: &Client, pat: &Person) {
    directory::patch_user(
        world.tenant(),
        pat.id(),
        &DirectoryPatch::one("replace", "displayName", Value::from("Pat Renamed")),
    )
    .send(linked)
    .await
    .ok();
    let renamed = people::get(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(renamed.display_name, "Pat Renamed");
    assert!(renamed.email_verified, "Pat's own proof still stands");
}

/// Changing Pat's address through SCIM does not prove the replacement mailbox.
async fn move_pat(world: &World<'_>, linked: &Client, pat: &Person, moved_to: &str) {
    directory::patch_user(
        world.tenant(),
        pat.id(),
        &DirectoryPatch::one("replace", "userName", Value::from(moved_to)),
    )
    .send(linked)
    .await
    .ok();
    let moved = people::get(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(moved.email, moved_to);
    assert!(
        !moved.email_verified,
        "the directory's word proves no new mailbox"
    );
}

/// SCIM search finds Pat only at the replacement address.
async fn assert_directory_search(world: &World<'_>, linked: &Client, pat: &Person, moved_to: &str) {
    let found = directory::find_users(world.tenant(), &format!("userName eq \"{moved_to}\""))
        .send(linked)
        .await
        .ok();
    assert_eq!(
        found.total_results, 1,
        "the search finds Pat at her new address"
    );
    assert_eq!(found.resources[0].id, pat.id());
    let gone = directory::find_users(world.tenant(), &format!("userName eq \"{}\"", pat.email()))
        .send(linked)
        .await
        .ok();
    assert_eq!(gone.total_results, 0, "nobody is at her old address");
}

/// Creating a second person at Pat's replacement address is refused.
async fn refuse_duplicate_person(world: &World<'_>, linked: &Client, moved_to: &str) {
    let twin = DirectoryUser {
        user_name: moved_to.to_owned(),
        display_name: "Pat's Twin".to_owned(),
        active: true,
        external_id: "external-twin".to_owned(),
    };
    let refused = directory::create_user(world.tenant(), &twin)
        .send(linked)
        .await;
    assert_eq!(
        refused.status(),
        Status::CONFLICT,
        "a second person at Pat's address is refused: {}",
        refused.summary()
    );
}

/// The directory makes Pat, who settles in and signs in. The directory
/// deactivates her: her session is dead and her password signs her in no
/// more. It lets her back in: her password signs her in again.
#[tokio::test]
async fn a_deactivated_pat_signs_in_again_only_once_the_directory_lets_her_back() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let mut pat = made(&world, &linked, "pat").await;
    settled_in(&world, &mut pat).await;
    deactivate_pat(&world, &linked, &pat).await;
    directory::patch_user(world.tenant(), pat.id(), &DirectoryPatch::reactivation())
        .send(&linked)
        .await
        .ok();
    pat.sign_in(&stack).await;
    people::me(world.tenant()).send(pat.client()).await.ok();
    stack.stop().await.expect("the stack stops cleanly");
}

/// SCIM deactivation revokes Pat's session and prevents password sign-in.
async fn deactivate_pat(world: &World<'_>, linked: &Client, pat: &Person) {
    directory::patch_user(world.tenant(), pat.id(), &DirectoryPatch::deactivation())
        .send(linked)
        .await
        .ok();
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let attempt = TenantPasswordSignIn {
        email: pat.email().to_owned(),
        password: OWN_PASSWORD.to_owned(),
        fingerprint_hash: None,
    };
    let refused = sessions::sign_in(world.tenant(), &attempt)
        .send(world.anonymous().client())
        .await;
    assert!(
        !refused.status().is_success(),
        "a deactivated Pat's password signs her in no more: {}",
        refused.summary()
    );
}

/// Tess has the people the directory removes kept: it removes Uma, and
/// Tess still reads her, deactivated. Tess has them deleted instead: it removes
/// Quinn, and neither Tess nor the directory finds him any more.
#[tokio::test]
async fn a_person_the_directory_removes_is_kept_or_deleted_as_tess_set_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    assert_deactivated_retained(&world, &linked).await;
    assert_deleted_absent(&world, &linked).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// The deactivation removal policy keeps Uma's record with deactivated status.
async fn assert_deactivated_retained(world: &World<'_>, linked: &Client) {
    let uma = made(world, linked, "uma").await;
    directory::delete_user(world.tenant(), uma.id())
        .send(linked)
        .await
        .ok();
    let kept = people::get(world.tenant(), uma.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(kept.status, "Deactivated", "Uma is kept, deactivated");
}

/// The delete removal policy hides Quinn from both administration and SCIM reads.
async fn assert_deleted_absent(world: &World<'_>, linked: &Client) {
    removals_set(world, OnRemove::Delete).await;
    let quinn = made(world, linked, "quinn").await;
    directory::delete_user(world.tenant(), quinn.id())
        .send(linked)
        .await
        .ok();
    let tess_reads = people::get(world.tenant(), quinn.id())
        .send(world.admin().client())
        .await;
    assert_eq!(
        tess_reads.status(),
        Status::NOT_FOUND,
        "Quinn is deleted: {}",
        tess_reads.summary()
    );
    let directory_reads = directory::get_user(world.tenant(), quinn.id())
        .send(linked)
        .await;
    assert_eq!(directory_reads.status(), Status::NOT_FOUND);
}
