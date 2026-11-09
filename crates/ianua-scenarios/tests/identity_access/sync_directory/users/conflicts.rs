//! Which records clash: an address is one person's alone, whatever its
//! letter case and however the directory asks, while the directory's own
//! id for someone is its own business and may repeat.

use ianua_scenarios::api::directory;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::directory::{DirectoryPatch, DirectoryRecord, DirectoryUser};
use ianua_scenarios::world::World;
use serde_json::Value;

use super::read;
use crate::support::{OnRemove, linked_directory, made};

/// The audit record a moved sign-in address leaves.
const EMAIL_CHANGED: &str = "identity.email_changed";

/// The directory makes Pat and Uma. A new person at Pat's address in
/// capitals is refused as a clash, and so are moving Uma onto Pat's
/// address by a patch and by a replaced record. Uma and Pat keep their
/// addresses and no move is recorded.
#[tokio::test]
async fn an_address_is_one_persons_alone_however_the_directory_asks() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let pat = made(&world, &linked, "pat").await;
    let uma = made(&world, &linked, "uma").await;
    let seen = world.trail().ids().await;
    let shouted = pat.email().to_ascii_uppercase();

    directory::create_record(
        world.tenant(),
        &DirectoryRecord {
            user_name: shouted.clone(),
            ..DirectoryRecord::default()
        },
    )
    .send(&linked)
    .await
    .refused(Status::CONFLICT, "uniqueness");

    directory::patch_user(
        world.tenant(),
        uma.id(),
        &DirectoryPatch::one("replace", "userName", Value::from(shouted.as_str())),
    )
    .send(&linked)
    .await
    .refused(Status::CONFLICT, "uniqueness");

    directory::replace_user(
        world.tenant(),
        uma.id(),
        &DirectoryRecord {
            user_name: pat.email().to_owned(),
            ..DirectoryRecord::default()
        },
    )
    .send(&linked)
    .await
    .refused(Status::CONFLICT, "uniqueness");

    assert_eq!(
        read(&world, &linked, uma.id()).await.user_name,
        uma.email(),
        "Uma stays where she was"
    );
    assert_eq!(
        read(&world, &linked, pat.id()).await.user_name,
        pat.email(),
        "Pat keeps her address"
    );
    world.trail().nothing_after(&seen, EMAIL_CHANGED).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The endpoint says the directory's own id need not be unique, and means
/// it: the directory makes Pat and Uma under the same one, and a search by
/// it finds them both, as long as it is spelled in the same letter case.
#[tokio::test]
async fn two_people_may_share_the_directorys_own_id() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let shared_id = "HR-RECORD-7";
    for name in ["pat", "uma"] {
        let person = world.newcomer(name, &format!("{name} Shared"));
        directory::create_user(
            world.tenant(),
            &DirectoryUser {
                user_name: person.email().to_owned(),
                display_name: person.account().display_name.clone(),
                active: true,
                external_id: shared_id.to_owned(),
            },
        )
        .send(&linked)
        .await
        .ok();
    }

    let both = directory::find_users(world.tenant(), &format!("externalId eq \"{shared_id}\""))
        .send(&linked)
        .await
        .ok();
    assert_eq!(both.total_results, 2, "both people carry the id");
    let neither = directory::find_users(
        world.tenant(),
        &format!("externalId eq \"{}\"", shared_id.to_ascii_lowercase()),
    )
    .send(&linked)
    .await
    .ok();
    assert_eq!(neither.total_results, 0, "the id compares with its case");

    stack.stop().await.expect("the stack stops cleanly");
}
