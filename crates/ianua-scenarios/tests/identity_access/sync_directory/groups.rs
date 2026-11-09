//! The groups a directory keeps in the tenant, and the access they carry:
//! a person holds what their group's role allows only while the directory
//! keeps them in it.

use std::time::Duration;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{directory, people, policies, roles};
use ianua_scenarios::expect::{Waiting, eventually_paced};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::directory::{DirectoryGroup, DirectoryMember, DirectoryPatch};
use ianua_scenarios::wire::policies::GroupRole;
use ianua_scenarios::wire::roles::{NewRole, SystemPermission};
use ianua_scenarios::world::World;
use serde_json::Value;

use crate::support::{OnRemove, linked_directory, made, settled_in};

/// How long a change to Pat's groups is given to reach her requests,
/// asked once a second as a person refreshing a page would.
const UNTIL_IT_HOLDS: Waiting = Waiting {
    patience: Duration::from_secs(30),
    every: Duration::from_secs(1),
};

/// The directory makes Pat, who settles in; as a plain member she may not
/// read the tenant's people. The directory makes the Finance group with
/// Pat in it, and Tess gives the group a role that reads people: Pat reads
/// them. The directory takes Pat out of the group, and she may not any
/// more. It puts her back and then deletes the group, and she may not
/// again.
#[tokio::test]
async fn pat_holds_her_directory_groups_access_only_while_she_is_in_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let mut pat = made(&world, &linked, "pat").await;
    settled_in(&world, &mut pat).await;
    let reads_people = people::list(world.tenant(), None);
    reads_people
        .clone()
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let finance = create_finance(&world, &linked, &pat).await;
    grant_readers(&world, &finance).await;
    eventually_paced(
        "Pat to read people through Finance",
        UNTIL_IT_HOLDS,
        || async {
            let read = reads_people.clone().send(pat.client()).await;
            read.status().is_success().then_some(())
        },
    )
    .await;
    remove_pat(&world, &linked, &pat, &finance).await;
    delete_finance(&world, &linked, &pat, &finance).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// The directory creates Finance with Pat as its initial member.
async fn create_finance(world: &World<'_>, linked: &Client, pat: &Person) -> String {
    let finance = directory::create_group(
        world.tenant(),
        &DirectoryGroup {
            display_name: "Finance".to_owned(),
            members: vec![DirectoryMember {
                value: pat.id().to_owned(),
            }],
        },
    )
    .send(linked)
    .await
    .ok();
    finance.id
}

/// Tess gives Finance a role that can read the tenant's people.
async fn grant_readers(world: &World<'_>, finance: &str) {
    let readers = roles::create(
        world.tenant(),
        &NewRole {
            name: "People readers".to_owned(),
            system_permissions: vec![SystemPermission::new("Users", "View")],
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    policies::grant_group_role(
        world.tenant(),
        finance,
        &GroupRole {
            role_id: readers.id,
        },
    )
    .send(world.admin().client())
    .await
    .ok();
}

/// Removing Pat from Finance withdraws her group's read permission.
async fn remove_pat(world: &World<'_>, linked: &Client, pat: &Person, finance: &str) {
    let without_pat = DirectoryPatch::one(
        "remove",
        &format!("members[value eq \"{}\"]", pat.id()),
        Value::Null,
    );
    directory::patch_group(world.tenant(), finance, &without_pat)
        .send(linked)
        .await
        .ok();
    let reads_people = people::list(world.tenant(), None);
    refused_in_time(&reads_people, pat, "out of Finance").await;
}

/// Restoring membership grants access again until the directory deletes Finance.
async fn delete_finance(world: &World<'_>, linked: &Client, pat: &Person, finance: &str) {
    let with_pat =
        DirectoryPatch::one("add", "members", serde_json::json!([{ "value": pat.id() }]));
    directory::patch_group(world.tenant(), finance, &with_pat)
        .send(linked)
        .await
        .ok();
    let reads_people = people::list(world.tenant(), None);
    eventually_paced("Pat to read people again", UNTIL_IT_HOLDS, || async {
        let read = reads_people.clone().send(pat.client()).await;
        read.status().is_success().then_some(())
    })
    .await;
    directory::delete_group(world.tenant(), finance)
        .send(linked)
        .await
        .ok();
    refused_in_time(&reads_people, pat, "with Finance deleted").await;
}

/// Waits until `pat`'s `request` is refused as forbidden, `why` saying
/// what changed.
async fn refused_in_time<T: serde::de::DeserializeOwned>(
    request: &ianua_scenarios::api::Request<T>,
    pat: &ianua_scenarios::actors::Person,
    why: &str,
) {
    eventually_paced(
        &format!("Pat to be refused {why}"),
        UNTIL_IT_HOLDS,
        || async {
            let read = request.clone().send(pat.client()).await;
            (read.status() == Status::FORBIDDEN).then_some(())
        },
    )
    .await;
}
