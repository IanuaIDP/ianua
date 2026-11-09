//! A directory replacing a group's whole list moves what the group gives:
//! the person left off loses it and the one put on gains it.

use std::time::Duration;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{directory, people, policies, roles};
use ianua_scenarios::expect::{Waiting, eventually_paced};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::directory::{DirectoryGroup, DirectoryMember};
use ianua_scenarios::wire::policies::GroupRole;
use ianua_scenarios::wire::roles::{NewRole, SystemPermission};
use ianua_scenarios::world::World;

use crate::support::{OnRemove, linked_directory, made, settled_in};

/// How long a change to a group is given to reach its people, asked once
/// a second as someone refreshing a page would.
const UNTIL_IT_HOLDS: Waiting = Waiting {
    patience: Duration::from_secs(30),
    every: Duration::from_secs(1),
};

/// Waits until `person` reading the tenant's people is answered `wanted`.
async fn reads_people_answered(world: &World<'_>, person: &Person, wanted: Status) {
    let reads_people = people::list(world.tenant(), None);
    eventually_paced(
        &format!("{} to be answered {wanted}", person.email()),
        UNTIL_IT_HOLDS,
        || async {
            let read = reads_people.clone().send(person.client()).await;
            (read.status() == wanted).then_some(())
        },
    )
    .await;
}

/// The directory makes Pat and Uma, who settle in, and Finance with Pat
/// in it; Tess gives Finance a role that reads people. Pat reads them and
/// Uma may not. The directory replaces Finance's list with Uma alone: Pat
/// loses the reading and Uma gains it, with no further step by Tess.
#[tokio::test]
async fn a_list_the_directory_replaces_moves_the_groups_access_from_pat_to_uma() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let mut pat = made(&world, &linked, "pat").await;
    let mut uma = made(&world, &linked, "uma").await;
    settled_in(&world, &mut pat).await;
    settled_in(&world, &mut uma).await;
    let list_of = |person: &Person, name: &str| DirectoryGroup {
        display_name: name.to_owned(),
        members: vec![DirectoryMember {
            value: person.id().to_owned(),
        }],
    };
    let finance = directory::create_group(world.tenant(), &list_of(&pat, "Finance"))
        .send(&linked)
        .await
        .ok();
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
        &finance.id,
        &GroupRole {
            role_id: readers.id,
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    reads_people_answered(&world, &pat, Status::OK).await;
    people::list(world.tenant(), None)
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    directory::replace_group(world.tenant(), &finance.id, &list_of(&uma, "Finance"))
        .send(&linked)
        .await
        .ok();

    reads_people_answered(&world, &pat, Status::FORBIDDEN).await;
    reads_people_answered(&world, &uma, Status::OK).await;

    stack.stop().await.expect("the stack stops cleanly");
}
