//! The room a tenant's plan leaves for the groups its directory makes.

use ianua_scenarios::api::directory;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::directory::{DirectoryGroup, DirectorySearch};
use ianua_scenarios::world::World;

use crate::support::{OnRemove, linked_directory};

/// How many groups the tenant's plan holds, of every kind.
const MOST_GROUPS: u32 = 5;

/// The directory makes groups until the tenant's plan holds no more. The
/// next one is refused as forbidden, and the directory still lists only
/// the groups made before it.
#[tokio::test]
async fn the_directory_makes_no_group_past_the_tenants_limit() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let mut kept = 0_u64;
    let mut refused = None;

    for number in 0..=MOST_GROUPS {
        let group = DirectoryGroup {
            display_name: format!("Team {number}"),
            members: vec![],
        };
        let answer = directory::create_group(world.tenant(), &group)
            .send(&linked)
            .await;
        if answer.status() != Status::CREATED {
            refused = Some((answer.status(), answer.summary()));
            break;
        }
        kept += 1;
    }

    let (status, why) = refused.expect("the plan holds no more than its limit");
    assert_eq!(status, Status::FORBIDDEN, "{why}");
    let listed = directory::search_groups(world.tenant(), &DirectorySearch::default())
        .send(&linked)
        .await
        .ok();
    assert_eq!(listed.total_results, kept, "the refused group was not made");

    stack.stop().await.expect("the stack stops cleanly");
}
