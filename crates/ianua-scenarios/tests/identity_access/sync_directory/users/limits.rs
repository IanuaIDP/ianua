//! The room a tenant's plan leaves for the people its directory makes.

use ianua_scenarios::api::directory;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::directory::{DirectoryRecord, DirectorySearch};
use ianua_scenarios::world::World;

use crate::support::{OnRemove, linked_directory};

/// How many accounts the tenant's plan holds.
const MOST_ACCOUNTS: u64 = 100;

/// How many accounts the directory can read in the tenant.
async fn accounts(world: &World<'_>, linked: &Client) -> u64 {
    directory::search_users(world.tenant(), &DirectorySearch::default())
        .send(linked)
        .await
        .ok()
        .total_results
}

/// A record for someone at an address unique to this world for `name`.
fn record(world: &World<'_>, name: &str) -> DirectoryRecord {
    DirectoryRecord {
        user_name: world.address(name),
        ..DirectoryRecord::default()
    }
}

/// The directory fills the tenant to the last account its plan holds.
/// One more is refused as forbidden, the record opens no account, and the
/// count stays at the limit.
#[tokio::test]
async fn the_directory_makes_no_account_past_the_tenants_limit() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let room = MOST_ACCOUNTS - accounts(&world, &linked).await;

    for number in 0..room {
        directory::create_record(world.tenant(), &record(&world, &format!("hire{number}")))
            .send(&linked)
            .await
            .ok();
    }

    let refused = directory::create_record(world.tenant(), &record(&world, "one.too.many"))
        .send(&linked)
        .await;
    assert_eq!(
        refused.status(),
        Status::FORBIDDEN,
        "the plan holds no more accounts: {}",
        refused.summary()
    );
    assert_eq!(
        accounts(&world, &linked).await,
        MOST_ACCOUNTS,
        "the refused record opened no account"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
