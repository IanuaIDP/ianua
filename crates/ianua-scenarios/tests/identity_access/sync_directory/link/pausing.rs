//! A link paused and switched back on: only Tess may do it, a paused link
//! refuses its token, and the same token works again when it returns.

use ianua_scenarios::api::directory;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::world::World;
use serde_json::Value;

use crate::support::{OnRemove, linked_directory, made};

/// The link is on and the directory makes Pat, so its status shows a
/// sync. Max, Sam and nobody signed in may neither pause it nor rotate its
/// token. Tess pauses it: its status reads off, the directory's token is
/// refused, and pausing it again is not a change it can make. Tess
/// switches it back on: no new token is shown, the old one works again,
/// and the trail holds the pause and both times it was switched on.
#[tokio::test]
async fn a_paused_link_refuses_its_token_until_tess_switches_it_back_on() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    made(&world, &linked, "pat").await;

    let status = directory::status(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(status.rest["enabled"], Value::Bool(true));
    assert!(
        !status.rest["last_sync_at"].is_null(),
        "the directory's write shows as a sync"
    );

    for call in [
        directory::disable(world.tenant()).call(),
        directory::rotate_token(world.tenant()).call(),
    ] {
        Matrix::new("changing the directory link", call)
            .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
            .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
            .refused(
                world.anonymous().client(),
                Status::UNAUTHORIZED,
                "unauthenticated",
            )
            .run()
            .await;
    }

    directory::disable(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let paused = directory::status(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert!(paused.configured, "a paused link is still set up");
    assert_eq!(paused.rest["enabled"], Value::Bool(false));
    let refused = directory::list_users(world.tenant()).send(&linked).await;
    assert_eq!(
        refused.status(),
        Status::UNAUTHORIZED,
        "a paused link takes no token: {}",
        refused.summary()
    );
    let twice = directory::disable(world.tenant())
        .send(world.admin().client())
        .await;
    assert!(
        !twice.status().is_success(),
        "a paused link cannot be paused again: {}",
        twice.summary()
    );

    let back_on = directory::enable(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert!(
        back_on.bearer_token.is_none(),
        "switching back on shows no new token"
    );
    directory::list_users(world.tenant())
        .send(&linked)
        .await
        .ok();

    world.trail().recorded("federation.scim_disabled").await;
    assert_eq!(
        world.trail().count("federation.scim_enabled").await,
        2,
        "the link is recorded as switched on twice"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
