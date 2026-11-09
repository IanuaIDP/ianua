//! A member leaving as Ann expects it: once she removes Max he is gone
//! from the list; and as Max finds it: the session he held dies at once
//! and his password opens nothing any more.

use ianua_scenarios::api::members;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::world::World;

use crate::support::{role_of, sign_in_refused};

/// Max reads his own account. Ann removes him. He is no longer among the
/// members; the session he still holds reads nothing, at once, not
/// minutes later; and signing in again with his password is told no more
/// than that nobody matched.
#[tokio::test]
async fn a_removed_member_is_cut_off_at_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let max = world.member();
    members::me(world.org()).send(max.client()).await.ok();

    members::remove(world.org(), max.id())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        role_of(&world, max.id()).await,
        None,
        "Max is gone from the members"
    );

    members::me(world.org())
        .send(max.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    sign_in_refused(max.client(), max.email(), max.password()).await;

    stack.stop().await.expect("the stack stops cleanly");
}
