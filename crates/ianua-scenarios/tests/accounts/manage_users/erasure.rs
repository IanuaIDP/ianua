//! Calling off an erasure from the staff side: Ann stops Pat's erasure
//! and opens her account again, and the person it concerns signs in
//! afresh. Uma, Max, Sam and nobody signed in stop nothing of hers.

use ianua_scenarios::api::{account, people};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::account::ErasureRequest;
use ianua_scenarios::world::World;

use crate::support::person;

/// The record a cancelled erasure leaves.
const CANCELLED: &str = "identity.erasure_cancelled";

/// Pat asks to be erased, closing her account. Uma, Max, Sam and nobody
/// signed in cannot call it off. Ann calls it off: Pat's account reads
/// active again, she signs in afresh, and the cancellation is on record.
/// Calling it off again changes nothing.
#[tokio::test]
async fn ann_calls_off_pat_s_erasure_and_nobody_else_can() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let request = account::erase(
        world.tenant(),
        pat.id(),
        &ErasureRequest {
            reason: "I am leaving".to_owned(),
        },
    )
    .send(pat.client())
    .await
    .ok();
    let closing = people::get(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(closing.status, "Closing", "Pat's account reads as closing");

    Matrix::new(
        "stopping Pat's erasure",
        account::staff_cancel_erasure(world.tenant(), &request.id).call(),
    )
    .refused(uma.client(), Status::FORBIDDEN, "forbidden")
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;

    account::staff_cancel_erasure(world.tenant(), &request.id)
        .send(world.owner().client())
        .await
        .ok();
    let reopened = people::get(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(reopened.status, "Active", "the account opened again");
    pat.sign_in(&stack).await;
    people::me(world.tenant()).send(pat.client()).await.ok();
    assert_eq!(
        world.trail().count(CANCELLED).await,
        1,
        "the call-off is recorded once"
    );

    account::staff_cancel_erasure(world.tenant(), &request.id)
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    stack.stop().await.expect("the stack stops cleanly");
}
