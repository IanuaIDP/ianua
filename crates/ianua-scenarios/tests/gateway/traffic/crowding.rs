//! An app that hangs holds up only its own requests: while several wait
//! on it, the gateway answers everybody else at once, and each waiting
//! request ends at the route's timeout.

use std::time::{Duration, Instant};

use ianua_scenarios::expect::eventually;
use ianua_scenarios::net::Call;
use ianua_scenarios::routes::{Placement, RouteSpec};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::{Echo, Hanging};
use ianua_scenarios::wire::Status;
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;

use crate::support::{app_host, probe, profile};

/// How long the stuck app's route waits for it, in seconds.
const TIMEOUT_SECS: u32 = 4;

/// How many requests wait on the stuck app at once.
const WAITING: usize = 4;

/// The most the working app's answer may take while the others wait.
const PROMPTLY: Duration = Duration::from_secs(3);

/// Four visitors' requests hang on a stuck app whose route gives it four
/// seconds. Meanwhile another request to a working app is answered at
/// once, inside those four seconds. Each hanging request then ends as a
/// gateway timeout, none of them held past the route's timeout.
#[tokio::test]
async fn requests_stuck_on_one_app_hold_nobody_else_up() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let host = app_host(&world).await;
    let stuck = Hanging::start().await.expect("the stuck app starts");
    let working = Echo::start(&stack, &host)
        .await
        .expect("the working app starts");
    let visitor = probe(&stack);
    for (route, upstream) in [
        (
            RouteSpec::public("stuck", "/stuck/*").timing_out_after(TIMEOUT_SECS),
            stuck.url(),
        ),
        (RouteSpec::public("working", "/working/*"), working.url()),
    ] {
        route
            .applied(
                world.admin().client(),
                &visitor,
                Placement {
                    tenant: world.tenant(),
                    upstream: &upstream,
                    host: &host,
                },
            )
            .await;
    }
    let reached = stuck.connections();
    let stuck_url = format!("https://{host}/stuck/report");
    let working_url = format!("https://{host}/working/report");

    let started = Instant::now();
    let waiting = futures_util::future::join_all(
        (0..WAITING).map(|_| visitor.send::<IgnoredAny>(Call::get(stuck_url.as_str()))),
    );
    let answered = async {
        eventually("all four to reach the stuck app", || async {
            (stuck.connections() >= reached + WAITING).then_some(())
        })
        .await;
        let before = Instant::now();
        let answer = visitor
            .send::<IgnoredAny>(Call::get(working_url.as_str()))
            .await;
        (answer.status(), before.elapsed())
    };
    let (ended, (working_status, took)) = tokio::join!(waiting, answered);

    assert_eq!(working_status, Status::OK, "the working app answered");
    assert!(
        took < PROMPTLY,
        "the working app's answer took {took:?} while others waited"
    );
    assert_eq!(ended.len(), WAITING, "every waiting request ended");
    for answer in ended {
        assert_eq!(
            answer.status(),
            Status::GATEWAY_TIMEOUT,
            "a stuck request is a timeout: {}",
            answer.summary()
        );
    }
    assert!(
        started.elapsed() < Duration::from_secs(u64::from(TIMEOUT_SECS) * 3),
        "the requests were held for {:?}, past the route's timeout",
        started.elapsed()
    );
    stack.stop().await.expect("the stack stops cleanly");
}
