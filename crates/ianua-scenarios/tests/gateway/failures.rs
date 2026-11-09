//! Apps that fail: one that never answers and one that drops every
//! connection. Tess puts each behind a route; the gateway ends the wait at
//! the route's timeout and answers for the app, never holding the request
//! open and never passing the failure off as the app's answer.

use std::time::{Duration, Instant};

use ianua_scenarios::expect::{Matrix, Records};
use ianua_scenarios::net::Call;
use ianua_scenarios::routes::{Placement, RouteSpec};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::{Failing, Hanging};
use ianua_scenarios::wire::Status;
use ianua_scenarios::world::World;

use crate::support::{app_host, probe, profile};

/// How long the hanging app's route gives it, in seconds: short enough to
/// wait out, long enough to tell from the gateway's own work.
const TIMEOUT_SECS: u32 = 2;

/// The most the refusal may take past the timeout, for the gateway's own
/// work and the handshake.
const SLACK: Duration = Duration::from_secs(5);

/// Tess puts an app that never answers behind a route giving it two
/// seconds, and an app that drops every connection behind another. A
/// visitor's request to the first is answered as a gateway timeout once
/// the two seconds are up, not held; one to the second is answered as a
/// bad gateway. Each reached its app, and the gateway records both with
/// the status it answered, not as the app's own answers.
#[tokio::test]
async fn a_hanging_app_times_out_and_a_failing_one_is_a_bad_gateway() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let host = app_host(&world).await;
    let hanging = Hanging::start().await.expect("the hanging app starts");
    let failing = Failing::start().await.expect("the failing app starts");
    let probe = probe(&stack);
    let slow = RouteSpec::public("slow", "/slow/*").timing_out_after(TIMEOUT_SECS);
    let broken = RouteSpec::public("broken", "/broken/*");
    for (route, upstream) in [(&slow, hanging.url()), (&broken, failing.url())] {
        route
            .applied(
                world.admin().client(),
                &probe,
                Placement {
                    tenant: world.tenant(),
                    upstream: &upstream,
                    host: &host,
                },
            )
            .await;
    }
    let reached = hanging.connections();

    let started = Instant::now();
    Matrix::new(
        "waiting on an app that never answers",
        Call::get(format!("https://{host}/slow/report")),
    )
    .refused(
        world.anonymous().client(),
        Status::GATEWAY_TIMEOUT,
        "gateway_timeout",
    )
    .run()
    .await;
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(u64::from(TIMEOUT_SECS))
            && waited < Duration::from_secs(u64::from(TIMEOUT_SECS)) + SLACK,
        "the request ended after {waited:?}, not at the route's timeout"
    );
    assert!(
        hanging.connections() > reached,
        "the request reached the hanging app"
    );

    Matrix::new(
        "reaching an app that drops the connection",
        Call::get(format!("https://{host}/broken/report")),
    )
    .refused(
        world.anonymous().client(),
        Status::BAD_GATEWAY,
        "bad_gateway",
    )
    .run()
    .await;
    assert!(
        failing.connections() > 0,
        "the request reached the failing app"
    );

    let records = Records::of_tenant(world.admin().client(), world.tenant());
    let timed_out = records.recorded("/slow/report").await;
    let dropped = records.recorded("/broken/report").await;
    assert_eq!(
        timed_out.status,
        Status::GATEWAY_TIMEOUT,
        "the record of the hanging app's request carries the timeout"
    );
    assert_eq!(
        dropped.status,
        Status::BAD_GATEWAY,
        "the record of the failing app's request carries the bad gateway"
    );
    stack.stop().await.expect("the stack stops cleanly");
}
