//! A route that cannot be decided forwards nothing: Tess saved one whose
//! pipeline she never switched on, and until she does, every request is
//! turned away and the app sees none of them.

use ianua_scenarios::api::routing;
use ianua_scenarios::expect::{Matrix, Records, eventually};
use ianua_scenarios::net::Call;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::{AssertionCheck, Echo};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::routing::{
    NewPipeline, NewRoute, NewService, RoutePolicy, TokenAudience, Upstream,
};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;

use crate::support::{app_host, profile};

/// How long the app may take to answer, in seconds.
const UPSTREAM_TIMEOUT: u32 = 30;

/// The page every step reads.
const DRAFT_PAGE: &str = "/draft/page";

/// Tess saves a route open to anyone but never switches its pipeline on.
/// Everyone asking is told the service is unavailable, signed in or not,
/// the app sees nothing, and the gateway records why. Once she switches
/// the pipeline on, a visitor gets through.
#[tokio::test]
async fn a_route_whose_pipeline_is_off_forwards_nothing() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let host = app_host(&world).await;
    let echo = Echo::start(&stack, &host)
        .await
        .expect("the draft app starts");
    let tess = world.admin().client();
    let service = routing::create_service(
        world.tenant(),
        &NewService {
            name: "draft-service".to_owned(),
            upstream: Upstream::at(
                &echo.url(),
                UPSTREAM_TIMEOUT,
                TokenAudience::NoTokenAccepted,
            ),
        },
    )
    .send(tess)
    .await
    .ok()
    .id;
    let pipeline = routing::create_pipeline(
        world.tenant(),
        &NewPipeline {
            name: "draft-pipeline".to_owned(),
        },
    )
    .send(tess)
    .await
    .ok()
    .id;
    routing::create_route(
        world.tenant(),
        &NewRoute {
            name: "draft".to_owned(),
            path_pattern: "/draft/*".to_owned(),
            methods: Vec::new(),
            service_id: service,
            policy: RoutePolicy::Public,
            pipeline_id: pipeline.clone(),
            hosts: Vec::new(),
        },
    )
    .send(tess)
    .await
    .ok();

    let page = format!("https://{host}{DRAFT_PAGE}");
    let visitor = world.anonymous().client();
    eventually("the gateway to hold the route", || async {
        let answer = visitor.send::<IgnoredAny>(Call::get(page.as_str())).await;
        (answer.status() == Status::SERVICE_UNAVAILABLE).then_some(())
    })
    .await;
    echo.forget();
    Matrix::new(
        "reading a route with its pipeline off",
        Call::get(page.as_str()),
    )
    .refused(visitor, Status::SERVICE_UNAVAILABLE, "unavailable")
    .refused(
        world.owner().client(),
        Status::SERVICE_UNAVAILABLE,
        "unavailable",
    )
    .run()
    .await;
    assert!(echo.arrivals().is_empty(), "the app saw nothing");
    Records::of_tenant(tess, world.tenant())
        .recorded_where(DRAFT_PAGE, "the visitor's pipeline-off", |record| {
            record.decision == "refused" && record.reason.as_deref() == Some("pipeline_inactive")
        })
        .await;

    routing::activate_pipeline(world.tenant(), &pipeline)
        .send(tess)
        .await
        .ok();
    eventually("the gateway to serve the route", || async {
        let answer = visitor.send::<IgnoredAny>(Call::get(page.as_str())).await;
        (answer.status() == Status::OK).then_some(())
    })
    .await;
    let arrived = echo.arrivals();
    assert_eq!(
        arrived.len(),
        1,
        "the first request let through reached the app"
    );
    assert_eq!(
        arrived[0].assertion,
        AssertionCheck::Absent,
        "a public route vouches for nobody"
    );
    stack.stop().await.expect("the stack stops cleanly");
}
