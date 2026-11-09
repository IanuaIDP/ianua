//! What a route asks of its callers, changed while it serves: the next
//! request after the change is held to the new rule, and the change is
//! Tess's to make.

use ianua_scenarios::api::routing;
use ianua_scenarios::expect::{Matrix, Records, eventually};
use ianua_scenarios::net::Call;
use ianua_scenarios::routes::RouteSpec;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::{AssertionCheck, Echo};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::routing::{PolicyChange, RoutePolicy};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;

use crate::support::{HostedApp, app_host, customer, last_caller, profile, signed_in_on};

/// The page every step reads.
const NOTES_PAGE: &str = "/notes/today";

/// Tess's notes app starts open: a visitor reads it and the app is told of
/// nobody. Max, Sam and nobody signed in may not change that. Tess closes
/// the route to signed-in people: the visitor is told to sign in, the app
/// seeing nothing, and the gateway records the missing credential, while
/// Pat, signed in on its host, reads on and the app reads her name in the
/// assertion. Tess opens the route again and the visitor reads it again.
/// Both changes are in the trail.
#[tokio::test]
async fn a_route_closed_or_opened_holds_on_the_next_request() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let echo = Echo::start(&stack, &app_host(&world).await)
        .await
        .expect("the notes app starts");
    let spec = RouteSpec::public("notes", "/notes/*");
    let app = HostedApp::opened(&world, "notes", spec, &echo.url()).await;
    let pat = customer(&world, "pat", "Pat Customer").await;
    signed_in_on(&app.host, &pat).await;
    let page = app.page(NOTES_PAGE);
    let visitor = world.anonymous().client();
    echo.forget();
    visitor
        .send::<IgnoredAny>(Call::get(page.as_str()))
        .await
        .ok();
    assert_eq!(echo.arrivals().len(), 1, "the visitor reached the open app");
    assert_eq!(
        echo.arrivals()[0].assertion,
        AssertionCheck::Absent,
        "the open app is told of nobody"
    );

    let closing = PolicyChange {
        policy: RoutePolicy::Authenticated,
    };
    let change = routing::change_policy(world.tenant(), &app.route.route_id, &closing);
    Matrix::new("closing the route", change.call())
        .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
        .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
        .refused(visitor, Status::UNAUTHORIZED, "unauthenticated")
        .run()
        .await;
    assert_eq!(
        world.trail().count("routing.route_updated").await,
        0,
        "a refused change records nothing"
    );

    routing::change_policy(world.tenant(), &app.route.route_id, &closing)
        .send(world.admin().client())
        .await
        .ok();
    eventually("the gateway to close the route", || async {
        let answer = visitor.send::<IgnoredAny>(Call::get(page.as_str())).await;
        (answer.status() == Status::UNAUTHORIZED).then_some(())
    })
    .await;
    echo.forget();
    Matrix::new("reading the closed route", Call::get(page.as_str()))
        .allowed(pat.client())
        .refused(visitor, Status::UNAUTHORIZED, "unauthenticated")
        .run()
        .await;
    assert_eq!(echo.arrivals().len(), 1, "only Pat reached the app");
    assert_eq!(last_caller(&echo).sub, pat.id(), "the app is told of Pat");
    let refused = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded_where(NOTES_PAGE, "the visitor's refused", |record| {
            record.subject.kind == "anonymous" && record.decision == "refused"
        })
        .await;
    assert_eq!(
        refused.reason.as_deref(),
        Some("sign_in_required"),
        "the record says the visitor must sign in"
    );

    routing::change_policy(
        world.tenant(),
        &app.route.route_id,
        &PolicyChange {
            policy: RoutePolicy::Public,
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    eventually("the gateway to open the route again", || async {
        let answer = visitor.send::<IgnoredAny>(Call::get(page.as_str())).await;
        (answer.status() == Status::OK).then_some(())
    })
    .await;
    assert_eq!(
        world.trail().count("routing.route_updated").await,
        2,
        "both changes are recorded"
    );
    stack.stop().await.expect("the stack stops cleanly");
}
