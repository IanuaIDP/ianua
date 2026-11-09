//! A public route: anyone reaches the app behind it, signed in or not, and
//! nothing a client claims about who it is ever reaches the app, whatever
//! header Mallory puts the claim in.

use ianua_scenarios::expect::{Matrix, Records};
use ianua_scenarios::net::Call;
use ianua_scenarios::routes::{Placement, RouteSpec};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::{AssertionCheck, Echo};
use ianua_scenarios::wire::Status;
use ianua_scenarios::world::World;

use crate::support::{app_host, probe, profile};

/// The headers Mallory sends to pass for Alice, in the spellings a
/// careless proxy would let through.
const SMUGGLED: [(&str, &str); 6] = [
    ("X-Forwarded-User", "alice"),
    ("X-Forwarded-Groups", "admins"),
    ("X-Forwarded-Email", "alice@example.com"),
    (
        "X-Ianua-Assertion",
        "a-forged-assertion.naming-alice.unsigned",
    ),
    (
        "X_Ianua_Assertion",
        "a-forged-assertion.naming-alice.unsigned",
    ),
    ("X-Ianua-User-Id", "alice"),
];

/// Tess puts the echo app behind a public route. Ann, Tess, Max, Sam and
/// nobody signed in all reach it, and no credential any of them holds
/// reaches the app. Mallory, signed in nowhere, claims to be Alice in
/// every header a proxy might trust: she gets through as nobody, none of
/// those headers arriving. The gateway records her request as allowed,
/// sent by nobody.
#[tokio::test]
async fn anyone_reaches_a_public_route_and_no_claimed_identity_arrives() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let host = app_host(&world).await;
    let echo = Echo::start(&stack, &host)
        .await
        .expect("the echo app starts");
    RouteSpec::public("echo", "/echo/*")
        .applied(
            world.admin().client(),
            &probe(&stack),
            Placement {
                tenant: world.tenant(),
                upstream: &echo.url(),
                host: &host,
            },
        )
        .await;
    echo.forget();

    let url = format!("https://{host}/echo/hello");
    Matrix::new("reaching the public route", Call::get(url.as_str()))
        .allowed(world.owner().client())
        .allowed(world.admin().client())
        .allowed(world.member().client())
        .allowed(world.stranger().client())
        .allowed(world.anonymous().client())
        .run()
        .await;
    let arrived = echo.arrivals();
    assert_eq!(arrived.len(), 5, "every actor reached the app once");
    for arrival in &arrived {
        assert_eq!(
            arrival.path, "/echo/hello",
            "the app got the path the actor asked for"
        );
        assert!(
            !arrival.has_header("authorization") && !arrival.has_header("cookie"),
            "a caller's credential reached the app: {arrival:?}"
        );
        assert_eq!(
            arrival.assertion,
            AssertionCheck::Absent,
            "a public route asserts nobody to the app"
        );
    }

    echo.forget();
    let claimed = format!("https://{host}/echo/claimed");
    let call = SMUGGLED
        .iter()
        .fold(Call::get(claimed.as_str()), |call, (name, value)| {
            call.header(name, value)
        });
    Matrix::new("Mallory claiming to be Alice", call)
        .allowed(world.anonymous().client())
        .run()
        .await;
    let arrived = echo.arrivals();
    assert_eq!(arrived.len(), 1, "Mallory's request reached the app once");
    for (name, _) in SMUGGLED {
        assert!(
            !arrived[0].has_header(name),
            "{name} reached the app: {:?}",
            arrived[0]
        );
    }
    assert_eq!(
        arrived[0].assertion,
        AssertionCheck::Absent,
        "Mallory's claims earned her no assertion"
    );

    let record = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded("/echo/claimed")
        .await;
    assert_eq!(record.decision, "allowed", "a public route allows anyone");
    assert_eq!(record.status, Status::OK, "the app's answer was passed on");
    assert_eq!(
        record.subject.kind, "anonymous",
        "the record names nobody as the sender"
    );
    stack.stop().await.expect("the stack stops cleanly");
}
