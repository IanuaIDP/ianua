//! The database goes away while the gateway keeps serving: nobody's
//! session can be checked, so nobody is let in, and everybody gets a plain
//! refusal. When it comes back so does Pat, with no restart.

use ianua_scenarios::actors::Person;
use ianua_scenarios::expect::{Matrix, eventually};
use ianua_scenarios::net::Call;
use ianua_scenarios::routes::RouteSpec;
use ianua_scenarios::stack::{Part, Profile, Stack};
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::routing::RoutePolicy;
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;

use crate::support::{HostedApp, app_host, customer, last_caller, signed_in_on};

/// The page every step reads.
const CLAIMS_PAGE: &str = "/claims/open";

/// Pat is signed in and reading claims when the database goes down. Her
/// next requests are let through only while the gateway's few seconds of
/// remembered answers last, and then she is told the service is
/// unavailable; never told she is signed out, and the app sees nothing
/// more of her. Someone with no session is still told to sign in. When
/// the database comes back Pat is let in again with the same cookie.
#[tokio::test]
async fn while_the_database_is_out_nobodys_session_is_taken_on_trust() {
    let stack = Stack::start(Profile::standard().with_cuttable_parts())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let echo = Echo::start(&stack, &app_host(&world).await)
        .await
        .expect("the claims app starts");
    let spec = RouteSpec::public("claims", "/claims/*").asking(RoutePolicy::Authenticated);
    let app = HostedApp::opened(&world, "claims", spec, &echo.url()).await;
    let pat = customer(&world, "pat", "Pat Customer").await;
    signed_in_on(&app.host, &pat).await;
    let page = app.page(CLAIMS_PAGE);
    read(&pat, &page).await.ok();

    stack.cut(Part::Database);
    eventually("Pat's session to be uncheckable", || async {
        let answer = read(&pat, &page).await;
        assert!(
            [Status::OK, Status::SERVICE_UNAVAILABLE].contains(&answer.status()),
            "Pat is let in or told to wait, never signed out: {}",
            answer.summary()
        );
        (answer.status() == Status::SERVICE_UNAVAILABLE).then_some(())
    })
    .await;
    echo.forget();
    Matrix::new(
        "reading claims with the database out",
        Call::get(page.as_str()),
    )
    .refused(pat.client(), Status::SERVICE_UNAVAILABLE, "unavailable")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
    assert!(
        echo.arrivals().is_empty(),
        "nothing reached the app while the database was out"
    );

    stack.mend(Part::Database);
    eventually("Pat to be let in again", || async {
        let answer = read(&pat, &page).await;
        (answer.status() == Status::OK).then_some(())
    })
    .await;
    assert_eq!(last_caller(&echo).sub, pat.id(), "the app sees Pat again");
    stack.stop().await.expect("the stack stops cleanly");
}

/// `person` asks for `page`.
async fn read(person: &Person, page: &str) -> Answer<IgnoredAny> {
    person.client().send::<IgnoredAny>(Call::get(page)).await
}
