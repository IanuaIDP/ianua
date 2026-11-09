//! A person whose standing changed while their session cookie still looks
//! good: deactivated or removed, they are refused on their next request,
//! the app seeing nothing, and everyone else goes on.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::people;
use ianua_scenarios::expect::{Records, eventually};
use ianua_scenarios::net::Call;
use ianua_scenarios::routes::RouteSpec;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::routing::RoutePolicy;
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;

use crate::support::{HostedApp, app_host, customer, last_caller, profile, signed_in_on};

/// The page every step reads.
const DESK_PAGE: &str = "/desk/inbox";

/// Pat, Uma and Rob are signed in on the desk app and each reaches it.
/// Tess deactivates Uma: her cookie, still good to look at, gets her
/// forbidden, and the gateway records that she may no longer sign in. Tess
/// removes Rob: he is told he is nobody here. Neither reaches the app
/// again, while Pat goes on and the app reads her name.
#[tokio::test]
async fn a_person_deactivated_or_removed_is_refused_on_their_next_request() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let echo = Echo::start(&stack, &app_host(&world).await)
        .await
        .expect("the desk app starts");
    let spec = RouteSpec::public("desk", "/desk/*").asking(RoutePolicy::Authenticated);
    let app = HostedApp::opened(&world, "desk", spec, &echo.url()).await;
    let pat = customer(&world, "pat", "Pat Customer").await;
    let uma = customer(&world, "uma", "Uma Colleague").await;
    let rob = customer(&world, "rob", "Rob Leaving").await;
    let page = app.page(DESK_PAGE);
    for person in [&pat, &uma, &rob] {
        signed_in_on(&app.host, person).await;
        person
            .client()
            .send::<IgnoredAny>(Call::get(page.as_str()))
            .await
            .ok();
    }

    people::deactivate(world.tenant(), uma.id())
        .send(world.admin().client())
        .await
        .ok();
    refused_with(&uma, &page, Status::FORBIDDEN).await;
    people::remove(world.tenant(), rob.id())
        .send(world.admin().client())
        .await
        .ok();
    refused_with(&rob, &page, Status::UNAUTHORIZED).await;

    echo.forget();
    uma.client()
        .send::<IgnoredAny>(Call::get(page.as_str()))
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    rob.client()
        .send::<IgnoredAny>(Call::get(page.as_str()))
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert!(
        echo.arrivals().is_empty(),
        "nothing of Uma or Rob reached the app"
    );
    pat.client()
        .send::<IgnoredAny>(Call::get(page.as_str()))
        .await
        .ok();
    assert_eq!(last_caller(&echo).sub, pat.id(), "Pat goes on");

    let refused = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded_where(DESK_PAGE, "Uma's refused", |record| {
            record.reason.as_deref() == Some("subject_inactive")
        })
        .await;
    assert_eq!(refused.status, Status::FORBIDDEN, "Uma was forbidden");
    assert_eq!(refused.decision, "refused", "Uma was refused");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Waits until `person`'s next request to `page` is answered `status`.
async fn refused_with(person: &Person, page: &str, status: Status) {
    let what = format!("{} to be refused", person.email());
    eventually(&what, || async {
        let answer = person.client().send::<IgnoredAny>(Call::get(page)).await;
        (answer.status() == status).then_some(())
    })
    .await;
}
