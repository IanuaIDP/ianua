//! A second app of the shop's, on a domain of its own, accepting the
//! shop's sign-in: Pat's browser is handed from the shop to the second
//! app and back through a chain of one-time redirects that sets the
//! second app a cookie of its own, and only that cookie lets her in there.

use ianua_scenarios::api::app_sign_in;
use ianua_scenarios::expect::eventually;
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::routes::{Placement, RouteSpec, domain};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::{AssertionCheck, Echo};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::routing::RoutePolicy;
use ianua_scenarios::world::World;
use serde::Deserialize;
use serde::de::IgnoredAny;
use serde_json::json;

use crate::support::{Shop, ShopOwner, customer, profile, word};

/// The most redirects a handoff chain is followed through before it must
/// have come back to the shop: to the second app, back, and a few to
/// spare for the hops the gateway adds.
const HOPS: usize = 6;

/// What the shop's sign-in answers when a second app waits for a handoff:
/// the sign-in itself, and the first address to follow.
#[derive(Deserialize)]
struct Handoff {
    signed_in: bool,
    hop_to: Option<String>,
}

/// Tess brings a second domain for the shop's orders app and lets it
/// accept the shop's sign-in with a cookie on its own host. Pat signs in
/// at the shop; the orders app refuses her still. Her browser follows the
/// handoff redirects until they land back at the shop, and then the orders
/// app lets her in, seeing an assertion naming her and no cookie. Mallory,
/// in a browser that followed no handoff, is refused there. Pat signs out
/// at the shop, and the orders app refuses her too.
#[tokio::test]
async fn a_second_app_lets_pat_in_only_after_the_handoff_sets_its_own_cookie() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let word = word();
    let shop = Shop::opened(
        &stack,
        &ShopOwner {
            tenant: world.tenant(),
            admin: world.admin().client(),
            word: &word,
        },
    )
    .await;
    let host = domain::brought(
        &stack,
        world.admin().client(),
        world.tenant(),
        &format!("orders-{word}.{}", stack.customer_domain()),
    )
    .await;
    let orders = Echo::start(&stack, &host)
        .await
        .expect("the orders app starts");
    let probe = Client::new(&stack, "a probe of the orders app").expect("a client");
    let route = RouteSpec::public(&format!("orders-{word}"), "/purchases/*")
        .asking(RoutePolicy::Authenticated)
        .pinned(&format!("orders-{word}"))
        .on_hosts(std::slice::from_ref(&host))
        .applied(
            world.admin().client(),
            &probe,
            Placement {
                tenant: world.tenant(),
                upstream: &orders.url(),
                host: &host,
            },
        )
        .await;
    let accepting = json!({
        "accepts_app_sign_in_of": shop.app_service_id,
        "delivery": { "kind": "own_cookie", "hosts": [host] },
    });
    world
        .admin()
        .client()
        .send::<IgnoredAny>(
            Call::put(
                world
                    .tenant()
                    .at(&format!("/services/{}/app-sign-in", route.service_id)),
            )
            .json(&accepting),
        )
        .await
        .ok();
    let pat = customer(&world, "pat", "Pat Customer").await;

    let waiting = pat
        .client()
        .send::<Handoff>(
            Call::post(shop.page("/.ianua/login"))
                .json(&json!({ "email": pat.email(), "password": pat.password() }))
                .header("origin", &format!("https://{}", shop.host))
                .header("sec-fetch-site", "same-origin"),
        )
        .await
        .ok();
    assert!(waiting.signed_in, "Pat is signed in at the shop");
    let page = format!("https://{host}/purchases/one");
    pat.client()
        .get::<IgnoredAny>(&page)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    let Some(mut next) = waiting.hop_to else {
        panic!("the shop's sign-in hands Pat's browser on to the orders app");
    };
    for _ in 0..HOPS {
        let hop = eventually("the gateway to serve the handoff navigation", || async {
            let answer = pat
                .client()
                .send::<IgnoredAny>(Call::get(&next).header("accept", "text/html"))
                .await;
            (answer.status() != Status::NOT_FOUND).then_some(answer)
        })
        .await;
        assert_eq!(
            hop.status(),
            Status::SEE_OTHER,
            "each handoff navigation sends the browser on: {}",
            hop.summary()
        );
        let Some(onward) = hop.header("location") else {
            panic!(
                "a handoff navigation says where to go next: {}",
                hop.summary()
            );
        };
        next = onward.to_owned();
        if next == format!("https://{}/", shop.host) {
            break;
        }
    }
    eventually(
        "the handoff cookie to let Pat into the orders app",
        || async {
            let answer = pat.client().get::<IgnoredAny>(&page).await;
            (answer.status() == Status::OK).then_some(())
        },
    )
    .await;
    let mallory = Client::new(&stack, "Mallory, who followed no handoff").expect("a client");
    mallory
        .get::<IgnoredAny>(&page)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let arrivals = orders.arrivals();
    let Some(last) = arrivals.last() else {
        panic!("Pat reached the orders app");
    };
    let AssertionCheck::Verified { caller } = &last.assertion else {
        panic!("the orders app could not check the gateway's assertion: {last:?}");
    };
    assert_eq!(caller.sub, pat.id(), "the assertion names Pat");
    assert!(
        !last.has_header("cookie"),
        "Pat's cookie reached the orders app"
    );

    app_sign_in::log_out(&shop.host)
        .send(pat.client())
        .await
        .ok();
    eventually(
        "signing out at the shop to end Pat's access to the orders app",
        || async {
            let answer = pat.client().get::<IgnoredAny>(&page).await;
            (answer.status() == Status::UNAUTHORIZED).then_some(())
        },
    )
    .await;
    stack.stop().await.expect("the stack stops cleanly");
}
