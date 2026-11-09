//! The short-lived tokens the shop's pages fetch for the shop's API: one
//! made for the API's audience reaches it, while no token, the API's token
//! at the shop, and a token the twin tenant's shop gave Rita are refused;
//! an expired token is refused and a fresh one works again.

use std::time::Duration;

use ianua_scenarios::actors::Person;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Matrix, Records};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::Status;
use ianua_scenarios::world::World;

use crate::signed_in::{asserted_as, open_shop, open_twin_shop};
use crate::support::{Shop, api_token, customer, profile, signed_in_at, twin_customer};

/// How long a token for an app lasts on the expiry deployment, in
/// seconds: short enough to pass in one step of the clock.
const SHORT_TOKEN_SECONDS: &str = "2";

/// Past the short token's lifetime, but within the minute of clock skew a
/// verifier allows.
const JUST_PAST: Duration = Duration::from_secs(3);

/// Past the clock skew too.
const WELL_PAST: Duration = Duration::from_secs(60);

/// Pat's page on the shop fetches a token for the shop's API, and with it
/// reaches the API on the tenant's apps host; the API sees a signed
/// assertion naming Pat and never the token. No token, the API's token at
/// the shop (another audience), and a token the twin tenant's shop gave
/// its own customer, Rita, are all refused, the apps seeing nothing.
#[tokio::test]
async fn a_token_for_the_apis_audience_reaches_it_and_no_other_does() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let shop = open_shop(&world).await;
    let pat = customer(&world, "pat", "Pat Customer").await;
    signed_in_at(&shop, &pat).await;
    let token = api_token(&shop, &pat).await;
    shop.app.forget();
    shop.api.forget();
    let scripted = Client::new(&stack, "Pat's page script").expect("a client");
    let bearer = format!("Bearer {token}");
    assert_api_access(&shop, &pat, &scripted, &bearer).await;
    refuse_wrong_audience(&world, &shop, &scripted, &bearer).await;
    let twin_shop = open_twin_shop(&world).await;
    let rita = twin_customer(&world, "rita", "Rita Elsewhere").await;
    signed_in_at(&twin_shop, &rita).await;
    let theirs = api_token(&twin_shop, &rita).await;
    refuse_foreign_token(&shop, &scripted, &theirs).await;
    assert!(shop.app.arrivals().is_empty(), "nothing reached the shop");
    assert_eq!(
        shop.api.arrivals().len(),
        1,
        "only Pat's token reached the API"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat's token reaches the API with a trusted assertion and no forwarded credential.
async fn assert_api_access(shop: &Shop, pat: &Person, scripted: &Client, bearer: &str) {
    let orders = shop.endpoint("/orders/1");
    Matrix::new(
        "reading orders with the API's token",
        Call::get(orders.as_str()).header("authorization", bearer),
    )
    .allowed(scripted)
    .run()
    .await;
    asserted_as(&shop.api, pat.id());
}

/// An absent token and an API token used at the shop are both refused.
async fn refuse_wrong_audience(world: &World<'_>, shop: &Shop, scripted: &Client, bearer: &str) {
    let orders = shop.endpoint("/orders/1");
    Matrix::new("reading orders with no token", Call::get(orders.as_str()))
        .refused(
            world.anonymous().client(),
            Status::UNAUTHORIZED,
            "unauthenticated",
        )
        .run()
        .await;
    Matrix::new(
        "reading the shop's account page with the API's token",
        Call::get(shop.page("/account/orders")).header("authorization", bearer),
    )
    .refused(scripted, Status::UNAUTHORIZED, "unauthenticated")
    .run()
    .await;
}

/// A token issued by the twin tenant cannot authorize a request to this API.
async fn refuse_foreign_token(shop: &Shop, scripted: &Client, theirs: &str) {
    let orders = shop.endpoint("/orders/1");
    Matrix::new(
        "reading orders with the twin tenant's token",
        Call::get(orders.as_str()).header("authorization", &format!("Bearer {theirs}")),
    )
    .refused(scripted, Status::UNAUTHORIZED, "unauthenticated")
    .run()
    .await;
}

/// Pat's page fetches a token for the shop's API, on a deployment whose
/// tokens for apps last two seconds. It works now and within the minute
/// of allowed clock skew, then is refused beyond it without reaching the
/// API, the gateway recording the expired credential. A fresh token still
/// works. The application clock advances through these instants while the
/// real verifier keeps its production tolerance.
#[tokio::test]
async fn an_expired_token_is_refused() {
    let clock = Clock::controlled();
    let profile = profile().with("AUTH_APP_SIGN_IN_ACCESS_TTL_SECONDS", SHORT_TOKEN_SECONDS);
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let shop = open_shop(&world).await;
    let pat = customer(&world, "pat", "Pat Customer").await;
    signed_in_at(&shop, &pat).await;
    let token = api_token(&shop, &pat).await;
    let scripted = Client::new(&stack, "Pat's page script").expect("a client");

    let orders =
        Call::get(shop.endpoint("/orders/1")).header("authorization", &format!("Bearer {token}"));
    Matrix::new("reading orders with a live token", orders.clone())
        .allowed(&scripted)
        .run()
        .await;
    asserted_as(&shop.api, pat.id());
    clock.advance(JUST_PAST);
    Matrix::new("reading orders within clock tolerance", orders.clone())
        .allowed(&scripted)
        .run()
        .await;

    clock.advance(WELL_PAST);
    assert_expired(&world, &shop, &scripted, orders).await;
    assert_fresh_token(&shop, &pat, &scripted).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// A fresh token still reaches the API after the earlier token expires.
async fn assert_fresh_token(shop: &Shop, pat: &Person, scripted: &Client) {
    let fresh = api_token(shop, pat).await;
    let orders =
        Call::get(shop.endpoint("/orders/1")).header("authorization", &format!("Bearer {fresh}"));
    Matrix::new("reading orders with a fresh token", orders)
        .allowed(scripted)
        .run()
        .await;
    asserted_as(&shop.api, pat.id());
}

/// An expired token reaches no upstream and records the expired credential reason.
async fn assert_expired(world: &World<'_>, shop: &Shop, scripted: &Client, orders: Call) {
    shop.api.forget();
    Matrix::new("reading orders with an expired token", orders)
        .refused(scripted, Status::UNAUTHORIZED, "unauthenticated")
        .run()
        .await;
    assert!(shop.api.arrivals().is_empty(), "nothing reached the API");
    let refused = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded_where("/orders/1", "a refused", |record| {
            record.decision == "refused"
        })
        .await;
    assert_eq!(
        refused.reason.as_deref(),
        Some("credential_expired"),
        "the record says the token had expired"
    );
}
