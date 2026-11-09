//! Identity headers on a signed-in route: whatever a caller claims in a
//! header is dropped before it can reach the app, even a real assertion
//! the gateway signed for somebody else. The app reads who is calling from
//! the assertion the gateway signed for this request alone, and verifies
//! it against the keys the tenant publishes.

use ianua_scenarios::actors::Person;
use ianua_scenarios::expect::Records;
use ianua_scenarios::net::Call;
use ianua_scenarios::routes::RouteSpec;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::{ASSERTION_HEADER, Arrival, AssertionCheck, Echo};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::routing::RoutePolicy;
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;

use crate::support::{HostedApp, app_host, customer, profile, signed_in_on};

/// The headers Pat sends to pass for Quinn, in the spellings a careless
/// proxy would let through.
const CLAIMS: [(&str, &str); 5] = [
    ("X-Forwarded-User", "quinn"),
    ("X-Forwarded-Groups", "admins"),
    ("X-Forwarded-Email", "quinn@example.com"),
    ("X_Forwarded_User", "quinn"),
    ("X-Ianua-User-Id", "quinn"),
];

/// The address Pat claims to be calling from.
const CLAIMED_ADDRESS: &str = "203.0.113.66";

/// The header carrying the request's reference to the app.
const REFERENCE_HEADER: &str = "x-ianua-correlation-id";

/// The app's own cookie Pat's browser also carries.
const APP_COOKIE: &str = "theme=dark";

/// The page every step reads.
const LEDGER_PAGE: &str = "/ledger/entries";

/// Quinn reads the ledger and Pat keeps the signed assertion the gateway
/// made for him. Pat then calls with that real assertion in the header,
/// claims to be Quinn in every header a proxy might trust, claims another
/// address, and carries the app's own cookie beside her session cookie.
/// The app verifies an assertion naming Pat, freshly signed, not Quinn's;
/// none of her claims arrive; the address it is told is not the one she
/// claimed; her session cookie stays behind and the app's own cookie
/// arrives. The reference the app gets is the one in the assertion and in
/// the gateway's record of the request.
#[tokio::test]
async fn a_callers_own_claims_are_dropped_and_only_the_gateways_signed_word_arrives() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let echo = Echo::start(&stack, &app_host(&world).await)
        .await
        .expect("the ledger app starts");
    let spec = RouteSpec::public("ledger", "/ledger/*").asking(RoutePolicy::Authenticated);
    let app = HostedApp::opened(&world, "ledger", spec, &echo.url()).await;
    let pat = customer(&world, "pat", "Pat Customer").await;
    let quinn = customer(&world, "quinn", "Quinn Contractor").await;
    signed_in_on(&app.host, &pat).await;
    signed_in_on(&app.host, &quinn).await;
    let page = app.page(LEDGER_PAGE);
    let quinns = kept_assertion(&echo, &quinn, &page).await;
    let call = claiming_call(&pat, &page, &quinns);

    echo.forget();
    let answer = pat.client().send::<IgnoredAny>(call).await;
    assert_eq!(answer.status(), Status::OK, "{}", answer.summary());
    let arrived = echo.arrivals();
    assert_eq!(arrived.len(), 1, "Pat's request reached the app once");
    let arrival = &arrived[0];
    let reference = assert_only_pats_word(arrival, &pat, &quinns);
    assert_claims_dropped(arrival);
    let record = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded_where(LEDGER_PAGE, "Pat's", |record| {
            record.subject.id.as_deref() == Some(pat.id())
        })
        .await;
    assert_eq!(
        uuid::Uuid::parse_str(&record.correlation_id).ok(),
        Some(reference),
        "the record and the app hold the same reference"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The assertion the gateway signed for `person`'s request to `page`, as
/// the app received it.
async fn kept_assertion(echo: &Echo, person: &Person, page: &str) -> String {
    echo.forget();
    person
        .client()
        .send::<IgnoredAny>(Call::get(page))
        .await
        .ok();
    let arrived = echo.arrivals();
    let Some(token) = arrived
        .last()
        .and_then(|last| last.header(ASSERTION_HEADER))
    else {
        panic!("the app got no assertion for Quinn: {arrived:?}");
    };
    token.to_owned()
}

/// Pat's request carrying every claim, Quinn's real assertion, a claimed
/// address, and the app's own cookie beside her session cookie.
fn claiming_call(pat: &Person, page: &str, assertion: &str) -> Call {
    let cookies = pat
        .client()
        .cookies_for(&page.parse().expect("the page is a URL"))
        .expect("Pat holds the app's session cookie");
    CLAIMS
        .iter()
        .fold(Call::get(page), |call, (name, value)| {
            call.header(name, value)
        })
        .header(ASSERTION_HEADER, assertion)
        .header("x-forwarded-for", CLAIMED_ADDRESS)
        .header(REFERENCE_HEADER, "a-reference-of-her-choosing")
        .header("cookie", &format!("{cookies}; {APP_COOKIE}"))
}

/// The app verified an assertion naming Pat alone, not the one she sent,
/// and the reference it was handed matches the assertion's; answers that
/// reference.
fn assert_only_pats_word(arrival: &Arrival, pat: &Person, quinns: &str) -> uuid::Uuid {
    let AssertionCheck::Verified { caller } = &arrival.assertion else {
        panic!("the app could not check the assertion: {arrival:?}");
    };
    assert_eq!(caller.sub, pat.id(), "the assertion names Pat");
    assert_eq!(caller.kind, "user", "the assertion names a tenant user");
    assert_ne!(
        arrival.header(ASSERTION_HEADER),
        Some(quinns),
        "Quinn's assertion did not get through"
    );
    let reference = arrival
        .header(REFERENCE_HEADER)
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .expect("the app is handed the gateway's own reference");
    assert_eq!(
        uuid::Uuid::parse_str(&caller.cid).ok(),
        Some(reference),
        "the assertion and the header hold the same reference"
    );
    reference
}

/// None of Pat's claims arrived, the address is not hers to choose, and
/// of her cookies the app's own alone came through.
fn assert_claims_dropped(arrival: &Arrival) {
    for (name, _) in CLAIMS {
        assert!(!arrival.has_header(name), "{name} reached the app");
    }
    assert_ne!(
        arrival.header("x-forwarded-for"),
        Some(CLAIMED_ADDRESS),
        "the app is not told the address Pat claimed"
    );
    assert_eq!(
        arrival.header("cookie"),
        Some(APP_COOKIE),
        "the session cookie stayed behind and the app's own arrived"
    );
}
