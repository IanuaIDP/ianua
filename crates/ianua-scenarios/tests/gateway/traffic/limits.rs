//! A route's rate limit: each person is held to their own count and told
//! when to come back, the next window lets them in again, and a counter
//! that cannot be reached refuses rather than counts nothing.

use std::time::Duration;

use ianua_scenarios::actors::Person;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Matrix, Records, eventually};
use ianua_scenarios::net::Call;
use ianua_scenarios::routes::RouteSpec;
use ianua_scenarios::stack::{Part, Profile, Stack};
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::routing::RoutePolicy;
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;
use serde_json::json;
use time::OffsetDateTime;

use crate::support::{HostedApp, app_host, customer, last_caller, profile, signed_in_on};

/// How many requests one person gets in a window.
const ALLOWED: u32 = 3;

/// How long a window lasts, in seconds: short of the tenant's idle window,
/// so stepping past it leaves everybody signed in.
const WINDOW_SECONDS: i64 = 600;

/// The page every step reads.
const REPORT_PAGE: &str = "/sums/report";

/// The rate limit stage, counted per person.
fn per_person() -> serde_json::Value {
    json!({
        "RateLimit": {
            "max_requests": ALLOWED,
            "window_seconds": WINDOW_SECONDS,
            "key_by": "UserId",
        }
    })
}

/// Tess's sums app, behind a signed-in route counted per person.
async fn sums_app(world: &World<'_>, echo: &Echo) -> HostedApp {
    let spec = RouteSpec::public("sums", "/sums/*")
        .asking(RoutePolicy::Authenticated)
        .with_stage(per_person());
    HostedApp::opened(world, "sums", spec, &echo.url()).await
}

/// How far to step the clock so the next instant opens a fresh window:
/// the scenario then has the whole window to work in, however long it
/// takes, and its counts cannot straddle two windows. Stepped only once
/// the stack runs: the internal links' certificates are dated by this
/// clock and checked against real time, so a stack started ahead of real
/// time would hold certificates not valid yet.
fn to_the_next_window() -> Duration {
    let into_window = OffsetDateTime::now_utc()
        .unix_timestamp()
        .rem_euclid(WINDOW_SECONDS);
    let left = u64::try_from(WINDOW_SECONDS - into_window + 1).expect("a window's end is ahead");
    Duration::from_secs(left)
}

/// Pat reads the report as often as her limit allows; one more and she is
/// told to come back, the app seeing nothing of it, and told when. Uma has
/// a count of her own. The gateway records the refusal as the rate limit's.
/// Once the window has passed Pat is let in again.
#[tokio::test]
async fn a_person_past_their_count_is_turned_away_until_the_next_window() {
    let clock = Clock::controlled();
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let echo = Echo::start(&stack, &app_host(&world).await)
        .await
        .expect("the sums app starts");
    let app = sums_app(&world, &echo).await;
    let pat = customer(&world, "pat", "Pat Customer").await;
    let uma = customer(&world, "uma", "Uma Colleague").await;
    signed_in_on(&app.host, &pat).await;
    signed_in_on(&app.host, &uma).await;
    let page = app.page(REPORT_PAGE);
    echo.forget();
    clock.advance(to_the_next_window());

    for _ in 0..ALLOWED {
        read(&pat, &page).await.ok();
    }
    let over = read(&pat, &page).await;
    let retry_after = over
        .header("retry-after")
        .and_then(|value| value.parse::<i64>().ok())
        .expect("the refusal says when to come back");
    assert!(
        (1..=WINDOW_SECONDS).contains(&retry_after),
        "come back within the window, not after {retry_after} seconds"
    );
    over.refused(Status::TOO_MANY_REQUESTS, "too_many_requests");
    assert_eq!(
        echo.arrivals().len(),
        usize::try_from(ALLOWED).expect("a small count"),
        "the request past her count never reached the app"
    );
    read(&uma, &page).await.ok();
    assert_eq!(last_caller(&echo).sub, uma.id(), "Uma has her own count");

    let refused = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded_where(REPORT_PAGE, "Pat's refused", |record| {
            record.subject.id.as_deref() == Some(pat.id()) && record.decision == "refused"
        })
        .await;
    assert_eq!(
        refused.status,
        Status::TOO_MANY_REQUESTS,
        "the record carries the refusal"
    );
    let decided_by = refused.decided_by.expect("the record says what refused");
    assert_eq!(decided_by.name, "rate_limit", "the rate limit refused her");

    clock.advance(Duration::from_secs(
        u64::try_from(WINDOW_SECONDS).expect("a positive window"),
    ));
    read(&pat, &page).await.ok();
    assert_eq!(last_caller(&echo).sub, pat.id(), "Pat is back");
    stack.stop().await.expect("the stack stops cleanly");
}

/// `person` asks for `page`.
async fn read(person: &Person, page: &str) -> Answer<IgnoredAny> {
    person.client().send::<IgnoredAny>(Call::get(page)).await
}

/// The shared counter goes away while Pat works. The limit cannot be
/// counted, so she is told the service is unavailable rather than let
/// through uncounted, the app seeing nothing. Once the counter is back
/// she gets through again.
#[tokio::test]
async fn a_limit_whose_counter_is_gone_refuses_rather_than_counts_nothing() {
    let stack = Stack::start(Profile::standard().with_cuttable_parts())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let echo = Echo::start(&stack, &app_host(&world).await)
        .await
        .expect("the sums app starts");
    let spec = RouteSpec::public("sums", "/sums/*")
        .asking(RoutePolicy::Authenticated)
        .with_stage(json!({
            "RateLimit": {
                "max_requests": 1000,
                "window_seconds": 60,
                "key_by": "UserId",
            }
        }));
    let app = HostedApp::opened(&world, "sums", spec, &echo.url()).await;
    let pat = customer(&world, "pat", "Pat Customer").await;
    signed_in_on(&app.host, &pat).await;
    let page = app.page(REPORT_PAGE);
    read(&pat, &page).await.ok();

    stack.cut(Part::Cache);
    eventually("the counter's loss to refuse Pat", || async {
        let answer = read(&pat, &page).await;
        (answer.status() == Status::SERVICE_UNAVAILABLE).then_some(())
    })
    .await;
    echo.forget();
    Matrix::new("reading with no counter", Call::get(page.as_str()))
        .refused(pat.client(), Status::SERVICE_UNAVAILABLE, "unavailable")
        .run()
        .await;
    assert!(echo.arrivals().is_empty(), "nothing went through uncounted");

    stack.mend(Part::Cache);
    eventually("Pat to get through again", || async {
        let answer = read(&pat, &page).await;
        (answer.status() == Status::OK).then_some(())
    })
    .await;
    assert_eq!(last_caller(&echo).sub, pat.id(), "the app sees Pat again");
    stack.stop().await.expect("the stack stops cleanly");
}
