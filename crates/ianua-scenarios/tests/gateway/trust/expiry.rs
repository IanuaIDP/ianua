//! A session on an app's own host left unused: within the tenant's idle
//! window it goes on working, past it the same cookie reaches nothing, for
//! Pat or anyone holding a copy, until a fresh sign-in.

use std::time::Duration;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::tenants;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Matrix, eventually};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::routes::RouteSpec;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::routing::RoutePolicy;
use ianua_scenarios::wire::tenants::{PasswordAgain, ReplaceSignInSettings};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;
use serde_json::json;

use crate::support::{HostedApp, app_host, customer, last_caller, profile, signed_in_on};

/// How long the tenant lets a session sit unused, in seconds.
const IDLE_SECONDS: u64 = 120;

/// How long the tenant lets a session live in all, in seconds: well past
/// the idle window, so the idle window is what ends it.
const LIFETIME_SECONDS: u64 = 3600;

/// The page every step reads.
const DIARY_PAGE: &str = "/diary/today";

/// Ann sets a two-minute idle window. Pat signs in on the diary app and
/// reads it, and reads it again a minute later. Once the session has sat
/// for more than the window she is told to sign in, the app seeing nothing,
/// and a copy of her cookie Mallory kept is refused the same way. Pat signs
/// in again and is back, the app reading her name.
#[tokio::test]
async fn a_session_left_idle_past_its_window_ends_until_a_fresh_sign_in() {
    let clock = Clock::controlled();
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let echo = Echo::start(&stack, &app_host(&world).await)
        .await
        .expect("the diary app starts");
    let spec = RouteSpec::public("diary", "/diary/*").asking(RoutePolicy::Authenticated);
    let app = HostedApp::opened(&world, "diary", spec, &echo.url()).await;
    shorten_sessions(&world).await;
    let pat = customer(&world, "pat", "Pat Customer").await;
    signed_in_on(&app.host, &pat).await;
    let page = app.page(DIARY_PAGE);
    let cookie = pat
        .client()
        .cookies_for(&page.parse().expect("the page is a URL"))
        .expect("Pat holds the app's session cookie");

    read_as(&pat, &page).await;
    clock.advance(Duration::from_secs(IDLE_SECONDS / 2));
    read_as(&pat, &page).await;
    clock.advance(Duration::from_secs(IDLE_SECONDS * 2));
    eventually("Pat's idle session to end", || async {
        let answer = pat
            .client()
            .send::<IgnoredAny>(Call::get(page.as_str()))
            .await;
        (answer.status() == Status::UNAUTHORIZED).then_some(())
    })
    .await;

    echo.forget();
    let mallory = Client::new(&stack, "Mallory, with a copy of Pat's cookie").expect("a client");
    Matrix::new(
        "using a copy of the idle session",
        Call::get(page.as_str()).header("cookie", &cookie),
    )
    .refused(&mallory, Status::UNAUTHORIZED, "unauthenticated")
    .run()
    .await;
    assert!(
        echo.arrivals().is_empty(),
        "the idle session reached nothing"
    );

    signed_in_on(&app.host, &pat).await;
    read_as(&pat, &page).await;
    assert_eq!(last_caller(&echo).sub, pat.id(), "Pat is back as herself");
    stack.stop().await.expect("the stack stops cleanly");
}

/// `person` reads `page` and is let through.
async fn read_as(person: &Person, page: &str) {
    person
        .client()
        .send::<IgnoredAny>(Call::get(page))
        .await
        .ok();
}

/// Ann sets the tenant's idle window and session lifetime, proving herself
/// with her password.
async fn shorten_sessions(world: &World<'_>) {
    let ann = world.owner();
    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(ann.client())
        .await
        .ok();
    settings
        .rest
        .insert("session_lifetime_secs".to_owned(), json!(LIFETIME_SECONDS));
    settings
        .rest
        .insert("idle_timeout_secs".to_owned(), json!(IDLE_SECONDS));
    let replace = ReplaceSignInSettings {
        settings,
        proof: PasswordAgain {
            password: ann.password().to_owned(),
            code: None,
        },
    };
    tenants::replace_sign_in_settings(world.tenant(), &replace)
        .send(ann.client())
        .await
        .ok();
}
