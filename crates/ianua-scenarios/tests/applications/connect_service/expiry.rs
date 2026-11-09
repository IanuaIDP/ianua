//! A partner program's description and the day its key stops. Tess writes
//! what the program is for and clears it, sets when its key stops and
//! takes it back to never; a time already past is refused. Once the time
//! comes, the gateway no longer knows the key. Nobody without the right
//! changes either.

use std::time::Duration;

use ianua_scenarios::api::{consumers, routing};
use ianua_scenarios::expect::{Matrix, eventually};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::routes::{Placement, RouteSpec};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::consumers::{DescriptionChange, ExpiryChange, NewConsumer};
use ianua_scenarios::wire::routing::RoutePolicy;
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::support::person;

/// The record a changed description leaves.
const DESCRIBED: &str = "consumers.description_changed";

/// The record a changed expiry leaves.
const EXPIRY_CHANGED: &str = "consumers.credential_expiry_changed";

/// `after` from now, as the API writes a time.
fn from_now(after: time::Duration) -> String {
    (OffsetDateTime::now_utc() + after)
        .format(&Rfc3339)
        .expect("an RFC 3339 time")
}

/// The partner's program, signing in with a key the platform makes.
fn partner_program() -> NewConsumer {
    NewConsumer {
        name: "Orders partner".to_owned(),
        description: None,
        credential_kind: "api_key".to_owned(),
    }
}

/// The app host the route to the partner's API answers on.
async fn app_host(world: &World<'_>) -> String {
    let names = routing::hostnames(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    names.slug_subdomain.unwrap_or(names.uuid_subdomain)
}

/// An answer from `url` for the program holding `key`.
async fn answer_to(client: &Client, url: &str, key: &str) -> Status {
    let call = Call::get(url).header("x-api-key", key);
    client.send::<IgnoredAny>(call).await.status()
}

/// `change` for the partner's description.
fn describing(text: Option<&str>) -> DescriptionChange {
    DescriptionChange {
        description: text.map(str::to_owned),
    }
}

/// Tess writes what the partner's program is for and reads it back, then
/// clears it, on record. She sets a month from now as when its key stops
/// and it is on record too; a time already past is refused, and she takes
/// it back to never.
#[tokio::test]
async fn tess_describes_a_partner_program_and_sets_when_its_key_stops() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let partner = consumers::create(world.tenant(), &partner_program())
        .send(tess)
        .await
        .ok();
    let seen = world.trail().ids().await;

    consumers::describe(
        world.tenant(),
        &partner.id,
        &describing(Some("Reads order status for the courier")),
    )
    .send(tess)
    .await
    .ok();
    world.trail().recorded_after(&seen, DESCRIBED).await;
    let read = consumers::get(world.tenant(), &partner.id)
        .send(tess)
        .await
        .ok();
    assert_eq!(
        read.description.as_deref(),
        Some("Reads order status for the courier")
    );
    consumers::describe(world.tenant(), &partner.id, &describing(None))
        .send(tess)
        .await
        .ok();
    let cleared = consumers::get(world.tenant(), &partner.id)
        .send(tess)
        .await
        .ok();
    assert_eq!(cleared.description, None, "the description is cleared");

    let in_a_month = ExpiryChange {
        expires_at: Some(from_now(time::Duration::days(30))),
    };
    let with_expiry = consumers::change_expiry(world.tenant(), &partner.id, &in_a_month)
        .send(tess)
        .await
        .ok();
    assert!(
        with_expiry.credential_expires_at.is_some(),
        "the key now stops at a set time"
    );
    world.trail().recorded_after(&seen, EXPIRY_CHANGED).await;

    let yesterday = ExpiryChange {
        expires_at: Some(from_now(-time::Duration::days(1))),
    };
    consumers::change_expiry(world.tenant(), &partner.id, &yesterday)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    let never = ExpiryChange { expires_at: None };
    let without = consumers::change_expiry(world.tenant(), &partner.id, &never)
        .send(tess)
        .await
        .ok();
    assert_eq!(without.credential_expires_at, None, "the key never stops");

    stack.stop().await.expect("the stack stops cleanly");
}

/// The partner's program calls its route behind the gateway with its key
/// and reaches the echo app. Tess sets its key to stop in three seconds;
/// once they are up the gateway no longer takes the key, and the refused
/// call never reaches the app.
#[tokio::test]
async fn an_expired_partner_is_refused_at_the_gateway() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let partner = consumers::create(world.tenant(), &partner_program())
        .send(tess)
        .await
        .ok();
    let key = partner.api_key.expect("the key is shown once");
    let host = app_host(&world).await;
    let echo = Echo::start(&stack, &host)
        .await
        .expect("the echo app starts");
    let probe = Client::new(&stack, "a probe").expect("a client for the probe");
    RouteSpec::public("partner-orders", "/orders/*")
        .asking(RoutePolicy::Authenticated)
        .pinned("partner-orders")
        .applied(
            tess,
            &probe,
            Placement {
                tenant: world.tenant(),
                upstream: &echo.url(),
                host: &host,
            },
        )
        .await;
    let caller = Client::new(&stack, "the partner's program").expect("a client for the partner");
    let url = format!("https://{host}/orders/1");
    eventually("the partner's key to be taken", || async {
        (answer_to(&caller, &url, &key).await == Status::OK).then_some(())
    })
    .await;

    let shortly = ExpiryChange {
        expires_at: Some(from_now(time::Duration::seconds(3))),
    };
    consumers::change_expiry(world.tenant(), &partner.id, &shortly)
        .send(tess)
        .await
        .ok();
    tokio::time::sleep(Duration::from_secs(3)).await;

    eventually("the expired key to be refused", || async {
        (answer_to(&caller, &url, &key).await == Status::UNAUTHORIZED).then_some(())
    })
    .await;
    echo.forget();
    assert_eq!(answer_to(&caller, &url, &key).await, Status::UNAUTHORIZED);
    assert!(
        echo.arrivals().is_empty(),
        "the refused call reached nothing"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma, an ordinary user of the tenant, Max, a member with no
/// administrator's rights, Sam from the other company and nobody signed
/// in change neither the program's description nor when its key stops,
/// and nothing is on record.
#[tokio::test]
async fn nobody_without_the_right_changes_a_partners_description_or_expiry() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let uma = person(&world, "uma").await;
    let partner = consumers::create(world.tenant(), &partner_program())
        .send(tess)
        .await
        .ok();
    let seen = world.trail().ids().await;
    let in_a_month = ExpiryChange {
        expires_at: Some(from_now(time::Duration::days(30))),
    };

    for call in [
        consumers::describe(world.tenant(), &partner.id, &describing(Some("Mine now"))).call(),
        consumers::change_expiry(world.tenant(), &partner.id, &in_a_month).call(),
    ] {
        Matrix::new("changing the partner's program", call)
            .refused(uma.client(), Status::FORBIDDEN, "forbidden")
            .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
            .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
            .refused(
                world.anonymous().client(),
                Status::UNAUTHORIZED,
                "unauthenticated",
            )
            .run()
            .await;
    }

    let read = consumers::get(world.tenant(), &partner.id)
        .send(tess)
        .await
        .ok();
    assert_eq!(read.description, None, "the description was not changed");
    assert_eq!(read.credential_expires_at, None, "nor was the expiry");
    world.trail().nothing_after(&seen, DESCRIBED).await;
    world.trail().nothing_after(&seen, EXPIRY_CHANGED).await;

    stack.stop().await.expect("the stack stops cleanly");
}
