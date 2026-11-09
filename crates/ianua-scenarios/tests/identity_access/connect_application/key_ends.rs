//! An API key with an end: Tess gives the contractor a key for three
//! weeks. It works up to its end, is then refused like a wrong key whether
//! or not the sweep has removed it, and the sweep records it once. An end
//! behind now is refused, and a key cannot make a key that outlives it.

use std::time::Duration as StdDuration;

use ianua_infra::test_support::clock;
use ianua_scenarios::api::{api_keys, people};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::api_keys::{ApiKeyMade, NewApiKey, NewEndingApiKey};
use ianua_scenarios::wire::{Problem, Status};
use ianua_scenarios::world::World;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

/// The scope the contractor's key is made with.
const VIEW_PEOPLE: &str = "idp:users:view";

/// The scope that lets a key make other keys.
const MAKE_KEYS: &str = "idp:api_keys:create";

/// How long the contractor's key lasts.
const THREE_WEEKS: Duration = Duration::weeks(3);

/// From the key being made to a minute before its end.
const TO_A_MINUTE_BEFORE: StdDuration = StdDuration::from_secs(21 * 24 * 3600 - 60);

/// From a minute before its end to a minute after.
const PAST_THE_END: StdDuration = StdDuration::from_secs(120);

/// Longer than the worker's one-second ticks, so the round due at the
/// jump has run and the next is an hour off.
const A_ROUND_OF_THE_SWEEP: StdDuration = StdDuration::from_secs(3);

/// Past the hour until the key sweep's next round.
const PAST_THE_NEXT_ROUND: StdDuration = StdDuration::from_secs(2 * 3600);

/// The record the sweep leaves of a key it removed.
const EXPIRED: &str = "oauth.api_key_expired";

/// A moment as the API reads it.
fn written(moment: OffsetDateTime) -> String {
    moment
        .format(&Rfc3339)
        .expect("a moment writes as RFC 3339")
}

/// A whole second `ahead` of the platform's clock.
fn ahead_by(ahead: Duration) -> OffsetDateTime {
    (clock::now() + ahead)
        .replace_nanosecond(0)
        .expect("zero is a valid fraction")
}

/// A key called `name`, reaching `scopes`, that stops working at `end`.
fn ending(name: &str, scopes: &[&str], end: OffsetDateTime) -> NewEndingApiKey {
    NewEndingApiKey {
        name: name.to_owned(),
        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        expires_at: written(end),
    }
}

/// A client calling the API with `key`.
fn holding(stack: &Stack, actor: &str, key: &str) -> Client {
    let mut client = Client::new(stack, actor).expect("a client");
    client.authorize(key);
    client
}

/// What a read of the tenant's people is refused with, as `client`.
async fn refused_read(world: &World<'_>, client: &Client) -> Problem {
    people::list(world.tenant(), None)
        .send(client)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated")
}

/// Tess makes the contractor a key for three weeks, and it shows its end.
/// A minute before the end it works, however many times it is used in a
/// row. A minute after, with the key still kept since the sweep's next
/// round is not due, it is refused exactly as a wrong key is, so nobody
/// can tell the two apart. Once the sweep's round comes, the key is gone
/// and one record says so.
#[tokio::test]
async fn the_contractors_key_works_to_its_end_and_is_swept_once() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().with("WORKER_SWEEP_TICK_SECONDS", "1"))
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let end = ahead_by(THREE_WEEKS);
    let made: ApiKeyMade =
        api_keys::create_ending(world.tenant(), &ending("contractor", &[VIEW_PEOPLE], end))
            .send(world.admin().client())
            .await
            .ok();
    let contractor = holding(&stack, "the contractor", &made.raw_key);
    let shown = api_keys::get(world.tenant(), &made.id)
        .send(world.admin().client())
        .await
        .ok();
    let shown_end = shown.expires_at.expect("the key shows its end");
    assert_eq!(
        OffsetDateTime::parse(&shown_end, &Rfc3339).expect("RFC 3339"),
        end,
        "the key ends when Tess said"
    );

    clock.advance(TO_A_MINUTE_BEFORE);
    for _ in 0..3 {
        people::list(world.tenant(), None)
            .send(&contractor)
            .await
            .ok();
    }
    world.owner_mut().sign_in(&stack).await;
    tokio::time::sleep(A_ROUND_OF_THE_SWEEP).await;

    clock.advance(PAST_THE_END);
    let past_its_end = refused_read(&world, &contractor).await;
    let mallory = holding(&stack, "Mallory", "ik_live_acme_wrong");
    assert_eq!(
        past_its_end,
        refused_read(&world, &mallory).await,
        "a key past its end reads as a wrong key"
    );
    api_keys::get(world.tenant(), &made.id)
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        world.trail().count(EXPIRED).await,
        0,
        "the sweep has not come yet"
    );

    clock.advance(PAST_THE_NEXT_ROUND);
    world.owner_mut().sign_in(&stack).await;
    world.trail().recorded(EXPIRED).await;
    assert_eq!(world.trail().count(EXPIRED).await, 1, "one record, once");
    api_keys::get(world.tenant(), &made.id)
        .send(world.owner().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    refused_read(&world, &contractor).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess mistypes the end, and it is already behind her. The key is
/// refused and none is made.
#[tokio::test]
async fn a_key_ending_in_the_past_is_refused_when_it_is_made() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    api_keys::create_ending(
        world.tenant(),
        &ending(
            "contractor",
            &[VIEW_PEOPLE],
            ahead_by(-Duration::minutes(1)),
        ),
    )
    .send(world.admin().client())
    .await
    .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    let keys = api_keys::list(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert!(
        keys.items.iter().all(|key| key.name != "contractor"),
        "no key was made"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The contractor's key may make keys and ends in a week. Asked for a key
/// that never ends, or one that ends a day after it, it is refused, so a
/// leaked key leaves no successor behind. A key ending when it does is
/// made.
#[tokio::test]
async fn a_key_cannot_make_a_key_that_outlives_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let end = ahead_by(Duration::weeks(1));
    let made = api_keys::create_ending(
        world.tenant(),
        &ending("contractor", &[VIEW_PEOPLE, MAKE_KEYS], end),
    )
    .send(world.admin().client())
    .await
    .ok();
    let contractor = holding(&stack, "the contractor", &made.raw_key);

    let for_ever = NewApiKey {
        name: "successor".to_owned(),
        scopes: vec![VIEW_PEOPLE.to_owned()],
    };
    api_keys::create(world.tenant(), &for_ever)
        .send(&contractor)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let a_day_later = ending("successor", &[VIEW_PEOPLE], end + Duration::days(1));
    api_keys::create_ending(world.tenant(), &a_day_later)
        .send(&contractor)
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let with_it = ending("nightly script", &[VIEW_PEOPLE], end);
    api_keys::create_ending(world.tenant(), &with_it)
        .send(&contractor)
        .await
        .ok();
    stack.stop().await.expect("the stack stops cleanly");
}
