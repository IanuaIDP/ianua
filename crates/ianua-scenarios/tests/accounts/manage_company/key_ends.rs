//! A company key with an end. Ann gives the nightly export an organization
//! key for one hour; it works, however often it is used, up to the last
//! second of that hour, and from the very second the hour ends it is
//! refused like a wrong key, however recently the platform answered it.

use std::time::Duration as StdDuration;

use ianua_infra::test_support::clock;
use ianua_scenarios::api::{api_keys, members};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::NewEndingOrgApiKey;
use ianua_scenarios::world::World;
use time::format_description::well_known::Rfc3339;

/// How long the nightly export's key lasts: one hour.
const ONE_HOUR: time::Duration = time::Duration::hours(1);

/// From the key being made to the second before its end.
const TO_A_SECOND_BEFORE: StdDuration = StdDuration::from_secs(3599);

/// The second before its end to the very end.
const TO_THE_END: StdDuration = StdDuration::from_secs(1);

/// What the key may do.
const ALL_ORGANIZATION: &str = "org:*:*";

/// Ann makes the nightly export a key for one hour. Three reads in a row
/// a second before its end work, the last answered from the platform's
/// copy of the caller. At the very end the same read is refused.
#[tokio::test]
async fn a_company_key_is_refused_at_its_exact_end_though_just_used() {
    let clock = Clock::fixed();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let end = clock::now() + ONE_HOUR;
    let made = api_keys::create_ending_for_organization(
        world.org(),
        &NewEndingOrgApiKey {
            name: "Nightly export".to_owned(),
            scopes: vec![ALL_ORGANIZATION.to_owned()],
            expires_at: end.format(&Rfc3339).expect("a moment writes as RFC 3339"),
        },
    )
    .send(world.owner().client())
    .await
    .ok();
    let mut export = Client::new(&stack, "the nightly export").expect("a client");
    export.authorize(&made.raw_key);

    clock.advance(TO_A_SECOND_BEFORE);
    for _ in 0..3 {
        members::list(world.org(), None).send(&export).await.ok();
    }

    clock.advance(TO_THE_END);
    members::list(world.org(), None)
        .send(&export)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    stack.stop().await.expect("the stack stops cleanly");
}
