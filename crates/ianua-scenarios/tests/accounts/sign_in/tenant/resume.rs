//! A session freezing because it stopped looking like the person who
//! signed in: Pat used it in Berlin, and twenty minutes later someone used
//! it from Poznań. Until Pat proves a factor nothing goes through on it, a
//! code from her own authenticator lifts it, and neither Uma nor nobody
//! signed in can lift it for her.

use std::time::Duration;

use ianua_scenarios::api::{factors, people};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::cities::{BERLIN, POZNAN};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::SessionCode;
use ianua_scenarios::world::World;

use crate::tenant::support::person;

/// A well-formed code nobody's factor shows.
const WRONG_CODE: &str = "000000";

/// The record a freeze leaves.
const SUSPENDED: &str = "authentication.session_suspended";

/// The record a lifted freeze leaves.
const RESUMED: &str = "authentication.session_resumed";

/// The record a wrong code leaves.
const FAILED: &str = "authentication.mfa_failed";

/// How long Pat takes from Berlin to Poznań: twenty minutes, inside every
/// session's idle hour, so nobody else has to sign in again.
const TRAVEL_TIME: Duration = Duration::from_secs(20 * 60);

/// Pat's session is active, so even her right code lifts nothing: it is
/// refused as not suspended. She uses it from Berlin, which places it
/// there. Twenty minutes later Mallory, holding a copy of it, uses it from
/// Poznań: 240 km away, 720 km/h, another country. Mallory's request is
/// refused and the session freezes, recorded once with its reason and no
/// token. Now even Pat's own reads stop. A wrong code is refused and
/// leaves it frozen, and that failure is on record. Uma cannot lift it by
/// naming it, and nobody signed in cannot try. A fresh code from Pat's
/// authenticator lifts it, she reads as herself again, and the resumption
/// is recorded once with no code in it.
#[tokio::test]
async fn a_session_used_too_far_apart_freezes_and_lifts_only_on_its_own_factor() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().placing_callers())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    pat.set_up_authenticator().await;
    let session_id = pat.session_id().to_owned();
    let mut phone = pat.lose_phone();

    let not_frozen = SessionCode {
        session_id: session_id.clone(),
        code: phone.code().await,
    };
    factors::resume_session(world.tenant(), &not_frozen)
        .send(pat.client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    let in_berlin =
        Client::same_bearer_at(pat.client(), &stack, "Pat in Berlin", BERLIN.address(7))
            .expect("a client for Pat in Berlin");
    people::me(world.tenant()).send(&in_berlin).await.ok();
    clock.advance(TRAVEL_TIME);
    let mallory =
        Client::same_bearer_at(pat.client(), &stack, "Mallory in Poznań", POZNAN.address(7))
            .expect("a client for Mallory");

    people::me(world.tenant())
        .send(&mallory)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let trail = world.trail();
    let frozen = trail.recorded(SUSPENDED).await;
    assert_eq!(frozen.details["reason"], "fast travel");
    let secrets = pat.secrets();
    no_secret_leaked(
        &frozen.details.to_string(),
        &secrets.iter().map(String::as_str).collect::<Vec<_>>(),
    );

    let failed_before = trail.count(FAILED).await;
    let wrong = SessionCode {
        session_id: session_id.clone(),
        code: WRONG_CODE.to_owned(),
    };
    factors::resume_session(world.tenant(), &wrong)
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    assert_eq!(
        trail.count(FAILED).await,
        failed_before + 1,
        "the wrong code is on record"
    );
    factors::resume_session(world.tenant(), &wrong)
        .send(uma.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    factors::resume_session(world.tenant(), &wrong)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    let right = SessionCode {
        session_id,
        code: phone.code().await,
    };
    factors::resume_session(world.tenant(), &right)
        .send(pat.client())
        .await
        .ok();
    let own = people::me(world.tenant()).send(pat.client()).await.ok();
    assert_eq!(own.id, pat.id(), "Pat reads as herself again");
    let recorded = trail.recorded(RESUMED).await;
    no_secret_leaked(&recorded.details.to_string(), &[&right.code]);
    assert_eq!(trail.count(RESUMED).await, 1, "the lift is recorded once");
    assert_eq!(
        trail.count(SUSPENDED).await,
        1,
        "the freeze is recorded once"
    );
    people::me(world.tenant()).send(&in_berlin).await.ok();

    stack.stop().await.expect("the stack stops cleanly");
}
