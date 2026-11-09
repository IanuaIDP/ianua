//! Where a caller arrives from, as company events that start workflows.
//! The stack writes a city database of its own placing three networks, in
//! Berlin, Poznań and São Paulo, and each client here stands for an
//! address in one of them.
//!
//! - Pat signs in in Berlin and, twenty minutes later, in Poznań: a
//!   journey of about 720 km/h into a country Pat never signed in from.
//!   Ann's workflow on `authentication.risky_sign_in` tells Bea that Pat
//!   signed in from Poland, once; the first sign-in, and Pat signing in
//!   again in Poznań, start nothing.
//! - Pat signs in in Berlin and, three days later, in São Paulo: an
//!   unhurried trip, but to a country Pat never signed in from, so Ann's
//!   workflow tells Bea it was Brazil, once.
//! - Acme's deploy key is first used in Germany, where it lives, then in
//!   Brazil. Ann's workflow on `oauth.api_key_used_from_new_country`
//!   pauses the key, once, and the next call from Brazil is refused; once
//!   Tess resumes it, calls from Brazil and Germany start nothing more.

use std::time::Duration;

use ianua_scenarios::actors::{Person, PersonAccount};
use ianua_scenarios::api::{api_keys, notifications, people, workflows};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::eventually;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::cities::{BERLIN, City, POZNAN, SAO_PAULO};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::api_keys::{ApiKeyMade, NewApiKey};
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::workflows::Graph;
use ianua_scenarios::world::{MEMBER_ROLE, World};

use crate::company_events::{on_event, runs_of, started_runs, watched_quietly};
use crate::company_steps::{company_step, in_order, output, through_run};
use crate::support::{ended, invited, read, written};

/// The event a sign-in that looked high risk raises.
const RISKY: &str = "authentication.risky_sign_in";

/// The event a key raises the first time it is used from another country.
const NEW_COUNTRY: &str = "oauth.api_key_used_from_new_country";

/// How long Pat takes from Berlin to Poznań: twenty minutes, inside every
/// session's idle hour, so nobody else has to sign in again.
const TRAVEL_TIME: Duration = Duration::from_secs(20 * 60);

/// What Ann's workflow tells Bea.
const NOTICE_TITLE: &str = "Someone signed in from somewhere new";

/// How long Pat takes from Berlin to São Paulo: three days, slow enough
/// for any traveller over its 10,000 km, and past every session's idle
/// hour, so Ann and Bea sign in again.
const LONG_TRIP: Duration = Duration::from_secs(3 * 86_400);

/// The key of the step pausing the key.
const PAUSE_STEP: &str = "pause";

/// Pat's account and password, to sign in as from any city.
struct Traveller {
    account: PersonAccount,
    password: String,
}

impl Traveller {
    /// Pat signing in through a client of their own that stands for an
    /// address in `city`.
    fn in_city(&self, world: &World<'_>, city: City) -> Person {
        let actor = format!("Pat in {}", city.country());
        let client = Client::at(world.stack(), &actor, city.address(7)).expect("a client for Pat");
        Person::new(client, self.account.clone(), &self.password)
    }
}

/// Tell the person at `address` where someone signed in from.
fn telling(address: &str) -> Graph {
    in_order(vec![company_step(
        "tell",
        "notify",
        "communicate",
        vec![
            ("person", written(address)),
            ("title", written(NOTICE_TITLE)),
            ("message", read("trigger.country")),
        ],
    )])
}

/// Sign out the person the event names, then tell them why.
fn signing_out_who_it_names() -> Graph {
    in_order(vec![
        company_step(
            "sign-out",
            "sign-out",
            "write",
            vec![("person", read("trigger.user.id"))],
        ),
        company_step(
            "tell",
            "notify",
            "communicate",
            vec![
                ("person", read("trigger.user.id")),
                ("title", written(NOTICE_TITLE)),
            ],
        ),
    ])
}

/// Ann's workflow signs out whoever signs in from somewhere risky. Pat
/// joins in Berlin and signs in in Poznań twenty minutes later. The run the
/// sign-in starts acts on Pat, named by the event, and ends that session.
#[tokio::test]
async fn a_risky_sign_in_signs_out_the_person_it_names() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().placing_callers())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let workflow = on_event(&world, RISKY, signing_out_who_it_names()).await;
    let pat = pat_joined_in_berlin(&world).await;
    watched_quietly().await;

    clock.advance(TRAVEL_TIME);
    let mut in_poznan = pat.in_city(&world, POZNAN);
    in_poznan.sign_in(&stack).await;
    let runs = started_runs(&world, &workflow.id).await;
    let ran = ended(&world, &runs[0].id, "succeeded").await;

    assert!(output(&ran, "sign-out")["sessions_ended"].as_u64() >= Some(1));
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann's workflow on risky sign-ins is in service, telling Bea. Pat joins
/// and signs in in Berlin, which has nothing to compare with and starts
/// nothing. Twenty minutes later Pat signs in in Poznań, 240 km away: the
/// sign-in goes ahead, recorded as a fast journey into a new country, and
/// Ann's workflow starts once and tells Bea it came from Poland. Pat signs
/// in in Poznań again a moment later, from the place of the last sign-in,
/// and nothing more starts.
#[tokio::test]
async fn a_sign_in_after_a_fast_journey_starts_the_workflow_once() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().placing_callers())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let bea = invited(&world, ("bea", "Bea On Call"), &[("Workflows", "View")]).await;
    let workflow = on_event(&world, RISKY, telling(bea.email())).await;
    let pat = pat_joined_in_berlin(&world).await;
    watched_quietly().await;
    let after_berlin = runs_of(&world, &workflow.id).await.len();

    clock.advance(TRAVEL_TIME);
    let mut in_poznan = pat.in_city(&world, POZNAN);
    in_poznan.sign_in(&stack).await;
    let runs = started_runs(&world, &workflow.id).await;
    ended(&world, &runs[0].id, "succeeded").await;
    in_poznan.sign_in(&stack).await;
    watched_quietly().await;

    assert_eq!(after_berlin, 0, "the first sign-in starts nothing");
    assert_eq!(runs[0].cause, "event");
    check_bea_told(&world, &bea, POZNAN.country()).await;
    assert_eq!(
        runs_of(&world, &workflow.id).await.len(),
        1,
        "one risky sign-in, one run"
    );
    let recorded = world.trail().entries(RISKY).await;
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].details["sign"], "fast_travel_to_new_country");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann's workflow on risky sign-ins is in service, telling Bea. Pat joins
/// and signs in in Berlin. Three days later Pat signs in in São Paulo: no
/// journey too fast, but a country Pat never signed in from, so the
/// sign-in goes ahead, recorded with its new country, Brazil, and Ann's
/// workflow starts once and tells Bea. Pat signs in there again, a
/// country now known, and nothing more starts.
#[tokio::test]
async fn a_first_sign_in_from_another_country_starts_the_workflow_once() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().placing_callers())
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let mut bea = invited(&world, ("bea", "Bea On Call"), &[("Workflows", "View")]).await;
    let workflow = on_event(&world, RISKY, telling(bea.email())).await;
    let pat = pat_joined_in_berlin(&world).await;

    clock.advance(LONG_TRIP);
    world.owner_mut().sign_in(&stack).await;
    bea.sign_in(&stack).await;
    let mut in_sao_paulo = pat.in_city(&world, SAO_PAULO);
    in_sao_paulo.sign_in(&stack).await;
    let runs = started_runs(&world, &workflow.id).await;
    succeeded_for_ann(&world, &runs[0].id).await;
    in_sao_paulo.sign_in(&stack).await;
    watched_quietly().await;

    assert_eq!(runs[0].cause, "event");
    check_bea_told(&world, &bea, SAO_PAULO.country()).await;
    assert_eq!(
        runs_of(&world, &workflow.id).await.len(),
        1,
        "one new country, one run"
    );
    let recorded = world.trail().entries(RISKY).await;
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].details["sign"], "new_country");
    assert_eq!(recorded[0].details["country"], "BR");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Waits until the run `execution_id` has ended, as Ann reads it, and
/// checks it succeeded: Tess's session ran out on the long trip.
async fn succeeded_for_ann(world: &World<'_>, execution_id: &str) {
    let execution = eventually("the run to end", || async {
        let execution = workflows::execution(world.tenant(), execution_id)
            .send(world.owner().client())
            .await
            .ok();
        (execution.status != "running").then_some(execution)
    })
    .await;
    assert_eq!(execution.status, "succeeded", "{:?}", execution.steps);
}

/// Pat, whom Tess invites with the Member role, accepting the mailed link
/// and signing in from Berlin; Pat's account and password.
async fn pat_joined_in_berlin(world: &World<'_>) -> Traveller {
    let newcomer = world.newcomer("pat", "Pat Traveller");
    let traveller = Traveller {
        account: newcomer.account().clone(),
        password: newcomer.password().to_owned(),
    };
    let mut pat = traveller.in_city(world, BERLIN);
    let invitation = InviteUser {
        email: pat.email().to_owned(),
        display_name: pat.account().display_name.clone(),
        role_id: world.role_id(MEMBER_ROLE).await,
    };
    let made = people::invite(world.tenant(), &invitation)
        .send(world.admin().client())
        .await
        .ok();
    pat.record_invitation(&made.id);
    pat.accept_invitation(world.stack()).await;
    pat.sign_in(world.stack()).await;
    traveller
}

/// Bea finds the notice in her inbox, naming the country `country`.
async fn check_bea_told(world: &World<'_>, bea: &Person, country: &str) {
    let inbox = notifications::inbox(world.tenant())
        .send(bea.client())
        .await
        .ok();
    let notice = inbox
        .items
        .iter()
        .find(|notice| notice.title == NOTICE_TITLE)
        .expect("Bea was told");
    assert_eq!(notice.body.as_deref(), Some(country));
}

/// Pause the key the event names.
fn pausing_the_key() -> Graph {
    in_order(vec![company_step(
        PAUSE_STEP,
        "pause-key",
        "write",
        vec![("key", read("trigger.key.id"))],
    )])
}

/// Ann's workflow on keys used from a new country is in service, pausing
/// the key. Acme's deploy program reads people from Germany, the key's
/// first country, which starts nothing, and a moment later, well inside
/// the minute between two stamps of its last use, from Brazil. Ann's
/// workflow starts once and pauses the key, as Ann, through that run, and
/// the next call from Brazil is refused. Tess resumes the key; calls from
/// Brazil and from Germany work again, both countries now known, and
/// nothing more starts.
#[tokio::test]
async fn a_key_used_in_germany_and_then_in_brazil_starts_the_workflow_once() {
    let stack = Stack::start(Profile::standard().placing_callers())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let workflow = on_event(&world, NEW_COUNTRY, pausing_the_key()).await;
    let key = deploy_key(&world).await;
    let in_germany = program_in(&world, &key, BERLIN);
    let in_brazil = program_in(&world, &key, SAO_PAULO);

    let first = reads(&world, &in_germany).await;
    let after_germany = runs_of(&world, &workflow.id).await.len();
    let abroad = reads(&world, &in_brazil).await;
    let runs = started_runs(&world, &workflow.id).await;
    let paused = ended(&world, &runs[0].id, "succeeded").await;
    let while_paused = reads(&world, &in_brazil).await;
    api_keys::resume(world.tenant(), &key.id)
        .send(world.admin().client())
        .await
        .ok();
    let brazil_again = reads(&world, &in_brazil).await;
    let germany_again = reads(&world, &in_germany).await;
    watched_quietly().await;

    assert_eq!(first, Status::OK);
    assert_eq!(after_germany, 0, "the key's first country starts nothing");
    assert_eq!(abroad, Status::OK, "the call that raised the event went on");
    assert_eq!(runs[0].cause, "event");
    assert_eq!(output(&paused, PAUSE_STEP)["key_id"], key.id.as_str());
    through_run(
        &world,
        "oauth.api_key_paused",
        &paused.id,
        world.owner().email(),
    )
    .await;
    assert_eq!(while_paused, Status::UNAUTHORIZED);
    assert_eq!((brazil_again, germany_again), (Status::OK, Status::OK));
    assert_eq!(
        runs_of(&world, &workflow.id).await.len(),
        1,
        "one new country, one run"
    );
    assert_eq!(world.trail().count(NEW_COUNTRY).await, 1);
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess makes Acme's deploy key, which may read people.
async fn deploy_key(world: &World<'_>) -> ApiKeyMade {
    let key = NewApiKey {
        name: "deploy".to_owned(),
        scopes: vec!["idp:users:view".to_owned()],
    };
    api_keys::create(world.tenant(), &key)
        .send(world.admin().client())
        .await
        .ok()
}

/// The deploy program calling with `key` from an address in `city`.
fn program_in(world: &World<'_>, key: &ApiKeyMade, city: City) -> Client {
    let actor = format!("the deploy program in {}", city.country());
    let mut client =
        Client::at(world.stack(), &actor, city.address(20)).expect("a client for the program");
    client.authorize(&key.raw_key);
    client
}

/// How the platform answers the program reading people.
async fn reads(world: &World<'_>, program: &Client) -> Status {
    people::list(world.tenant(), None)
        .send(program)
        .await
        .status()
}
