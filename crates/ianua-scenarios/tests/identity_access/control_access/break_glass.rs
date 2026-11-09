//! Emergency access: Tess gives Pat named rights for a short while, or
//! Pat gives herself what the tenant's policy lets her. It ends when
//! closed or when its time is up, every grant is recorded, and nobody
//! without the right opens or closes one, nor learns who exists.

use std::time::Duration;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::control_access;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::control_access::{BreakGlass, BreakGlassPolicy};
use ianua_scenarios::wire::roles::SystemPermission;
use ianua_scenarios::world::World;

use crate::support::{
    comes_to_be_refused, comes_to_read, person, reads_the_users, refused_the_users,
};

/// An hour, as a grant's length is written.
const AN_HOUR: i64 = 3600;

/// Why Pat needs the access.
const REASON: &str = "The billing database is down and Pat is on call";

/// A grant to `person` of reading the users for `duration_seconds`.
fn for_reading(person: &Person, duration_seconds: i64) -> BreakGlass {
    BreakGlass {
        user_id: person.id().to_owned(),
        reason: REASON.to_owned(),
        duration_seconds,
        system_permissions: vec![SystemPermission::new("Users", "View")],
    }
}

/// Tess grants Pat an hour of reading the users: Pat reads them, and a
/// second grant is refused while the first runs. Tess closes it: Pat is
/// refused again, closing it twice is refused, and both are recorded.
/// Tess grants her another hour; two hours later, signed in again, Pat
/// is refused with nobody having closed it.
#[tokio::test]
async fn emergency_access_ends_when_closed_and_when_its_time_is_up() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().with("WORKER_SWEEP_TICK_SECONDS", "1"))
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    refused_the_users(&world, &pat).await;

    let grant = control_access::break_glass(world.tenant(), &for_reading(&pat, AN_HOUR))
        .send(world.admin().client())
        .await
        .ok();
    comes_to_read(&world, &pat, "under her emergency access").await;
    reads_the_users(&world, &pat).await;
    control_access::break_glass(world.tenant(), &for_reading(&pat, AN_HOUR))
        .send(world.admin().client())
        .await
        .refused(Status::CONFLICT, "conflict");
    world
        .trail()
        .recorded("authentication.break_glass_granted")
        .await;

    control_access::revoke_break_glass(world.tenant(), &grant.grant_id)
        .send(world.admin().client())
        .await
        .ok();
    comes_to_be_refused(&world, &pat, "once the grant is closed").await;
    control_access::revoke_break_glass(world.tenant(), &grant.grant_id)
        .send(world.admin().client())
        .await
        .refused(Status::CONFLICT, "conflict");
    world
        .trail()
        .recorded("authentication.break_glass_revoked")
        .await;

    control_access::break_glass(world.tenant(), &for_reading(&pat, AN_HOUR))
        .send(world.admin().client())
        .await
        .ok();
    comes_to_read(&world, &pat, "under her second grant").await;
    clock.advance(Duration::from_secs(2 * 3600));
    world.owner_mut().sign_in(&stack).await;
    pat.sign_in(&stack).await;
    comes_to_be_refused(&world, &pat, "when her hour is up").await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// A tenant starts letting nobody give themselves anything: Pat is
/// refused. Tess lets users give themselves reading the users; Max may
/// not set that. Pat is still refused asking herself more than the policy
/// lets, and given what it does, reads the users and may close her own
/// grant. The policy change is recorded.
#[tokio::test]
async fn pat_gives_herself_only_what_the_tenants_policy_lets() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;

    control_access::break_glass(world.tenant(), &for_reading(&pat, AN_HOUR))
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let letting_reading = BreakGlassPolicy {
        system_permissions: vec![SystemPermission::new("Users", "View")],
        custom_permissions: vec![],
    };
    control_access::change_break_glass_policy(world.tenant(), &letting_reading)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    control_access::change_break_glass_policy(world.tenant(), &letting_reading)
        .send(world.admin().client())
        .await
        .ok();
    world
        .trail()
        .recorded("authorization.break_glass_policy_changed")
        .await;

    let mut asking_more = for_reading(&pat, AN_HOUR);
    asking_more.system_permissions = vec![SystemPermission::new("Users", "Update")];
    control_access::break_glass(world.tenant(), &asking_more)
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let granted = control_access::break_glass(world.tenant(), &for_reading(&pat, AN_HOUR))
        .send(pat.client())
        .await
        .ok();
    comes_to_read(&world, &pat, "under her own grant").await;
    control_access::revoke_break_glass(world.tenant(), &granted.grant_id)
        .send(pat.client())
        .await
        .ok();
    comes_to_be_refused(&world, &pat, "once she closed it").await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Max, Sam and nobody signed in open no grant for Pat; Max cannot tell
/// her from someone who does not exist. Tess may not open one for longer
/// than a day, for no time at all, or naming nothing. Max may neither
/// close Pat's grant nor learn it exists. No refused attempt is recorded.
#[tokio::test]
async fn nobody_without_the_right_opens_or_closes_emergency_access() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let granting = control_access::break_glass(world.tenant(), &for_reading(&pat, AN_HOUR)).call();

    Matrix::new("opening a grant for Pat", granting)
        .refused(world.member().client(), Status::NOT_FOUND, "not_found")
        .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
        .refused(
            world.anonymous().client(),
            Status::UNAUTHORIZED,
            "unauthenticated",
        )
        .run()
        .await;
    assert_eq!(
        world
            .trail()
            .count("authentication.break_glass_granted")
            .await,
        0,
        "no refused grant is recorded"
    );

    let tess = world.admin().client();
    control_access::break_glass(world.tenant(), &for_reading(&pat, 25 * AN_HOUR))
        .send(tess)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    control_access::break_glass(world.tenant(), &for_reading(&pat, 0))
        .send(tess)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let mut naming_nothing = for_reading(&pat, AN_HOUR);
    naming_nothing.system_permissions = vec![];
    control_access::break_glass(world.tenant(), &naming_nothing)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    let granted = control_access::break_glass(world.tenant(), &for_reading(&pat, AN_HOUR))
        .send(tess)
        .await
        .ok();
    control_access::revoke_break_glass(world.tenant(), &granted.grant_id)
        .send(world.member().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    comes_to_read(&world, &pat, "with her grant still open").await;
    stack.stop().await.expect("the stack stops cleanly");
}
