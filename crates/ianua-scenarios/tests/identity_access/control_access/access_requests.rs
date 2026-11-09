//! Asking for access for a while: Pat asks for a place in a group, Tess
//! answers, and only an approval gives anything, for as long as was asked.
//! Nobody answers their own request, Max and Sam answer none, a request
//! past the tenant's limit is refused, and one nobody answers runs out.

use std::time::Duration;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{control_access, policies};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Matrix, eventually};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::control_access::{AccessRequestDetail, AccessRequestLimit};
use ianua_scenarios::wire::policies::{AskForGroup, AskedGroup};
use ianua_scenarios::world::World;

use crate::support::{
    USER, comes_to_be_refused, comes_to_read, group_with_role, person, reader, reads_the_users,
    refused_the_users,
};

/// An hour, as a request's length and the tenant's limit are written.
const AN_HOUR: i64 = 3600;

/// How a person asking for a place in a group says why.
const REASON: &str = "I cover the help desk this week";

/// The body of a request for a place in `group` for `length_seconds`.
fn asking(group: &str, length_seconds: i64) -> AskForGroup {
    AskForGroup {
        asked: AskedGroup {
            kind: "group",
            id: group.to_owned(),
        },
        reason: REASON.to_owned(),
        length_seconds,
    }
}

/// `person` asks for a place in `group` for `length_seconds`; the
/// request's id.
async fn asks(world: &World<'_>, person: &mut Person, group: &str, length: i64) -> String {
    person
        .send(policies::ask_for_group(
            world.tenant(),
            &asking(group, length),
        ))
        .await
        .ok()
        .id
}

/// Pat may not read the users. She asks for an hour in the Readers group,
/// and asking gives her nothing. Tess finds the request among those still
/// waiting; Max may not list them, though Pat may list her own. Tess
/// approves: Pat reads the users, holding the place until an end the
/// platform shows. Two hours later, signed in again, Pat is refused: the
/// place counted for the hour she asked and no more, and the sweep records
/// its end.
#[tokio::test]
async fn pat_asks_for_an_hour_in_a_group_and_it_ends_when_the_hour_is_up() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().with("WORKER_SWEEP_TICK_SECONDS", "1"))
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    let role = reader(&world).await;
    let readers = group_with_role(&world, "Readers", &role).await;
    refused_the_users(&world, &pat).await;

    let asked = pat
        .send(policies::ask_for_group(
            world.tenant(),
            &asking(&readers, AN_HOUR),
        ))
        .await
        .ok();
    assert_eq!(asked.status, "pending", "asking leaves it pending");
    refused_the_users(&world, &pat).await;
    let waiting = control_access::list_requests(world.tenant(), &[("status", "pending")])
        .send(world.admin().client())
        .await
        .ok();
    assert!(waiting.items.iter().any(|item| item.id == asked.id));
    control_access::list_requests(world.tenant(), &[])
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let own = control_access::list_requests(
        world.tenant(),
        &[("asked_by_kind", USER), ("asked_by_id", pat.id())],
    )
    .send(pat.client())
    .await
    .ok();
    assert_eq!(own.items.len(), 1, "Pat lists her own request");

    let approved = policies::approve_request(world.tenant(), &asked.id)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(approved.status, "approved");
    comes_to_read(&world, &pat, "after Tess approves").await;
    reads_the_users(&world, &pat).await;
    let access = control_access::principal_access(world.tenant(), USER, pat.id())
        .send(world.admin().client())
        .await
        .ok();
    let held = access
        .memberships
        .iter()
        .find(|membership| membership.group_id == readers)
        .expect("Pat holds a place in Readers");
    assert!(held.until.is_some(), "the place has an end");
    world
        .trail()
        .recorded("authorization.access_requested")
        .await;
    world
        .trail()
        .recorded("authorization.access_request_approved")
        .await;

    clock.advance(Duration::from_secs(2 * 3600));
    world.owner_mut().sign_in(&stack).await;
    pat.sign_in(&stack).await;
    comes_to_be_refused(&world, &pat, "after her hour").await;
    world
        .trail()
        .recorded("authorization.group_membership_expired")
        .await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Max, Sam and nobody signed in neither approve nor deny Pat's request,
/// and nobody answers their own: Tess, who could give the place, asks for
/// it herself and is refused approving it, and Ann approves it. Pat's
/// request is still waiting, and only Tess's answer was recorded.
#[tokio::test]
async fn nobody_answers_their_own_request_and_mallory_answers_none() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    let role = reader(&world).await;
    let readers = group_with_role(&world, "Readers", &role).await;
    let pats = asks(&world, &mut pat, &readers, AN_HOUR).await;

    for answer in [
        policies::approve_request(world.tenant(), &pats).call(),
        control_access::deny_request(world.tenant(), &pats).call(),
    ] {
        Matrix::new("answering Pat's request", answer)
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
    refused_the_users(&world, &pat).await;

    let tess = policies::ask_for_group(world.tenant(), &asking(&readers, AN_HOUR))
        .send(world.admin().client())
        .await
        .ok();
    policies::approve_request(world.tenant(), &tess.id)
        .send(world.admin().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let answered = policies::approve_request(world.tenant(), &tess.id)
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(answered.status, "approved", "Ann may answer Tess's request");

    let waiting = control_access::list_requests(world.tenant(), &[("status", "pending")])
        .send(world.admin().client())
        .await
        .ok();
    assert!(
        waiting.items.iter().any(|item| item.id == pats),
        "Pat's request still waits"
    );
    assert_eq!(
        world
            .trail()
            .count("authorization.access_request_approved")
            .await,
        1,
        "only Tess's request was approved"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess denies Pat's request, naming herself as who answered, and Pat
/// reads nothing; answering again is refused as no longer open. Pat
/// withdraws a second request; Max cannot tell whether it exists, and only
/// Pat may take it back. Withdrawing it twice is refused. Both answers are
/// recorded once.
#[tokio::test]
async fn tess_denies_pat_and_pat_withdraws_her_second_request() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    let role = reader(&world).await;
    let readers = group_with_role(&world, "Readers", &role).await;
    let first = asks(&world, &mut pat, &readers, AN_HOUR).await;

    let denied = control_access::deny_request(world.tenant(), &first)
        .send(world.admin().client())
        .await
        .ok();
    assert_denied(&denied, world.admin().id());
    refused_the_users(&world, &pat).await;
    control_access::deny_request(world.tenant(), &first)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    let second = asks(&world, &mut pat, &readers, AN_HOUR).await;
    control_access::cancel_request(world.tenant(), &second)
        .send(world.member().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    control_access::cancel_request(world.tenant(), &second)
        .send(world.admin().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let cancelled = control_access::cancel_request(world.tenant(), &second)
        .send(pat.client())
        .await
        .ok();
    assert_eq!(cancelled.status, "cancelled");
    control_access::cancel_request(world.tenant(), &second)
        .send(pat.client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    assert_eq!(
        world
            .trail()
            .count("authorization.access_request_denied")
            .await,
        1,
        "the denial is recorded once"
    );
    assert_eq!(
        world
            .trail()
            .count("authorization.access_request_cancelled")
            .await,
        1,
        "the withdrawal is recorded once"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The denial answers as denied and names who answered.
fn assert_denied(denied: &AccessRequestDetail, answered_by: &str) {
    assert_eq!(denied.status, "denied");
    let answerer = denied.answered_by.as_ref().expect("the answer names Tess");
    assert_eq!(answerer.id, answered_by);
}

/// The tenant allows thirty days until Tess sets a shorter limit. Max may
/// read the limit but not change it. Tess holds requests to an hour: Pat
/// is refused asking for two, and may ask for one. Setting the same limit
/// records nothing, and a limit past thirty days is refused.
#[tokio::test]
async fn tess_holds_pat_to_the_tenants_longest_request() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    let role = reader(&world).await;
    let readers = group_with_role(&world, "Readers", &role).await;

    let default = control_access::request_limit(world.tenant())
        .send(world.member().client())
        .await
        .ok();
    assert_eq!(default.longest_seconds, 30 * 24 * AN_HOUR);
    let an_hour = AccessRequestLimit {
        longest_seconds: AN_HOUR,
    };
    control_access::change_request_limit(world.tenant(), &an_hour)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let changed = control_access::change_request_limit(world.tenant(), &an_hour)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(changed.longest_seconds, AN_HOUR);
    pat.send(policies::ask_for_group(
        world.tenant(),
        &asking(&readers, 2 * AN_HOUR),
    ))
    .await
    .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    asks(&world, &mut pat, &readers, AN_HOUR).await;

    control_access::change_request_limit(world.tenant(), &an_hour)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(
        world
            .trail()
            .count("authorization.access_request_policy_changed")
            .await,
        1,
        "setting the limit already set records nothing"
    );
    let too_long = AccessRequestLimit {
        longest_seconds: 31 * 24 * AN_HOUR,
    };
    control_access::change_request_limit(world.tenant(), &too_long)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat asks for a place and nobody answers. Eight days on, the sweep has
/// closed her request as run out and recorded it. Ann, who could have
/// given it, finds it closed and is refused approving it; Pat still may
/// not read the users.
#[tokio::test]
async fn a_request_nobody_answers_runs_out_after_a_week() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().with("WORKER_SWEEP_TICK_SECONDS", "1"))
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    let role = reader(&world).await;
    let readers = group_with_role(&world, "Readers", &role).await;
    let request = asks(&world, &mut pat, &readers, AN_HOUR).await;

    clock.advance(Duration::from_secs(8 * 24 * 3600));
    world.owner_mut().sign_in(&stack).await;
    pat.sign_in(&stack).await;
    eventually("Pat's request to run out", || async {
        let listed = control_access::list_requests(world.tenant(), &[])
            .send(world.owner().client())
            .await
            .ok();
        listed
            .items
            .iter()
            .any(|item| item.id == request && item.status == "expired")
            .then_some(())
    })
    .await;
    world
        .trail()
        .recorded("authorization.access_request_expired")
        .await;

    policies::approve_request(world.tenant(), &request)
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    refused_the_users(&world, &pat).await;
    stack.stop().await.expect("the stack stops cleanly");
}
