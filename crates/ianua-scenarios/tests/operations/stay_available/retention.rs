//! Retention at its edges, on a clock the scenario moves: what is an hour
//! past its keeping period is removed by the worker's sweep, what is an
//! hour short of it is kept, and the next round removes that too once its
//! time has come. Each removal is recorded once, by the platform.
//!
//! - Audit records: a tenant keeps its records a year by default.
//! - Memories set to be deleted: each waits thirty days, in which it can
//!   still be brought back, then goes for good.
//! - Notifications: a notice is kept ninety days.
//! - Evaluations: an ended evaluation is kept thirty days.
//! - Workflow runs: a run that ended is kept ninety days, and the audit
//!   trail of its start is not touched by its going.

use std::time::Duration;

use ianua_scenarios::actors::{Member, Person};
use ianua_scenarios::api::{audit, memories, notifications, people, roles, workflows};
use ianua_scenarios::automation::{
    connected_account, delivery_graph, drafted, ended, published, started,
};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Waiting, eventually, eventually_paced};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{LetterEmbeddings, OutsideService};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::memories::{DeleteMemory, Memory, NewMemory};
use ianua_scenarios::wire::notifications::Notification;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::roles::{AssignRole, NewRole, SystemPermission};
use ianua_scenarios::wire::workflows::{
    CaseCheck, Evaluation, EvaluationCase, NewEvaluationSet, Trigger, Workflow,
};
use ianua_scenarios::world::{MEMBER_ROLE, World};
use serde_json::json;

use crate::support::watched_for;

/// An hour.
const AN_HOUR: Duration = Duration::from_secs(3600);

/// A day.
const A_DAY: Duration = Duration::from_secs(86_400);

/// How long a tenant keeps its audit records unless its posture says
/// otherwise: a year.
const DEFAULT_RETENTION: Duration = Duration::from_secs(365 * 86_400);

/// How long a memory set to be deleted can still be brought back.
const DELETION_WAIT: Duration = Duration::from_secs(30 * 86_400);

/// How long a notice is kept.
const NOTICES_KEPT: Duration = Duration::from_secs(90 * 86_400);

/// How long an ended evaluation is kept.
const EVALUATIONS_KEPT: Duration = Duration::from_secs(30 * 86_400);

/// How long a workflow run that ended is kept.
const RUNS_KEPT: Duration = Duration::from_secs(90 * 86_400);

/// How long the platform is watched for a removal that must not come, on
/// the real clock: three of the worker's one-second sweep ticks.
const QUIET: Duration = Duration::from_secs(3);

/// How Ann waits for a sweep: once a second, as a person refreshing a
/// page would, so the platform's rate limit never answers, for at most a
/// minute.
const AS_A_PERSON_ASKS: Waiting = Waiting {
    patience: Duration::from_secs(60),
    every: Duration::from_secs(1),
};

/// The record an invitation into the tenant leaves.
const INVITED: &str = "identity.user_invited";

/// The record a purge of audit records leaves.
const RECORDS_PURGED: &str = "tenant.audit_records_purged";

/// The record a memory deleted for good leaves.
const MEMORY_PURGED: &str = "workflows.memory_purged";

/// The model the stand-in embedding server says it serves.
const LETTERS: &str = "letters-v1";

/// The category a role given or taken back is told under.
const AUTHORIZATION: &str = "Authorization";

/// The record a run started leaves.
const RUN_STARTED: &str = "workflows.execution_started";

/// Ann invites Uma, and two hours later Pat. A year less an hour after
/// Pat's invitation the worker's daily purge runs: Uma's record, an hour
/// past the year, is gone, Pat's, an hour short of it, is kept, and the
/// purge is recorded. A day later the next round removes Pat's record too,
/// and that purge is recorded as well.
#[tokio::test]
async fn an_audit_record_an_hour_past_its_year_goes_and_one_an_hour_short_stays() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().with("WORKER_SWEEP_TICK_SECONDS", "1"))
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let member = world.role_id(MEMBER_ROLE).await;
    let uma = invited(&world, &member, "uma").await;
    clock.advance(2 * AN_HOUR);
    world.owner_mut().sign_in(&stack).await;
    let pat = invited(&world, &member, "pat").await;
    let purged_before = recorded(&world, RECORDS_PURGED).await;

    clock.advance(DEFAULT_RETENTION - AN_HOUR);
    world.owner_mut().sign_in(&stack).await;
    let purged = purges_reach(&world, purged_before + 1).await;
    assert!(
        !invitation_recorded(&world, &uma).await,
        "Uma's invitation, an hour past the year, is purged"
    );
    assert!(
        invitation_recorded(&world, &pat).await,
        "Pat's invitation, an hour short of the year, is kept"
    );

    clock.advance(A_DAY);
    world.owner_mut().sign_in(&stack).await;
    purges_reach(&world, purged + 1).await;
    assert!(
        !invitation_recorded(&world, &pat).await,
        "Pat's invitation is purged by the next day's round"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann keeps two memories and sets the old one to be deleted, typing its
/// name, and two hours later the recent one. Thirty days less an hour
/// after the second, the worker's sweep deletes the old memory for good,
/// an hour past its wait, and records it once; the recent one, an hour
/// short of its wait, is still there and still set to be deleted, and Ann
/// brings it back. Nothing more is deleted afterwards.
#[tokio::test]
async fn a_memory_an_hour_past_its_wait_is_deleted_and_one_an_hour_short_comes_back() {
    let embeddings = LetterEmbeddings::start()
        .await
        .expect("the embedding server starts");
    let clock = Clock::controlled();
    let stack = Stack::start(
        Profile::standard()
            .with("EMBEDDING_URL", &embeddings.base())
            .with("EMBEDDING_MODEL", LETTERS)
            .with("WORKER_SWEEP_TICK_SECONDS", "1"),
    )
    .await
    .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let old = memory_made(&world, "Old tickets").await;
    let recent = memory_made(&world, "Recent tickets").await;
    set_to_delete(&world, &old).await;
    clock.advance(2 * AN_HOUR);
    world.owner_mut().sign_in(&stack).await;
    set_to_delete(&world, &recent).await;

    clock.advance(DELETION_WAIT - AN_HOUR);
    world.owner_mut().sign_in(&stack).await;
    eventually_paced(
        "the worker to delete the old memory for good",
        AS_A_PERSON_ASKS,
        || async { (recorded(&world, MEMORY_PURGED).await == 1).then_some(()) },
    )
    .await;
    let left = memories::list(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    assert!(
        left.iter().all(|memory| memory.id != old.id),
        "the old memory, an hour past its wait, is gone"
    );
    let waiting = left.iter().find(|memory| memory.id == recent.id);
    assert!(
        waiting.is_some_and(|memory| memory.status == "deletion_requested"),
        "the recent memory, an hour short of its wait, still waits to be deleted"
    );
    let back = memories::restore(world.tenant(), &recent.id)
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(back.status, "active", "Ann brings the recent memory back");
    watched_for(QUIET).await;
    assert_eq!(
        recorded(&world, MEMORY_PURGED).await,
        1,
        "one memory was deleted for good, recorded once"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann invites someone called `name` into the tenant with the role
/// `role_id`; the account's id.
async fn invited(world: &World<'_>, role_id: &str, name: &str) -> String {
    let invitation = InviteUser {
        email: world.address(name),
        display_name: format!("{name} Person"),
        role_id: role_id.to_owned(),
    };
    people::invite(world.tenant(), &invitation)
        .send(world.owner().client())
        .await
        .ok()
        .id
}

/// Whether the tenant's trail still holds the record of the invitation
/// that made the account `user_id`, as Ann reads it.
async fn invitation_recorded(world: &World<'_>, user_id: &str) -> bool {
    audit::tenant_log(world.tenant(), INVITED)
        .send(world.owner().client())
        .await
        .ok()
        .items
        .iter()
        .any(|record| record.details["user"]["id"].as_str() == Some(user_id))
}

/// How many records of exactly `event_type` the tenant's trail holds, as
/// Ann reads it.
async fn recorded(world: &World<'_>, event_type: &str) -> usize {
    audit::tenant_log(world.tenant(), event_type)
        .send(world.owner().client())
        .await
        .ok()
        .items
        .iter()
        .filter(|record| record.event_type == event_type)
        .count()
}

/// The number of purges on record once it has reached at least `least`.
async fn purges_reach(world: &World<'_>, least: usize) -> usize {
    eventually_paced(
        "the worker's purge of expired records",
        AS_A_PERSON_ASKS,
        || async {
            let purges = recorded(world, RECORDS_PURGED).await;
            (purges >= least).then_some(purges)
        },
    )
    .await
}

/// Ann keeps a memory named `name` for internal texts, filled by the
/// platform's embedding server.
async fn memory_made(world: &World<'_>, name: &str) -> Memory {
    let memory = NewMemory {
        name: name.to_owned(),
        provider_id: None,
        clearance: "Internal".to_owned(),
    };
    memories::create(world.tenant(), &memory)
        .send(world.owner().client())
        .await
        .ok()
}

/// Ann sets `memory` to be deleted, typing its name.
async fn set_to_delete(world: &World<'_>, memory: &Memory) {
    let typed = DeleteMemory {
        name: memory.name.clone(),
    };
    let waiting = memories::delete(world.tenant(), &memory.id, &typed)
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        waiting.status, "deletion_requested",
        "{} waits to be deleted",
        memory.name
    );
}

/// Tess gives Pat a reader role and Ann's company inbox gets a notice;
/// two hours later Tess gives Quinn the same role and Ann gets another.
/// Ninety days less an hour after Quinn's, the worker's daily purge has
/// run: Pat's notice, an hour past ninety days, is gone from Ann's inbox;
/// Quinn's, an hour short, is still there.
#[tokio::test]
async fn a_notice_an_hour_past_its_keeping_goes_and_one_an_hour_short_stays() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().with("WORKER_SWEEP_TICK_SECONDS", "1"))
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let pat = joined(&world, "pat").await;
    let quinn = joined(&world, "quinn").await;
    let role = reader_role(&world).await;
    let first = fresh_notice_after(&world, || {
        give_role(&world, world.admin().client(), &pat, &role)
    })
    .await;

    clock.advance(2 * AN_HOUR);
    world.owner_mut().sign_in(&stack).await;
    let tess = tess_signed_in_again(&world).await;
    let second =
        fresh_notice_after(&world, || give_role(&world, tess.client(), &quinn, &role)).await;

    clock.advance(NOTICES_KEPT - AN_HOUR);
    world.owner_mut().sign_in(&stack).await;
    eventually_paced(
        "the worker to purge the notice past its keeping",
        AS_A_PERSON_ASKS,
        || async { (!notice_kept(&world, &first.id).await).then_some(()) },
    )
    .await;
    assert!(
        notice_kept(&world, &second.id).await,
        "Quinn's notice, an hour short of ninety days, is kept"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess evaluates her draft; two hours later Ann evaluates it again. Thirty
/// days less an hour after the second, the worker's daily purge has run:
/// the first evaluation, an hour past thirty days, can no longer be read,
/// the second still reads, passed.
#[tokio::test]
async fn an_evaluation_an_hour_past_its_keeping_goes_and_one_an_hour_short_stays() {
    let service = OutsideService::start().await;
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().with("WORKER_SWEEP_TICK_SECONDS", "1"))
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let draft = evaluable_draft(&world, &service).await;
    let first = evaluated(&world, world.admin().client(), &draft).await;

    clock.advance(2 * AN_HOUR);
    world.owner_mut().sign_in(&stack).await;
    let second = evaluated(&world, world.owner().client(), &draft).await;

    clock.advance(EVALUATIONS_KEPT - AN_HOUR);
    world.owner_mut().sign_in(&stack).await;
    eventually_paced(
        "the worker to purge the evaluation past its keeping",
        AS_A_PERSON_ASKS,
        || async { (!evaluation_kept(&world, &draft, &first.id).await).then_some(()) },
    )
    .await;
    let kept = workflows::evaluation(world.tenant(), &draft.id, &second.id)
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(kept.status, "passed", "the second evaluation is kept");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann's workflow runs twice, two hours apart. Ninety days less an hour
/// after the second, the worker's sweep has run: the first run, an hour
/// past ninety days, can no longer be read, the second still reads as
/// succeeded, and both starts are still in the audit trail, which keeps
/// its own year.
#[tokio::test]
async fn a_run_an_hour_past_ninety_days_goes_and_one_an_hour_short_stays() {
    let service = OutsideService::start().await;
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().with("WORKER_SWEEP_TICK_SECONDS", "1"))
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let account = connected_account(&world, &service).await;
    let draft = drafted(&world, Trigger::Manual, delivery_graph(&service, &account)).await;
    let workflow = published(&world, &draft).await;
    let first = run_to_its_end(&world, &workflow).await;

    clock.advance(2 * AN_HOUR);
    world.owner_mut().sign_in(&stack).await;
    let second = run_to_its_end(&world, &workflow).await;

    clock.advance(RUNS_KEPT - AN_HOUR);
    world.owner_mut().sign_in(&stack).await;
    eventually_paced(
        "the worker to remove the run past its keeping",
        AS_A_PERSON_ASKS,
        || async { (!run_kept(&world, &first).await).then_some(()) },
    )
    .await;
    assert!(
        run_kept(&world, &second).await,
        "the second run, an hour short of ninety days, is kept"
    );
    assert_eq!(
        recorded(&world, RUN_STARTED).await,
        2,
        "both starts stay in the audit trail"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann starts `workflow` by hand and waits for it to end; the run's id.
async fn run_to_its_end(world: &World<'_>, workflow: &Workflow) -> String {
    let run = started(world, world.owner().client(), workflow).await;
    ended(
        world,
        world.owner().client(),
        &run.execution_id,
        "succeeded",
    )
    .await;
    run.execution_id
}

/// Whether the run `id` still reads for Ann.
async fn run_kept(world: &World<'_>, id: &str) -> bool {
    workflows::execution(world.tenant(), id)
        .send(world.owner().client())
        .await
        .status()
        != Status::NOT_FOUND
}

/// Tess connects the outside service, drafts a delivery and saves one case
/// the draft passes; the draft.
async fn evaluable_draft(world: &World<'_>, service: &OutsideService) -> Workflow {
    let account = connected_account(world, service).await;
    let draft = drafted(world, Trigger::Manual, delivery_graph(service, &account)).await;
    let set = NewEvaluationSet {
        cases: vec![EvaluationCase {
            name: "Order delivered".to_owned(),
            input: json!({"order": "visible-order"}),
            exposure: "internal".to_owned(),
            checks: vec![CaseCheck {
                kind: "equals".to_owned(),
                at: "trigger.order".to_owned(),
                value: Some(json!("visible-order")),
                text: None,
                pattern: None,
            }],
        }],
        publish_gate: None,
    };
    workflows::save_evaluation_set(world.tenant(), &draft.id, &set)
        .send(world.admin().client())
        .await
        .ok();
    draft
}

/// `by` evaluates `draft`; the evaluation once every case is decided.
async fn evaluated(world: &World<'_>, by: &Client, draft: &Workflow) -> Evaluation {
    let begun = workflows::start_evaluation(world.tenant(), &draft.id)
        .send(by)
        .await
        .ok();
    eventually("the evaluation to end", || async {
        let evaluation = workflows::evaluation(world.tenant(), &draft.id, &begun.id)
            .send(by)
            .await
            .ok();
        (evaluation.status != "running").then_some(evaluation)
    })
    .await
}

/// Whether the evaluation `id` of `draft` still reads for Ann.
async fn evaluation_kept(world: &World<'_>, draft: &Workflow, id: &str) -> bool {
    workflows::evaluation(world.tenant(), &draft.id, id)
        .send(world.owner().client())
        .await
        .status()
        != Status::NOT_FOUND
}

/// Someone at the address `name`, invited by Tess, who accepted.
async fn joined(world: &World<'_>, name: &str) -> Person {
    let mut person = world.newcomer(name, &format!("{name} Notified"));
    let invitation = InviteUser {
        email: person.email().to_owned(),
        display_name: person.account().display_name.clone(),
        role_id: world.role_id(MEMBER_ROLE).await,
    };
    let made = people::invite(world.tenant(), &invitation)
        .send(world.admin().client())
        .await
        .ok();
    person.record_invitation(&made.id);
    person.accept_invitation(world.stack()).await;
    person
}

/// A role Tess makes letting its holder read the tenant's users.
async fn reader_role(world: &World<'_>) -> String {
    roles::create(
        world.tenant(),
        &NewRole {
            name: "Notified Readers".to_owned(),
            system_permissions: vec![SystemPermission::new("Users", "View")],
        },
    )
    .send(world.admin().client())
    .await
    .ok()
    .id
}

/// `by`, Tess, gives `person` the role `role_id`.
async fn give_role(world: &World<'_>, by: &Client, person: &Person, role_id: &str) {
    let assignment = AssignRole {
        user_id: person.id().to_owned(),
    };
    roles::assign(world.tenant(), role_id, &assignment)
        .send(by)
        .await
        .ok();
}

/// Tess signed in again on a new client, landing in the tenant: her first
/// session is over once the clock has moved.
async fn tess_signed_in_again(world: &World<'_>) -> Member {
    let client = Client::new(world.stack(), "Tess, signed in again").expect("a client");
    let mut tess = Member::new(
        client,
        world.admin().account().clone(),
        world.admin().password(),
    );
    tess.land_in(world.tenant().slug());
    tess.sign_in(world.stack()).await;
    tess
}

/// The ids of the notices in Ann's company inbox now.
async fn ann_notices(world: &World<'_>) -> Vec<Notification> {
    notifications::member_inbox(world.org())
        .send(world.owner().client())
        .await
        .ok()
        .items
}

/// Whether the notice `id` is still in Ann's company inbox.
async fn notice_kept(world: &World<'_>, id: &str) -> bool {
    ann_notices(world)
        .await
        .iter()
        .any(|notice| notice.id == id)
}

/// The notice about a change of who may do what that `change` puts in
/// Ann's company inbox, once the worker has put it there.
async fn fresh_notice_after<F, Fut>(world: &World<'_>, change: F) -> Notification
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    let seen: Vec<String> = ann_notices(world)
        .await
        .into_iter()
        .map(|notice| notice.id)
        .collect();
    change().await;
    let seen = &seen;
    eventually("a new notice in Ann's inbox", || async move {
        ann_notices(world)
            .await
            .into_iter()
            .find(|notice| notice.category == AUTHORIZATION && !seen.contains(&notice.id))
    })
    .await
}
