//! The jobs the platform gave up on, as Bob the operator looks into them
//! and retries them: a mail that could not go out within its tries is left
//! dead, shown to operators with its kind, tenant, tries and why its last
//! try failed, never with what it carried. Nobody else may look, and the
//! platform does not quietly try it again once the mail service is back.
//! Bob's retry sends it once, survives a restart, is refused a second
//! time, and is recorded once in the platform's log.

use std::time::Duration;

use ianua_scenarios::api::{audit, operators, people, tenants};
use ianua_scenarios::expect::{Waiting, eventually_paced};
use ianua_scenarios::stack::{Part, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::operators::DeadJob;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::world::{MEMBER_ROLE, World};

use crate::support::{Bob, bob_signed_in};

/// The kind of job a queued mail is.
const MAIL_JOB: &str = "mail.send";

/// The tries each mail gets in this deployment before it is given up.
const MAIL_TRIES: u32 = 2;

/// How long Uma's address is watched for a mail that must not come: three
/// of the worker's one-second polls and sweeps, past its one-second retry
/// backoff.
const QUIET: Duration = Duration::from_secs(3);

/// The record a retry leaves in the platform's log.
const RETRIED: &str = "operator.dead_job_retried";

/// How Bob waits for the mail to be given up: every two seconds, as a
/// person refreshing a page would, for at most a minute.
const AS_BOB_REFRESHES: Waiting = Waiting {
    patience: Duration::from_secs(60),
    every: Duration::from_secs(2),
};

/// The mail service goes down, and Tess invites Uma into the tenant. The
/// invitation's mail is tried twice, a second apart, and given up. Bob
/// finds it among the dead jobs: a mail of Tess's tenant, tried twice,
/// with why its last try failed, and nothing of the mail itself, not even
/// Uma's address. Tess may neither look at the dead jobs nor retry one.
/// The mail service comes back, and no mail reaches Uma on its own: the
/// platform leaves a dead job dead. Bob retries it, and the platform
/// restarts as during a deploy. Uma's invitation reaches her exactly once,
/// the job is dead no more, and Bob's second retry is refused as a
/// conflict. The platform's log holds one retry, made by Bob, naming the
/// job and never Uma's address.
#[tokio::test]
async fn bob_retries_a_mail_given_up_on_and_it_goes_out_once() {
    let stack = Stack::start(
        Profile::standard()
            .with_cuttable_parts()
            .with("EMAIL_SEND_TIMEOUT_SECONDS", "1")
            .with("JOB_RETRY_BACKOFF_SECONDS", "1")
            .with("MAIL_DELIVERY_ATTEMPTS", &MAIL_TRIES.to_string()),
    )
    .await
    .expect("the stack starts");
    let world = World::new(&stack).await;
    let bob = bob_signed_in(&stack).await;
    let tenant = tenants::get(world.tenant())
        .send(world.owner().client())
        .await
        .ok()
        .id;
    let uma = world.address("uma");

    stack.cut(Part::Mail);
    invite_uma(&world, &uma).await;
    let dead = eventually_paced("Uma's mail to be given up", AS_BOB_REFRESHES, || {
        dead_mail_of(&bob, &tenant)
    })
    .await;
    assert_given_up(&dead, &uma);
    assert_closed_to_tess(&world, &dead.id).await;

    stack.mend(Part::Mail);
    stack.mailbox().nothing_for(&uma, QUIET).await;
    let still = dead_mail_of(&bob, &tenant).await;
    assert!(
        still.is_some_and(|job| job.id == dead.id),
        "the given-up mail stays dead once the mail service is back"
    );

    operators::retry_dead_job(&dead.id)
        .send(&bob.client)
        .await
        .ok();
    stack.restart().await.expect("the platform restarts");
    stack.mailbox().next_for(&uma).await;
    stack.mailbox().nothing_for(&uma, QUIET).await;
    assert!(
        dead_mail_of(&bob, &tenant).await.is_none(),
        "the retried mail is dead no more"
    );
    operators::retry_dead_job(&dead.id)
        .send(&bob.client)
        .await
        .refused(Status::CONFLICT, "conflict");
    assert_retry_recorded_once(&bob, &dead.id, &uma).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess invites Uma, at the address `uma`, into her tenant.
async fn invite_uma(world: &World<'_>, uma: &str) {
    let invitation = InviteUser {
        email: uma.to_owned(),
        display_name: "Uma Unreached".to_owned(),
        role_id: world.role_id(MEMBER_ROLE).await,
    };
    people::invite(world.tenant(), &invitation)
        .send(world.admin().client())
        .await
        .ok();
}

/// `dead` was tried as often as allowed and says why it failed, without
/// what it carried, not even the address `uma`.
fn assert_given_up(dead: &DeadJob, uma: &str) {
    assert_eq!(
        dead.attempts, MAIL_TRIES,
        "the mail was tried as often as allowed"
    );
    assert!(
        !dead.reason.trim().is_empty(),
        "Bob reads why its last try failed"
    );
    assert!(
        !dead.reason.contains(uma),
        "what the mail carried, even its address, is not shown"
    );
}

/// Tess may neither read the dead jobs nor retry the job `job_id`.
async fn assert_closed_to_tess(world: &World<'_>, job_id: &str) {
    operators::dead_jobs()
        .send(world.admin().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    operators::retry_dead_job(job_id)
        .send(world.admin().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// The platform's log holds one retry of the job `job_id`, made by Bob,
/// and none of the retries names the address `uma`.
async fn assert_retry_recorded_once(bob: &Bob, job_id: &str, uma: &str) {
    let bobs_actor = format!("operator:{}", bob.id);
    let records =
        audit::platform_log_where(&[("event_type", RETRIED), ("actor", bobs_actor.as_str())])
            .send(&bob.client)
            .await
            .ok()
            .items;
    let of_the_job: Vec<_> = records
        .iter()
        .filter(|record| record.details["job_id"] == job_id)
        .collect();
    assert_eq!(of_the_job.len(), 1, "Bob's retry is recorded once");
    assert_eq!(
        of_the_job[0].details["retried_by"],
        bob.id.as_str(),
        "the record names Bob"
    );
    let written = serde_json::to_string(&of_the_job[0].details).expect("the details as JSON");
    assert!(
        !written.contains(uma),
        "the record never holds what the mail carried"
    );
}

/// The dead mail job of the tenant `tenant`, as Bob reads the dead jobs,
/// once there is one.
async fn dead_mail_of(bob: &Bob, tenant: &str) -> Option<DeadJob> {
    operators::dead_jobs()
        .send(&bob.client)
        .await
        .ok()
        .items
        .into_iter()
        .find(|job| job.job_type == MAIL_JOB && job.tenant_id.as_deref() == Some(tenant))
}
