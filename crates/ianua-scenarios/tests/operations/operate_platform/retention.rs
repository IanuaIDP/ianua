//! A tenant's audit records kept as long as its compliance posture says,
//! and then removed by the worker. Shortening the retention never deletes
//! a record early: while records written before the change are still owed
//! the longer period, nothing goes; once that period has run out, the
//! shorter one applies. Every removal is itself recorded.

use std::time::Duration;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{audit, people, tenants};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Waiting, eventually_paced};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::tenants::{PasswordAgain, ReplaceCompliance};
use ianua_scenarios::world::{MEMBER_ROLE, World};

/// The shortest retention a tenant may set, in days.
const SHORTEST_RETENTION_DAYS: u32 = 30;

/// A month and a day: past the shortest retention, well within the
/// default year that records written before the change are owed.
const A_MONTH_LATER: Duration = Duration::from_secs(31 * 86_400);

/// The rest of a year and a day from the change: past the default year,
/// so the records written before the change are owed nothing more.
const PAST_THE_DEFAULT_YEAR: Duration = Duration::from_secs(335 * 86_400);

/// How long the worker is watched for a purge that must not come: three
/// of its one-second sweeps.
const QUIET: Duration = Duration::from_secs(3);

/// How Ann waits for the purge: once a second, as a person refreshing a
/// page would, so the platform's rate limit never answers, for at most a
/// minute.
const AS_A_PERSON_ASKS: Waiting = Waiting {
    patience: Duration::from_secs(60),
    every: Duration::from_secs(1),
};

/// The record an invitation leaves.
const INVITED: &str = "identity.user_invited";

/// The record a purge leaves.
const PURGED: &str = "tenant.audit_records_purged";

/// Tess invites Uma under the default year. Ann cuts the retention to
/// thirty days, and Tess invites Pat. A month later the worker sweeps and
/// deletes nothing: Uma's record is still owed its year, so even Pat's
/// stays. A year and a day after the change both invitations are gone,
/// the purge is recorded, and Quinn, invited that day, is still on record.
#[tokio::test]
async fn a_shortened_retention_deletes_nothing_early() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().with("WORKER_SWEEP_TICK_SECONDS", "1"))
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let member = world.role_id(MEMBER_ROLE).await;

    let uma = invited(&world, world.admin().client(), &member, "uma").await;
    retention_cut_to_the_shortest(&world).await;
    let pat = invited(&world, world.admin().client(), &member, "pat").await;

    clock.advance(A_MONTH_LATER);
    world.owner_mut().sign_in(&stack).await;
    assert_records_retained(&world, &uma, &pat).await;
    clock.advance(PAST_THE_DEFAULT_YEAR);
    world.owner_mut().sign_in(&stack).await;
    let quinn = invited(&world, world.owner().client(), &member, "quinn").await;
    assert_expired_records_purged(&world, &uma, &pat, &quinn).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// The shorter policy cannot purge either invitation while the older promise holds.
async fn assert_records_retained(world: &World<'_>, uma: &Person, pat: &Person) {
    watched_for(QUIET).await;
    assert!(
        purges(world).await == 0,
        "nothing is purged while older records are owed their year"
    );
    assert!(
        invitation_recorded(world, uma).await && invitation_recorded(world, pat).await,
        "both invitations are still on record a month later"
    );
}

/// Once both invitations expire, the recorded purge removes them but keeps Quinn's.
async fn assert_expired_records_purged(
    world: &World<'_>,
    uma: &Person,
    pat: &Person,
    quinn: &Person,
) {
    eventually_paced(
        "the worker to purge the expired records",
        AS_A_PERSON_ASKS,
        || async { (purges(world).await > 0).then_some(()) },
    )
    .await;
    assert!(
        !invitation_recorded(world, uma).await,
        "Uma's invitation is purged once its year has run out"
    );
    assert!(
        !invitation_recorded(world, pat).await,
        "Pat's invitation, older than thirty days, is purged with it"
    );
    assert!(
        invitation_recorded(world, quinn).await,
        "Quinn's invitation, made that day, is still on record"
    );
}

/// Someone called `name`, invited into the tenant with the role `role_id`
/// by whoever `inviter` is signed in as.
async fn invited(world: &World<'_>, inviter: &Client, role_id: &str, name: &str) -> Person {
    let mut person = world.newcomer(name, &format!("{name} Person"));
    let invitation = InviteUser {
        email: person.email().to_owned(),
        display_name: person.account().display_name.clone(),
        role_id: role_id.to_owned(),
    };
    let made = people::invite(world.tenant(), &invitation)
        .send(inviter)
        .await
        .ok();
    person.record_invitation(&made.id);
    person
}

/// Ann cuts the tenant's audit retention to the shortest it may be,
/// proving who she is with her password.
async fn retention_cut_to_the_shortest(world: &World<'_>) {
    let posture = tenants::compliance(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    let shortened = ReplaceCompliance {
        data_residency: posture.data_residency,
        audit_retention_days: SHORTEST_RETENTION_DAYS,
        operator_impersonation: posture.operator_impersonation,
        proof: PasswordAgain {
            password: world.owner().password().to_owned(),
            code: None,
        },
    };
    tenants::replace_compliance(world.tenant(), &shortened)
        .send(world.owner().client())
        .await
        .ok();
}

/// How many purges the tenant's trail records, as Ann reads it.
async fn purges(world: &World<'_>) -> usize {
    audit::tenant_log(world.tenant(), PURGED)
        .send(world.owner().client())
        .await
        .ok()
        .items
        .len()
}

/// Whether the tenant's trail still holds the record of `person`'s
/// invitation, as Ann reads it.
async fn invitation_recorded(world: &World<'_>, person: &Person) -> bool {
    audit::tenant_log(world.tenant(), INVITED)
        .send(world.owner().client())
        .await
        .ok()
        .items
        .iter()
        .any(|record| record.details["user"]["id"].as_str() == Some(person.id()))
}

/// Waits out `duration` on the real clock, the worker sweeping meanwhile.
async fn watched_for(duration: Duration) {
    let since = std::time::Instant::now();
    eventually_paced(
        "the watch for a purge that must not come",
        Waiting {
            patience: duration * 2,
            every: Duration::from_millis(250),
        },
        || async { (since.elapsed() > duration).then_some(()) },
    )
    .await;
}
