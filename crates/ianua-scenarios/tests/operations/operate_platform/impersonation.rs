//! Bob, the platform's operator, acting as Pat to help her: he asks for a
//! grant naming Pat, her tenant and why, and names it on his requests to
//! her tenant. He does there what Pat may, and nowhere else; his own key
//! alone reaches no tenant, and the moment he revokes the grant he is Pat
//! no more. Pages that are a person's own account, such as reading "me",
//! answer only to the person's own sign-in, so they are not his to read.
//!
//! What he changes as Pat is recorded as Bob acting as Pat, and Ann sees
//! in her own log that he took the grant, why, and when he gave it back.
//! A grant reaches only what its person may: acting as Lou, an ordinary
//! member, Bob may not read the users or replace the keys. A grant ends
//! on its own at the time it names, and none is given for more than a
//! day, nor before Ann lets operators in.

use std::time::Duration as StdDuration;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{audit, crypto, operators, people};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Waiting, eventually_paced};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::audit::AuditEntry;
use ianua_scenarios::wire::crypto::RotateKey;
use ianua_scenarios::wire::operators::GrantImpersonation;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::world::{MEMBER_ROLE, World};
use time::Duration;

use crate::support::{
    Bob, bob_signed_in, from_now, impersonation_allowed, lou_joined, pat_joined, tenant_id,
};

/// The record a grant leaves in the tenant's log.
const GRANTED: &str = "operator.impersonation_granted";

/// The record a revoked grant leaves in the tenant's log.
const REVOKED: &str = "operator.impersonation_revoked";

/// The record an invitation leaves.
const INVITED: &str = "identity.user_invited";

/// The record a replaced signing key leaves.
const ROTATED: &str = "crypto.key_rotated";

/// Why Bob takes his grant, as Ann reads it in her log.
const TICKET: &str = "Support ticket: Pat cannot see her orders";

/// How long Bob's short grant lasts.
const TEN_MINUTES: Duration = Duration::minutes(10);

/// Past the end of Bob's short grant.
const ELEVEN_MINUTES: StdDuration = StdDuration::from_secs(11 * 60);

/// How Bob waits for his ended grant to stop working: once a second, as a
/// person retrying would, for at most twenty seconds.
const AS_BOB_RETRIES: Waiting = Waiting {
    patience: StdDuration::from_secs(20),
    every: StdDuration::from_secs(1),
};

/// Pat, who administers Ann's tenant, has trouble, and Ann lets operators
/// act as the tenant's users. Bob takes an hour's grant to act as Pat for
/// her support ticket, and naming it he reads the tenant's users, as Pat
/// may. The grant cannot reach the twin tenant, Bob's key alone cannot read
/// tenant users, and Max cannot use Bob's grant. Bob also cannot read Pat's
/// personal account page. Revoking the grant then ends his access to the
/// tenant's user list.
#[tokio::test]
async fn bob_acts_as_pat_only_in_her_tenant_and_only_while_his_grant_holds() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat_joined(&world).await;
    let bob = bob_signed_in(&stack).await;
    let tenant = tenant_id(&world).await;
    impersonation_allowed(&world).await;

    let made = operators::grant(&bob.id, &grant_for(&tenant, &pat, Duration::hours(1)))
        .send(&bob.client)
        .await
        .ok();
    assert_impersonated_read(&world, &bob, &pat, &made.id).await;
    assert_grant_boundaries(&world, &bob, &made.id).await;
    revoke_and_refuse(&world, &bob, &made.id).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Before Ann lets operators in, Bob's grant to act as Pat is refused.
/// Once she does, Bob takes it, and Ann reads in her log that he did, as
/// Pat, and why. Acting as Pat, Bob invites Quinn: Quinn's invitation is
/// recorded as made by Bob acting as Pat, in Ann's log and in the
/// platform's log Bob reads. Bob gives the grant back, and Ann reads that
/// too.
#[tokio::test]
async fn what_bob_does_as_pat_is_recorded_as_bob_acting_for_her_tenant() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat_joined(&world).await;
    let bob = bob_signed_in(&stack).await;
    let tenant = tenant_id(&world).await;
    let terms = grant_for(&tenant, &pat, Duration::hours(1));

    operators::grant(&bob.id, &terms)
        .send(&bob.client)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    impersonation_allowed(&world).await;
    let made = operators::grant(&bob.id, &terms)
        .send(&bob.client)
        .await
        .ok();
    assert_grant_recorded(&world, &pat).await;

    let seen = world.trail().ids().await;
    let quinn = invited_as_pat(&world, &bob, &made.id).await;
    let invitation = world.trail().recorded_after(&seen, INVITED).await;
    assert_acted_as(&invitation, &bob, &pat, "Ann's log");
    let platform =
        audit::platform_log_where(&[("event_type", INVITED), ("tenant_id", tenant.as_str())])
            .send(&bob.client)
            .await
            .ok();
    let Some(seen_by_bob) = platform
        .items
        .iter()
        .find(|entry| entry.id == invitation.id)
    else {
        panic!("the platform's log holds Quinn's invitation {quinn}");
    };
    assert_acted_as(seen_by_bob, &bob, &pat, "the platform's log");

    operators::revoke_grant(&made.id)
        .send(&bob.client)
        .await
        .ok();
    let revoked = world.trail().recorded(REVOKED).await;
    assert_eq!(
        revoked.tenant_id.as_deref(),
        Some(tenant.as_str()),
        "the revoked grant is filed under Ann's tenant"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann lets operators in, and Bob takes a grant to act as Lou, who holds
/// only the tenant's `Member` role. Acting as Lou he may not read the
/// tenant's users, and may not replace the tenant's signing key; no
/// replaced key is recorded. The grant gives Bob nothing Lou herself does
/// not have.
#[tokio::test]
async fn acting_as_lou_bob_may_do_only_what_lou_may() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let lou = lou_joined(&world).await;
    let bob = bob_signed_in(&stack).await;
    let tenant = tenant_id(&world).await;
    impersonation_allowed(&world).await;
    let made = operators::grant(&bob.id, &grant_for(&tenant, &lou, Duration::hours(1)))
        .send(&bob.client)
        .await
        .ok();
    let seen = world.trail().ids().await;

    people::list(world.tenant(), None)
        .header(operators::IMPERSONATION_HEADER, &made.id)
        .send(&bob.client)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let rotation = RotateKey {
        algorithm: "RS256".to_owned(),
    };
    crypto::rotate(world.tenant(), &rotation)
        .header(operators::IMPERSONATION_HEADER, &made.id)
        .send(&bob.client)
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    world.trail().nothing_after(&seen, ROTATED).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann lets operators in. Bob asks for a grant to act as Pat for a day
/// and an hour, and is refused: no grant lasts more than a day. He takes
/// one for ten minutes and reads the tenant's users as Pat. Eleven
/// minutes later the grant has ended on its own: naming it gets him
/// nothing, while his own key still reads his account.
#[tokio::test]
async fn bobs_grant_ends_on_its_own_at_the_time_it_names() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat_joined(&world).await;
    let bob = bob_signed_in(&stack).await;
    let tenant = tenant_id(&world).await;
    impersonation_allowed(&world).await;

    operators::grant(&bob.id, &grant_for(&tenant, &pat, Duration::hours(25)))
        .send(&bob.client)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let made = operators::grant(&bob.id, &grant_for(&tenant, &pat, TEN_MINUTES))
        .send(&bob.client)
        .await
        .ok();
    assert_impersonated_read(&world, &bob, &pat, &made.id).await;

    clock.advance(ELEVEN_MINUTES);
    eventually_paced("Bob's ended grant to be refused", AS_BOB_RETRIES, || {
        refused_as_pat(&world, &bob, &made.id)
    })
    .await;
    operators::get(&bob.id).send(&bob.client).await.ok();
    stack.stop().await.expect("the stack stops cleanly");
}

/// Bob's grant to act as `person` in the tenant `tenant`, for a support
/// ticket, ending `lasting` from now.
fn grant_for(tenant: &str, person: &Person, lasting: Duration) -> GrantImpersonation {
    GrantImpersonation {
        tenant_id: tenant.to_owned(),
        user_id: person.id().to_owned(),
        reason: TICKET.to_owned(),
        expires_at: from_now(lasting),
    }
}

/// Bob's grant permits the same tenant user listing that Pat can read.
async fn assert_impersonated_read(world: &World<'_>, bob: &Bob, pat: &Person, grant: &str) {
    let as_pat = people::list(world.tenant(), None)
        .header(operators::IMPERSONATION_HEADER, grant)
        .send(&bob.client)
        .await
        .ok();
    assert!(
        as_pat.items.iter().any(|user| user.id == pat.id()),
        "naming the grant, Bob reads the tenant's users as Pat may"
    );
}

/// The grant cannot cross tenants, change holders or open Pat's personal account.
async fn assert_grant_boundaries(world: &World<'_>, bob: &Bob, grant: &str) {
    people::list(world.twin(), None)
        .header(operators::IMPERSONATION_HEADER, grant)
        .send(&bob.client)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    people::list(world.tenant(), None)
        .send(&bob.client)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    people::list(world.tenant(), None)
        .header(operators::IMPERSONATION_HEADER, grant)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    people::me(world.tenant())
        .header(operators::IMPERSONATION_HEADER, grant)
        .send(&bob.client)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Revoking Bob's grant prevents his next impersonated tenant read.
async fn revoke_and_refuse(world: &World<'_>, bob: &Bob, grant: &str) {
    operators::revoke_grant(grant).send(&bob.client).await.ok();
    people::list(world.tenant(), None)
        .header(operators::IMPERSONATION_HEADER, grant)
        .send(&bob.client)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Ann's log holds Bob's grant over Pat, with the reason he gave.
async fn assert_grant_recorded(world: &World<'_>, pat: &Person) {
    let granted = world.trail().recorded(GRANTED).await;
    assert_eq!(
        granted.details["reason"], TICKET,
        "Ann reads why Bob took the grant"
    );
    assert_eq!(
        granted.details["user"]["id"],
        pat.id(),
        "Ann reads whom Bob may act as"
    );
}

/// Quinn, invited into the tenant by Bob acting as Pat through `grant`:
/// her address, which the record is told by.
async fn invited_as_pat(world: &World<'_>, bob: &Bob, grant: &str) -> String {
    let quinn = world.address("quinn");
    let invitation = InviteUser {
        email: quinn.clone(),
        display_name: "Quinn Invited".to_owned(),
        role_id: world.role_id(MEMBER_ROLE).await,
    };
    people::invite(world.tenant(), &invitation)
        .header(operators::IMPERSONATION_HEADER, grant)
        .send(&bob.client)
        .await
        .ok();
    quinn
}

/// `entry` was made by Bob acting as Pat, as `log` shows it.
fn assert_acted_as(entry: &AuditEntry, bob: &Bob, pat: &Person, log: &str) {
    let Some(through) = &entry.acted_through else {
        panic!("{log} records Quinn's invitation as made through a grant");
    };
    assert_eq!(through.kind, "impersonation", "{log} names the grant");
    assert_eq!(
        through.operator_id.as_deref(),
        Some(bob.id.as_str()),
        "{log} names Bob as the one who acted"
    );
    assert_eq!(
        through.as_user_id.as_deref(),
        Some(pat.id()),
        "{log} names Pat as the one he acted as"
    );
}

/// `Some` once naming `grant` no longer reads the tenant's users.
async fn refused_as_pat(world: &World<'_>, bob: &Bob, grant: &str) -> Option<()> {
    let answer = people::list(world.tenant(), None)
        .header(operators::IMPERSONATION_HEADER, grant)
        .send(&bob.client)
        .await;
    (answer.status() == Status::FORBIDDEN).then_some(())
}
