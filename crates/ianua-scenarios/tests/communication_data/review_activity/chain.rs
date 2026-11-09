//! The tenant's tamper-evident audit chain: walked by the worker, intact
//! while every record stands as written, and broken from the first record
//! anyone changed, even someone holding the database itself.

use std::time::Duration;

use ianua_scenarios::api::{audit, people};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Waiting, eventually_paced};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::audit::ChainCheck;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::world::{MEMBER_ROLE, World};

use crate::support::invited;

/// Past the hour between two walks of the chain.
const PAST_A_WALK: Duration = Duration::from_secs(3600 + 60);

/// How long the worker is given to walk the chain, asked once a second as
/// a person refreshing a page would.
const UNTIL_WALKED: Waiting = Waiting {
    patience: Duration::from_secs(60),
    every: Duration::from_secs(1),
};

/// Tess invites Vic. An hour on, the worker has walked the chain and Ann
/// reads it intact. Ann invites Uma, and before the next walk someone
/// holding the database itself changes what Uma's invitation record says,
/// past every store. An hour on, the worker has walked on from where it
/// stopped, and Ann reads the chain broken at a record past the last one
/// it had found intact.
#[tokio::test]
async fn a_record_changed_in_the_database_breaks_the_chain() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().with("WORKER_SWEEP_TICK_SECONDS", "1"))
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    invited(&world, "vic").await;
    let member = world.role_id(MEMBER_ROLE).await;

    clock.advance(PAST_A_WALK);
    world.owner_mut().sign_in(&stack).await;
    let intact = walked(&world, "intact").await;
    let checked = intact
        .checked_through_seq
        .expect("an intact walk names the last record it verified");
    let uma = invited_by_ann(&world, "uma", &member).await;

    tamper_with_invitation(&stack, &uma).await;
    clock.advance(PAST_A_WALK);
    world.owner_mut().sign_in(&stack).await;
    let broken = walked(&world, "broken").await;
    let at = broken
        .broken_at_seq
        .expect("a broken chain names where it breaks");
    assert!(
        at > checked,
        "the break is at Uma's record, past the last one verified: {at} after {checked}"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Changes Uma's recorded label directly, bypassing the audited store.
async fn tamper_with_invitation(stack: &Stack, uma: &str) {
    stack
        .tamper_with_audit_records(
            "payload = jsonb_set(payload, '{value,user,label}', '\"mallory@elsewhere.example\"')",
            &format!(
                "event_type = 'identity.user_invited' \
                 AND payload #>> '{{value,user,id}}' = '{uma}'"
            ),
        )
        .await;
}

/// The id of someone called `name`, invited by Ann with the role
/// `role_id`.
async fn invited_by_ann(world: &World<'_>, name: &str, role_id: &str) -> String {
    let person = world.newcomer(name, &format!("{name} Reviewed"));
    let invitation = InviteUser {
        email: person.email().to_owned(),
        display_name: person.account().display_name.clone(),
        role_id: role_id.to_owned(),
    };
    people::invite(world.tenant(), &invitation)
        .send(world.owner().client())
        .await
        .ok()
        .id
}

/// The chain's standing once the worker has walked it to `status`, as Ann
/// reads it.
async fn walked(world: &World<'_>, status: &str) -> ChainCheck {
    eventually_paced(
        &format!("the worker to find the chain {status}"),
        UNTIL_WALKED,
        || async {
            let check = audit::verify_chain(world.tenant())
                .send(world.owner().client())
                .await
                .ok();
            (check.status == status).then_some(check)
        },
    )
    .await
}
