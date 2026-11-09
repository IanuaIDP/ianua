//! The control plane is killed in the middle of its work, as a node lost
//! during a deploy is: the API and the worker lose every connection at
//! once, whatever they were doing is rolled back, and they start again.
//! A job the dead worker held stays its own until its hold runs out, so
//! the new worker never runs it beside it; then it is taken again and done
//! once, and its effect is recorded once.

use std::time::Duration;

use ianua_scenarios::actors::FOUNDER_PASSWORD;
use ianua_scenarios::api::members;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Trail, eventually};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Part, Profile, Stack};
use ianua_scenarios::wire::organization::{AcceptMemberInvitation, InviteMember, OrgRole};
use ianua_scenarios::world::World;

use crate::support::{
    STAGING, TENANT_CREATED, ann_in_staging, assert_made_once, assert_recorded_once, once_set_up,
    room_for_another_tenant, staging_made, watched_for,
};

/// Past every hold a crashed worker's jobs may still have: the long
/// lane's half hour and its margin, and the quarter hour after which
/// setup work left standing is handed out again.
const HOLDS_RUN_OUT: Duration = Duration::from_secs(3600);

/// Past one round of the sweep that hands out work left standing, which
/// runs every five minutes.
const ANOTHER_ROUND: Duration = Duration::from_secs(6 * 60);

/// How long a mail sent twice would take to arrive the second time.
const SECOND_MAIL_WAIT: Duration = Duration::from_secs(5);

/// How long the lanes are given, on the real clock, to give up the jobs
/// whose holds ran out: several of their one-second polls.
const LANES_POLL: Duration = Duration::from_secs(3);

/// How long the mail server may keep the worker waiting for its greeting:
/// far longer than the scenario takes to kill the worker meanwhile.
const MAIL_WAITED_FOR_SECONDS: &str = "60";

/// The record an invitation leaves.
const INVITED: &str = "organization.org_user_invited";

/// Ann invites Carl while the mail server hangs, so the worker is waiting
/// on it in the middle of mailing him when the control plane is killed.
/// After the restart nothing reaches Carl while the dead worker's hold on
/// the mail lasts: the new worker does not run the job beside it. Once the
/// hold has run out, the mail reaches Carl once; he joins from it as the
/// member Ann invited, and one invitation of him is recorded.
#[tokio::test]
async fn a_mail_cut_off_by_a_crash_mid_delivery_is_sent_once_after_it() {
    let clock = Clock::controlled();
    let stack = Stack::start(
        Profile::standard()
            .with_cuttable_parts()
            .with("EMAIL_SEND_TIMEOUT_SECONDS", MAIL_WAITED_FOR_SECONDS)
            .with("JOB_RETRY_BACKOFF_SECONDS", "1,1,1,1"),
    )
    .await
    .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let carl = world.address("carl");
    let before = world.trail().count(INVITED).await;
    stack.hold(Part::Mail);
    let invited = members::invite(world.org(), &carls_invitation(&carl))
        .send(world.owner().client())
        .await
        .ok();
    eventually(
        "the worker to wait on the mail server mid-delivery",
        || async { (stack.held(Part::Mail) > 0).then_some(()) },
    )
    .await;

    stack
        .crash()
        .await
        .expect("the platform crashes and starts again");
    stack.mailbox().nothing_for(&carl, SECOND_MAIL_WAIT).await;
    clock.advance(HOLDS_RUN_OUT);
    accept_once(&stack, &world, &carl, &invited.id).await;
    world.owner_mut().sign_in(&stack).await;
    assert_eq!(
        world.trail().count(INVITED).await,
        before + 1,
        "taking the mail again does not invite Carl again"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann makes `staging`, and the control plane is killed at once, while its
/// setup is announced or under way. Once every hold the dead worker had
/// has run out and the work left standing has been handed out again, the
/// setup finishes: Ann signs in to `staging` and finds its two starting
/// roles once each and one signing key; the trail holds one creation of
/// it, two seeded roles, one key and one move into use, none written
/// twice by the recovery.
#[tokio::test]
async fn a_tenant_setup_cut_off_by_a_crash_is_finished_once_after_it() {
    let clock = Clock::controlled();
    let stack = Stack::start(
        Profile::standard()
            .with_cuttable_parts()
            .with("WORKER_SWEEP_TICK_SECONDS", "1"),
    )
    .await
    .expect("the stack starts");
    let mut world = World::new(&stack).await;
    room_for_another_tenant(&world).await;
    let before = world.trail().count(TENANT_CREATED).await;

    let staging = staging_made(&world).await;
    stack
        .crash()
        .await
        .expect("the platform crashes and starts again");
    clock.advance(HOLDS_RUN_OUT);
    watched_for(LANES_POLL).await;
    clock.advance(ANOTHER_ROUND);
    world.owner_mut().sign_in(&stack).await;
    once_set_up(&world, &staging).await;

    let ann = ann_in_staging(&world).await;
    assert_made_once(&world.org().tenant(STAGING), &ann).await;
    assert_recorded_once(&world, ann.client(), &staging).await;
    assert_eq!(
        Trail::of_organization(ann.client(), world.org().slug())
            .count(TENANT_CREATED)
            .await,
        before + 1,
        "one creation of staging is recorded"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann invites Carl with the member role.
fn carls_invitation(carl: &str) -> InviteMember {
    InviteMember {
        email: carl.to_owned(),
        display_name: "Carl Crash".to_owned(),
        role: OrgRole::Member,
    }
}

/// Carl receives the mail once and activates the membership Ann made.
async fn accept_once(stack: &Stack, world: &World<'_>, carl: &str, invited_id: &str) {
    let mail = stack.mailbox().next_for(carl).await;
    stack.mailbox().nothing_for(carl, SECOND_MAIL_WAIT).await;
    let browser = Client::new(stack, "Carl accepting after a crash").expect("a client");
    let accept = AcceptMemberInvitation {
        token: mail.token_in("/accept-invite"),
        password: FOUNDER_PASSWORD.to_owned(),
    };
    let joined = members::accept_invitation(world.org(), &accept)
        .send(&browser)
        .await
        .ok();
    assert_eq!(joined.id, invited_id, "the mailed link activates Carl");
}
