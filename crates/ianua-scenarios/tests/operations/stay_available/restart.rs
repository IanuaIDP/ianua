//! The control plane restarts as during a deploy: the API and worker stop
//! and start again on the same database while the gateway keeps running.
//! Nothing Ann did is lost, neither she nor Tess is signed out by it, and
//! the invitation Ann queued for Carl before it is delivered after it,
//! once.

use std::time::Duration;

use ianua_scenarios::actors::FOUNDER_PASSWORD;
use ianua_scenarios::api::{members, people};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Part, Profile, Stack};
use ianua_scenarios::wire::organization::{AcceptMemberInvitation, InviteMember, Member, OrgRole};
use ianua_scenarios::world::World;

/// How long a mail sent twice would take to arrive the second time.
const SECOND_MAIL_WAIT: Duration = Duration::from_secs(5);

/// The record a member's sign-in leaves.
const SIGNED_IN: &str = "organization.org_login_succeeded";

/// The record an invitation leaves.
const INVITED: &str = "organization.org_user_invited";

/// Acme exists, Ann and Tess are signed in. The platform restarts. Acme
/// and its members are all still there, Ann's session still reads them,
/// Tess's session still reads her tenant's users, and no sign-in is
/// recorded that nobody made.
#[tokio::test]
async fn a_restart_loses_nothing_and_signs_nobody_out() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let ann = world.owner().client();
    let before = members::list(world.org(), None).send(ann).await.ok();
    let trail = world.trail();
    let sign_ins = trail.count(SIGNED_IN).await;

    stack.restart().await.expect("the platform restarts");

    let after = members::list(world.org(), None).send(ann).await.ok();
    assert_eq!(
        roster(&before.items),
        roster(&after.items),
        "Ann's session reads the same members after the restart"
    );
    people::list(world.tenant(), None)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(
        trail.count(SIGNED_IN).await,
        sign_ins,
        "keeping the sessions records no sign-in"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann invites Carl while the mail service is down, then the API and the
/// worker restart. The mail service back, Carl's invitation is mailed
/// once; he joins from it as the member Ann invited, and one invitation
/// of him is recorded.
#[tokio::test]
async fn work_queued_before_a_restart_is_done_once_after_it() {
    let stack = Stack::start(
        Profile::standard()
            .with_cuttable_parts()
            .with("EMAIL_SEND_TIMEOUT_SECONDS", "1")
            .with("JOB_RETRY_BACKOFF_SECONDS", "1,2,3"),
    )
    .await
    .expect("the stack starts");
    let world = World::new(&stack).await;
    let carl = world.address("carl");
    let invitation = carls_invitation(&carl);
    let trail = world.trail();
    let before = trail.count(INVITED).await;
    stack.cut(Part::Mail);
    let invited = members::invite(world.org(), &invitation)
        .send(world.owner().client())
        .await
        .ok();

    stack.restart().await.expect("the platform restarts");
    stack.mend(Part::Mail);
    accept_queued_invitation(&stack, &world, &carl, &invited.id).await;
    assert_eq!(
        trail.count(INVITED).await,
        before + 1,
        "a delivery retry does not invite Carl again"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann invites Carl with the member role before the mail outage and restart.
fn carls_invitation(carl: &str) -> InviteMember {
    InviteMember {
        email: carl.to_owned(),
        display_name: "Carl Restart".to_owned(),
        role: OrgRole::Member,
    }
}

/// Carl receives the queued mail once and activates the same invited membership.
async fn accept_queued_invitation(stack: &Stack, world: &World<'_>, carl: &str, invited_id: &str) {
    let mail = stack.mailbox().next_for(carl).await;
    stack.mailbox().nothing_for(carl, SECOND_MAIL_WAIT).await;
    let browser = Client::new(stack, "Carl accepting after a restart").expect("a client");
    let accept = AcceptMemberInvitation {
        token: mail.token_in("/accept-invite"),
        password: FOUNDER_PASSWORD.to_owned(),
    };
    let joined = members::accept_invitation(world.org(), &accept)
        .send(&browser)
        .await
        .ok();
    assert_eq!(joined.id, invited_id, "the queued link activates Carl");
}

/// Who `members` are and what they hold, to compare two readings.
fn roster(members: &[Member]) -> Vec<(&str, &str, &str, Option<OrgRole>)> {
    members
        .iter()
        .map(|member| {
            (
                member.id.as_str(),
                member.email.as_str(),
                member.status.as_str(),
                member.role,
            )
        })
        .collect()
}
