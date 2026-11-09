//! Ann and her co-owner Uma each step down at the same moment; the
//! company keeps one active owner whichever of them was first.

use ianua_scenarios::actors::Member;
use ianua_scenarios::api::{OrgPath, members};
use ianua_scenarios::expect::Trail;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::organization::{ChangeRole, OrgRole};
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;

/// Which of the two owners stepping down at once the platform let go.
#[derive(Debug, Clone, Copy)]
enum SteppedDown {
    /// Ann stepped down; Uma keeps the company.
    Ann,
    /// Uma stepped down; Ann keeps the company.
    Uma,
}

/// When owners Ann and Uma demote themselves at the same moment, exactly
/// one succeeds and the other is refused. The refused owner is still
/// in on the session they hold, the one let go signs in again as an
/// administrator, the company has one owner, and one change is recorded.
#[tokio::test]
async fn two_owners_cannot_both_step_down_at_the_same_time() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let org = world.org().clone();
    let mut uma = world.colleague("uma", "Uma Owner", OrgRole::Owner).await;
    uma.sign_in(&stack).await;
    let stepped_down = race_demotions(&world, &uma).await;
    let keeper = match stepped_down {
        SteppedDown::Ann => {
            signed_in_again_as_administrator(&stack, &org, world.owner_mut()).await;
            uma.client()
        }
        SteppedDown::Uma => {
            signed_in_again_as_administrator(&stack, &org, &mut uma).await;
            world.owner().client()
        }
    };
    check_retained_owner(&org, keeper).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Both owners submit their own demotions concurrently.
async fn race_demotions(world: &World<'_>, uma: &Member) -> SteppedDown {
    let org = world.org();
    let request = ChangeRole {
        role: OrgRole::Admin,
    };
    let ann_steps_down = members::change_role(org, world.owner().id(), &request);
    let uma_steps_down = members::change_role(org, uma.id(), &request);
    let (ann_answer, uma_answer) = tokio::join!(
        ann_steps_down.send(world.owner().client()),
        uma_steps_down.send(uma.client())
    );
    accepted_demotion(ann_answer, uma_answer)
}

/// Exactly one demotion succeeds and the losing request is refused for ownership conflict.
fn accepted_demotion(ann_answer: Answer<()>, uma_answer: Answer<()>) -> SteppedDown {
    match (ann_answer.status(), uma_answer.status()) {
        (Status::NO_CONTENT, Status::NO_CONTENT) => {
            panic!("both owners stepped down, leaving the company with no owner");
        }
        (Status::NO_CONTENT, _) => {
            ann_answer.ok();
            uma_answer.refused(Status::CONFLICT, "conflict");
            SteppedDown::Ann
        }
        (_, Status::NO_CONTENT) => {
            uma_answer.ok();
            ann_answer.refused(Status::CONFLICT, "conflict");
            SteppedDown::Uma
        }
        (_, _) => panic!(
            "one of the two owners steps down, but Ann got {} and Uma {}",
            ann_answer.summary(),
            uma_answer.summary()
        ),
    }
}

/// The refused owner keeps the current session, sole ownership and one recorded role change.
async fn check_retained_owner(org: &OrgPath, keeper: &Client) {
    let kept = members::me(org).send(keeper).await.ok();
    assert_eq!(
        kept.role,
        Some(OrgRole::Owner),
        "the owner refused stepping down still owns the company"
    );
    let team = members::list(org, None).send(keeper).await.ok();
    assert_eq!(
        team.items
            .iter()
            .filter(|member| member.role == Some(OrgRole::Owner))
            .count(),
        1,
        "the company has one owner"
    );
    assert_eq!(
        Trail::of_organization(keeper, org.slug())
            .count("organization.org_user_role_changed")
            .await,
        1,
        "one change of role is recorded"
    );
}

/// `member`, let go as an owner: the session they held is dead, and
/// signed in again they are an administrator.
async fn signed_in_again_as_administrator(stack: &Stack, org: &OrgPath, member: &mut Member) {
    members::me(org)
        .send(member.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    member.sign_in(stack).await;
    let own = members::me(org).send(member.client()).await.ok();
    assert_eq!(
        own.role,
        Some(OrgRole::Admin),
        "{} stepped down to administrator",
        member.email()
    );
}
