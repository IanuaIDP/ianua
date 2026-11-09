//! Ann hands her company to Uma and to Max at the same moment; one of
//! them becomes the owner whole, the other is left as he or she was.

use ianua_scenarios::actors::Member;
use ianua_scenarios::api::members;
use ianua_scenarios::expect::Trail;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::organization::OrgRole;
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;

/// The recipient whose concurrent handover succeeded.
enum Heir {
    Uma,
    Max,
}

/// Ann's simultaneous transfers to Uma and Max cannot both succeed or
/// partly promote the losing recipient. Exactly one
/// becomes the owner: Ann's and the winner's sessions end, the loser is
/// still a member on the session they hold, and signed in afresh the
/// winner owns the company and Ann is an administrator. The trail holds
/// one handover and two role changes; the original Max and Sam are still in.
#[tokio::test]
async fn competing_handovers_choose_one_heir_without_partially_promoting_the_other() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let mut uma = world.colleague("uma", "Uma Heir", OrgRole::Member).await;
    let mut max = world
        .colleague("max-heir", "Max Heir", OrgRole::Member)
        .await;
    uma.sign_in(&stack).await;
    max.sign_in(&stack).await;
    let heir = race_handovers(&world, &uma, &max).await;
    let (winner, loser) = match heir {
        Heir::Uma => (&mut uma, &mut max),
        Heir::Max => (&mut max, &mut uma),
    };
    check_original_sessions(&world, winner, loser).await;
    winner.sign_in(&stack).await;
    world.owner_mut().sign_in(&stack).await;
    check_winning_roles(&world, winner).await;
    check_handover_records(&world, winner).await;
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    members::me(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann submits both handovers concurrently on her current session.
async fn race_handovers(world: &World<'_>, uma: &Member, max: &Member) -> Heir {
    let to_uma = members::transfer_ownership(world.org(), uma.id());
    let to_max = members::transfer_ownership(world.org(), max.id());
    let (to_uma, to_max) = tokio::join!(
        to_uma.send(world.owner().client()),
        to_max.send(world.owner().client())
    );
    accepted_handover(to_uma, to_max)
}

/// Exactly one heir wins, and the later handover must fail for a permitted refusal reason.
fn accepted_handover(to_uma: Answer<()>, to_max: Answer<()>) -> Heir {
    let (winner, refused) = match (to_uma.status(), to_max.status()) {
        (Status::NO_CONTENT, Status::NO_CONTENT) => {
            panic!("both handovers succeeded, making two owners of one company");
        }
        (Status::NO_CONTENT, _) => {
            to_uma.ok();
            (Heir::Uma, to_max)
        }
        (_, Status::NO_CONTENT) => {
            to_max.ok();
            (Heir::Max, to_uma)
        }
        (_, _) => panic!(
            "one handover succeeds, but Uma's got {} and Max's {}",
            to_uma.summary(),
            to_max.summary()
        ),
    };
    refused_as_the_late_handover(refused);
    winner
}

/// Ann and the winning heir lose their sessions while the losing heir remains a member.
async fn check_original_sessions(world: &World<'_>, winner: &Member, loser: &Member) {
    members::me(world.org())
        .send(world.owner().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    members::me(world.org())
        .send(winner.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let left = members::me(world.org()).send(loser.client()).await.ok();
    assert_eq!(
        left.role,
        Some(OrgRole::Member),
        "the heir not chosen is still a member on the session they hold"
    );
}

/// Fresh sessions expose the complete handover, with exactly one owner on the team.
async fn check_winning_roles(world: &World<'_>, winner: &Member) {
    let won = members::me(world.org()).send(winner.client()).await.ok();
    assert_eq!(
        won.role,
        Some(OrgRole::Owner),
        "the chosen heir owns the company"
    );
    let ann = members::me(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        ann.role,
        Some(OrgRole::Admin),
        "Ann is an administrator after the handover"
    );
    let team = members::list(world.org(), None)
        .send(winner.client())
        .await
        .ok();
    assert_eq!(
        team.items
            .iter()
            .filter(|member| member.role == Some(OrgRole::Owner))
            .count(),
        1,
        "the company has one owner"
    );
}

/// One handover and its two role changes are recorded under the winner's accessible trail.
async fn check_handover_records(world: &World<'_>, winner: &Member) {
    let trail = Trail::of_organization(winner.client(), world.org().slug());
    assert_eq!(
        trail.count("organization.ownership_transferred").await,
        1,
        "one handover is recorded"
    );
    assert_eq!(
        trail.count("organization.org_user_role_changed").await,
        2,
        "the handover records both role changes"
    );
}

/// The handover that lost is refused as the platform saw it: Ann's
/// session already ended by the winner, Ann no longer an owner, or the
/// company's ownership held against it.
fn refused_as_the_late_handover(refused: Answer<()>) {
    match refused.status() {
        Status::UNAUTHORIZED => {
            refused.refused(Status::UNAUTHORIZED, "unauthenticated");
        }
        Status::FORBIDDEN => {
            refused.refused(Status::FORBIDDEN, "forbidden");
        }
        Status::CONFLICT => {
            refused.refused(Status::CONFLICT, "conflict");
        }
        _ => panic!(
            "the late handover is refused for the session, the role or the ownership, not {}",
            refused.summary()
        ),
    }
}
