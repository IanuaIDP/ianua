//! A team as Ann runs it: Zoe is invited, joins, is promoted and steps
//! back again; and as Max, Tess and Sam try it: nobody raises their own
//! rank, or anyone else's without the right.

use ianua_scenarios::api::members;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::OrgRole;
use ianua_scenarios::world::World;

use crate::support::{change_to, role_of};

/// Ann invites Zoe as a member. Zoe joins from the mail, signs in and
/// sees herself as a member. Ann makes her an administrator: the session
/// Zoe held, which carried her old role, is ended at once, and once she
/// signs in again she is an administrator. Then a member again, the same
/// way.
#[tokio::test]
async fn a_colleague_joins_is_promoted_and_steps_back() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut zoe = world
        .colleague("zoe", "Zoe Colleague", OrgRole::Member)
        .await;
    zoe.sign_in(&stack).await;

    let me = members::me(world.org()).send(zoe.client()).await.ok();
    assert_eq!(me.role, Some(OrgRole::Member), "Zoe joins as a member");
    assert_eq!(me.status, "Active", "Zoe is active once she accepted");

    for role in [OrgRole::Admin, OrgRole::Member] {
        members::change_role(world.org(), zoe.id(), &change_to(role))
            .send(world.owner().client())
            .await
            .ok();
        members::me(world.org())
            .send(zoe.client())
            .await
            .refused(Status::UNAUTHORIZED, "unauthenticated");
        zoe.sign_in(&stack).await;
        let me = members::me(world.org()).send(zoe.client()).await.ok();
        assert_eq!(me.role, Some(role), "Zoe is {role:?} once signed in again");
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max, a plain member, tries to make himself the owner, then an
/// administrator, then to raise Tess. Tess, who runs a tenant but is a
/// plain member of the organization, tries to make herself its
/// administrator. Sam, from another company, tries to change Max. All
/// are refused, and every role is what it was.
#[tokio::test]
async fn nobody_raises_their_own_rank_or_anyone_elses_without_the_right() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let max = world.member();
    let tess = world.admin();
    refuse_maxs_promotions(&world).await;
    refuse_others_promotions(&world).await;
    assert_eq!(
        role_of(&world, max.id()).await,
        Some(OrgRole::Member),
        "Max is the member he was"
    );
    assert_eq!(
        role_of(&world, tess.id()).await,
        Some(OrgRole::Member),
        "Tess is the member she was"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Max cannot promote himself to owner or administrator.
async fn refuse_maxs_promotions(world: &World<'_>) {
    let max = world.member();
    let attempts = [
        (
            "Max making himself the owner",
            max,
            max.id(),
            OrgRole::Owner,
        ),
        (
            "Max making himself an administrator",
            max,
            max.id(),
            OrgRole::Admin,
        ),
    ];
    for (what, actor, target, role) in attempts {
        let changing = members::change_role(world.org(), target, &change_to(role));
        Matrix::new(what, changing.call())
            .refused(actor.client(), Status::FORBIDDEN, "forbidden")
            .run()
            .await;
    }
}

/// Max and Tess cannot promote Tess, and Sam cannot change Max across companies.
async fn refuse_others_promotions(world: &World<'_>) {
    let max = world.member();
    let tess = world.admin();
    let attempts = [
        (
            "Max making Tess an administrator",
            max,
            tess.id(),
            OrgRole::Admin,
        ),
        (
            "Tess making herself an administrator",
            tess,
            tess.id(),
            OrgRole::Admin,
        ),
    ];
    for (what, actor, target, role) in attempts {
        let changing = members::change_role(world.org(), target, &change_to(role));
        Matrix::new(what, changing.call())
            .refused(actor.client(), Status::FORBIDDEN, "forbidden")
            .run()
            .await;
    }
    refuse_sams_change(world).await;
}

/// Sam's company membership grants no authority over Max's company role.
async fn refuse_sams_change(world: &World<'_>) {
    let changing =
        members::change_role(world.org(), world.member().id(), &change_to(OrgRole::Owner));
    Matrix::new("Sam changing Max", changing.call())
        .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
        .run()
        .await;
}
