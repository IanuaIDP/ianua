//! Ownership as Ann hands it to Zoe, and as it must never be lost: a
//! company always keeps an owner, and an owner who stepped down cannot
//! take it back alone.

use ianua_scenarios::actors::Member;
use ianua_scenarios::api::members;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::OrgRole;
use ianua_scenarios::world::World;

use crate::support::{change_to, role_of};

/// Ann is the only owner: she can neither step down nor remove herself,
/// so the company is never left without one. She makes Zoe an owner,
/// then steps down to administrator; each change ends the sessions of
/// the one it changed, which carried the old role. Signed in again, Zoe
/// is the only owner and cannot step down either, and Ann cannot make
/// herself the owner again. Zoe owns the company; Ann administers it.
#[tokio::test]
async fn ownership_is_handed_over_and_never_dropped() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    refuse_ownerless_company(&world).await;
    let mut zoe = world
        .colleague("zoe", "Zoe Colleague", OrgRole::Member)
        .await;
    zoe.sign_in(&stack).await;
    members::change_role(world.org(), zoe.id(), &change_to(OrgRole::Owner))
        .send(world.owner().client())
        .await
        .ok();
    signed_in_again(&stack, &mut zoe, &world).await;
    demote_ann(&stack, &mut world).await;
    assert_zoe_owns_company(&world, &zoe).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann cannot demote or remove herself while she is the company's only owner.
async fn refuse_ownerless_company(world: &World<'_>) {
    let ann = world.owner();
    members::change_role(world.org(), ann.id(), &change_to(OrgRole::Admin))
        .send(ann.client())
        .await
        .refused(Status::CONFLICT, "conflict");
    members::remove(world.org(), ann.id())
        .send(ann.client())
        .await
        .refused(Status::CONFLICT, "conflict");
}

/// Ann steps down, loses her old session and signs in with her administrator role.
async fn demote_ann(stack: &Stack, world: &mut World<'_>) {
    let ann = world.owner();
    members::change_role(world.org(), ann.id(), &change_to(OrgRole::Admin))
        .send(ann.client())
        .await
        .ok();
    let org = world.org().clone();
    let ann = world.owner_mut();
    members::me(&org)
        .send(ann.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    ann.sign_in(stack).await;
}

/// Zoe cannot abandon sole ownership, and Ann cannot reclaim it herself.
async fn assert_zoe_owns_company(world: &World<'_>, zoe: &Member) {
    members::change_role(world.org(), zoe.id(), &change_to(OrgRole::Admin))
        .send(zoe.client())
        .await
        .refused(Status::CONFLICT, "conflict");
    let ann = world.owner();
    members::change_role(world.org(), ann.id(), &change_to(OrgRole::Owner))
        .send(ann.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    assert_eq!(
        role_of(world, zoe.id()).await,
        Some(OrgRole::Owner),
        "Zoe owns the company"
    );
    assert_eq!(
        role_of(world, world.owner().id()).await,
        Some(OrgRole::Admin),
        "Ann administers it"
    );
}

/// Asserts the session `member` held before their role changed is ended,
/// then signs them in again.
async fn signed_in_again(stack: &Stack, member: &mut Member, world: &World<'_>) {
    members::me(world.org())
        .send(member.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    member.sign_in(stack).await;
}
