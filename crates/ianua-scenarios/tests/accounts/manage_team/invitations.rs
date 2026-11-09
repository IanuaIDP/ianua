//! Ann invites Uma; Max, Tess, Sam and nobody signed in can neither send
//! the invitation again nor take it back, and it still joins Uma once.
//! A colleague who already joined, and a stranger, have no invitation
//! for Ann to send again or take back.

use ianua_scenarios::api::{members, registration};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::{AcceptMemberInvitation, InviteMember, OrgRole};
use ianua_scenarios::world::World;

use crate::support::{PASSWORD, listed};

/// After Ann invites Uma, Max, Tess, Sam and an anonymous caller cannot
/// resend or revoke the invitation. Neither action is
/// recorded, and the link Uma was mailed still joins her, active, with
/// the account the invitation made.
#[tokio::test]
async fn nobody_without_the_right_resends_or_revokes_an_invitation() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let email = world.address("uma");
    let invited = members::invite(
        world.org(),
        &InviteMember {
            email: email.clone(),
            display_name: "Uma Colleague".to_owned(),
            role: OrgRole::Member,
        },
    )
    .send(world.owner().client())
    .await
    .ok();
    let mail = stack.mailbox().next_for(&email).await;
    let token = mail.token_in("/accept-invite");
    refuse_invitation_callers(&world, &invited.id).await;
    check_no_invitation_changes(&world).await;
    accept_original_invitation(&world, &invited.id, token).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Every caller without invitation rights is refused both resend and revocation.
async fn refuse_invitation_callers(world: &World<'_>, id: &str) {
    for call in [
        registration::resend_member(world.org(), id).call(),
        registration::revoke_member(world.org(), id).call(),
    ] {
        Matrix::new("sending an invitation again or taking it back", call)
            .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
            .refused(world.admin().client(), Status::FORBIDDEN, "forbidden")
            .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
            .refused(
                world.anonymous().client(),
                Status::UNAUTHORIZED,
                "unauthenticated",
            )
            .run()
            .await;
    }
}

/// Refused invitation operations record neither a resend nor a revocation.
async fn check_no_invitation_changes(world: &World<'_>) {
    assert_eq!(
        world
            .trail()
            .count("organization.org_user_invitation_resent")
            .await,
        0,
        "no refused resend is recorded"
    );
    assert_eq!(
        world
            .trail()
            .count("organization.org_user_invitation_revoked")
            .await,
        0,
        "no refused revocation is recorded"
    );
}

/// The original mailed token still activates the account created by the invitation.
async fn accept_original_invitation(world: &World<'_>, id: &str, token: String) {
    let joined = members::accept_invitation(
        world.org(),
        &AcceptMemberInvitation {
            token,
            password: PASSWORD.to_owned(),
        },
    )
    .send(world.anonymous().client())
    .await
    .ok();
    assert_eq!(
        joined.id, id,
        "the link joins the account the invitation made"
    );
    assert_eq!(
        listed(world, &joined.id).await.status,
        "Active",
        "Uma is active once joined"
    );
}

/// Ann cannot resend or revoke invitations for Max, who already joined,
/// or Sam, who belongs to another company. Neither action is recorded,
/// and both members remain signed in.
#[tokio::test]
async fn a_joined_colleague_or_a_stranger_has_no_invitation_to_resend_or_revoke() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    for id in [world.member().id(), world.stranger().id()] {
        registration::resend_member(world.org(), id)
            .send(world.owner().client())
            .await
            .refused(Status::NOT_FOUND, "not_found");
        registration::revoke_member(world.org(), id)
            .send(world.owner().client())
            .await
            .refused(Status::NOT_FOUND, "not_found");
    }
    check_no_invitation_changes(&world).await;

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
