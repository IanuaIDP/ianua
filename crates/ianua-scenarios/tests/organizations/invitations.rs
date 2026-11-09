//! Invitations as Ann sends them and as Mallory, Max and Sam abuse them:
//! Uma joins as the role offered, never more; her link works once; Vic's
//! seat, not yet accepted, opens nothing; and only someone with the right
//! invites at all.

use ianua_scenarios::api::members;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::{
    AcceptMemberInvitation, InviteMember, MemberJoined, OrgRole,
};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{QUIET, role_of, sign_in_refused};

/// The password the invitees choose: a sentence, so no scanner takes it
/// for a key.
const PASSWORD: &str = "Invited lantern harbour meadow 5823";

/// The password Mallory would set on Uma's seat: a sentence, so no
/// scanner takes it for a key.
const MALLORYS_PASSWORD: &str = "Mallory takes this seat now 7193";

/// Ann invites Uma as a member. Uma accepts from the mail with a form
/// that adds a role of owner the real form never has: she joins as the
/// member she was invited as. Mallory, who saw the link, opens it again
/// with a password of her own: the link is spent, and that password does
/// not sign in as Uma.
#[tokio::test]
async fn an_invitee_joins_as_offered_and_the_link_works_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = world.address("uma");
    let token = invited(&world, &uma, OrgRole::Member).await;

    let uma_client = Client::new(&stack, "Uma, invited").expect("a client");
    let raised = json!({
        "token": token,
        "password": PASSWORD,
        "role": "Owner",
    });
    let accept = Call::post(world.org().at("/users/accept-invitation")).json(&raised);
    let joined = uma_client.send::<MemberJoined>(accept).await.ok();
    assert_eq!(
        role_of(&world, &joined.id).await,
        Some(OrgRole::Member),
        "Uma joins as the member she was invited as"
    );

    let mallory = Client::new(&stack, "Mallory, with Uma's link").expect("a client");
    let again = AcceptMemberInvitation {
        token,
        password: MALLORYS_PASSWORD.to_owned(),
    };
    members::accept_invitation(world.org(), &again)
        .send(&mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    sign_in_refused(&mallory, &uma, MALLORYS_PASSWORD).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann invites Vic, who has not accepted yet. Someone guessing at his
/// seat with the password invitees usually choose is told no more than
/// that nobody matched.
#[tokio::test]
async fn an_invitation_not_yet_accepted_opens_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let vic = world.address("vic");
    invited(&world, &vic, OrgRole::Admin).await;

    let guesser = Client::new(&stack, "someone guessing Vic's seat").expect("a client");
    sign_in_refused(&guesser, &vic, PASSWORD).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max, a plain member, tries to bring Eve in: as an owner, as an
/// administrator, as a member. Sam, from another company, tries to
/// invite her into Ann's as an owner. Every invitation is refused, and
/// Eve is mailed no link.
#[tokio::test]
async fn only_someone_with_the_right_invites() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let eve = world.address("eve");

    let attempts = [
        ("Max inviting an owner", world.member(), OrgRole::Owner),
        (
            "Max inviting an administrator",
            world.member(),
            OrgRole::Admin,
        ),
        ("Max inviting a member", world.member(), OrgRole::Member),
        (
            "Sam inviting into Ann's company",
            world.stranger(),
            OrgRole::Owner,
        ),
    ];
    for (what, actor, role) in attempts {
        let inviting = members::invite(world.org(), &invitation_of(&eve, role));
        Matrix::new(what, inviting.call())
            .refused(actor.client(), Status::FORBIDDEN, "forbidden")
            .run()
            .await;
    }
    stack.mailbox().nothing_for(&eve, QUIET).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann invites `email` as `role`; the token of the mailed link.
async fn invited(world: &World<'_>, email: &str, role: OrgRole) -> String {
    members::invite(world.org(), &invitation_of(email, role))
        .send(world.owner().client())
        .await
        .ok();
    let mail = world.stack().mailbox().next_for(email).await;
    mail.token_in("/accept-invite")
}

/// An invitation of `email` as `role`.
fn invitation_of(email: &str, role: OrgRole) -> InviteMember {
    InviteMember {
        email: email.to_owned(),
        display_name: "Invited Person".to_owned(),
        role,
    }
}
