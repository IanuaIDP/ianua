//! Uma invited into Ann's organization as an administrator: the mailed
//! link joins her with the offered role and nothing more, and signs
//! nobody in; an expired link is resent, a revoked or declined one is
//! dead; the sender's authority is checked again when she accepts; and
//! nobody without organization authority invites anyone.

use std::time::Duration;

use ianua_scenarios::actors::{Member, MemberAccount};
use ianua_scenarios::api::{members, registration, sessions};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Matrix, no_secret_leaked};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::{
    AcceptMemberInvitation, ChangeRole, InviteMember, MemberJoined, OrgRole,
};
use ianua_scenarios::wire::people::LinkToken;
use ianua_scenarios::wire::sign_in::PasswordSignIn;
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::QUIET;

/// The password Uma chooses when she accepts, unlike any existing
/// member's: a sentence, so no scanner takes it for a key.
const UMAS_PASSWORD: &str = "Invited quiet orchard lantern 9527";

/// How long an invitation is kept in the expiry scenario, on the
/// controlled clock.
const INVITATION_LIFETIME: Duration = Duration::from_secs(5);

/// One second past the invitation's lifetime.
const PAST_THE_INVITATION: Duration = Duration::from_secs(6);

/// The record of an invitation accepted.
const ACCEPTED: &str = "organization.org_user_invitation_accepted";

/// An invitation sent to Uma. Holds the link's token, so it has no
/// `Debug`.
struct Invitation {
    /// Uma's id, as the invitation made it.
    id: String,
    /// Uma's address.
    email: String,
    /// The token in the mailed link.
    proof: LinkToken,
}

/// Uma cannot sign in before accepting. The wrong company and a weak
/// password are refused without consuming her invitation; extra owner-role
/// and organization fields cannot change the offered administrator account.
/// Acceptance signs nobody in and cannot be repeated. Uma signs in separately,
/// reads her verified role and is refused the other company; Ann keeps access.
/// One acceptance is recorded without the password or invitation token.
#[tokio::test]
async fn a_member_invitation_joins_only_its_offered_account_and_role() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let before = world.trail().count(ACCEPTED).await;
    let invitation = invited(&world, world.owner()).await;

    assert_pending_invitation(&world, &invitation).await;
    accept_with_extra_fields(&world, &invitation).await;
    members::me(world.org())
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    members::accept_invitation(world.org(), &accepting(&invitation))
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    uma_signed_in(&world, &invitation).await;
    assert_acceptance_record(&world, &invitation, before).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pending Uma cannot sign in, and wrong-company or weak-password attempts leave her proof usable.
async fn assert_pending_invitation(world: &World<'_>, invitation: &Invitation) {
    sessions::member_sign_in(&PasswordSignIn::of(&invitation.email, UMAS_PASSWORD))
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    members::accept_invitation(world.stranger().org(), &accepting(invitation))
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let mut weak = accepting(invitation);
    weak.password = "abc".to_owned();
    members::accept_invitation(world.org(), &weak)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
}

/// Unrequested role and company fields cannot change the invited seat being accepted.
async fn accept_with_extra_fields(world: &World<'_>, invitation: &Invitation) {
    let smuggling = json!({
        "token": invitation.proof.token,
        "password": UMAS_PASSWORD,
        "role": "Owner",
        "organization_id": "not-the-invited-company",
    });
    let joined = world
        .anonymous()
        .client()
        .send::<MemberJoined>(
            Call::post(world.org().at("/users/accept-invitation")).json(&smuggling),
        )
        .await
        .ok();
    assert_eq!(
        joined.id, invitation.id,
        "the seat joined is the one offered"
    );
}

/// Uma's acceptance adds one audit record and none of the records expose either secret.
async fn assert_acceptance_record(world: &World<'_>, invitation: &Invitation, before: usize) {
    let records = world.trail().entries(ACCEPTED).await;
    assert_eq!(
        world.trail().count(ACCEPTED).await,
        before + 1,
        "one acceptance was recorded"
    );
    for record in records {
        no_secret_leaked(
            &record.details.to_string(),
            &[UMAS_PASSWORD, &invitation.proof.token],
        );
    }
}

/// Uma's invitation expires unopened, so it joins nothing. Ann sends it
/// again: the old link is now dead, the fresh one joins Uma, and she uses
/// her seat.
#[tokio::test]
async fn an_expired_member_invitation_can_be_resent_and_only_the_new_proof_joins() {
    let clock = Clock::controlled();
    let stack = Stack::start(
        Profile::standard()
            .with(
                "ORG_INVITATION_TTL_SECONDS",
                &INVITATION_LIFETIME.as_secs().to_string(),
            )
            .with("MAIL_COOLDOWN_SECONDS", "0"),
    )
    .await
    .expect("the stack starts");
    let world = World::new(&stack).await;
    let old = invited(&world, world.owner()).await;

    clock.advance(PAST_THE_INVITATION);
    members::accept_invitation(world.org(), &accepting(&old))
        .send(world.anonymous().client())
        .await
        .refused(Status::GONE, "link_expired");

    let fresh = resend_invitation(&world, &old).await;
    members::accept_invitation(world.org(), &accepting(&old))
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    members::accept_invitation(world.org(), &accepting(&fresh))
        .send(world.anonymous().client())
        .await
        .ok();
    uma_signed_in(&world, &fresh).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann resends the invitation for the same seat and mailbox with a fresh proof.
async fn resend_invitation(world: &World<'_>, old: &Invitation) -> Invitation {
    registration::resend_member(world.org(), &old.id)
        .send(world.owner().client())
        .await
        .ok();
    let mail = world.stack().mailbox().next_for(&old.email).await;
    Invitation {
        id: old.id.clone(),
        email: old.email.clone(),
        proof: LinkToken {
            token: mail.token_in("/accept-invite"),
        },
    }
}

/// After Ann revokes Uma's invitation, its link and proposed password both
/// return not found. The revocation is recorded without an acceptance, and
/// Ann can still read her own record.
#[tokio::test]
async fn a_revoked_member_invitation_cannot_join_or_sign_in() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let invitation = invited(&world, world.owner()).await;
    let before = world.trail().count(ACCEPTED).await;

    registration::revoke_member(world.org(), &invitation.id)
        .send(world.owner().client())
        .await
        .ok();
    assert_invitation_unusable(&world, &invitation).await;

    assert_eq!(
        world.trail().count(ACCEPTED).await,
        before,
        "a refused link records no acceptance"
    );
    world
        .trail()
        .recorded("organization.org_user_invitation_revoked")
        .await;
    members::me(world.org())
        .send(world.owner().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Neither the revoked invitation nor its proposed password opens the invited seat.
async fn assert_invitation_unusable(world: &World<'_>, invitation: &Invitation) {
    members::accept_invitation(world.org(), &accepting(invitation))
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    sessions::member_sign_in(&PasswordSignIn::of(&invitation.email, UMAS_PASSWORD))
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// After Uma declines, accepting the same link and signing in with her
/// proposed password both return not found. The decline is recorded and
/// Ann can still read her own record.
#[tokio::test]
async fn a_declined_member_invitation_cannot_later_be_accepted() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let invitation = invited(&world, world.owner()).await;

    registration::decline_member(world.org(), &invitation.proof)
        .send(world.anonymous().client())
        .await
        .ok();
    members::accept_invitation(world.org(), &accepting(&invitation))
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    sessions::member_sign_in(&PasswordSignIn::of(&invitation.email, UMAS_PASSWORD))
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    world
        .trail()
        .recorded("organization.org_user_invitation_declined")
        .await;
    members::me(world.org())
        .send(world.owner().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ivy invites Uma as an administrator, then Ann makes Ivy a viewer.
/// Uma's acceptance is forbidden until Ann restores Ivy's administrator
/// role. The same link then joins Uma, who signs in with the offered role
/// and cannot access the other company; Ann keeps access to her account.
#[tokio::test]
async fn a_member_invitation_rechecks_its_senders_current_authority() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut ivy = world.colleague("ivy", "Ivy Admin", OrgRole::Admin).await;
    ivy.sign_in(&stack).await;
    let invitation = invited(&world, &ivy).await;

    change_inviter_role(&world, &ivy, OrgRole::Viewer).await;
    members::accept_invitation(world.org(), &accepting(&invitation))
        .send(world.anonymous().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    change_inviter_role(&world, &ivy, OrgRole::Admin).await;
    members::accept_invitation(world.org(), &accepting(&invitation))
        .send(world.anonymous().client())
        .await
        .ok();
    uma_signed_in(&world, &invitation).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann changes the inviter's current authority while the invitation remains pending.
async fn change_inviter_role(world: &World<'_>, ivy: &Member, role: OrgRole) {
    members::change_role(world.org(), ivy.id(), &ChangeRole { role })
        .send(world.owner().client())
        .await
        .ok();
}

/// Tess, who administers a tenant, Max, a plain member, Sam from the
/// twin company, and nobody signed in each try to invite Uma as an
/// administrator: all refused, and nothing is mailed to her. Ann's own
/// invitation to the same address goes out, and Uma joins from it.
#[tokio::test]
async fn nobody_but_organization_authority_invites_a_member() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let email = world.address("uma");
    let invite = InviteMember {
        email: email.clone(),
        display_name: "Uma Invitee".to_owned(),
        role: OrgRole::Admin,
    };

    assert_unauthorized_inviters(&world, &invite).await;
    stack.mailbox().nothing_for(&email, QUIET).await;

    let invitation = invited(&world, world.owner()).await;
    members::accept_invitation(world.org(), &accepting(&invitation))
        .send(world.anonymous().client())
        .await
        .ok();
    uma_signed_in(&world, &invitation).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tenant administration, ordinary membership and foreign sessions cannot invite an org admin.
async fn assert_unauthorized_inviters(world: &World<'_>, invite: &InviteMember) {
    Matrix::new(
        "inviting a member",
        members::invite(world.org(), invite).call(),
    )
    .refused(world.admin().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
}

/// Uma, invited by `sender` into the organization as an administrator,
/// with the link mailed to her.
///
/// # Panics
///
/// When the invitation is refused, or no link comes.
async fn invited(world: &World<'_>, sender: &Member) -> Invitation {
    let email = world.address("uma");
    let made = members::invite(
        world.org(),
        &InviteMember {
            email: email.clone(),
            display_name: "Uma Invitee".to_owned(),
            role: OrgRole::Admin,
        },
    )
    .send(sender.client())
    .await
    .ok();
    let mail = world.stack().mailbox().next_for(&email).await;
    Invitation {
        id: made.id,
        email,
        proof: LinkToken {
            token: mail.token_in("/accept-invite"),
        },
    }
}

/// Uma accepting `invitation` with her own password; the form names no
/// role and no organization.
fn accepting(invitation: &Invitation) -> AcceptMemberInvitation {
    AcceptMemberInvitation {
        token: invitation.proof.token.clone(),
        password: UMAS_PASSWORD.to_owned(),
    }
}

/// Uma signs in on a browser of her own with the password she chose and
/// reads her own record: hers, verified, an administrator's. Sam's
/// company is refused her; Ann still reads her own record.
///
/// # Panics
///
/// When the sign-in or a read is refused, or the record is not hers.
async fn uma_signed_in(world: &World<'_>, invitation: &Invitation) {
    let browser = Client::new(world.stack(), "Uma, signing in after accepting").expect("a client");
    let mut uma = Member::new(
        browser,
        MemberAccount {
            id: invitation.id.clone(),
            email: invitation.email.clone(),
            display_name: "Uma Invitee".to_owned(),
            org: world.org().clone(),
            role: OrgRole::Admin,
            landing: None,
        },
        UMAS_PASSWORD,
    );
    uma.sign_in(world.stack()).await;
    let own = members::me(world.org()).send(uma.client()).await.ok();
    assert_eq!(own.id, invitation.id, "the record read is Uma's own");
    assert!(own.email_verified, "the mailed link proved her address");
    assert_eq!(own.role, Some(OrgRole::Admin), "with the role offered");
    members::me(world.stranger().org())
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    members::me(world.org())
        .send(world.owner().client())
        .await
        .ok();
}
