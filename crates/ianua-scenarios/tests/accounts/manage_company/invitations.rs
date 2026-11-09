//! The holder of a mailed invitation link, signed in to nothing, asks
//! what it is worth and, when it ran out, asks for another. Reading never
//! spends a link. Another is mailed only to the address the invitation
//! was sent to, and never from a link that still works or one this
//! company never sent.

use std::time::Duration;

use ianua_scenarios::api::{members, registration};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::{AcceptMemberInvitation, InviteMember, OrgRole};
use ianua_scenarios::wire::people::LinkToken;
use ianua_scenarios::world::World;

/// The password Uma chooses when she joins: a sentence, so no scanner
/// takes it for a key.
const PASSWORD: &str = "Quiet orchard pathway beneath lanterns 8214";

/// How long an invitation lasts in the expiry scenario, on the
/// controlled clock.
const LINK_LIFETIME: Duration = Duration::from_secs(5);

/// One second past the link's lifetime.
const PAST_THE_LINK: Duration = Duration::from_secs(6);

/// The record of an invitation mailed again.
const RESENT: &str = "organization.org_user_invitation_resent";

/// Ann invites Uma. Answers the token mailed to her and her address.
async fn invite_uma(world: &World<'_>) -> (LinkToken, String) {
    let email = world.address("uma");
    members::invite(
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
    let mail = world.stack().mailbox().next_for(&email).await;
    (
        LinkToken {
            token: mail.token_in("/accept-invite"),
        },
        email,
    )
}

/// What the link `proof` is worth, read by nobody signed in.
async fn link_status(world: &World<'_>, proof: &LinkToken) -> String {
    registration::member_invitation_status(world.org(), proof)
        .send(world.anonymous().client())
        .await
        .ok()
        .status
}

/// A link reads as usable, with the password rules for the form, however
/// often it is read. Once Uma joined with it, it reads as used. A link
/// this company never sent reads as invalid, and telling so confirms no
/// invitation exists; the empty token is refused.
#[tokio::test]
async fn a_mailed_invitation_link_is_read_without_being_spent() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let (proof, _email) = invite_uma(&world).await;

    let first = registration::member_invitation_status(world.org(), &proof)
        .send(world.anonymous().client())
        .await
        .ok();
    assert_eq!(first.status, "Valid", "the link is usable");
    assert!(first.password_policy.is_some(), "with the form's rules");
    assert_eq!(
        link_status(&world, &proof).await,
        "Valid",
        "reading spends nothing"
    );

    let invented = LinkToken {
        token: "an invented invitation link".to_owned(),
    };
    assert_eq!(
        link_status(&world, &invented).await,
        "Invalid",
        "a link never sent reads invalid"
    );
    let sams = registration::member_invitation_status(world.stranger().org(), &proof)
        .send(world.anonymous().client())
        .await
        .ok();
    assert_eq!(sams.status, "Invalid", "Sam's company never sent it");
    let empty = LinkToken {
        token: String::new(),
    };
    registration::member_invitation_status(world.org(), &empty)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    members::accept_invitation(
        world.org(),
        &AcceptMemberInvitation {
            token: proof.token.clone(),
            password: PASSWORD.to_owned(),
        },
    )
    .send(world.anonymous().client())
    .await
    .ok();
    assert_eq!(
        link_status(&world, &proof).await,
        "AlreadyUsed",
        "it spends once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma's link ran out: it reads expired and joins nothing. She asks for
/// another with the link she still holds: a new one reaches the address
/// the invitation was for, the old one is dead, the new one joins her,
/// and the resend is recorded once under her. A link of Ann's company is
/// nothing in Sam's, and an invented one is unknown.
#[tokio::test]
async fn uma_renews_her_invitation_with_the_link_she_still_holds() {
    let clock = Clock::controlled();
    let stack = Stack::start(
        Profile::standard()
            .with(
                "ORG_INVITATION_TTL_SECONDS",
                &LINK_LIFETIME.as_secs().to_string(),
            )
            .with("MAIL_COOLDOWN_SECONDS", "0"),
    )
    .await
    .expect("the stack starts");
    let world = World::new(&stack).await;
    let (old, email) = invite_uma(&world).await;

    registration::renew_member_invitation(world.org(), &old)
        .send(world.anonymous().client())
        .await
        .refused(Status::CONFLICT, "conflict");

    clock.advance(PAST_THE_LINK);
    check_expired_and_refused(&world, &old).await;

    let renewed = registration::renew_member_invitation(world.org(), &old)
        .send(world.anonymous().client())
        .await
        .ok();
    assert!(
        renewed.retry_after_seconds > 0,
        "she is told how long to wait for another"
    );
    let mail = world.stack().mailbox().next_for(&email).await;
    let fresh = LinkToken {
        token: mail.token_in("/accept-invite"),
    };
    assert_ne!(fresh.token, old.token, "a new link is mailed");

    join_with_the_new_link(&world, &old, &fresh).await;
    let records = world.trail().entries(RESENT).await;
    let [record] = records.as_slice() else {
        panic!("one {RESENT} is recorded, not {}", records.len());
    };
    assert!(
        record.actor.contains(&email),
        "the renewal is recorded under Uma"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The expired link joins nobody and reads as expired. Renewal asked of
/// Sam's company with it, and of Ann's with an invented link, finds
/// nothing.
async fn check_expired_and_refused(world: &World<'_>, old: &LinkToken) {
    let read = registration::member_invitation_status(world.org(), old)
        .send(world.anonymous().client())
        .await
        .ok();
    assert_eq!(read.status, "Expired", "the link ran out");
    assert!(read.password_policy.is_none(), "so no form is offered");

    registration::renew_member_invitation(world.stranger().org(), old)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let invented = LinkToken {
        token: "an invented invitation link".to_owned(),
    };
    registration::renew_member_invitation(world.org(), &invented)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert_eq!(
        world.trail().count(RESENT).await,
        0,
        "no refused renewal is recorded"
    );
}

/// The old link no longer joins or reads as anything; the new link
/// joins Uma.
async fn join_with_the_new_link(world: &World<'_>, old: &LinkToken, fresh: &LinkToken) {
    members::accept_invitation(
        world.org(),
        &AcceptMemberInvitation {
            token: old.token.clone(),
            password: PASSWORD.to_owned(),
        },
    )
    .send(world.anonymous().client())
    .await
    .refused(Status::NOT_FOUND, "not_found");
    assert_eq!(
        link_status(world, old).await,
        "Invalid",
        "the old link is dead"
    );
    assert_eq!(
        link_status(world, fresh).await,
        "Valid",
        "the new link is live"
    );
    members::accept_invitation(
        world.org(),
        &AcceptMemberInvitation {
            token: fresh.token.clone(),
            password: PASSWORD.to_owned(),
        },
    )
    .send(world.anonymous().client())
    .await
    .ok();
}
