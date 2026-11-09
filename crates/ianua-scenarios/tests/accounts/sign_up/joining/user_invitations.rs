//! Pat invited into the tenant by Tess: the mailed link joins Pat with
//! the offered role and signs nobody in; an expired link is resent for
//! the same seat, a revoked or declined one is dead; Tess's tenant grants
//! are checked again when Pat accepts; and nobody but a tenant
//! administrator invites anyone.

use std::time::Duration;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{members, people, registration, sessions};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::TenantRoles;
use ianua_scenarios::wire::people::{AcceptInvitation, InviteUser, LinkToken};
use ianua_scenarios::wire::tenant_sign_in::TenantPasswordSignIn;
use ianua_scenarios::world::{ADMIN_ROLE, MEMBER_ROLE, World};

use super::support::{own_record_only, tenant_records};
use crate::support::QUIET;

/// How long an invitation is kept in the expiry scenario, on the
/// controlled clock.
const INVITATION_LIFETIME: Duration = Duration::from_secs(5);

/// One second past the invitation's lifetime.
const PAST_THE_INVITATION: Duration = Duration::from_secs(6);

/// The record of an invitation accepted.
const ACCEPTED: &str = "identity.invitation_accepted";

/// Pat cannot sign in or read an account before accepting. The other tenant
/// and a weak password are refused without consuming the invitation.
/// Acceptance joins Pat with the offered member role and verified address,
/// creates no session and cannot be repeated. After signing in separately,
/// Pat reads only their own record; one acceptance is recorded without secrets.
#[tokio::test]
async fn a_tenant_invitation_joins_its_own_account_without_implicit_sign_in() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = world.newcomer("pat", "Pat Invitee");
    let proof = invited(&world, &mut pat).await;

    still_outside(&world, &pat).await;
    assert_invalid_acceptance(&world, &mut pat, &proof).await;
    accepted_and_signed_in(&world, &mut pat, &proof).await;
    assert_offered_role(&world, &pat).await;
    let password = pat.password().to_owned();
    pat.accept_with(&proof.token, &password)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    own_record_only(&world, &pat).await;
    assert_eq!(
        tenant_records(&world, ACCEPTED, &[pat.password(), &proof.token]).await,
        1,
        "one acceptance"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// A foreign tenant and a weak password cannot spend Pat's pending invitation.
async fn assert_invalid_acceptance(world: &World<'_>, pat: &mut Person, proof: &LinkToken) {
    people::accept_invitation(
        world.twin(),
        &AcceptInvitation {
            token: proof.token.clone(),
            password: pat.password().to_owned(),
        },
    )
    .send(pat.client())
    .await
    .refused(Status::NOT_FOUND, "not_found");
    pat.accept_with(&proof.token, "abc")
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
}

/// Tess lists one account for Pat with the offered member role and no administrator role.
async fn assert_offered_role(world: &World<'_>, pat: &Person) {
    let listed = people::list(world.tenant(), Some(pat.email()))
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(listed.items.len(), 1, "one account for Pat");
    let kept = &listed.items[0];
    assert!(
        kept.roles.iter().any(|role| role.name == MEMBER_ROLE),
        "Pat holds the role offered"
    );
    assert!(
        kept.roles.iter().all(|role| role.name != ADMIN_ROLE),
        "and not the administrator's"
    );
}

/// Pat's invitation expires unopened, so it joins nothing. Tess sends it
/// again for the same seat: the old link is now dead, the fresh one joins
/// Pat under the same id, with no second account.
#[tokio::test]
async fn an_expired_tenant_invitation_can_be_resent_for_the_same_seat() {
    let clock = Clock::controlled();
    let stack = Stack::start(expiring_invitation_profile())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = world.newcomer("pat", "Pat Invitee");
    let old = invited(&world, &mut pat).await;
    let id = pat.id().to_owned();

    clock.advance(PAST_THE_INVITATION);
    let password = pat.password().to_owned();
    pat.accept_with(&old.token, &password)
        .await
        .refused(Status::GONE, "link_expired");

    let fresh = resend_invitation(&world, &pat).await;
    pat.accept_with(&old.token, &password)
        .await
        .refused(Status::NOT_FOUND, "not_found");

    accepted_and_signed_in(&world, &mut pat, &fresh).await;
    assert_eq!(pat.id(), id, "the same seat");
    let listed = people::list(world.tenant(), Some(pat.email()))
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(listed.items.len(), 1, "and no second account");

    stack.stop().await.expect("the stack stops cleanly");
}

/// The controlled clock can expire an invitation before an immediate resend.
fn expiring_invitation_profile() -> Profile {
    Profile::standard()
        .with(
            "INVITATION_TTL_SECONDS",
            &INVITATION_LIFETIME.as_secs().to_string(),
        )
        .with("MAIL_COOLDOWN_SECONDS", "0")
}

/// Tess requests a fresh proof for Pat's existing invited seat.
async fn resend_invitation(world: &World<'_>, pat: &Person) -> LinkToken {
    registration::resend_user(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    let mail = world.stack().mailbox().next_for(pat.email()).await;
    LinkToken {
        token: mail.token_in("/accept-invite"),
    }
}

/// After Tess revokes Pat's invitation, its link is refused and Pat cannot
/// sign in or read an account. One revocation and no acceptance are recorded
/// without secrets, while Tess can still list users.
#[tokio::test]
async fn a_revoked_tenant_invitation_cannot_activate_the_account() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = world.newcomer("pat", "Pat Invitee");
    let proof = invited(&world, &mut pat).await;

    registration::revoke_user(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_dead_invitation(&world, &mut pat, &proof).await;

    let secrets = [pat.password(), proof.token.as_str()];
    assert_eq!(
        tenant_records(&world, ACCEPTED, &secrets).await,
        0,
        "a revoked link records no acceptance"
    );
    assert_eq!(
        tenant_records(&world, "identity.invitation_revoked", &secrets).await,
        1,
        "the revocation is recorded"
    );
    people::list(world.tenant(), None)
        .send(world.admin().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// After Pat declines the invitation, accepting the same link is refused
/// and Pat cannot sign in or read an account. One decline and no acceptance
/// are recorded without secrets, while Tess can still list users.
#[tokio::test]
async fn a_declined_tenant_invitation_cannot_be_accepted_later() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = world.newcomer("pat", "Pat Invitee");
    let proof = invited(&world, &mut pat).await;

    registration::decline_user(world.tenant(), &proof)
        .send(pat.client())
        .await
        .ok();
    assert_dead_invitation(&world, &mut pat, &proof).await;

    let secrets = [pat.password(), proof.token.as_str()];
    assert_eq!(
        tenant_records(&world, "identity.invitation_declined", &secrets).await,
        1,
        "the decline is recorded"
    );
    assert_eq!(
        tenant_records(&world, ACCEPTED, &secrets).await,
        0,
        "and no acceptance"
    );
    people::list(world.tenant(), None)
        .send(world.admin().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// A revoked or declined proof cannot activate Pat or grant account access.
async fn assert_dead_invitation(world: &World<'_>, pat: &mut Person, proof: &LinkToken) {
    let password = pat.password().to_owned();
    pat.accept_with(&proof.token, &password)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    still_outside(world, pat).await;
}

/// Ann withdraws Tess's tenant grants after Tess invites Pat, so Pat's
/// acceptance is forbidden. Restoring Tess's administrator grant makes the
/// same link usable; Pat accepts, signs in separately and reads their own
/// verified record while user-list and other-tenant reads remain refused.
#[tokio::test]
async fn a_tenant_invitation_rechecks_the_senders_current_tenant_grants() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = world.newcomer("pat", "Pat Invitee");
    let proof = invited(&world, &mut pat).await;

    set_inviter_roles(&world, Vec::new()).await;
    let password = pat.password().to_owned();
    pat.accept_with(&proof.token, &password)
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    set_inviter_roles(&world, vec![ADMIN_ROLE.to_owned()]).await;
    accepted_and_signed_in(&world, &mut pat, &proof).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann replaces Tess's tenant grants while Pat's invitation stays pending.
async fn set_inviter_roles(world: &World<'_>, roles: Vec<String>) {
    members::set_tenant_roles(
        world.org(),
        world.admin().id(),
        world.tenant().slug(),
        &TenantRoles { roles },
    )
    .send(world.owner().client())
    .await
    .ok();
}

/// Max, a plain member, Sam from the twin company, and nobody signed in
/// each try to invite Pat: all refused, with no account made and nothing
/// mailed. Tess then invites the same address, and Pat joins from it.
#[tokio::test]
async fn nobody_but_a_tenant_administrator_invites_a_user() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = world.newcomer("pat", "Pat Invitee");
    let invite = InviteUser {
        email: pat.email().to_owned(),
        display_name: pat.account().display_name.clone(),
        role_id: world.role_id(MEMBER_ROLE).await,
    };

    assert_unauthorized_inviters(&world, &invite).await;
    let listed = people::list(world.tenant(), Some(pat.email()))
        .send(world.admin().client())
        .await
        .ok();
    assert!(
        listed.items.is_empty(),
        "a refused invitation makes no account"
    );
    stack.mailbox().nothing_for(pat.email(), QUIET).await;

    let proof = invited(&world, &mut pat).await;
    accepted_and_signed_in(&world, &mut pat, &proof).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ordinary members, foreign sessions and anonymous callers cannot invite a tenant user.
async fn assert_unauthorized_inviters(world: &World<'_>, invite: &InviteUser) {
    Matrix::new(
        "inviting a user",
        people::invite(world.tenant(), invite).call(),
    )
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

/// The link mailed to `pat`, invited by Tess as a plain member; `pat`
/// learns the id of the seat.
///
/// # Panics
///
/// When the invitation is refused, or no link comes.
async fn invited(world: &World<'_>, pat: &mut Person) -> LinkToken {
    let invite = InviteUser {
        email: pat.email().to_owned(),
        display_name: pat.account().display_name.clone(),
        role_id: world.role_id(MEMBER_ROLE).await,
    };
    let made = people::invite(world.tenant(), &invite)
        .send(world.admin().client())
        .await
        .ok();
    pat.record_invitation(&made.id);
    let mail = world.stack().mailbox().next_for(pat.email()).await;
    LinkToken {
        token: mail.token_in("/accept-invite"),
    }
}

/// `pat`, still invited and not joined: their password is refused as if
/// unknown, and their client reads nothing.
async fn still_outside(world: &World<'_>, pat: &Person) {
    sessions::sign_in(
        world.tenant(),
        &TenantPasswordSignIn {
            email: pat.email().to_owned(),
            password: pat.password().to_owned(),
            fingerprint_hash: None,
        },
    )
    .send(pat.client())
    .await
    .refused(Status::NOT_FOUND, "not_found");
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// `pat` accepts `proof` with their own password, which signs them in
/// nowhere; they sign in themselves and read only what is their own.
///
/// # Panics
///
/// When the acceptance, the sign-in or the read is refused.
async fn accepted_and_signed_in(world: &World<'_>, pat: &mut Person, proof: &LinkToken) {
    let password = pat.password().to_owned();
    pat.accept_with(&proof.token, &password).await.ok();
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    pat.sign_in(world.stack()).await;
    own_record_only(world, pat).await;
}
