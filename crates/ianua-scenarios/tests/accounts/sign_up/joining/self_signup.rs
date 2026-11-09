//! Pat registering through the tenant's public form: the account waits
//! for its mailbox proof and reads nothing before; a closed or
//! passwordless tenant offers no form; Mallory sending Pat's address
//! again changes nothing; a weak password leaves nothing behind; the
//! proof works in its own tenant and for its own purpose only; and an
//! expired proof is replaced from the link in hand.

use std::time::Duration;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{people, registration, sessions};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::stack::{BREACHED_PASSWORDS, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::people::{AcceptInvitation, LinkToken};
use ianua_scenarios::wire::tenant_sign_in::TenantPasswordSignIn;
use ianua_scenarios::world::World;

use super::support::{
    Enrollment, enrollment, form, mailed_proof, own_record_only, tenant_records,
    verified_and_signed_in,
};
use crate::support::QUIET;

/// How long a verification proof is kept in the expiry scenario, on the
/// controlled clock.
const PROOF_LIFETIME: Duration = Duration::from_secs(5);

/// One second past the proof's lifetime.
const PAST_THE_PROOF: Duration = Duration::from_secs(6);

/// The password Mallory sends with Pat's address: a sentence, so no
/// scanner takes it for a key.
const MALLORYS_PASSWORD: &str = "Different quiet meadow lantern 7251";

/// Ann opens the tenant to the public; the form says so and shows its
/// password rules. Pat registers: until the mailed proof is opened, Pat's
/// password is refused as unverified and reads nothing. Opened, it
/// activates Pat, who reads only what is their own; opened again it is
/// refused. One registration and one proof are recorded, with no secret.
#[tokio::test]
async fn a_tenant_signup_requires_its_mailbox_proof_before_protected_access() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    enrollment(&world, Enrollment::Open).await;

    assert_open_registration(&world).await;

    let mut pat = world.newcomer("pat", "Pat Newcomer");
    let proof = mailed_proof(&world, &mut pat).await;
    assert_unverified_access(&world, &pat).await;

    verified_and_signed_in(&world, &mut pat, &proof).await;
    registration::verify(world.tenant(), &proof)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    own_record_only(&world, &pat).await;
    for event in ["identity.user_registered", "identity.email_verified"] {
        assert_eq!(
            tenant_records(&world, event, &[pat.password(), &proof.token]).await,
            1,
            "one {event}"
        );
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// The public form advertises both open registration and its password requirements.
async fn assert_open_registration(world: &World<'_>) {
    let rules = registration::rules(world.tenant())
        .send(world.anonymous().client())
        .await
        .ok();
    assert!(rules.open, "the form says it is open");
    assert!(
        rules.password_policy.is_some(),
        "and shows its password rules"
    );
}

/// Before mailbox proof, Pat can neither sign in nor read the pending account.
async fn assert_unverified_access(world: &World<'_>, pat: &Person) {
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
    .refused(Status::FORBIDDEN, "email_not_verified");
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Ann closes the tenant, then opens it with passkeys as the only way in:
/// either way the form says it is closed and shows no password rules.
/// Pat's submitted form is refused without an account, mail or
/// registration record.
#[tokio::test]
async fn a_closed_or_passwordless_tenant_offers_no_form_and_takes_none() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = world.newcomer("pat", "Pat Newcomer");

    for choice in [Enrollment::Closed, Enrollment::Passwordless] {
        enrollment(&world, choice).await;
        assert_closed_registration(&world, &pat).await;
    }

    assert_eq!(
        tenant_records(&world, "identity.user_registered", &[pat.password()]).await,
        0,
        "no registration was recorded"
    );
    stack.mailbox().nothing_for(pat.email(), QUIET).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The closed form exposes no password policy and refuses signup without creating Pat.
async fn assert_closed_registration(world: &World<'_>, pat: &Person) {
    let rules = registration::rules(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert!(!rules.open, "the form says it is closed");
    assert!(
        rules.password_policy.is_none(),
        "and shows no password rules"
    );
    registration::sign_up(world.tenant(), &form(pat))
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let listed = people::list(world.tenant(), Some(pat.email()))
        .send(world.admin().client())
        .await
        .ok();
    assert!(listed.items.is_empty(), "no account was made for Pat");
}

/// Pat's form waits for its proof. Mallory sends Pat's address again with
/// her own name and password: answered as any form is, so she learns
/// nothing, and nothing more is mailed. Pat's proof activates Pat as
/// first filled in; Mallory's password opens nothing, and one
/// registration is recorded.
#[tokio::test]
async fn a_duplicate_tenant_signup_preserves_the_original_account_and_proof() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    enrollment(&world, Enrollment::Open).await;
    let mut pat = world.newcomer("pat", "Pat Newcomer");
    let proof = mailed_proof(&world, &mut pat).await;

    submit_duplicate_signup(&world, &pat).await;
    stack.mailbox().nothing_for(pat.email(), QUIET).await;

    verified_and_signed_in(&world, &mut pat, &proof).await;
    assert_original_account(&world, &pat).await;
    assert_eq!(
        tenant_records(
            &world,
            "identity.user_registered",
            &[pat.password(), MALLORYS_PASSWORD, &proof.token]
        )
        .await,
        1,
        "one registration"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory's replacement details receive the same empty response as a fresh signup.
async fn submit_duplicate_signup(world: &World<'_>, pat: &Person) {
    let mut as_pat = form(pat);
    as_pat.display_name = "Mallory".to_owned();
    as_pat.password = MALLORYS_PASSWORD.to_owned();
    let answered = registration::sign_up(world.tenant(), &as_pat)
        .send(world.anonymous().client())
        .await;
    assert_eq!(
        answered.status(),
        Status::NO_CONTENT,
        "Pat's address again is answered as any form is: {}",
        answered.summary()
    );
    answered.ok();
}

/// Pat retains the original name and Mallory's chosen password cannot sign in.
async fn assert_original_account(world: &World<'_>, pat: &Person) {
    sessions::sign_in(
        world.tenant(),
        &TenantPasswordSignIn {
            email: pat.email().to_owned(),
            password: MALLORYS_PASSWORD.to_owned(),
            fingerprint_hash: None,
        },
    )
    .send(world.anonymous().client())
    .await
    .refused(Status::NOT_FOUND, "not_found");
    let own = people::me(world.tenant()).send(pat.client()).await.ok();
    assert_eq!(
        own.display_name, "Pat Newcomer",
        "Pat's record carries the name Pat gave"
    );
}

/// Pat tries a password of three letters, then one from a breach: each is
/// refused before an account or a mail exists. The same form with a
/// proper password is taken, and Pat proves the mailbox and signs in.
#[tokio::test]
async fn a_refused_tenant_password_can_be_corrected_without_partial_registration() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    enrollment(&world, Enrollment::Open).await;
    let mut pat = world.newcomer("pat", "Pat Newcomer");

    for password in ["abc", BREACHED_PASSWORDS[0]] {
        let mut attempt = form(&pat);
        attempt.password = password.to_owned();
        registration::sign_up(world.tenant(), &attempt)
            .send(pat.client())
            .await
            .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    }
    let listed = people::list(world.tenant(), Some(pat.email()))
        .send(world.admin().client())
        .await
        .ok();
    assert!(listed.items.is_empty(), "a refused form leaves no account");
    stack.mailbox().nothing_for(pat.email(), QUIET).await;

    let proof = mailed_proof(&world, &mut pat).await;
    verified_and_signed_in(&world, &mut pat, &proof).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat's proof is tried on Sam's twin tenant, and as an invitation
/// accepted in Pat's own. Both attempts are refused without spending the
/// proof. Opened where it was meant, it activates Pat, recorded once.
#[tokio::test]
async fn a_tenant_verification_proof_cannot_cross_tenants_or_invitation_purposes() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    enrollment(&world, Enrollment::Open).await;
    let mut pat = world.newcomer("pat", "Pat Newcomer");
    let proof = mailed_proof(&world, &mut pat).await;

    assert_verification_scope(&world, &pat, &proof).await;
    verified_and_signed_in(&world, &mut pat, &proof).await;
    assert_eq!(
        tenant_records(
            &world,
            "identity.email_verified",
            &[pat.password(), &proof.token]
        )
        .await,
        1,
        "one mailbox proof"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Verification cannot spend Pat's proof in the twin tenant or as an invitation.
async fn assert_verification_scope(world: &World<'_>, pat: &Person, proof: &LinkToken) {
    registration::verify(world.twin(), proof)
        .send(pat.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    people::accept_invitation(
        world.tenant(),
        &AcceptInvitation {
            token: proof.token.clone(),
            password: pat.password().to_owned(),
        },
    )
    .send(pat.client())
    .await
    .refused(Status::NOT_FOUND, "not_found");
}

/// Pat's proof expires unopened, so it activates nothing. From the dead
/// link Pat asks for another: a fresh proof comes, the expired one is
/// still refused, and the fresh one activates Pat, who is registered
/// once, with no second account.
#[tokio::test]
async fn an_expired_tenant_verification_can_be_replaced_without_reregistering() {
    let clock = Clock::controlled();
    let stack = Stack::start(expiring_proof_profile())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    enrollment(&world, Enrollment::Open).await;
    let mut pat = world.newcomer("pat", "Pat Newcomer");
    let old = mailed_proof(&world, &mut pat).await;

    clock.advance(PAST_THE_PROOF);
    registration::verify(world.tenant(), &old)
        .send(pat.client())
        .await
        .refused(Status::GONE, "link_expired");

    let fresh = resend_expired_proof(&world, &pat, &old).await;

    verified_and_signed_in(&world, &mut pat, &fresh).await;
    assert_eq!(
        tenant_records(
            &world,
            "identity.user_registered",
            &[pat.password(), &old.token, &fresh.token]
        )
        .await,
        1,
        "one registration, however many proofs"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The controlled-clock scenario expires proofs quickly and permits a resend afterward.
fn expiring_proof_profile() -> Profile {
    Profile::standard()
        .with(
            "EMAIL_VERIFICATION_TTL_SECONDS",
            &PROOF_LIFETIME.as_secs().to_string(),
        )
        .with("MAIL_RESEND_COOLDOWN_SECONDS", "1")
}

/// Resending issues a different proof while the expired original stays refused.
async fn resend_expired_proof(world: &World<'_>, pat: &Person, old: &LinkToken) -> LinkToken {
    registration::resend_verification(world.tenant(), old)
        .send(pat.client())
        .await
        .ok();
    let mail = world.stack().mailbox().next_for(pat.email()).await;
    let fresh = LinkToken {
        token: mail.token_in("/verify-email"),
    };
    assert_ne!(fresh.token, old.token, "the fresh proof is its own");
    registration::verify(world.tenant(), old)
        .send(pat.client())
        .await
        .refused(Status::GONE, "link_expired");

    fresh
}
