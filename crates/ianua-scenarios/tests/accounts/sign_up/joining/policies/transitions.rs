//! A policy changed while something is pending: Pat's mailbox proof
//! outlives a tenant closed to the public and its passwords switched off;
//! Tess's invitations are accepted in a closed tenant under every
//! second-factor policy; an invitation sent before a stricter password
//! rule is held to the rule of the day it is accepted; and a passwordless
//! invitation keeps no password it was handed.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{people, registration, sessions, tenants};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::people::{InviteUser, LinkToken, UserJoined};
use ianua_scenarios::wire::sign_in::Owed;
use ianua_scenarios::wire::tenant_sign_in::{TenantPasswordSignIn, TenantSession};
use ianua_scenarios::wire::tenants::{MfaPolicy, SignInSettings};
use ianua_scenarios::world::{MEMBER_ROLE, World};
use serde_json::json;

use super::super::support::{Enrollment, enrollment, mailed_proof, tenant_records};
use super::support::{saved, signed_in_under};
use crate::support::mail_linking_to;

/// Every second-factor policy.
const MFA_POLICIES: [MfaPolicy; 3] = [
    MfaPolicy::Disabled,
    MfaPolicy::Optional,
    MfaPolicy::Required,
];

/// The shortest password the stricter rule asks for: the platform's
/// longest, so no earlier password keeps it.
const STRICT_MINIMUM: usize = 128;

/// A password as long as the strict rule asks: a sentence would not be,
/// so a letter is repeated.
fn strict_password() -> String {
    format!("Z7!{}", "v".repeat(STRICT_MINIMUM - 3))
}

/// Ann closes registration, disables passwords, requires MFA and raises
/// the password minimum while Pat's mailbox proof waits. Verification still
/// succeeds, but password sign-in is forbidden. Once passwords are enabled,
/// Pat's existing password works with the required authenticator; their
/// verified account remains isolated, and the proof is consumed and audited once.
#[tokio::test]
async fn a_pending_mailbox_proof_does_not_freeze_registration_or_sign_in_policy() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    enrollment(&world, Enrollment::Open).await;
    let mut pat = world.newcomer("pat", "Pat Registrant");
    let proof = mailed_proof(&world, &mut pat).await;

    let mut settings = close_password_registration(&world).await;
    registration::verify(world.tenant(), &proof)
        .send(pat.client())
        .await
        .ok();
    assert_password_disabled(&world, &pat).await;

    settings.enabled_methods = vec!["Password".to_owned()];
    saved(&world, settings).await;
    signed_in_under(&world, &pat, MfaPolicy::Required).await;
    registration::verify(world.tenant(), &proof)
        .send(pat.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert_verification_record(&world, &pat, &proof).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The proof consumed across the policy change appears once without either signup secret.
async fn assert_verification_record(world: &World<'_>, pat: &Person, proof: &LinkToken) {
    assert_eq!(
        tenant_records(
            world,
            "identity.email_verified",
            &[&proof.token, pat.password()]
        )
        .await,
        1,
        "one mailbox proof"
    );
}

/// Ann closes registration and password sign-in while raising password and factor requirements.
async fn close_password_registration(world: &World<'_>) -> SignInSettings {
    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    settings
        .rest
        .insert("self_registration".to_owned(), json!(false));
    settings.rest["password_policy"]["min_length"] = json!(STRICT_MINIMUM);
    settings.enabled_methods = vec!["Passkey".to_owned()];
    settings.mfa_policy = MfaPolicy::Required;
    saved(world, settings.clone()).await;
    settings
}

/// Pat's verified mailbox does not bypass the disabled password method or create a session.
async fn assert_password_disabled(world: &World<'_>, pat: &Person) {
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
    .refused(Status::FORBIDDEN, "forbidden");
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Ann closes the tenant to the public. Under each second-factor policy
/// Tess invites Pat, who accepts, which signs nobody in; Pat then signs
/// in as the policy asks and reads their own record. No registration is
/// recorded, and three acceptances are.
#[tokio::test]
async fn closed_registration_still_accepts_invitations_under_every_mfa_policy() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    enrollment(&world, Enrollment::Closed).await;

    for mfa in MFA_POLICIES {
        accept_under_policy(&world, mfa).await;
    }

    assert_eq!(
        tenant_records(&world, "identity.user_registered", &[]).await,
        0,
        "no public registration was recorded"
    );
    assert_eq!(
        tenant_records(&world, "identity.invitation_accepted", &[]).await,
        3,
        "one acceptance under each policy"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// An invitation in a closed tenant opens access only after sign-in satisfies the chosen MFA policy.
async fn accept_under_policy(world: &World<'_>, mfa: MfaPolicy) {
    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    settings.mfa_policy = mfa;
    saved(world, settings).await;
    let mut pat = world.newcomer(&format!("invited-{mfa:?}").to_lowercase(), "Pat Invitee");
    let proof = invited(world, &mut pat).await;
    let password = pat.password().to_owned();
    pat.accept_with(&proof.token, &password).await.ok();
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    signed_in_under(world, &pat, mfa).await;
}

/// Ann raises the minimum password length after Tess invites Pat. Omitting
/// the password or using the earlier short password is refused, leaving Pat
/// invited with no acceptance event. The same proof accepts a long enough
/// password, and Pat signs in to their verified account with one acceptance
/// recorded; user-list and other-tenant reads remain forbidden.
#[tokio::test]
async fn an_invitation_requires_the_current_password_policy_without_spending_failed_proofs() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = world.newcomer("pat", "Pat Invitee");
    let proof = invited(&world, &mut pat).await;

    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    settings.rest["password_policy"]["min_length"] = json!(STRICT_MINIMUM);
    saved(&world, settings).await;

    assert_strict_password_refusals(&world, &mut pat, &proof).await;
    pat.accept_with(&proof.token, &strict_password()).await.ok();
    signed_in_under(&world, &pat, MfaPolicy::Optional).await;
    assert_eq!(
        tenant_records(&world, "identity.invitation_accepted", &[&proof.token]).await,
        1,
        "one acceptance"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Missing and formerly valid passwords leave Pat invited without an acceptance event.
async fn assert_strict_password_refusals(world: &World<'_>, pat: &mut Person, proof: &LinkToken) {
    pat.client()
        .post::<UserJoined>(
            &world.tenant().at("/users/accept-invitation"),
            &json!({ "token": proof.token }),
        )
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let earlier = pat.password().to_owned();
    pat.accept_with(&proof.token, &earlier)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let listed = people::list(world.tenant(), Some(pat.email()))
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(listed.items[0].status, "Invited", "Pat is still invited");
    assert_eq!(
        tenant_records(world, "identity.invitation_accepted", &[&proof.token]).await,
        0,
        "a refused acceptance records nothing"
    );
}

/// With magic links as the only sign-in method, two invitees accept with
/// an omitted or short password. Enabling passwords afterward still refuses
/// a guessed password for the first account and the short one for the second.
/// Both invitees sign in by magic link owing no further proof and read their
/// own verified records. They cannot list users or access the other tenant;
/// two acceptances are recorded.
#[tokio::test]
async fn a_passwordless_invitation_keeps_no_password_it_was_handed() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    settings.enabled_methods = vec!["MagicLink".to_owned()];
    saved(&world, settings.clone()).await;

    for (name, handed) in [("omitted", None), ("extra", Some("short"))] {
        exercise_passwordless_invitation(&world, &mut settings, name, handed).await;
    }

    assert_eq!(
        tenant_records(&world, "identity.invitation_accepted", &[]).await,
        2,
        "one acceptance for each Pat"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// One passwordless invitation ignores the supplied password and later admits only mailed proof.
async fn exercise_passwordless_invitation(
    world: &World<'_>,
    settings: &mut SignInSettings,
    name: &str,
    handed: Option<&str>,
) {
    let mut pat = world.newcomer(name, "Pat Invitee");
    let proof = invited(world, &mut pat).await;
    pat.client()
        .post::<UserJoined>(
            &world.tenant().at("/users/accept-invitation"),
            &json!({ "token": proof.token, "password": handed }),
        )
        .await
        .ok();

    settings.enabled_methods = vec!["Password".to_owned(), "MagicLink".to_owned()];
    saved(world, settings.clone()).await;
    assert_password_not_kept(world, &pat, handed).await;
    let device = sign_in_by_mail(world, &pat).await;
    assert_mail_session_access(world, &pat, &device).await;

    settings.enabled_methods = vec!["MagicLink".to_owned()];
    saved(world, settings.clone()).await;
}

/// Enabling passwords afterward cannot authenticate with an ignored or invented password.
async fn assert_password_not_kept(world: &World<'_>, pat: &Person, handed: Option<&str>) {
    sessions::sign_in(
        world.tenant(),
        &TenantPasswordSignIn {
            email: pat.email().to_owned(),
            password: handed.unwrap_or("Unknown quiet meadow 7543").to_owned(),
            fingerprint_hash: None,
        },
    )
    .send(pat.client())
    .await
    .refused(Status::NOT_FOUND, "not_found");
}

/// The accepted invitee opens a separate browser session with a mailed link and owes nothing else.
async fn sign_in_by_mail(world: &World<'_>, pat: &Person) -> Client {
    pat.client()
        .post::<()>(
            &world.tenant().at("/auth/magic-link"),
            &json!({ "email": pat.email() }),
        )
        .await
        .ok();
    let mail = mail_linking_to(world.stack(), pat.email(), "/magic-link").await;
    let link = LinkToken {
        token: mail.token_in("/magic-link"),
    };
    let session = pat
        .client()
        .post::<TenantSession>(&world.tenant().at("/auth/magic-link/verify"), &link)
        .await
        .ok();
    assert_eq!(
        session.owed(),
        Owed::Nothing,
        "a mailed link signs in owing nothing"
    );
    let mut device =
        Client::new(world.stack(), "Pat, signed in by the mailed link").expect("a client");
    device.authorize(&session.refresh_token);
    device
}

/// The mailed session reads only Pat's verified account, with no listing or twin-tenant access.
async fn assert_mail_session_access(world: &World<'_>, pat: &Person, device: &Client) {
    let own = people::me(world.tenant()).send(device).await.ok();
    assert_eq!(own.id, pat.id(), "the record read is Pat's own");
    assert!(
        own.email_verified,
        "with the address proved by the invitation"
    );
    people::list(world.tenant(), None)
        .send(device)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    people::me(world.twin())
        .send(device)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// The link mailed to `person`, invited by Tess as a plain member;
/// `person` learns the id of the seat.
///
/// # Panics
///
/// When the invitation is refused, or no link comes.
async fn invited(world: &World<'_>, person: &mut Person) -> LinkToken {
    let made = people::invite(
        world.tenant(),
        &InviteUser {
            email: person.email().to_owned(),
            display_name: person.account().display_name.clone(),
            role_id: world.role_id(MEMBER_ROLE).await,
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    person.record_invitation(&made.id);
    let mail = world.stack().mailbox().next_for(person.email()).await;
    LinkToken {
        token: mail.token_in("/accept-invite"),
    }
}
