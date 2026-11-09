//! What the joining scenarios share: the tenant opened or closed to the
//! public, Pat's form, the proof it mails, Pat proved and signed in, what
//! a new user may read, and the tenant's audit log counted.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{audit, people, registration, tenants};
use ianua_scenarios::expect::{Matrix, no_secret_leaked};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::people::LinkToken;
use ianua_scenarios::wire::registration::TenantSignup;
use ianua_scenarios::wire::tenants::{PasswordAgain, ReplaceSignInSettings};
use ianua_scenarios::world::World;
use serde_json::json;

/// Whether the tenant takes accounts from its public form.
pub(super) enum Enrollment {
    /// Anyone may register with a password.
    Open,
    /// Only administrators make accounts.
    Closed,
    /// Anyone may register, but passkeys are the only way in, so no
    /// password form is offered.
    Passwordless,
}

/// Ann sets the tenant to `choice`, changing nothing else of how its
/// users sign in.
///
/// # Panics
///
/// When the settings cannot be read or saved.
pub(super) async fn enrollment(world: &World<'_>, choice: Enrollment) {
    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    settings.rest.insert(
        "self_registration".to_owned(),
        json!(!matches!(choice, Enrollment::Closed)),
    );
    if matches!(choice, Enrollment::Passwordless) {
        settings.enabled_methods = vec!["Passkey".to_owned()];
    }
    tenants::replace_sign_in_settings(
        world.tenant(),
        &ReplaceSignInSettings {
            settings,
            proof: PasswordAgain {
                password: world.owner().password().to_owned(),
                code: None,
            },
        },
    )
    .send(world.owner().client())
    .await
    .ok();
}

/// The public form as `person` fills it in: their address, name and own
/// password.
pub(super) fn form(person: &Person) -> TenantSignup {
    TenantSignup {
        email: person.email().to_owned(),
        display_name: person.account().display_name.clone(),
        password: person.password().to_owned(),
    }
}

/// The proof mailed to `person` once their form is taken. Tess lists the
/// account as pending, its address unproved; `person` learns their id.
///
/// # Panics
///
/// When the form is refused, the account is not listed as pending, or no
/// proof comes.
pub(super) async fn mailed_proof(world: &World<'_>, person: &mut Person) -> LinkToken {
    registration::sign_up(world.tenant(), &form(person))
        .send(person.client())
        .await
        .ok();
    let listed = people::list(world.tenant(), Some(person.email()))
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(listed.items.len(), 1, "the form made one account");
    assert_eq!(
        listed.items[0].status, "PendingVerification",
        "which waits for its mailbox proof"
    );
    assert!(!listed.items[0].email_verified, "its address unproved");
    person.record_invitation(&listed.items[0].id);
    let mail = world.stack().mailbox().next_for(person.email()).await;
    LinkToken {
        token: mail.token_in("/verify-email"),
    }
}

/// `person` proves the mailbox with `proof`, signs in with their own
/// password, and reads only what is their own.
///
/// # Panics
///
/// When the proof, the sign-in or the read is refused.
pub(super) async fn verified_and_signed_in(
    world: &World<'_>,
    person: &mut Person,
    proof: &LinkToken,
) {
    registration::verify(world.tenant(), proof)
        .send(person.client())
        .await
        .ok();
    person.sign_in(world.stack()).await;
    own_record_only(world, person).await;
}

/// What `person`, signed in as a new user, may read: their own verified
/// record. Not the tenant's users, which Tess reads and Sam and nobody
/// signed in are refused; nor anything in the twin tenant.
///
/// # Panics
///
/// When their own record is refused or is someone else's, or anyone is
/// answered otherwise.
pub(super) async fn own_record_only(world: &World<'_>, person: &Person) {
    let own = people::me(world.tenant()).send(person.client()).await.ok();
    assert_eq!(own.id, person.id(), "the record read is their own");
    assert!(own.email_verified, "with the address proved");
    Matrix::new(
        "listing the tenant's users",
        people::list(world.tenant(), None).call(),
    )
    .allowed(world.admin().client())
    .refused(person.client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
    people::me(world.twin())
        .send(person.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// How many records of exactly `event` the tenant's audit log holds, as
/// Tess reads it, none of them carrying any of `secrets`.
///
/// # Panics
///
/// When the log cannot be read, or a record carries a secret.
pub(super) async fn tenant_records(world: &World<'_>, event: &str, secrets: &[&str]) -> usize {
    let records = audit::tenant_log(world.tenant(), event)
        .send(world.admin().client())
        .await
        .ok();
    for record in &records.items {
        no_secret_leaked(&record.details.to_string(), secrets);
    }
    records
        .items
        .iter()
        .filter(|record| record.event_type == event)
        .count()
}
