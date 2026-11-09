//! The tenant's directory link and the people it makes, as the scenarios
//! here share them.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{directory, registration};
use ianua_scenarios::ldap::{ClientCertificate, DeviceKey};
use ianua_scenarios::net::Client;
use ianua_scenarios::wire::directory::{CertificateAsked, DirectorySettings, DirectoryUser};
use ianua_scenarios::wire::people::LinkToken;
use ianua_scenarios::wire::tenants::PasswordAgain;
use ianua_scenarios::world::World;

/// The password a person the directory made sets through a reset link,
/// once their mailbox is proved: a sentence, so no scanner takes it for a
/// key.
pub(crate) const OWN_PASSWORD: &str = "Gentle harbour willow sentence 6284!";

/// The most mails passed over before the verification link, so a missing
/// link fails rather than reading forever.
const PASSED_OVER: usize = 10;

/// What becomes of a person the directory removes.
#[derive(Clone, Copy)]
pub(crate) enum OnRemove {
    /// They are deactivated and kept.
    Deactivate,
    /// They are deleted.
    Delete,
}

/// The directory, as a client of its own: Tess switches the link on, gives
/// the directory the token shown that once, and has the people it makes
/// active at once and handled as `on_remove` says when it removes them.
pub(crate) async fn linked_directory(world: &World<'_>, on_remove: OnRemove) -> Client {
    let token = directory::enable(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let mut client = Client::new(world.stack(), "the directory").expect("a client");
    client.authorize(
        token
            .bearer_token
            .as_deref()
            .expect("the first setup shows its token"),
    );
    removals_set(world, on_remove).await;
    client
}

/// A client of its own for a directory calling with `token`, named
/// `actor` in failures.
pub(crate) fn holding(world: &World<'_>, actor: &str, token: &str) -> Client {
    let mut client = Client::new(world.stack(), actor).expect("a client");
    client.authorize(token);
    client
}

/// Tess sets what becomes of a person the directory removes.
pub(crate) async fn removals_set(world: &World<'_>, on_remove: OnRemove) {
    let settings = DirectorySettings {
        default_role_id: None,
        auto_activate: true,
        deactivate_on_remove: matches!(on_remove, OnRemove::Deactivate),
    };
    directory::replace_settings(world.tenant(), &settings)
        .send(world.admin().client())
        .await
        .ok();
}

/// Someone called `name`, made by `linked` as an active user.
pub(crate) async fn made(world: &World<'_>, linked: &Client, name: &str) -> Person {
    let mut person = world.newcomer(name, &format!("{name} Directory"));
    let user = DirectoryUser {
        user_name: person.email().to_owned(),
        display_name: person.account().display_name.clone(),
        active: true,
        external_id: format!("external-{name}"),
    };
    let made = directory::create_user(world.tenant(), &user)
        .send(linked)
        .await
        .ok();
    person.record_invitation(&made.id);
    person
}

/// `person` proves their mailbox through the link mailed to them, sets
/// their own password through a reset link, and signs in.
pub(crate) async fn settled_in(world: &World<'_>, person: &mut Person) {
    proved_mailbox(world, person.email()).await;
    let reset = person.reset_link(world.stack()).await;
    person.confirm_reset(&reset, OWN_PASSWORD).await.ok();
    person.sign_in(world.stack()).await;
}

/// The mailbox `email` proved through the verification link mailed to it,
/// passing over any other mail that came first.
pub(crate) async fn proved_mailbox(world: &World<'_>, email: &str) {
    let proof = verification_link(world, email).await;
    registration::verify(world.tenant(), &proof)
        .send(world.anonymous().client())
        .await
        .ok();
}

/// The token of the verification link mailed to `email`.
async fn verification_link(world: &World<'_>, email: &str) -> LinkToken {
    for _ in 0..=PASSED_OVER {
        let mail = world.stack().mailbox().next_for(email).await;
        if mail
            .links()
            .iter()
            .any(|link| link.path().ends_with("/verify-email"))
        {
            return LinkToken {
                token: mail.token_in("/verify-email"),
            };
        }
    }
    panic!("{email} got {PASSED_OVER} mails before one linking to /verify-email");
}

/// The client certificate the laptop of `person`, settled in with
/// [`OWN_PASSWORD`], gets: its own key's signing request, signed by the
/// tenant once they type their password again.
pub(crate) async fn laptop_certificate(world: &World<'_>, person: &Person) -> ClientCertificate {
    let key = DeviceKey::new();
    let asked = CertificateAsked {
        csr_pem: key.signing_request(),
        device_label: format!("{}'s laptop", person.account().display_name),
        proof: PasswordAgain {
            password: OWN_PASSWORD.to_owned(),
            code: None,
        },
    };
    let issued = directory::issue_ldap_certificate(world.tenant(), &asked)
        .send(person.client())
        .await
        .ok();
    key.certified(&issued.certificate_pem)
}
