//! The cast and the steps the application scenarios share.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{people, saml_apps};
use ianua_scenarios::providers::parameter;
use ianua_scenarios::services::saml::sign_in::Accepted;
use ianua_scenarios::services::saml::{App, IdentityProvider, Sent};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::saml_apps::{AnswerSignIn, NewSamlApp, SamlAppMade};
use ianua_scenarios::world::{MEMBER_ROLE, World};

/// Pat, a member of the tenant, invited by Tess and signed in.
pub(crate) async fn pat(world: &World<'_>) -> Person {
    let member = world.role_id(MEMBER_ROLE).await;
    let mut pat = world.newcomer("pat", "Pat Member");
    let invitation = InviteUser {
        email: pat.email().to_owned(),
        display_name: pat.account().display_name.clone(),
        role_id: member,
    };
    let made = people::invite(world.tenant(), &invitation)
        .send(world.admin().client())
        .await
        .ok();
    pat.record_invitation(&made.id);
    pat.accept_invitation(world.stack()).await;
    pat.sign_in(world.stack()).await;
    pat
}

/// `app`, registered by Tess as `name`, taking answers and logouts at its
/// own addresses only, with the certificate its requests are signed with
/// when it signs them.
pub(crate) async fn registered(world: &World<'_>, app: &App, name: &str) -> SamlAppMade {
    let registration = NewSamlApp {
        name: name.to_owned(),
        entity_id: app.entity_id().to_owned(),
        acs_urls: vec![app.acs_url().to_owned()],
        logout_url: Some(app.logout_url().to_owned()),
        request_signing_certificate: app.certificate().map(str::to_owned),
    };
    saml_apps::create(world.tenant(), &registration)
        .send(world.admin().client())
        .await
        .ok()
}

/// The tenant as an app learns it, from the metadata it publishes to
/// anyone.
pub(crate) async fn the_tenant(world: &World<'_>) -> IdentityProvider {
    let metadata = saml_apps::metadata(world.tenant())
        .send_text(world.anonymous().client())
        .await
        .ok();
    IdentityProvider::from_metadata(&metadata)
}

/// The id the platform holds `request` under once `person`'s browser
/// carried it from `app` to the tenant's sign-in service, read from where
/// the platform sends the browser on.
pub(crate) async fn carried(
    person: &Person,
    app: &App,
    provider: &IdentityProvider,
    request: &Sent,
) -> String {
    let onward = sent_on(person, app, provider.sso_url(), request).await;
    parameter(&onward, "request")
}

/// Where the platform sends `person`'s browser once it carried `message`
/// from `app` to the tenant's service at `url`.
pub(crate) async fn sent_on(person: &Person, app: &App, url: &str, message: &Sent) -> String {
    let carried = saml_apps::carry(url, message.form(), &app.site())
        .send(person.client())
        .await;
    assert_eq!(
        carried.status(),
        Status::FOUND,
        "the platform sends the browser on: {}",
        carried.summary()
    );
    carried
        .header("location")
        .expect("the platform says where the browser goes")
        .to_owned()
}

/// What `app` knows of `person` once they signed in to it through the
/// tenant `provider`.
pub(crate) async fn signed_in_to(
    world: &World<'_>,
    person: &Person,
    app: &App,
    provider: &IdentityProvider,
) -> Accepted {
    let request = app.sign_in_request(provider, "/");
    let held = AnswerSignIn {
        request: carried(person, app, provider, &request).await,
    };
    let answer = saml_apps::answer(world.tenant(), &held)
        .send(person.client())
        .await
        .ok();
    app.accepted(provider, &request, &answer.message)
        .expect("the app accepts the platform's answer")
}
