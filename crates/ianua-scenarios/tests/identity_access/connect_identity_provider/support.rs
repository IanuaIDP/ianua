//! The tenant's link to Acme's SAML provider, and Pat signing in through
//! it on the dashboard, as the scenarios here share them.

use ianua_scenarios::actors::{Person, PersonAccount};
use ianua_scenarios::api::{people, roles, tenants};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::providers::saml::{Claim, Provider, ServiceProvider, SignIn};
use ianua_scenarios::routes::domain;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::account::Requested;
use ianua_scenarios::wire::federation::{Begun, ProviderAnswer};
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::roles::NewRole;
use ianua_scenarios::wire::tenants::{PasswordAgain, ReplaceSignInSettings};
use ianua_scenarios::world::World;
use serde::Deserialize;
use serde::de::IgnoredAny;
use serde_json::{Value, json};

/// The password Pat's account holds, which the provider never asks for:
/// a sentence, so no scanner takes it for a key.
const PAT_PASSWORD: &str = "Quiet harbour lantern meadow 5821!";

/// The value the dashboard keeps while Pat signs in, sent again with the
/// one-time code: at least 32 characters.
const DASHBOARD_STATE: &str = "the-dashboard-keeps-this-value-for-pat";

/// The persistent `NameID` format, the only one a sign-in connection
/// takes.
const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

/// The site the provider posts its answers from.
pub(crate) const PROVIDER_SITE: &str = "https://identity.acme.example";

/// How the connection is set up.
pub(crate) struct Settings<'a> {
    /// The provider it trusts now.
    pub(crate) provider: &'a Provider,
    /// The provider's next key, while it rolls its key over.
    pub(crate) next: Option<&'a Provider>,
    /// Whether the sign-in requests sent to it are signed.
    pub(crate) sign_requests: bool,
}

/// How Pat's sign-in through the provider ended.
#[derive(Debug)]
pub(crate) enum Outcome {
    /// Signed in, Pat's client holding the session.
    SignedIn,
    /// Sent back to the dashboard's sign-in page.
    Failed,
}

/// The provider's response to one redirected sign-in request.
pub(crate) struct SamlAnswer<'a> {
    /// The provider whose key signs the answer.
    pub(crate) provider: &'a Provider,
    /// The sign-in request carried by the browser.
    pub(crate) redirect: String,
    /// The claim whose acceptance or refusal the scenario checks.
    pub(crate) claim: Claim,
}

/// The session the dashboard trades the one-time code for.
#[derive(Deserialize)]
struct Exchanged {
    refresh_token: String,
}

/// A domain Tess brings into the tenant and proves, for Pat's address.
pub(crate) async fn owned_domain(world: &World<'_>) -> String {
    let stack = world.stack();
    let word = uuid::Uuid::new_v4().simple().to_string();
    let name = format!("acme-{}.{}", &word[..8], stack.customer_domain());
    domain::brought(stack, world.admin().client(), world.tenant(), &name).await
}

/// The id of the connection Tess makes to the provider as `settings`
/// say, for addresses at `domain`, its addresses trusted and its sign-in
/// method enabled by Ann.
pub(crate) async fn connected(world: &World<'_>, domain: &str, settings: &Settings<'_>) -> String {
    connected_by(world, domain, config(settings)).await
}

/// The id of the connection Tess makes with the settings `config`, the
/// API's own shape, for addresses at `domain`, its addresses trusted and
/// its sign-in method enabled by Ann.
pub(crate) async fn connected_by(world: &World<'_>, domain: &str, config: Value) -> String {
    let connection = json!({
        "provider_name": "Acme SAML",
        "config": config,
        "allowed_domains": [domain],
    });
    let made = world
        .admin()
        .client()
        .post::<Requested>(&world.tenant().at("/federation/connections"), &connection)
        .await
        .ok();
    let trusted = Call::patch(
        world
            .tenant()
            .at(&format!("/federation/connections/{}", made.id)),
    )
    .json(&json!({"email_trust": "Authoritative"}));
    world.admin().client().send::<()>(trusted).await.ok();
    method_enabled(world).await;
    made.id
}

/// Tess changes the connection to `settings`.
pub(crate) async fn reconfigured(world: &World<'_>, connection: &str, settings: &Settings<'_>) {
    let change = Call::patch(
        world
            .tenant()
            .at(&format!("/federation/connections/{connection}")),
    )
    .json(&json!({"config": config(settings)}));
    world.admin().client().send::<()>(change).await.ok();
}

/// The connection's settings as the API takes them.
fn config(settings: &Settings<'_>) -> Value {
    let provider = settings.provider;
    json!({"Saml": {
        "entity_id": provider.entity_id(),
        "sso_url": format!("{}/sso", provider.entity_id()),
        "slo_url": provider.slo_url(),
        "certificate": provider.certificate(),
        "next_certificate": settings.next.map(Provider::certificate),
        "name_id_format": PERSISTENT,
        "sign_requests": settings.sign_requests,
    }})
}

/// Ann enables SAML among the tenant's sign-in methods.
async fn method_enabled(world: &World<'_>) {
    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    settings.enabled_methods.push("Saml".to_owned());
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

/// Pat, invited by Tess with an address at `domain`, her invitation
/// accepted.
pub(crate) async fn pat(world: &World<'_>, domain: &str) -> Person {
    let role_id = create_staff_role(world).await;
    let email = format!("pat@{domain}");
    let invited = people::invite(
        world.tenant(),
        &InviteUser {
            email: email.clone(),
            display_name: "Pat Acme".to_owned(),
            role_id,
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    let mut pat = Person::new(
        Client::new(world.stack(), "Pat, signing in through Acme's provider").expect("a client"),
        PersonAccount {
            email,
            display_name: "Pat Acme".to_owned(),
            tenant: world.tenant().clone(),
        },
        PAT_PASSWORD,
    );
    pat.record_invitation(&invited.id);
    pat.accept_invitation(world.stack()).await;
    pat
}

/// Tess gives Acme's staff a role without administrative permissions.
async fn create_staff_role(world: &World<'_>) -> String {
    let role = roles::create(
        world.tenant(),
        &NewRole {
            name: "Acme staff".to_owned(),
            system_permissions: Vec::new(),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    role.id
}

/// Where the dashboard's "Sign in with Acme" sends Pat's browser: the
/// provider's sign-in address, carrying the platform's request.
pub(crate) async fn begun(world: &World<'_>, pat: &Person, connection: &str) -> String {
    let login = world.tenant().at(&format!(
        "/federation/connections/{connection}/login?state={DASHBOARD_STATE}"
    ));
    let begun = pat.client().send::<IgnoredAny>(Call::get(login)).await;
    assert_eq!(
        begun.status(),
        Status::SEE_OTHER,
        "the browser is sent to the provider: {}",
        begun.summary()
    );
    begun
        .header("location")
        .expect("the provider's address")
        .to_owned()
}

/// How Pat's sign-in ends once the provider answers the redirected request
/// with the requested claim, and her browser posts the answer
/// to the tenant; signed in, her client holds the session.
pub(crate) async fn signed_in(
    world: &World<'_>,
    pat: &mut Person,
    answer: SamlAnswer<'_>,
) -> Outcome {
    let form = provider_form(world, pat, answer);
    let posted = pat
        .client()
        .send::<IgnoredAny>(
            Call::post(world.tenant().at("/federation/saml/acs"))
                .raw("application/x-www-form-urlencoded", form)
                .header("origin", PROVIDER_SITE)
                .header("sec-fetch-site", "cross-site"),
        )
        .await;
    let back = posted.header("location").unwrap_or_default().to_owned();
    let Some(code) = url::Url::parse(&back).ok().and_then(|url| {
        url.query_pairs()
            .find(|(name, _)| name == "code")
            .map(|(_, code)| code.into_owned())
    }) else {
        return Outcome::Failed;
    };
    let exchanged = pat
        .client()
        .post::<Exchanged>(
            &world.tenant().at("/auth/sso/exchange"),
            &json!({"code": code, "state": DASHBOARD_STATE}),
        )
        .await
        .ok();
    pat.hold_session(&exchanged.refresh_token);
    Outcome::SignedIn
}

/// Encodes the provider's response and relay state for Pat's browser to post.
fn provider_form(world: &World<'_>, pat: &Person, answer: SamlAnswer<'_>) -> String {
    let SamlAnswer {
        provider,
        redirect,
        claim,
    } = answer;
    let to = platform_service_provider(world);
    let begun = Begun {
        redirect_url: redirect,
        binding: String::new(),
    };
    let ProviderAnswer::Saml {
        relay_state,
        saml_response,
    } = provider
        .answer(
            &to,
            SignIn {
                email: pat.email(),
                begun,
                claim,
            },
        )
        .answer
    else {
        panic!("a SAML provider answers with a posted response");
    };
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("SAMLResponse", &saml_response)
        .append_pair("RelayState", &relay_state)
        .finish()
}

/// The platform's audience and tenant callback identify where the provider signs Pat in.
fn platform_service_provider(world: &World<'_>) -> ServiceProvider {
    let base = world
        .stack()
        .app_url()
        .as_str()
        .trim_end_matches('/')
        .to_owned();
    ServiceProvider {
        recipient: format!("{base}{}", world.tenant().at("/federation/saml/acs")),
        audience: base,
    }
}
