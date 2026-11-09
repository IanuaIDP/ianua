//! Independent identity providers signing Pat in at the shop: the shop's
//! sign-in address sends her browser to the provider, and the provider's
//! answer finishes the sign-in only in the browser that began it; a
//! browser that never began it gets nothing from the same answer. An OIDC
//! provider sends the browser back with a code; a SAML provider posts a
//! signed assertion from its own site, addressed to the shop.

use ianua_scenarios::actors::{Person, PersonAccount};
use ianua_scenarios::api::{people, roles, tenants};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::providers::{oidc, saml};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::AssertionCheck;
use ianua_scenarios::wire::account::Requested;
use ianua_scenarios::wire::app_sign_in::AppSignedIn;
use ianua_scenarios::wire::federation::{Begun, ProviderAnswer};
use ianua_scenarios::wire::organization::IdentityProviderConfig;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::roles::NewRole;
use ianua_scenarios::wire::tenants::{PasswordAgain, ReplaceSignInSettings};
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;
use serde::Deserialize;
use serde::de::{DeserializeOwned, IgnoredAny};
use serde_json::json;

use crate::support::{Shop, ShopOwner, profile, word};

/// The password Pat's account holds, which a provider's sign-in never
/// asks for: a sentence, so no scanner takes it for a key.
const PAT_PASSWORD: &str = "Local orchard lantern meadow 8472!";

/// The page of the shop only a signed-in customer reaches.
const ORDERS: &str = "/account/orders";

/// The site a SAML provider posts its answer from.
const PROVIDER_SITE: &str = "https://identity.acme.example";

/// Where the shop's sign-in address sends a browser starting a sign-in
/// through a provider.
#[derive(Deserialize)]
struct Redirect {
    redirect_to: String,
}

/// The linked SAML provider and the shop callback it must address.
struct SamlConnection<'a> {
    provider: &'a saml::Provider,
    target: saml::ServiceProvider,
    id: &'a str,
}

/// Tess connects an independent OIDC provider to the tenant for the
/// shop's domain, Ann enables the method, and Tess invites Pat with an
/// address at the shop's domain. Pat starts the sign-in at the shop, which
/// sends her to the provider; the provider answers for her. Mallory, in a
/// browser that never began the sign-in, hands the same answer back and
/// is not let in; Pat is not in either until her own browser hands it
/// back. Then Pat reaches her account page, the shop seeing an assertion
/// naming her and none of her cookies.
#[tokio::test]
async fn the_providers_answer_signs_pat_in_only_in_the_browser_that_began_it() {
    let provider = oidc::Provider::start().await;
    let stack = Stack::start(profile().with("OIDC_PROVIDER_CA_FILE", provider.authority_file()))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let shop = opened(&stack, &world).await;
    let connection = connected(&world, &shop, "Shop OIDC", provider.config()).await;
    let pat = customer(&stack, &world, &shop).await;
    let return_to = oidc_callback(&provider, &pat, &shop, &connection).await;
    let mallory = Client::new(&stack, "Mallory, who never began the sign-in").expect("a client");
    mallory
        .get::<IgnoredAny>(&return_to)
        .await
        .refused(Status::BAD_REQUEST, "missing_single_sign_on");
    nobody_in(&shop, &[&mallory, pat.client()]).await;
    let completed = pat.client().get::<AppSignedIn>(&return_to).await.ok();
    assert!(
        completed.signed_in,
        "the provider's answer signs Pat in, in the browser that began it"
    );
    only_pat_reaches_the_shop(&shop, &pat).await;
    stack.stop().await.expect("the stack stops cleanly");
    provider.stop().await;
}

/// Starts Pat's OIDC sign-in and encodes the provider's code for the shop callback.
async fn oidc_callback(
    provider: &oidc::Provider,
    pat: &Person,
    shop: &Shop,
    connection: &str,
) -> String {
    let callback = provider.callback(
        begun(pat, shop, connection).await,
        pat.email(),
        oidc::Claim::Correct,
    );
    let ProviderAnswer::Oidc { state, code } = callback.answer else {
        panic!("an OIDC provider answers with a state and a code");
    };
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("state", &state)
        .append_pair("code", &code)
        .finish();
    shop.page(&format!("/.ianua/sso-callback?{query}"))
}

/// Tess connects an independent SAML provider to the tenant for the
/// shop's domain, Ann enables the method, and Pat starts the sign-in at
/// the shop. The provider's answer is posted to the shop from the
/// provider's own site. An answer whose signed recipient is another
/// address lets Pat in nowhere, though the unsigned envelope names the
/// shop. The provider's true answer is refused too while nobody has said
/// the provider owns the shop's addresses: SAML carries no word that an
/// address was checked. Once Tess says so, Mallory posts the answer from
/// a browser that never began the sign-in and is not let in, and the
/// same answer posted in Pat's own browser signs her in, the shop seeing
/// an assertion naming her.
#[tokio::test]
async fn a_saml_providers_answer_posted_to_the_shop_signs_pat_in() {
    let provider = saml::Provider::new();
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let shop = opened(&stack, &world).await;
    let connection = connected(&world, &shop, "Shop SAML", provider.config()).await;
    let pat = customer(&stack, &world, &shop).await;
    let to = saml::ServiceProvider {
        audience: stack.app_url().as_str().trim_end_matches('/').to_owned(),
        recipient: shop.page("/.ianua/sso-callback"),
    };
    let linked = SamlConnection {
        provider: &provider,
        target: to,
        id: &connection,
    };
    refuse_saml_claims(&pat, &shop, &linked).await;
    addresses_vouched_for(&world, &connection).await;
    let answered = provider.answer(
        &linked.target,
        saml::SignIn {
            email: pat.email(),
            begun: begun(&pat, &shop, &connection).await,
            claim: saml::Claim::Correct,
        },
    );
    let mallory = Client::new(&stack, "Mallory, who never began the sign-in").expect("a client");
    finish_saml(&pat, &shop, &answered.answer, &mallory).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// A wrong recipient and an untrusted address both fail before address ownership is vouched for.
async fn refuse_saml_claims(pat: &Person, shop: &Shop, linked: &SamlConnection<'_>) {
    for (claim, why) in [
        (saml::Claim::WrongRecipient, "a forged recipient"),
        (saml::Claim::Correct, "an address nobody vouched for"),
    ] {
        let refused = linked.provider.answer(
            &linked.target,
            saml::SignIn {
                email: pat.email(),
                begun: begun(pat, shop, linked.id).await,
                claim,
            },
        );
        let answer = posted::<IgnoredAny>(pat.client(), shop, &refused.answer).await;
        assert_eq!(
            answer.status(),
            Status::FORBIDDEN,
            "{why} is refused: {}",
            answer.summary()
        );
        nobody_in(shop, &[pat.client()]).await;
    }
}

/// Only Pat's browser can complete the trusted answer and reach the shop.
async fn finish_saml(pat: &Person, shop: &Shop, answer: &ProviderAnswer, mallory: &Client) {
    posted::<IgnoredAny>(mallory, shop, answer)
        .await
        .refused(Status::BAD_REQUEST, "missing_single_sign_on");
    nobody_in(shop, &[mallory, pat.client()]).await;

    let completed = posted::<AppSignedIn>(pat.client(), shop, answer).await.ok();
    assert!(
        completed.signed_in,
        "the provider's answer signs Pat in, in the browser that began it"
    );
    only_pat_reaches_the_shop(shop, pat).await;
}

/// The shop, opened by Tess in the world's tenant.
async fn opened(stack: &Stack, world: &World<'_>) -> Shop {
    Shop::opened(
        stack,
        &ShopOwner {
            tenant: world.tenant(),
            admin: world.admin().client(),
            word: &word(),
        },
    )
    .await
}

/// The id of the provider Tess connects to the tenant under `name`, for
/// addresses at the shop's domain, with its sign-in method enabled by Ann.
async fn connected(
    world: &World<'_>,
    shop: &Shop,
    name: &str,
    config: IdentityProviderConfig,
) -> String {
    let method = config.method();
    let connection = json!({
        "provider_name": name,
        "config": config,
        "allowed_domains": [shop.host],
    });
    let connected = world
        .admin()
        .client()
        .post::<Requested>(&world.tenant().at("/federation/connections"), &connection)
        .await
        .ok();
    enable_method(world, method).await;
    connected.id
}

/// Ann enables the provider's sign-in method with her password proof.
async fn enable_method(world: &World<'_>, method: &str) {
    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    settings.enabled_methods.push(method.to_owned());
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

/// Tess says the provider `connection` assigns the addresses it names and
/// its users cannot change them, so its word on an address counts.
async fn addresses_vouched_for(world: &World<'_>, connection: &str) {
    let vouched = Call::patch(
        world
            .tenant()
            .at(&format!("/federation/connections/{connection}")),
    )
    .json(&json!({"email_trust": "Authoritative"}));
    world.admin().client().send::<()>(vouched).await.ok();
}

/// Pat, invited by Tess as a shop customer with an address at the shop's
/// domain, her invitation accepted.
async fn customer(stack: &Stack, world: &World<'_>, shop: &Shop) -> Person {
    let role_id = create_customer_role(world).await;
    let email = format!("pat@{}", shop.host);
    let invited = people::invite(
        world.tenant(),
        &InviteUser {
            email: email.clone(),
            display_name: "Pat Shop Customer".to_owned(),
            role_id,
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    let mut pat = Person::new(
        Client::new(stack, "Pat, signing in through a provider").expect("a client"),
        PersonAccount {
            email,
            display_name: "Pat Shop Customer".to_owned(),
            tenant: world.tenant().clone(),
        },
        PAT_PASSWORD,
    );
    pat.record_invitation(&invited.id);
    pat.accept_invitation(stack).await;
    pat
}

/// Tess creates a shop customer role without administrative permissions.
async fn create_customer_role(world: &World<'_>) -> String {
    let role = roles::create(
        world.tenant(),
        &NewRole {
            name: "Shop customer".to_owned(),
            system_permissions: Vec::new(),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    role.id
}

/// The sign-in Pat begins at the shop through the provider `connection`:
/// where the shop sends her browser, which keeps the shop's cookie.
async fn begun(pat: &Person, shop: &Shop, connection: &str) -> Begun {
    let sso = shop.page(&format!("/.ianua/sso?connection_id={connection}"));
    let started = pat
        .client()
        .send::<Redirect>(
            Call::get(sso)
                .header("accept", "text/html")
                .header("origin", &format!("https://{}", shop.host))
                .header("sec-fetch-site", "same-origin"),
        )
        .await
        .ok();
    Begun {
        redirect_url: started.redirect_to,
        binding: String::new(),
    }
}

/// The shop's answer to a SAML provider's `answer`, posted by `browser`
/// from the provider's site to the shop's way back.
async fn posted<T: DeserializeOwned>(
    browser: &Client,
    shop: &Shop,
    answer: &ProviderAnswer,
) -> Answer<T> {
    let ProviderAnswer::Saml {
        relay_state,
        saml_response,
    } = answer
    else {
        panic!("a SAML provider answers with a posted response");
    };
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("SAMLResponse", saml_response)
        .append_pair("RelayState", relay_state)
        .finish();
    browser
        .send::<T>(
            Call::post(shop.page("/.ianua/sso-callback"))
                .raw("application/x-www-form-urlencoded", form)
                .header("origin", PROVIDER_SITE)
                .header("sec-fetch-site", "cross-site"),
        )
        .await
}

/// Checks none of `browsers` reaches the shop's customer page.
async fn nobody_in(shop: &Shop, browsers: &[&Client]) {
    for browser in browsers {
        browser
            .get::<IgnoredAny>(&shop.page(ORDERS))
            .await
            .refused(Status::UNAUTHORIZED, "unauthenticated");
    }
}

/// Checks Pat reaches the shop's customer page, the shop seeing one
/// arrival, with an assertion naming her and none of her cookies.
async fn only_pat_reaches_the_shop(shop: &Shop, pat: &Person) {
    shop.app.forget();
    pat.client()
        .get::<IgnoredAny>(&shop.page(ORDERS))
        .await
        .ok();
    let arrivals = shop.app.arrivals();
    assert_eq!(arrivals.len(), 1, "only Pat reached the shop");
    let AssertionCheck::Verified { caller } = &arrivals[0].assertion else {
        panic!("the shop could not check the gateway's assertion: {arrivals:?}");
    };
    assert_eq!(caller.sub, pat.id(), "the assertion names Pat");
    assert!(
        !arrivals[0].has_header("cookie"),
        "Pat's cookie reached the shop"
    );
}
