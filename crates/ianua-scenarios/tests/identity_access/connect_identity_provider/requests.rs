//! The sign-in requests the platform sends Acme's provider, signed once
//! Tess asks, with the certificate the connection publishes.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{Request, Text};
use ianua_scenarios::net::Call;
use ianua_scenarios::providers::parameter;
use ianua_scenarios::providers::saml::{Claim, Provider, RequestSignature};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::world::World;

use crate::support::{
    Outcome, SamlAnswer, Settings, begun, connected, owned_domain, pat, reconfigured, signed_in,
};

/// Tess links the tenant to Acme's provider, and the requests the
/// platform sends it go unsigned. Tess asks for them to be signed: the
/// connection's published metadata now names a signing certificate, and
/// the provider finds the next request signed by it. The same request
/// with its relay state changed fails the provider's check. Pat still
/// signs in through the signed request.
#[tokio::test]
async fn the_provider_finds_the_platforms_requests_signed_once_tess_asks() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let domain = owned_domain(&world).await;
    let provider = Provider::new();
    let mut settings = Settings {
        provider: &provider,
        next: None,
        sign_requests: false,
    };
    let connection = connected(&world, &domain, &settings).await;
    let mut pat = pat(&world, &domain).await;
    let metadata = Request::<Text>::text(Call::get(world.tenant().at(&format!(
        "/federation/connections/{connection}/saml/metadata"
    ))));

    let unsigned = begun(&world, &pat, &connection).await;
    assert_unsigned(&world, metadata.clone(), &unsigned).await;
    settings.sign_requests = true;
    reconfigured(&world, &connection, &settings).await;
    let published = metadata.send_text(world.anonymous().client()).await.ok();
    let signed = begun(&world, &pat, &connection).await;
    assert_signed_request(&signed, &published);
    assert_sign_in(&world, &mut pat, &provider, signed).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Before signing is enabled, the published metadata verifies no request signature.
async fn assert_unsigned(world: &World<'_>, metadata: Request<Text>, unsigned: &str) {
    let published = metadata.send_text(world.anonymous().client()).await.ok();
    assert_eq!(
        Provider::request_signature(unsigned, &published),
        RequestSignature::Unsigned
    );
}

/// The published certificate verifies the request and rejects changed relay state.
fn assert_signed_request(signed: &str, published: &str) {
    assert_eq!(
        Provider::request_signature(signed, published),
        RequestSignature::Verified,
        "the request is signed with the published certificate"
    );
    let relay_state = parameter(signed, "RelayState");
    let changed = signed.replace(&relay_state, "_another_request");
    assert_eq!(
        Provider::request_signature(&changed, published),
        RequestSignature::Broken,
        "a changed request fails the provider's check"
    );
}

/// Pat completes the provider's answer to the newly signed request.
async fn assert_sign_in(world: &World<'_>, pat: &mut Person, provider: &Provider, signed: String) {
    let answer = SamlAnswer {
        provider,
        redirect: signed,
        claim: Claim::Correct,
    };
    let outcome = signed_in(world, pat, answer).await;
    assert!(
        matches!(outcome, Outcome::SignedIn),
        "Pat signs in through the signed request: {outcome:?}"
    );
}
