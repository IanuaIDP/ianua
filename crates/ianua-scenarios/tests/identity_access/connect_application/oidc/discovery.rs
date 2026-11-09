//! What the tenant publishes for apps to configure themselves with, and
//! Ledger's own check of Pat's ID token against nothing but that.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_scenarios::api::oauth;
use ianua_scenarios::expect::verified_rs256;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::oauth::{ClientSettings, Discovery, Tokens};
use ianua_scenarios::world::World;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::clients::{
    NONCE, Provider, callback, code_for, code_grant, provider, public_app, registered, wall_seconds,
};
use crate::support::pat;

/// The type an ID token's header names.
const ID_TOKEN_TYPE: &str = "JWT";

/// The members of a JWK that only a private key has.
const PRIVATE_MEMBERS: [&str; 7] = ["d", "p", "q", "dp", "dq", "qi", "k"];

/// How far ahead of the clock an ID token's issue time may be.
const ALLOWED_DRIFT: i64 = 60;

/// The claims of an ID token Ledger relies on.
#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: Value,
    sub: String,
    nonce: String,
    iat: i64,
    exp: i64,
    at_hash: String,
    email: String,
}

/// Whom an ID token for Pat must name.
struct Expected<'a> {
    issuer: &'a str,
    ledger: &'a str,
    pat: &'a str,
}

/// A developer reads the tenant's discovery document with no account. It
/// names one issuer with every endpoint under it, answers only the code
/// flow with PKCE, and signs nothing with `none` or a shared secret. Its
/// published keys carry no private part, and neither issuer nor any key
/// is shared with the other company's tenant. Pat signs in to Ledger:
/// Ledger's own check takes her ID token against the tenant's keys and
/// finds it issued for Ledger, naming Pat, with its own nonce, within its
/// times, and tied to the access token beside it. The same token checked
/// against the other tenant's keys is refused.
#[tokio::test]
async fn ledger_trusts_only_what_the_tenant_publishes() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tenant = provider(&world).await;
    assert_offers_only_safe_flows(&tenant.discovery);
    assert_keys_are_public(&world, &tenant.discovery.jwks_uri).await;
    let twin = twin_provider(&world).await;
    assert_stands_apart(&tenant, &twin);

    let pat = pat(&world).await;
    let at = callback(&stack, "ledger");
    let ledger = registered(
        &world,
        &public_app("Ledger", &at, ClientSettings::default()),
    )
    .await;
    let code = code_for(&world, &pat, &ledger.client_id, &at).await;
    let tokens = oauth::token(world.tenant(), &code_grant(&ledger.client_id, &code, &at))
        .send(world.anonymous().client())
        .await
        .ok();

    let id_token = tokens
        .id_token
        .as_deref()
        .expect("openid issues an ID token");
    let claims = verified_rs256(&tenant.keys, id_token, ID_TOKEN_TYPE)
        .expect("the tenant's published key verifies Pat's ID token");
    let expected = Expected {
        issuer: &tenant.discovery.issuer,
        ledger: &ledger.client_id,
        pat: pat.id(),
    };
    assert_for_ledger(claims, &expected, &tokens);
    assert_eq!(
        verified_rs256(&twin.keys, id_token, ID_TOKEN_TYPE),
        Err("the header names no published key".to_owned()),
        "the other tenant's keys do not vouch for Pat"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The other company's tenant, read as any app reads it.
async fn twin_provider(world: &World<'_>) -> Provider {
    let discovery = oauth::discovery(world.twin())
        .send(world.anonymous().client())
        .await
        .ok();
    let keys = oauth::keys(&discovery.jwks_uri)
        .send(world.anonymous().client())
        .await
        .ok();
    Provider { discovery, keys }
}

/// The document names one issuer, every endpoint under it, the code flow
/// with S256 alone, and no way to go unsigned.
fn assert_offers_only_safe_flows(discovery: &Discovery) {
    for endpoint in [
        &discovery.authorization_endpoint,
        &discovery.token_endpoint,
        &discovery.userinfo_endpoint,
        &discovery.jwks_uri,
        &discovery.introspection_endpoint,
        &discovery.revocation_endpoint,
        &discovery.end_session_endpoint,
        &discovery.device_authorization_endpoint,
    ] {
        assert!(
            endpoint.starts_with(&discovery.issuer),
            "{endpoint} is under the issuer {}",
            discovery.issuer
        );
    }
    assert_eq!(discovery.response_types_supported, ["code"]);
    assert_eq!(discovery.code_challenge_methods_supported, ["S256"]);
    assert!(discovery.authorization_response_iss_parameter_supported);
    assert!(
        !discovery
            .token_endpoint_auth_methods_supported
            .iter()
            .any(|method| method == "tls_client_auth"),
        "no certificate reaches the platform, so none is offered"
    );
    for grant in ["authorization_code", "refresh_token", "client_credentials"] {
        assert!(
            discovery
                .grant_types_supported
                .iter()
                .any(|offered| offered == grant),
            "{grant} is offered"
        );
    }
    for algorithms in [
        &discovery.id_token_signing_alg_values_supported,
        &discovery.token_endpoint_auth_signing_alg_values_supported,
        &discovery.dpop_signing_alg_values_supported,
    ] {
        assert!(!algorithms.is_empty(), "something signs");
        assert!(
            algorithms
                .iter()
                .all(|alg| alg != "none" && !alg.starts_with("HS")),
            "nothing unsigned or shared-secret is offered: {algorithms:?}"
        );
    }
}

/// Every key at `jwks_uri` names itself and shows only its public part.
async fn assert_keys_are_public(world: &World<'_>, jwks_uri: &str) {
    let published: Value = world.anonymous().client().get::<Value>(jwks_uri).await.ok();
    let keys = published["keys"].as_array().expect("a JWK Set");
    assert!(!keys.is_empty(), "the tenant publishes a key");
    for key in keys {
        assert!(key["kid"].is_string(), "each key names itself");
        for member in PRIVATE_MEMBERS {
            assert!(key.get(member).is_none(), "no key shows {member}");
        }
    }
}

/// The two tenants share neither an issuer nor a key.
fn assert_stands_apart(tenant: &Provider, twin: &Provider) {
    assert_ne!(tenant.discovery.issuer, twin.discovery.issuer);
    for key in &tenant.keys.keys {
        assert!(
            !twin.keys.keys.iter().any(|other| other.kid == key.kid),
            "the tenants share no key"
        );
    }
}

/// The verified `claims` name the tenant, Ledger and Pat, Ledger's nonce
/// and honest times, and the access token issued beside the ID token.
fn assert_for_ledger(claims: Value, expected: &Expected<'_>, tokens: &Tokens) {
    let claims: Claims = serde_json::from_value(claims).expect("OIDC claims");
    let now = wall_seconds();
    assert_eq!(claims.iss, expected.issuer, "issued by the tenant");
    assert!(names(&claims.aud, expected.ledger), "issued for Ledger");
    assert_eq!(claims.sub, expected.pat, "naming Pat");
    assert_eq!(claims.nonce, NONCE, "carrying Ledger's nonce");
    assert!(
        claims.iat <= now + ALLOWED_DRIFT,
        "not issued ahead of time"
    );
    assert!(
        claims.exp > now && claims.exp > claims.iat,
        "within its times"
    );
    assert!(
        claims.email.contains('@'),
        "the email scope gives her address"
    );
    let hash = Sha256::digest(tokens.access_token.as_bytes());
    assert_eq!(
        claims.at_hash,
        URL_SAFE_NO_PAD.encode(&hash[..16]),
        "tied to the access token beside it"
    );
}

/// Whether the `aud` claim `audience` names `client`.
fn names(audience: &Value, client: &str) -> bool {
    audience == client
        || audience
            .as_array()
            .is_some_and(|many| many.iter().any(|one| one == client))
}
