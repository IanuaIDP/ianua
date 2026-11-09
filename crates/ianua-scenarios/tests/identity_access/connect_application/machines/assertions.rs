//! A service proving itself with a JWT it signs with its own key
//! (`private_key_jwt`): each assertion is good once, and none Mallory
//! makes, unsigned, signed by another key or stating the wrong times or
//! audience, gets a token.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_scenarios::agent::keys::AgentKey;
use ianua_scenarios::api::oauth;
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::oauth::{ClientProof, ClientSettings, NewConfiguredClient};
use ianua_scenarios::world::World;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::clients::{own_tokens, provider, registered, wall_seconds};

/// The id of the key the service registers.
const KEY_ID: &str = "first";

/// How long a good assertion lasts, in seconds.
const LIFETIME: i64 = 60;

/// Well past the minute of allowed drift, in seconds.
const FAR_OFF: i64 = 300;

/// The record of a token handed out.
const ISSUED: &str = "oauth.access_token_issued";

/// The JWK Set the service registers: `key`'s public half, named
/// [`KEY_ID`].
fn key_set(key: &AgentKey) -> Value {
    let public = key.jwk();
    json!({"keys": [{
        "kty": public.kty,
        "crv": public.crv,
        "x": public.x,
        "y": public.y,
        "kid": KEY_ID,
    }]})
}

/// The service's key, its client and the audience its assertions name.
struct Signer<'a> {
    key: &'a AgentKey,
    client_id: &'a str,
    audience: &'a str,
}

impl Signer<'_> {
    /// Fresh claims of a good assertion, with a `jti` of their own.
    fn claims(&self) -> Value {
        let now = wall_seconds();
        json!({
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": self.audience,
            "jti": Uuid::now_v7().to_string(),
            "iat": now,
            "exp": now + LIFETIME,
        })
    }

    /// `claims` signed by the service's key.
    fn signed(&self, claims: &Value) -> String {
        self.key
            .signed_jws(&json!({"alg": "ES256", "kid": KEY_ID}), claims)
    }

    /// The proof carrying `assertion`.
    fn proof(&self, assertion: String) -> ClientProof {
        ClientProof::Assertion {
            client_id: self.client_id.to_owned(),
            assertion,
        }
    }

    /// A good assertion, then `change` applied to its claims.
    fn altered(&self, change: impl FnOnce(&mut Value)) -> String {
        let mut claims = self.claims();
        change(&mut claims);
        self.signed(&claims)
    }
}

/// The service registers its public key and proves itself with a JWT it
/// signed for the tenant's token endpoint: a token is handed out. The same
/// JWT sent again is refused, and one naming the tenant's issuer works
/// too. Every assertion Mallory can make is refused the same way, and so
/// is a secret in place of a signature, since the service registered a
/// key. A fresh assertion still works after all of it, and the record of
/// the token shows no assertion.
#[tokio::test]
async fn a_signed_assertion_is_good_once_and_no_forged_one_is_good_at_all() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let key = AgentKey::generate();
    let mallory = AgentKey::generate();
    let service = registered(
        &world,
        &NewConfiguredClient {
            name: "Signing service".to_owned(),
            redirect_uris: Vec::new(),
            grant_types: vec!["ClientCredentials".to_owned()],
            scopes: vec!["orders:read".to_owned()],
            token_endpoint_auth_method: "private_key_jwt".to_owned(),
            jwks: Some(key_set(&key)),
            settings: ClientSettings::default(),
        },
    )
    .await;
    let tenant = provider(&world).await;
    let twin = oauth::discovery(world.twin())
        .send(world.anonymous().client())
        .await
        .ok();
    let signer = Signer {
        key: &key,
        client_id: &service.client_id,
        audience: &tenant.discovery.token_endpoint,
    };

    let first = signer.signed(&signer.claims());
    let proof = signer.proof(first.clone());
    oauth::proven_token(world.tenant(), &own_tokens(&proof, None))
        .send(world.anonymous().client())
        .await
        .ok();
    oauth::proven_token(world.tenant(), &own_tokens(&proof, None))
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "invalid_client");

    let to_issuer = signer.altered(|claims| claims["aud"] = json!(tenant.discovery.issuer));
    oauth::proven_token(world.tenant(), &own_tokens(&signer.proof(to_issuer), None))
        .send(world.anonymous().client())
        .await
        .ok();

    for (forged, why) in forgeries(&signer, &mallory, &twin.token_endpoint) {
        let answer = oauth::proven_token(world.tenant(), &own_tokens(&signer.proof(forged), None))
            .send(world.anonymous().client())
            .await;
        assert_eq!(
            answer.status(),
            Status::UNAUTHORIZED,
            "{why}: {}",
            answer.summary()
        );
        answer.refused(Status::UNAUTHORIZED, "invalid_client");
    }
    let with_a_secret = ClientProof::Secret {
        client_id: service.client_id.clone(),
        client_secret: "a secret this service never had".to_owned(),
    };
    oauth::proven_token(world.tenant(), &own_tokens(&with_a_secret, None))
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "invalid_client");

    let last = signer.signed(&signer.claims());
    oauth::proven_token(
        world.tenant(),
        &own_tokens(&signer.proof(last.clone()), None),
    )
    .send(world.anonymous().client())
    .await
    .ok();
    for record in world.trail().entries(ISSUED).await {
        no_secret_leaked(
            &record.details.to_string(),
            &[first.as_str(), last.as_str()],
        );
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Every assertion Mallory makes for the service, each with what it tries.
fn forgeries(
    signer: &Signer<'_>,
    mallory: &AgentKey,
    twin_token_endpoint: &str,
) -> Vec<(String, &'static str)> {
    let now = wall_seconds();
    let head = json!({"alg": "ES256", "kid": KEY_ID});
    vec![
        (
            mallory.signed_jws(&head, &signer.claims()),
            "signed by another key",
        ),
        (unsigned(&signer.claims()), "alg none with no signature"),
        (
            signer
                .key
                .signed_jws(&json!({"alg": "HS256", "kid": KEY_ID}), &signer.claims()),
            "naming an algorithm its key does not sign with",
        ),
        (
            signer.key.signed_jws(
                &json!({"alg": "ES256", "kid": "another-key"}),
                &signer.claims(),
            ),
            "naming a key the service never registered",
        ),
        (
            signer.altered(|claims| claims["aud"] = json!(twin_token_endpoint)),
            "for another tenant's token endpoint",
        ),
        (
            signer.altered(|claims| claims["aud"] = json!("https://elsewhere.example/token")),
            "for another audience",
        ),
        (
            signer.altered(|claims| {
                claims.as_object_mut().expect("claims").remove("exp");
            }),
            "with no expiry",
        ),
        (
            signer.altered(|claims| claims["exp"] = json!(now - FAR_OFF)),
            "expired",
        ),
        (
            signer.altered(|claims| claims["nbf"] = json!(now + FAR_OFF)),
            "not valid yet",
        ),
        (
            signer.altered(|claims| claims["iat"] = json!(now + FAR_OFF)),
            "issued in the future",
        ),
        (
            signer.altered(|claims| claims["iss"] = json!("cli_someone_else")),
            "issued by someone other than its subject",
        ),
        (
            signer.altered(|claims| {
                claims["iss"] = json!("cli_someone_else");
                claims["sub"] = json!("cli_someone_else");
            }),
            "naming another client",
        ),
    ]
}

/// `claims` under `alg: none`, with no signature.
fn unsigned(claims: &Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(json!({"alg": "none", "kid": KEY_ID}).to_string());
    let body = URL_SAFE_NO_PAD.encode(claims.to_string());
    format!("{header}.{body}.")
}
