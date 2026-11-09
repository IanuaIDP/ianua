//! Tokens the platform must refuse, made by Mallory out of a real one:
//! unsigned, signed with the tenant's public key as a shared secret, its
//! claims changed, an ID token used as an access token, one from another
//! tenant. A real token works, and stops working when its time is up.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac as _};
use ianua_scenarios::api::oauth;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::verified_rs256;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::oauth::{
    ClientProof, ClientSettings, Key, NewConfiguredClient, OwnTokenLifetimes, ProvenGrant,
    ProvenQuestion, ProvenTokenRequest, RegisteredClient,
};
use ianua_scenarios::world::World;
use serde_json::{Value, json};
use sha2::Sha256;

use crate::clients::{
    callback, code_for, code_grant, provider, public_app, registered, secret_of, service,
};
use crate::support::pat;

/// How long Ledger's tokens last: five minutes.
const TOKEN_SECONDS: i64 = 300;

/// From a token's issue to past its end, drift included.
const PAST_ITS_END: Duration = Duration::from_secs(420);

/// The type a JWT access token's header names.
const ACCESS_TOKEN_TYPE: &str = "at+jwt";

/// Someone Pat is not.
const SOMEONE_ELSE: &str = "00000000-0000-4000-8000-000000000001";

/// Settings of a client whose access tokens are JWTs that last five
/// minutes.
fn jwt_for_five_minutes() -> ClientSettings {
    ClientSettings {
        access_token_format: Some("jwt".to_owned()),
        sender_constraint: None,
        token_lifetimes: Some(OwnTokenLifetimes {
            kind: "own".to_owned(),
            access_token_seconds: TOKEN_SECONDS,
            id_token_seconds: TOKEN_SECONDS,
            refresh_idle_seconds: 3_600,
            refresh_family_seconds: 86_400,
        }),
    }
}

/// The orders API, a confidential client of the tenant, that asks the
/// platform what the tokens it is shown are worth.
struct OrdersApi<'a> {
    world: &'a World<'a>,
    proof: ClientProof,
}

impl OrdersApi<'_> {
    /// Whether the platform says `token` works.
    async fn finds_active(&self, token: &str) -> bool {
        let question = ProvenQuestion {
            proof: self.proof.clone(),
            token: token.to_owned(),
        };
        oauth::proven_introspect(self.world.tenant(), &question)
            .send(self.world.anonymous().client())
            .await
            .ok()
            .active
    }
}

/// Pat signs in to Ledger, whose access tokens are JWTs lasting five
/// minutes: it verifies against the tenant's published keys, reads Pat at
/// user info and the orders API finds it active. Mallory then remakes it
/// every way she can and each one reads nothing at user info and is
/// inactive to the orders API. A token made by the other company's tenant
/// is nothing here, and Pat's is nothing there. Six minutes on, Pat's own
/// token is past its end and works no more.
#[tokio::test]
async fn forged_foreign_and_expired_tokens_get_nothing() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat(&world).await;
    let at = callback(&stack, "ledger");
    let ledger = registered(&world, &public_app("Ledger", &at, jwt_for_five_minutes())).await;
    let orders = OrdersApi {
        world: &world,
        proof: secret_of(
            &registered(
                &world,
                &service("Orders API", &["ClientCredentials"], &["orders:read"]),
            )
            .await,
        ),
    };
    let tenant = provider(&world).await;
    let code = code_for(&world, &pat, &ledger.client_id, &at).await;
    let tokens = oauth::token(world.tenant(), &code_grant(&ledger.client_id, &code, &at))
        .send(world.anonymous().client())
        .await
        .ok();
    let access = tokens.access_token.as_str();

    verified_rs256(&tenant.keys, access, ACCESS_TOKEN_TYPE)
        .expect("the tenant's published key verifies the access token");
    let info = oauth::user_info(world.tenant(), access)
        .send(world.anonymous().client())
        .await
        .ok();
    assert_eq!(info.sub, pat.id(), "the real token reads Pat");
    assert!(orders.finds_active(access).await, "the real token works");

    let id_token = tokens
        .id_token
        .as_deref()
        .expect("openid issues an ID token");
    let published = tenant
        .keys
        .keys
        .first()
        .expect("the tenant publishes a key");
    for (forged, why) in forgeries(access, id_token, published) {
        assert_worthless(&world, &orders, &forged, why).await;
    }

    assert_foreign_tokens_refused(&world, &orders, access).await;
    clock.advance(PAST_ITS_END);
    assert_worthless(&world, &orders, access, "a token past its end").await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// A token at the other tenant is worth nothing here, and Pat's token is
/// worth nothing there.
async fn assert_foreign_tokens_refused(world: &World<'_>, orders: &OrdersApi<'_>, pats: &str) {
    let sams = twin_token(world).await;
    assert!(
        !orders.finds_active(&sams).await,
        "the other tenant's token is nothing here"
    );
    oauth::user_info(world.twin(), pats)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "invalid_token");
}

/// A signed access token of a service Sam registered in his own tenant.
async fn twin_token(world: &World<'_>) -> String {
    let client = NewConfiguredClient {
        settings: jwt_for_five_minutes(),
        ..service("Globex orders", &["ClientCredentials"], &["orders:read"])
    };
    let made: RegisteredClient = oauth::register_configured(world.twin(), &client)
        .send(world.stranger().client())
        .await
        .ok();
    let grant = ProvenTokenRequest {
        proof: secret_of(&made),
        grant: ProvenGrant::ClientCredentials { scope: None },
    };
    oauth::proven_token(world.twin(), &grant)
        .send(world.anonymous().client())
        .await
        .ok()
        .access_token
}

/// `token`, named `why`, reads nothing at user info and is inactive to
/// the orders API.
async fn assert_worthless(world: &World<'_>, orders: &OrdersApi<'_>, token: &str, why: &str) {
    let answer = oauth::user_info(world.tenant(), token)
        .send(world.anonymous().client())
        .await;
    assert_eq!(
        answer.status(),
        Status::UNAUTHORIZED,
        "{why}: {}",
        answer.summary()
    );
    answer.refused(Status::UNAUTHORIZED, "invalid_token");
    assert!(!orders.finds_active(token).await, "{why} is inactive");
}

/// Every token Mallory makes out of `access`, Pat's real access token,
/// `id_token` beside it, and `published`, the tenant's public key, each
/// with what it tries.
fn forgeries(access: &str, id_token: &str, published: &Key) -> Vec<(String, &'static str)> {
    let [header, claims, signature] = parts(access);
    let unsigned = with_algorithm(&header, "none");
    let shared_secret = with_algorithm(&header, "HS256");
    let signed_input = format!("{shared_secret}.{claims}");
    vec![
        (
            format!("{unsigned}.{claims}."),
            "alg none with no signature",
        ),
        (
            format!("{unsigned}.{claims}.{signature}"),
            "alg none with the signature kept",
        ),
        (
            format!("{signed_input}.{}", keyed_with(published, &signed_input)),
            "HS256 keyed with the published key",
        ),
        (
            format!("{header}.{}.{signature}", about_someone_else(&claims)),
            "its subject changed under the same signature",
        ),
        (
            id_token.to_owned(),
            "an ID token presented as an access token",
        ),
    ]
}

/// The three dot-separated parts of `token`.
fn parts(token: &str) -> [String; 3] {
    let parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    parts.try_into().expect("a compact JWT has three parts")
}

/// `header`, base64url JSON, naming the algorithm `alg` instead.
fn with_algorithm(header: &str, alg: &str) -> String {
    let mut read = decoded(header);
    read["alg"] = json!(alg);
    URL_SAFE_NO_PAD.encode(read.to_string())
}

/// `claims`, base64url JSON, naming someone other than Pat.
fn about_someone_else(claims: &str) -> String {
    let mut read = decoded(claims);
    read["sub"] = json!(SOMEONE_ELSE);
    URL_SAFE_NO_PAD.encode(read.to_string())
}

/// A base64url part read as JSON.
fn decoded(part: &str) -> Value {
    let bytes = URL_SAFE_NO_PAD.decode(part).expect("base64url");
    serde_json::from_slice(&bytes).expect("JSON")
}

/// The HS256 signature of `input`, base64url, keyed with the modulus of
/// `published`: the old trick of letting a public key pass as a secret.
fn keyed_with(published: &Key, input: &str) -> String {
    let secret = URL_SAFE_NO_PAD.decode(&published.n).expect("base64url");
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret).expect("any key is taken");
    mac.update(input.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}
