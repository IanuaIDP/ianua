//! Bob, the platform's operator, replacing a tenant's signing key for Ann
//! while the tenant's services keep working: a token the old key signed
//! still works until its own end, every token made afterwards is signed
//! with the new key, and the old token past its end works no more.
//!
//! The platform has no signing key of its own for an operator to replace:
//! every token is signed with its tenant's key, so Bob replaces Ann's
//! through a grant to act as Pat, who administers the tenant.

use std::time::Duration as StdDuration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_scenarios::api::{audit, crypto, oauth, operators};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Waiting, eventually_paced, verified_rs256};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::crypto::RotateKey;
use ianua_scenarios::wire::oauth::{
    ClientCredentialsGrant, ConfidentialClientRegistered, Introspection, MachineClientSettings,
    NewMachineClient, OwnTokenLifetimes,
};
use ianua_scenarios::wire::operators::GrantImpersonation;
use ianua_scenarios::world::World;
use serde_json::Value;
use time::Duration;

use crate::support::{Bob, bob_signed_in, from_now, impersonation_allowed, pat_joined, tenant_id};

/// How long the orders service's access tokens last: five minutes.
const TOKEN_SECONDS: i64 = 300;

/// When Bob replaces the key: well within the first token's five minutes.
const BEFORE_THE_ROTATION: StdDuration = StdDuration::from_secs(200);

/// From the rotation to past the first token's end, and well before the
/// end of a token made at the rotation.
const PAST_THE_OLD_TOKENS_END: StdDuration = StdDuration::from_secs(150);

/// The algorithm Bob rotates to, the one the tenant signs with already.
const ALGORITHM: &str = "RS256";

/// The type a JWT access token's header carries.
const ACCESS_TOKEN_TYPE: &str = "at+jwt";

/// The record a replaced signing key leaves.
const ROTATED: &str = "crypto.key_rotated";

/// How the orders service waits for a token signed with the new key:
/// once a second, for at most twenty seconds.
const AS_A_SERVICE_RETRIES: Waiting = Waiting {
    patience: StdDuration::from_secs(20),
    every: StdDuration::from_secs(1),
};

/// Tess registers the orders service, whose access tokens are JWTs that
/// last five minutes, and it gets a token signed with the tenant's key.
/// Ann lets operators in, and Bob takes a grant to act as Pat. Three
/// minutes later Bob, as Pat, replaces the signing key: the new key signs,
/// the old one is kept as rotated, and the replacement is recorded as
/// Bob acting as Pat. The first token still verifies against the
/// published keys and still works. The orders service's next token is
/// signed with the new key and verifies too. Two and a half minutes
/// later the first token is past its end and works no more, while the
/// second, made at the rotation, still works.
#[tokio::test]
async fn tokens_signed_with_the_old_key_work_until_their_own_end() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat_joined(&world).await;
    let bob = bob_signed_in(&stack).await;
    let tenant = tenant_id(&world).await;
    let service = orders_service(&world).await;
    impersonation_allowed(&world).await;
    let terms = GrantImpersonation {
        tenant_id: tenant.clone(),
        user_id: pat.id().to_owned(),
        reason: "Ann asked for the tenant's signing key to be replaced".to_owned(),
        expires_at: from_now(Duration::hours(1)),
    };
    let grant = operators::grant(&bob.id, &terms)
        .send(&bob.client)
        .await
        .ok();
    let old_key = active_key(&world, &bob, &grant.id).await;
    let first = token_for(&world, &service).await;
    assert_eq!(
        kid_of(&first),
        old_key,
        "the first token is signed with the key that signs now"
    );
    assert_verified(&world, &first).await;

    clock.advance(BEFORE_THE_ROTATION);
    let rotation = RotateKey {
        algorithm: ALGORITHM.to_owned(),
    };
    crypto::rotate(world.tenant(), &rotation)
        .header(operators::IMPERSONATION_HEADER, &grant.id)
        .send(&bob.client)
        .await
        .ok();
    let new_key = active_key(&world, &bob, &grant.id).await;
    assert_ne!(new_key, old_key, "the replacement key signs from now on");
    assert_old_key_rotated(&world, &bob, &grant.id, &old_key).await;
    assert_rotation_recorded(&bob, &tenant, pat.id()).await;
    assert_verified(&world, &first).await;
    assert!(
        works(&world, &service, &first).await,
        "the first token still works"
    );

    let second = eventually_paced(
        "a token signed with the new key",
        AS_A_SERVICE_RETRIES,
        || signed_with(&world, &service, &new_key),
    )
    .await;
    assert_verified(&world, &second).await;

    clock.advance(PAST_THE_OLD_TOKENS_END);
    assert!(
        !works(&world, &service, &first).await,
        "the first token works no more past its end"
    );
    assert!(
        works(&world, &service, &second).await,
        "the token made at the rotation still works"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The orders service, registered by Tess as a machine client with its
/// own secret, whose access tokens are JWTs lasting five minutes.
async fn orders_service(world: &World<'_>) -> ConfidentialClientRegistered {
    let client = NewMachineClient {
        name: "Orders service".to_owned(),
        grant_types: vec!["ClientCredentials".to_owned()],
        scopes: vec!["orders:read".to_owned()],
        token_endpoint_auth_method: "client_secret_post".to_owned(),
        settings: MachineClientSettings {
            access_token_format: "jwt".to_owned(),
            token_lifetimes: OwnTokenLifetimes {
                kind: "own".to_owned(),
                access_token_seconds: TOKEN_SECONDS,
                id_token_seconds: TOKEN_SECONDS,
                refresh_idle_seconds: 3_600,
                refresh_family_seconds: 86_400,
            },
        },
    };
    oauth::register_machine_client(world.tenant(), &client)
        .send(world.admin().client())
        .await
        .ok()
}

/// A fresh access token the orders service gets for itself.
async fn token_for(world: &World<'_>, service: &ConfidentialClientRegistered) -> String {
    let grant = ClientCredentialsGrant {
        client_id: service.client_id.clone(),
        client_secret: service.client_secret.clone(),
    };
    oauth::machine_token(world.tenant(), &grant)
        .send(world.anonymous().client())
        .await
        .ok()
        .access_token
}

/// A fresh token of the orders service, once one is signed with the key
/// `kid`.
async fn signed_with(
    world: &World<'_>,
    service: &ConfidentialClientRegistered,
    kid: &str,
) -> Option<String> {
    let token = token_for(world, service).await;
    (kid_of(&token) == kid).then_some(token)
}

/// Whether `token` works, as the orders service's introspection says.
async fn works(world: &World<'_>, service: &ConfidentialClientRegistered, token: &str) -> bool {
    let question = Introspection {
        client_id: service.client_id.clone(),
        client_secret: service.client_secret.clone(),
        token: token.to_owned(),
    };
    oauth::introspect(world.tenant(), &question)
        .send(world.anonymous().client())
        .await
        .ok()
        .active
}

/// `token` verifies against the keys the tenant publishes, as anyone
/// checking it would, with nothing but those keys.
async fn assert_verified(world: &World<'_>, token: &str) {
    let discovery = oauth::discovery(world.tenant())
        .send(world.anonymous().client())
        .await
        .ok();
    let published = oauth::keys(&discovery.jwks_uri)
        .send(world.anonymous().client())
        .await
        .ok();
    verified_rs256(&published, token, ACCESS_TOKEN_TYPE)
        .expect("a published key verifies the access token");
}

/// The id of the key that signs the tenant's tokens now, as Bob reads it
/// acting as Pat through `grant`.
async fn active_key(world: &World<'_>, bob: &Bob, grant: &str) -> String {
    let keys = crypto::keys(world.tenant())
        .header(operators::IMPERSONATION_HEADER, grant)
        .send(&bob.client)
        .await
        .ok();
    let active: Vec<_> = keys
        .keys
        .into_iter()
        .filter(|key| key.status == "Active")
        .collect();
    let [only] = active.as_slice() else {
        panic!("exactly one key signs, found {}", active.len());
    };
    only.kid.clone()
}

/// The old key `old` is kept as rotated, as Bob reads the keys acting as
/// Pat through `grant`.
async fn assert_old_key_rotated(world: &World<'_>, bob: &Bob, grant: &str, old: &str) {
    let keys = crypto::keys(world.tenant())
        .header(operators::IMPERSONATION_HEADER, grant)
        .send(&bob.client)
        .await
        .ok();
    assert!(
        keys.keys
            .iter()
            .any(|key| key.kid == old && key.status == "Rotated"),
        "the old key is kept as rotated, so its tokens still check"
    );
}

/// The replacement is in the platform's log for the tenant `tenant`,
/// recorded as Bob acting as the person `pat_id`.
async fn assert_rotation_recorded(bob: &Bob, tenant: &str, pat_id: &str) {
    let records = audit::platform_log_where(&[("event_type", ROTATED), ("tenant_id", tenant)])
        .send(&bob.client)
        .await
        .ok();
    let recorded = records.items.iter().any(|record| {
        record.acted_through.as_ref().is_some_and(|through| {
            through.kind == "impersonation"
                && through.operator_id.as_deref() == Some(bob.id.as_str())
                && through.as_user_id.as_deref() == Some(pat_id)
        })
    });
    assert!(recorded, "the replacement is recorded as Bob acting as Pat");
}

/// The key id `token`'s header names.
fn kid_of(token: &str) -> String {
    let header = token.split('.').next().expect("a compact JWT has a header");
    let bytes = URL_SAFE_NO_PAD
        .decode(header)
        .expect("the header is base64url");
    let header: Value = serde_json::from_slice(&bytes).expect("the header is JSON");
    header["kid"]
        .as_str()
        .expect("the header names a key")
        .to_owned()
}
