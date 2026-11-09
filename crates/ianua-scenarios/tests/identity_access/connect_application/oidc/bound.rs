//! Tokens bound to an app's key (`DPoP`): Ledger proves its key for each
//! request, and a token Mallory copies is no use to her without it.

use ianua_scenarios::agent::external::dpop::{ProvenRequest, proof};
use ianua_scenarios::agent::keys::AgentKey;
use ianua_scenarios::api::oauth;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::oauth::{ClientSettings, Discovery, ProvenQuestion, Tokens, UserInfo};
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;

use crate::clients::{
    callback, code_for, code_grant, provider, public_app, refresh_grant, registered, secret_of,
    service, wall_seconds,
};
use crate::support::pat;

/// The header a proof is sent in.
const DPOP: &str = "dpop";

/// Older than a proof may be.
const STALE_SECONDS: i64 = 300;

/// What Ledger's requests are made against.
struct Requests<'a> {
    world: &'a World<'a>,
    discovery: &'a Discovery,
    client_id: &'a str,
}

impl Requests<'_> {
    /// A proof by `key` made now for a request to the token endpoint.
    fn for_tokens(&self, key: &AgentKey) -> String {
        let request = ProvenRequest {
            method: "POST",
            url: &self.discovery.token_endpoint,
        };
        proof(key, request, None, wall_seconds())
    }

    /// A proof by `key` made now for reading user info with `token`.
    fn for_user_info(&self, key: &AgentKey, token: &str) -> String {
        let request = ProvenRequest {
            method: "GET",
            url: &self.discovery.userinfo_endpoint,
        };
        proof(key, request, Some(token), wall_seconds())
    }

    /// What user info says of `token`, presented beside `proof`.
    async fn user_info(&self, token: &str, proof: &str) -> Answer<UserInfo> {
        oauth::bound_user_info(self.world.tenant(), token, proof)
            .send(self.world.anonymous().client())
            .await
    }
}

/// Ledger's tokens are always bound to a key. A code redeemed with no
/// proof gets nothing. With a proof from Ledger's key the tokens come as
/// `DPoP`, bound to that key by its thumbprint, as the orders API reads
/// them. The same proof does not fetch another token. User info answers
/// only a fresh proof from that key, naming this request and this token;
/// the token as a plain bearer, a replayed proof, one made for another
/// address or method, naming no token or another, an old one or one
/// signed by Mallory's key all read nothing. Ledger's key still works
/// after all of that. Mallory, holding the refresh token and proving her
/// own key, gets nothing, and neither does a request proving no key;
/// Ledger's own proof refreshes and the new token is bound too.
#[tokio::test]
async fn a_bound_token_works_only_with_a_fresh_proof_from_its_key() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat(&world).await;
    let at = callback(&stack, "ledger");
    let settings = ClientSettings {
        sender_constraint: Some("dpop".to_owned()),
        ..ClientSettings::default()
    };
    let ledger = registered(&world, &public_app("Ledger", &at, settings)).await;
    let orders = registered(
        &world,
        &service("Orders API", &["ClientCredentials"], &["orders:read"]),
    )
    .await;
    let tenant = provider(&world).await;
    let requests = Requests {
        world: &world,
        discovery: &tenant.discovery,
        client_id: &ledger.client_id,
    };
    let key = AgentKey::generate();
    let mallory = AgentKey::generate();

    let bare = code_for(&world, &pat, &ledger.client_id, &at).await;
    oauth::token(world.tenant(), &code_grant(&ledger.client_id, &bare, &at))
        .send(world.anonymous().client())
        .await
        .refused(Status::BAD_REQUEST, "invalid_dpop_proof");

    let code = code_for(&world, &pat, &ledger.client_id, &at).await;
    let first_proof = requests.for_tokens(&key);
    let tokens: Tokens = oauth::token(world.tenant(), &code_grant(&ledger.client_id, &code, &at))
        .header(DPOP, &first_proof)
        .send(world.anonymous().client())
        .await
        .ok();
    assert_eq!(
        tokens.token_type.as_deref(),
        Some("DPoP"),
        "bound tokens say so"
    );
    let second = code_for(&world, &pat, &ledger.client_id, &at).await;
    oauth::token(world.tenant(), &code_grant(&ledger.client_id, &second, &at))
        .header(DPOP, &first_proof)
        .send(world.anonymous().client())
        .await
        .refused(Status::BAD_REQUEST, "invalid_dpop_proof");

    let facts = oauth::proven_introspect(
        world.tenant(),
        &ProvenQuestion {
            proof: secret_of(&orders),
            token: tokens.access_token.clone(),
        },
    )
    .send(world.anonymous().client())
    .await
    .ok();
    assert!(facts.active, "the token works");
    assert_eq!(facts.token_type.as_deref(), Some("DPoP"));
    assert_eq!(
        facts.cnf.as_ref().and_then(|cnf| cnf.jkt.as_deref()),
        Some(key.thumbprint().as_str()),
        "the token is bound to Ledger's key"
    );

    assert_fresh_proof_reads_pat(&requests, &key, &tokens, pat.id()).await;
    refuse_bad_presentations(&requests, &key, &mallory, &tokens).await;
    let reused = requests.for_user_info(&key, &tokens.access_token);
    let info = requests.user_info(&tokens.access_token, &reused).await.ok();
    assert_eq!(info.sub, pat.id(), "Ledger's key still works");

    refresh_only_with_its_key(&requests, &key, &mallory, &tokens).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// A fresh proof from Ledger's key reads Pat, and the same proof again
/// reads nothing.
async fn assert_fresh_proof_reads_pat(
    requests: &Requests<'_>,
    key: &AgentKey,
    tokens: &Tokens,
    pat_id: &str,
) {
    let fresh = requests.for_user_info(key, &tokens.access_token);
    let info = requests.user_info(&tokens.access_token, &fresh).await.ok();
    assert_eq!(info.sub, pat_id, "a fresh proof reads Pat");
    requests
        .user_info(&tokens.access_token, &fresh)
        .await
        .refused(Status::UNAUTHORIZED, "invalid_token");
}

/// Every way of presenting the token without a fresh proof for this
/// request from Ledger's key reads nothing.
async fn refuse_bad_presentations(
    requests: &Requests<'_>,
    key: &AgentKey,
    mallory: &AgentKey,
    tokens: &Tokens,
) {
    let world = requests.world;
    let access = tokens.access_token.as_str();
    oauth::user_info(world.tenant(), access)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "invalid_token");

    let user_info = requests.discovery.userinfo_endpoint.as_str();
    let token_endpoint = requests.discovery.token_endpoint.as_str();
    let get = ProvenRequest {
        method: "GET",
        url: user_info,
    };
    let elsewhere = ProvenRequest {
        method: "GET",
        url: token_endpoint,
    };
    let posted = ProvenRequest {
        method: "POST",
        url: user_info,
    };
    let now = wall_seconds();
    let attempts = [
        (
            proof(key, elsewhere, Some(access), now),
            "made for another address",
        ),
        (
            proof(key, posted, Some(access), now),
            "made for another method",
        ),
        (
            proof(key, get, Some("another token"), now),
            "naming another token",
        ),
        (proof(key, get, None, now), "naming no token"),
        (
            proof(key, get, Some(access), now - STALE_SECONDS),
            "too old",
        ),
        (
            proof(key, get, Some(access), now + STALE_SECONDS),
            "made ahead of time",
        ),
        (
            proof(mallory, get, Some(access), now),
            "signed by Mallory's key",
        ),
    ];
    for (attempt, why) in attempts {
        let answer = requests.user_info(access, &attempt).await;
        assert_eq!(
            answer.status(),
            Status::UNAUTHORIZED,
            "a proof {why}: {}",
            answer.summary()
        );
        answer.refused(Status::UNAUTHORIZED, "invalid_token");
    }
}

/// Mallory, proving her own key, and a request proving no key get nothing
/// for the refresh token; Ledger's own proof refreshes it, still bound.
async fn refresh_only_with_its_key(
    requests: &Requests<'_>,
    key: &AgentKey,
    mallory: &AgentKey,
    tokens: &Tokens,
) {
    let world = requests.world;
    let refresh = refresh_grant(
        requests.client_id,
        tokens
            .refresh_token
            .as_deref()
            .expect("offline access issues one"),
    );
    oauth::token(world.tenant(), &refresh)
        .header(DPOP, &requests.for_tokens(mallory))
        .send(world.anonymous().client())
        .await
        .refused(Status::BAD_REQUEST, "invalid_grant");
    oauth::token(world.tenant(), &refresh)
        .send(world.anonymous().client())
        .await
        .refused(Status::BAD_REQUEST, "invalid_dpop_proof");
    let renewed = oauth::token(world.tenant(), &refresh)
        .header(DPOP, &requests.for_tokens(key))
        .send(world.anonymous().client())
        .await
        .ok();
    assert_eq!(
        renewed.token_type.as_deref(),
        Some("DPoP"),
        "the new token is bound too"
    );
    assert!(
        renewed.refresh_token.as_deref() != tokens.refresh_token.as_deref(),
        "the refresh token rotates"
    );
}
