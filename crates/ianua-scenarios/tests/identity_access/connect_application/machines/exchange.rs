//! Token exchange: a gateway service trades the token it holds for a
//! narrower one meant for the orders API. Nothing is widened, nothing is
//! taken from a token the service was never handed, and a client not
//! allowed to exchange cannot.

use ianua_scenarios::api::oauth;
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::oauth::{
    ClientProof, ProvenGrant, ProvenQuestion, ProvenTokenRequest, Tokens,
};
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;

use crate::clients::{facts_about, own_tokens, registered, secret_of, service, service_tokens};

/// The scope the orders API needs.
const READ: &str = "orders:read";

/// The further scope the gateway holds.
const WRITE: &str = "orders:write";

/// The token type an exchange issues.
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// The record an exchange leaves.
const EXCHANGED: &str = "oauth.token_exchanged";

/// One exchange: the service asking, the token traded and whom for.
struct Exchange<'a> {
    asking: &'a ClientProof,
    subject_token: &'a str,
    audience: &'a str,
    scope: Option<&'a str>,
}

/// What the token endpoint answers `exchange`.
async fn exchanged(world: &World<'_>, exchange: Exchange<'_>) -> Answer<Tokens> {
    let request = ProvenTokenRequest {
        proof: exchange.asking.clone(),
        grant: ProvenGrant::Exchange {
            subject_token: exchange.subject_token.to_owned(),
            audience: exchange.audience.to_owned(),
            scope: exchange.scope.map(str::to_owned),
        },
    };
    oauth::proven_token(world.tenant(), &request)
        .send(world.anonymous().client())
        .await
}

/// The gateway, allowed to exchange, gets a token for itself and trades it
/// for one meant for the orders API, reading only. The new token is a
/// plain access token, with no refresh and no ID token, and the orders API
/// reads that it is meant for it, held by the gateway, for that one scope.
/// The trade is on record and shows neither token.
#[tokio::test]
async fn the_gateway_trades_its_token_for_a_narrower_one_meant_for_the_orders_api() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let gateway = registered(
        &world,
        &service(
            "Gateway",
            &["ClientCredentials", "TokenExchange"],
            &[READ, WRITE],
        ),
    )
    .await;
    let orders = registered(
        &world,
        &service("Orders API", &["ClientCredentials"], &[READ]),
    )
    .await;
    let gateway_proof = secret_of(&gateway);
    let held = service_tokens(&world, &gateway_proof).await;

    let trade = Exchange {
        asking: &gateway_proof,
        subject_token: &held.access_token,
        audience: &orders.client_id,
        scope: Some(READ),
    };
    let traded = exchanged(&world, trade).await.ok();

    assert_eq!(traded.issued_token_type.as_deref(), Some(ACCESS_TOKEN_TYPE));
    assert_eq!(traded.scope.as_deref(), Some(READ), "only what was asked");
    assert!(traded.refresh_token.is_none() && traded.id_token.is_none());
    assert_ne!(traded.access_token, held.access_token, "a new token");
    let facts = facts_about(&world, &secret_of(&orders), &traded.access_token).await;
    assert!(facts.active, "the orders API finds it working");
    assert_eq!(
        facts.aud.as_deref(),
        Some(orders.client_id.as_str()),
        "meant for it"
    );
    assert_eq!(
        facts.client_id.as_deref(),
        Some(gateway.client_id.as_str()),
        "held by the gateway"
    );
    assert_eq!(facts.scope.as_deref(), Some(READ));

    let record = world.trail().recorded(EXCHANGED).await;
    no_secret_leaked(
        &record.details.to_string(),
        &[held.access_token.as_str(), traded.access_token.as_str()],
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The gateway cannot widen what it holds, trade for a client that does
/// not exist or trade something that is no token. It cannot trade a token
/// the orders API holds, which it was never handed, nor one it gave up.
/// The orders API, not allowed to exchange at all, cannot trade even its
/// own. None of it is on record.
#[tokio::test]
async fn no_exchange_widens_a_token_or_reaches_beyond_what_the_service_holds() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let gateway = registered(
        &world,
        &service(
            "Gateway",
            &["ClientCredentials", "TokenExchange"],
            &[READ, WRITE],
        ),
    )
    .await;
    let orders = registered(
        &world,
        &service("Orders API", &["ClientCredentials"], &[READ]),
    )
    .await;
    let gateway_proof = secret_of(&gateway);
    let orders_proof = secret_of(&orders);
    let read_only = oauth::proven_token(world.tenant(), &own_tokens(&gateway_proof, Some(READ)))
        .send(world.anonymous().client())
        .await
        .ok();
    let held_by_orders = service_tokens(&world, &orders_proof).await;
    let given_up = service_tokens(&world, &gateway_proof).await;
    oauth::proven_revoke(
        world.tenant(),
        &ProvenQuestion {
            proof: gateway_proof.clone(),
            token: given_up.access_token.clone(),
        },
    )
    .send(world.anonymous().client())
    .await
    .ok();

    let wider = format!("{READ} {WRITE}");
    let attempts = [
        (
            Exchange {
                asking: &gateway_proof,
                subject_token: &read_only.access_token,
                audience: &orders.client_id,
                scope: Some(&wider),
            },
            "invalid_scope",
            "more scopes than the token holds",
        ),
        (
            Exchange {
                asking: &gateway_proof,
                subject_token: &read_only.access_token,
                audience: "cli_nobody_registered",
                scope: None,
            },
            "invalid_target",
            "a client that does not exist",
        ),
        (
            Exchange {
                asking: &gateway_proof,
                subject_token: "not-a-token-of-this-tenant",
                audience: &orders.client_id,
                scope: None,
            },
            "invalid_grant",
            "something that is no token",
        ),
        (
            Exchange {
                asking: &gateway_proof,
                subject_token: &held_by_orders.access_token,
                audience: &orders.client_id,
                scope: None,
            },
            "invalid_grant",
            "a token held by another service",
        ),
        (
            Exchange {
                asking: &gateway_proof,
                subject_token: &given_up.access_token,
                audience: &orders.client_id,
                scope: None,
            },
            "invalid_grant",
            "a token its holder gave up",
        ),
        (
            Exchange {
                asking: &orders_proof,
                subject_token: &held_by_orders.access_token,
                audience: &gateway.client_id,
                scope: None,
            },
            "unauthorized_client",
            "a client not allowed to exchange",
        ),
    ];
    for (attempt, code, why) in attempts {
        let answer = exchanged(&world, attempt).await;
        assert_eq!(
            answer.status(),
            Status::BAD_REQUEST,
            "{why}: {}",
            answer.summary()
        );
        answer.refused(Status::BAD_REQUEST, code);
    }
    assert_eq!(
        world.trail().count(EXCHANGED).await,
        0,
        "no refused trade is on record"
    );
    stack.stop().await.expect("the stack stops cleanly");
}
