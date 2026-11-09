//! A service getting tokens for itself with its secret, and what the
//! tenant says of them to a resource server: Tess rotates the secret and
//! ends the service, and only a client that proves itself is told
//! anything or ends anything.

use ianua_scenarios::api::oauth;
use ianua_scenarios::expect::{Matrix, no_secret_leaked};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::oauth::{ClientProof, ClientSettings, ProvenQuestion, RotateSecret};
use ianua_scenarios::world::World;

use crate::clients::{
    callback, facts_about, own_tokens, provider, public_app, registered, secret_of, service,
    service_tokens,
};

/// The orders service's own scopes.
const ORDERS_READ: &str = "orders:read";

/// The other scope it holds.
const ORDERS_WRITE: &str = "orders:write";

/// Longer than the test runs: an hour of overlap, in seconds.
const OVERLAP_SECONDS: u32 = 3_600;

/// The record a rotated secret leaves.
const SECRET_ROTATED: &str = "oauth.client_secret_rotated";

/// The record a revoked client leaves.
const CLIENT_REVOKED: &str = "oauth.client_revoked";

/// The record of a token ended by its holder.
const TOKEN_REVOKED: &str = "oauth.token_revoked";

/// `client_id` proving itself with `secret`, as a form sends it.
fn secret_proof(client_id: &str, secret: &str) -> ClientProof {
    ClientProof::Secret {
        client_id: client_id.to_owned(),
        client_secret: secret.to_owned(),
    }
}

/// The orders service asks for tokens with its secret: it gets a bearer
/// token for its own scopes, no refresh and no ID token, and a narrower
/// one when it names a scope. A wrong secret, a client that does not
/// exist or a scope it was never given get nothing. The reporting service,
/// proving itself, is told who the token belongs to. Max, Sam and nobody
/// signed in cannot rotate the secret. Tess rotates it, the old secret
/// ends at once and the new one works; a rotation with an overlap keeps
/// both working. Tess ends the service: its token is worth nothing, and
/// its secret gets no more. Every step is recorded and no record shows a
/// secret.
#[tokio::test]
async fn a_service_proves_itself_for_tokens_and_loses_them_when_tess_ends_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let orders = registered(
        &world,
        &service(
            "Orders",
            &["ClientCredentials"],
            &[ORDERS_READ, ORDERS_WRITE],
        ),
    )
    .await;
    let reporting = registered(
        &world,
        &service("Reporting API", &["ClientCredentials"], &[ORDERS_READ]),
    )
    .await;
    let orders_proof = secret_of(&orders);
    let reporting_proof = secret_of(&reporting);
    let issuer = provider(&world).await.discovery.issuer;

    let tokens = service_tokens(&world, &orders_proof).await;
    assert_eq!(tokens.token_type.as_deref(), Some("Bearer"));
    assert!(
        tokens.refresh_token.is_none(),
        "a service proves itself again instead"
    );
    assert!(tokens.id_token.is_none(), "it acts for no person");
    let scope = tokens.scope.as_deref().unwrap_or_default();
    assert!(
        scope.contains(ORDERS_READ) && scope.contains(ORDERS_WRITE),
        "both scopes: {scope}"
    );
    let narrow = oauth::proven_token(
        world.tenant(),
        &own_tokens(&orders_proof, Some(ORDERS_READ)),
    )
    .send(world.anonymous().client())
    .await
    .ok();
    assert_eq!(
        narrow.scope.as_deref(),
        Some(ORDERS_READ),
        "only what it named"
    );

    refuse_bad_requests(&world, &orders.client_id, &orders_proof).await;

    let facts = facts_about(&world, &reporting_proof, &tokens.access_token).await;
    assert!(facts.active, "the token works");
    assert_eq!(facts.client_id.as_deref(), Some(orders.client_id.as_str()));
    assert_eq!(facts.sub.as_deref(), Some(orders.client_id.as_str()));
    assert_eq!(facts.aud.as_deref(), Some(orders.client_id.as_str()));
    assert_eq!(facts.iss.as_deref(), Some(issuer.as_str()));
    assert!(
        !facts_about(&world, &reporting_proof, "no-such-token")
            .await
            .active,
        "a token never issued is inactive"
    );

    refuse_rotation_by_others(&world, &orders.id).await;
    let rotated = oauth::rotate_secret(
        world.tenant(),
        &orders.id,
        &RotateSecret { overlap_seconds: 0 },
    )
    .send(world.admin().client())
    .await
    .ok();
    oauth::proven_token(world.tenant(), &own_tokens(&orders_proof, None))
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "invalid_client");
    let current = secret_proof(&orders.client_id, &rotated.client_secret);
    let live = service_tokens(&world, &current).await;

    let again = oauth::rotate_secret(
        world.tenant(),
        &orders.id,
        &RotateSecret {
            overlap_seconds: OVERLAP_SECONDS,
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    let newest = secret_proof(&orders.client_id, &again.client_secret);
    service_tokens(&world, &current).await;
    let replaced = service_tokens(&world, &newest).await;

    oauth::revoke_client(world.tenant(), &orders.id)
        .send(world.admin().client())
        .await
        .ok();
    assert!(
        !facts_about(&world, &reporting_proof, &replaced.access_token)
            .await
            .active,
        "an ended client's tokens are worth nothing"
    );
    assert!(
        !facts_about(&world, &reporting_proof, &live.access_token)
            .await
            .active,
        "nor its earlier ones"
    );
    oauth::proven_token(world.tenant(), &own_tokens(&newest, None))
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "invalid_client");

    assert_on_record_without_secrets(
        &world,
        &[
            rotated.client_secret.as_str(),
            again.client_secret.as_str(),
            orders.client_secret.as_deref().unwrap_or("unset"),
            tokens.access_token.as_str(),
        ],
    )
    .await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// A wrong secret, a client that does not exist and a scope never given
/// each get nothing.
async fn refuse_bad_requests(world: &World<'_>, orders: &str, proof: &ClientProof) {
    let wrong = secret_proof(orders, "not the secret this client was shown");
    let unknown = secret_proof("cli_nobody_registered", "not a secret anyone was shown");
    for (attempt, why) in [(&wrong, "a wrong secret"), (&unknown, "an unknown client")] {
        let answer = oauth::proven_token(world.tenant(), &own_tokens(attempt, None))
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
    oauth::proven_token(world.tenant(), &own_tokens(proof, Some("orders:admin")))
        .send(world.anonymous().client())
        .await
        .refused(Status::BAD_REQUEST, "invalid_scope");
}

/// Max, Sam and nobody signed in cannot give the service a new secret.
async fn refuse_rotation_by_others(world: &World<'_>, id: &str) {
    Matrix::new(
        "rotating the service's secret",
        oauth::rotate_secret(world.tenant(), id, &RotateSecret { overlap_seconds: 0 }).call(),
    )
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
}

/// The two rotations and the ending of the client are recorded, and no
/// record shows any of `secrets`.
async fn assert_on_record_without_secrets(world: &World<'_>, secrets: &[&str]) {
    assert_eq!(
        world.trail().count(SECRET_ROTATED).await,
        2,
        "both rotations are recorded"
    );
    let trail = world.trail();
    let revoked = trail.recorded(CLIENT_REVOKED).await;
    no_secret_leaked(&revoked.details.to_string(), secrets);
    for entry in trail.entries("oauth.").await {
        no_secret_leaked(&entry.details.to_string(), secrets);
    }
}

/// A token the orders service holds, asked about or given up by clients
/// proving themselves. The reporting service, which does not hold it, is
/// answered as if it ended it, yet the token still works and nothing is
/// recorded. A wrong secret gets a refusal. The orders service ends it,
/// on record. A client proving nothing is told nothing, not even a public
/// one Tess registered, which can prove nothing.
#[tokio::test]
async fn only_a_client_that_proves_itself_asks_and_each_ends_only_its_own_tokens() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let orders = registered(
        &world,
        &service("Orders", &["ClientCredentials"], &[ORDERS_READ]),
    )
    .await;
    let reporting = registered(
        &world,
        &service("Reporting API", &["ClientCredentials"], &[ORDERS_READ]),
    )
    .await;
    let orders_proof = secret_of(&orders);
    let reporting_proof = secret_of(&reporting);
    let tokens = service_tokens(&world, &orders_proof).await;
    let question_by = |proof: &ClientProof| ProvenQuestion {
        proof: proof.clone(),
        token: tokens.access_token.clone(),
    };
    let application = Client::new(&stack, "a client application").expect("a client");

    oauth::proven_revoke(world.tenant(), &question_by(&reporting_proof))
        .send(&application)
        .await
        .ok();
    assert!(
        facts_about(&world, &reporting_proof, &tokens.access_token)
            .await
            .active,
        "another client cannot end it"
    );
    assert_eq!(
        world.trail().count(TOKEN_REVOKED).await,
        0,
        "and nothing is recorded"
    );
    let wrong = secret_proof(&orders.client_id, "not the secret this client was shown");
    oauth::proven_revoke(world.tenant(), &question_by(&wrong))
        .send(&application)
        .await
        .refused(Status::UNAUTHORIZED, "invalid_client");

    let nothing = ClientProof::Nothing {
        client_id: reporting.client_id.clone(),
    };
    oauth::proven_introspect(world.tenant(), &question_by(&nothing))
        .send(&application)
        .await
        .refused(Status::UNAUTHORIZED, "invalid_client");

    oauth::proven_revoke(world.tenant(), &question_by(&orders_proof))
        .send(&application)
        .await
        .ok();
    assert!(
        !facts_about(&world, &reporting_proof, &tokens.access_token)
            .await
            .active,
        "its holder ended it"
    );
    world.trail().recorded(TOKEN_REVOKED).await;

    oauth::revoke_client(world.tenant(), &orders.id)
        .send(world.admin().client())
        .await
        .ok();
    let at = callback(&stack, "ledger");
    let ledger = registered(
        &world,
        &public_app("Ledger", &at, ClientSettings::default()),
    )
    .await;
    let public = ClientProof::Nothing {
        client_id: ledger.client_id.clone(),
    };
    oauth::proven_introspect(world.tenant(), &question_by(&public))
        .send(&application)
        .await
        .refused(Status::UNAUTHORIZED, "invalid_client");
    stack.stop().await.expect("the stack stops cleanly");
}
