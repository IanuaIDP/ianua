//! What a company publishes for anyone, signed in or not: how its sign-in
//! is found, the keys its tokens are checked with, and the keys the
//! gateway's word for a caller is checked with. A customer's app reads
//! them; Mallory reads them too, and finds only public halves, nothing
//! shared between two tenants, and nothing about tenants that do not
//! exist.

use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Problem;
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;
use serde_json::Value;

/// The members a JSON Web Key holds only in its private half.
const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "k", "oth"];

/// Acme's app finds the tenant's sign-in by its discovery document, with
/// nobody signed in: it names the tenant as issuer and points at the key
/// set, which answers.
#[tokio::test]
async fn an_app_finds_the_tenants_sign_in_without_signing_in() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let app = world.anonymous().client();

    let discovery = app
        .get::<Value>(&world.tenant().at("/.well-known/openid-configuration"))
        .await
        .ok();

    let issuer = discovery["issuer"].as_str().unwrap_or_default();
    assert!(
        issuer.starts_with("https://") && issuer.ends_with(world.tenant().slug()),
        "the issuer is the tenant's own address: {issuer}"
    );
    let key_set = discovery["jwks_uri"].as_str().unwrap_or_default();
    assert!(
        key_set.ends_with("/.well-known/jwks.json"),
        "the discovery points at the key set: {key_set}"
    );
    app.get::<IgnoredAny>(&world.tenant().at("/.well-known/jwks.json"))
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory reads both published key sets of a tenant: every key is a
/// public half with its id, no key is in both sets, and the twin tenant
/// of the same company shares none of them.
#[tokio::test]
async fn a_published_key_is_a_public_half_and_never_shared() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mallory = Client::new(&stack, "Mallory, reading key sets").expect("a client");

    let tokens = key_ids(&mallory, &world.tenant().at("/.well-known/jwks.json")).await;
    let assertions = key_ids(
        &mallory,
        &world.tenant().at("/.well-known/ianua-assertion-keys.json"),
    )
    .await;
    let twins = key_ids(&mallory, &world.twin().at("/.well-known/jwks.json")).await;

    assert!(!tokens.is_empty(), "the tenant publishes its token keys");
    assert!(
        !assertions.is_empty(),
        "the tenant publishes its assertion keys"
    );
    assert!(
        tokens.iter().all(|kid| !assertions.contains(kid)),
        "no key checks both tokens and the gateway's assertions"
    );
    assert!(
        tokens.iter().all(|kid| !twins.contains(kid)),
        "two tenants share no key"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory asks for the key set of a tenant that does not exist, in a
/// company that does and in one that does not: both answer the same, so
/// neither tells her which companies exist.
#[tokio::test]
async fn a_tenant_that_does_not_exist_tells_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mallory = Client::new(&stack, "Mallory, guessing tenants").expect("a client");

    let in_a_real_company = mallory
        .get::<IgnoredAny>(&world.org().at("/tenants/nowhere/.well-known/jwks.json"))
        .await;
    let in_no_company = mallory
        .get::<IgnoredAny>(
            "/api/v1/organizations/no-such-company-4127/tenants/nowhere/.well-known/jwks.json",
        )
        .await;

    assert_eq!(
        in_a_real_company.status(),
        in_no_company.status(),
        "the same answer either way: {} and {}",
        in_a_real_company.summary(),
        in_no_company.summary()
    );
    assert_eq!(
        in_a_real_company.problem().map(Problem::message),
        in_no_company.problem().map(Problem::message),
        "the same words either way"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The ids of the keys published at `path`, each checked to be a public
/// half with an id.
async fn key_ids(client: &Client, path: &str) -> Vec<String> {
    let set = client.get::<Value>(path).await.ok();
    let keys = set["keys"].as_array().cloned().unwrap_or_default();
    keys.iter()
        .map(|key| {
            for member in PRIVATE_MEMBERS {
                assert!(
                    key.get(member).is_none(),
                    "{path}: a published key holds its private member {member:?}"
                );
            }
            key["kid"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| panic!("{path}: a published key has no id: {key}"))
        })
        .collect()
}
