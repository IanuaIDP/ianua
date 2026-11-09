//! Salesforce's account check: an account holds the company's own domain
//! and a connected app's grant, which is exchanged at the deployment's
//! token address before the domain is asked anything. A stand-in for that
//! token address shows the check: a domain the deployment does not allow,
//! or one asked over plain `http`, is refused before the grant goes
//! anywhere, and a grant Salesforce refuses is never connected.
//!
//! A company's own domain is reached at `https://` on a port the deployment
//! listed; a stand-in for it, under an authority the deployment trusts,
//! shows the exact requests a step sends.

use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp, OutsideReceiver};
use ianua_scenarios::wire::workflows::Graph;
use ianua_scenarios::world::World;
use serde_json::json;

use crate::integrations::calls::{Offered, chain, never_connected, only_call, ran};
use crate::support::{Action, account_at, action, written};

/// The grant's refresh token: a sentence, so no scanner takes it for a
/// key.
const GRANT: &str = "acme salesforce grant for workflows";

/// Where a grant is exchanged for a token.
const TOKEN: &str = "/services/oauth2/token";

/// Tess offers a grant for acme.example.com, which is no Salesforce
/// domain, and then for Acme's own domain over plain `http`: neither
/// account is connected, and the grant never reaches the token address.
#[tokio::test]
async fn a_domain_the_deployment_does_not_allow_is_never_connected() {
    let salesforce = salesforce_answering(Canned::json(&json!({ "access_token": "unused" }))).await;
    let stack = Stack::start(profile(&salesforce))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    for site in ["https://acme.example.com", "http://acme.my.salesforce.com"] {
        let offered = grant_for(site);
        never_connected(
            &world,
            Offered {
                integration: "salesforce",
                credential: &offered,
            },
        )
        .await;
    }

    assert!(salesforce.received().is_empty(), "the grant went nowhere");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess offers a grant for Acme's own domain that Salesforce's token
/// address refuses, as for a revoked one: it was offered there once, as a
/// form exchanging the refresh token, and no account is connected.
#[tokio::test]
async fn a_grant_salesforce_refuses_is_never_connected() {
    let salesforce = salesforce_answering(Canned::refusing(400)).await;
    let stack = Stack::start(profile(&salesforce))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let offered = grant_for("https://acme.my.salesforce.com");

    never_connected(
        &world,
        Offered {
            integration: "salesforce",
            credential: &offered,
        },
    )
    .await;

    let exchange = only_call(&salesforce, "POST", TOKEN);
    let form: Vec<(String, String)> = url::form_urlencoded::parse(exchange.body.as_bytes())
        .into_owned()
        .collect();
    assert!(form.contains(&("grant_type".to_owned(), "refresh_token".to_owned())));
    assert!(form.contains(&("refresh_token".to_owned(), GRANT.to_owned())));
    stack.stop().await.expect("the stack stops cleanly");
}

/// A stand-in for Salesforce's token address answering every exchange
/// with `exchange`.
async fn salesforce_answering(exchange: Canned) -> CannedApp {
    CannedApp::start([(TOKEN, exchange)])
        .await
        .expect("the Salesforce stand-in starts")
}

/// The standard deployment, Salesforce's token address at `salesforce`.
fn profile(salesforce: &CannedApp) -> Profile {
    Profile::standard().with(
        "SALESFORCE_TOKEN_URL",
        &format!("{}{TOKEN}", salesforce.url()),
    )
}

/// A connected app's grant for the domain `site`, as the account holds it.
fn grant_for(site: &str) -> String {
    json!({
        "site": site,
        "client_id": "acme salesforce app",
        "client_secret": "acme salesforce app words",
        "refresh_token": GRANT
    })
    .to_string()
}

/// The token a grant exchanges for, used for the REST API.
const SHORT_TOKEN: &str = "acme salesforce short token";

/// Acme's REST API's kinds of object, the probe an account is proven by.
const OBJECTS: &str = "/services/data/v62.0/sobjects";

/// Where a record of kind Account is added.
const ACCOUNTS: &str = "/services/data/v62.0/sobjects/Account";

/// Where a SOQL query is run.
const QUERY: &str = "/services/data/v62.0/query";

/// Tess connects Acme's own domain, which is asked about its kinds of
/// object. Ann publishes a workflow adding an account and finding it with
/// SOQL; Tess runs it. Acme's domain receives exactly the fields as the
/// body, and the query, each signed with the token the grant was
/// exchanged for and never the grant, and the run succeeds.
#[tokio::test]
async fn a_run_adds_a_record_and_finds_it_on_acmes_own_domain() {
    let token = salesforce_answering(Canned::json(&json!({ "access_token": SHORT_TOKEN }))).await;
    let site = domain_answering().await;
    let stack = Stack::start(
        profile(&token)
            .with("OUTBOUND_DELIVERY_CA_FILE", site.authority_file())
            .with("SALESFORCE_SITES", &site.host_and_port()),
    )
    .await
    .expect("the stack starts");
    let world = World::new(&stack).await;
    let origin = site.url_on(&stack, "");

    let account = account_at(&world, "salesforce", &grant_for(&origin)).await;
    let probe = site.received_at("GET", OBJECTS);
    assert_eq!(probe.len(), 1, "the account was tried once");
    assert_eq!(
        probe[0].header("authorization"),
        Some(format!("Bearer {SHORT_TOKEN}").as_str())
    );

    ran(&world, account_and_query_graph(&account), "succeeded").await;

    let adds = site.received_at("POST", ACCOUNTS);
    assert_eq!(adds.len(), 1, "one account was added");
    assert_eq!(adds[0].json(), json!({ "Name": "Acme Bakery" }));
    assert_eq!(
        adds[0].header("authorization"),
        Some(format!("Bearer {SHORT_TOKEN}").as_str())
    );
    let queries = site.received_at("GET", QUERY);
    assert_eq!(queries.len(), 1, "the query ran once");
    assert_eq!(
        queries[0].query_pairs(),
        [("q".to_owned(), SOQL.to_owned())]
    );
    for arrival in site.received() {
        no_secret_leaked(&arrival.body, &[GRANT, "acme salesforce app words"]);
        no_secret_leaked(
            arrival.header("authorization").unwrap_or_default(),
            &[GRANT],
        );
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// The SOQL the workflow runs.
const SOQL: &str = "SELECT Id FROM Account WHERE Name = 'Acme Bakery'";

/// A stand-in for Acme's REST API on its own domain.
async fn domain_answering() -> OutsideReceiver {
    OutsideReceiver::start(
        "acme.salesforce.example",
        [
            (OBJECTS, Canned::json(&json!({ "sobjects": [] }))),
            (
                ACCOUNTS,
                Canned::json(&json!({ "id": "001xx000003DGb2AAG", "success": true })),
            ),
            (
                QUERY,
                Canned::json(
                    &json!({ "totalSize": 1, "records": [{ "Id": "001xx000003DGb2AAG" }] }),
                ),
            ),
        ],
    )
    .await
}

/// The workflow adds a Salesforce account, then finds it with SOQL.
fn account_and_query_graph(account: &str) -> Graph {
    let add = action(
        Action {
            integration: "salesforce",
            operation: "create-record",
        },
        account,
        "write",
        vec![
            ("object", written("Account")),
            ("fields", written(json!({ "Name": "Acme Bakery" }))),
        ],
    );
    let query = action(
        Action {
            integration: "salesforce",
            operation: "query",
        },
        account,
        "read",
        vec![("soql", written(SOQL))],
    );
    chain(vec![add, query])
}
