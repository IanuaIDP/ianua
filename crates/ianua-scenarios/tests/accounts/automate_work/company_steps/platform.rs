//! Company steps about the platform itself: Pat's workflow asks for a
//! sealed audit pack of Acme's invitations, which an auditor checks with
//! nothing but Acme's published keys, and searches the trail for them;
//! another classifies card numbers and closes the orders app to
//! workflows, each once Bea and Cal say yes.

use ianua_scenarios::api::{audit, classification, oauth, routing, workflows};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{eventually, verified_rs256};
use ianua_scenarios::net::Client;
use ianua_scenarios::routes::{Placement, RouteSpec};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::audit::AuditExport;
use ianua_scenarios::wire::routing::RoutePolicy;
use ianua_scenarios::wire::workflows::Graph;
use ianua_scenarios::world::World;
use serde_json::Value;

use super::{TwoApprovers, company_step, in_order, output, started_by, through_run, yes};
use crate::support::{ended, invited, written};

/// The type a seal carries, so no token passes for one.
const SEAL_TYPE: &str = "ianua-audit-seal+jwt";

/// The records the pack and the search are about.
const INVITATIONS: &str = "identity.user_invited";

/// The key of the step asking for the pack.
const PACK_STEP: &str = "pack";

/// The key of the step searching the trail.
const SEARCH_STEP: &str = "search";

/// The key of the first approval in a run.
const FIRST_YES: &str = "first-yes";

/// The key of the second approval in a run.
const SECOND_YES: &str = "second-yes";

/// The field the classifying step names.
const CARD_FIELD: &str = "orders.card_last4";

/// What Pat may do when she reads and exports the audit trail.
const AUDITS: &[(&str, &str)] = &[
    ("Workflows", "View"),
    ("Workflows", "Run"),
    ("AuditLog", "View"),
    ("AuditLog", "Export"),
];

/// What Pat may do when she runs the incident desk: classify data and
/// manage routes.
const RUNS_INCIDENTS: &[(&str, &str)] = &[
    ("Workflows", "View"),
    ("Workflows", "Run"),
    ("Classification", "Manage"),
    ("Routing", "Manage"),
];

/// Ask for a JSON pack of the invitations of the last hour, then search
/// the trail for them.
fn packing_and_searching() -> Graph {
    in_order(vec![
        company_step(
            PACK_STEP,
            "make-audit-pack",
            "read",
            vec![
                ("what", written(INVITATIONS)),
                ("since", written("hour")),
                ("format", written("json")),
            ],
        ),
        company_step(
            SEARCH_STEP,
            "search-audit",
            "read",
            vec![("what", written(INVITATIONS)), ("since", written("hour"))],
        ),
    ])
}

/// Pat may read and export the trail. Her workflow asks for a pack of the
/// last hour's invitations and searches the trail for them. The search
/// finds Pat's and Lee's invitations; the worker writes and seals the
/// pack, and an auditor checks the seal against Acme's published keys: it
/// names the pack, its JSON and how many records it holds. The trail says
/// Pat asked for the pack, through the run.
#[tokio::test]
async fn pat_s_run_makes_a_sealed_audit_pack_an_auditor_checks() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Auditor"), AUDITS).await;
    invited(&world, ("lee", "Lee Lost"), &[("Workflows", "View")]).await;

    let execution_id = started_by(&world, &mut pat, packing_and_searching()).await;
    let finished = ended(&world, &execution_id, "succeeded").await;

    let pack = output(&finished, PACK_STEP);
    assert_eq!(pack["status"], "pending");
    let export_id = pack["export_id"]
        .as_str()
        .expect("the pack names its export");
    let ready = written_pack(&world, export_id).await;
    let claims = checked_seal(&world, &ready).await;
    assert_eq!(claims["jti"], export_id, "the seal names the pack");
    assert_eq!(claims["audit_export"]["format"], "json");
    assert_eq!(
        claims["audit_export"]["rows"],
        ready.rows.expect("a ready pack counts its rows")
    );
    check_search(&output(&finished, SEARCH_STEP));
    through_run(
        &world,
        "tenant.audit_log_export_requested",
        &execution_id,
        pat.email(),
    )
    .await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// The search found at least Pat's and Lee's invitations, and only
/// invitations.
fn check_search(found: &Value) {
    assert!(
        found["count"].as_f64().is_some_and(|count| count >= 2.0),
        "{found}"
    );
    let records = found["records"]
        .as_array()
        .expect("the search lists records");
    assert!(
        records
            .iter()
            .all(|record| record["event_type"] == INVITATIONS),
        "{found}"
    );
}

/// The pack `export_id`, once the worker has written and sealed it.
async fn written_pack(world: &World<'_>, export_id: &str) -> AuditExport {
    eventually("the worker to write and seal the pack", || async {
        let standing = audit::tenant_export(world.tenant(), export_id)
            .send(world.admin().client())
            .await
            .ok();
        (standing.status == "ready").then_some(standing)
    })
    .await
}

/// The claims of `ready`'s seal, checked as an auditor checks them: against
/// the keys Acme's discovery document points to, issued by Acme.
async fn checked_seal(world: &World<'_>, ready: &AuditExport) -> Value {
    let discovery = oauth::discovery(world.tenant())
        .send(world.anonymous().client())
        .await
        .ok();
    let published = oauth::keys(&discovery.jwks_uri)
        .send(world.anonymous().client())
        .await
        .ok();
    let seal = ready.seal.as_deref().expect("a tenant's pack is sealed");
    let claims =
        verified_rs256(&published, seal, SEAL_TYPE).expect("a published key verifies the seal");
    assert_eq!(
        claims["iss"], discovery.issuer,
        "the seal is issued by Acme"
    );
    claims
}

/// Tess puts Acme's orders app behind the gateway and opens it to
/// workflows; the route's id.
async fn orders_app_open_to_workflows(world: &World<'_>) -> String {
    let names = routing::hostnames(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let host = names.slug_subdomain.unwrap_or(names.uuid_subdomain);
    let upstream = Echo::start(world.stack(), &host)
        .await
        .expect("the orders app starts");
    let probe = Client::new(world.stack(), "a visitor of the orders app").expect("a client");
    let route = RouteSpec::public("orders-app", "/orders/*")
        .asking(RoutePolicy::Authenticated)
        .pinned("orders-app")
        .applied(
            world.admin().client(),
            &probe,
            Placement {
                tenant: world.tenant(),
                upstream: &upstream.url(),
                host: &host,
            },
        )
        .await;
    routing::open_route_to_workflows(world.tenant(), &route.route_id)
        .send(world.admin().client())
        .await
        .ok();
    route.route_id
}

/// Classify card numbers as confidential, then close the app `route_id`
/// to workflows, each once two people say yes.
fn classifying_and_closing(route_id: &str) -> Graph {
    in_order(vec![
        yes(FIRST_YES, "Classify card numbers"),
        company_step(
            "classify",
            "classify-field",
            "admin",
            vec![
                ("field", written(CARD_FIELD)),
                ("level", written("confidential")),
            ],
        ),
        yes(SECOND_YES, "Close the orders app to workflows"),
        company_step(
            "close",
            "close-app",
            "admin",
            vec![("app", written(route_id))],
        ),
    ])
}

/// The orders app is open to workflows. Pat's incident workflow classifies
/// card numbers as confidential and closes the orders app to workflows,
/// each once Bea and Cal say yes. The tenant's rules then hold card
/// numbers, the builder is offered no app, and the trail says Pat did
/// both, through the run.
#[tokio::test]
async fn pat_s_run_classifies_card_numbers_and_closes_the_orders_app() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Responder"), RUNS_INCIDENTS).await;
    let route_id = orders_app_open_to_workflows(&world).await;
    let mut approvers = TwoApprovers::joined(&world).await;

    let execution_id = started_by(&world, &mut pat, classifying_and_closing(&route_id)).await;
    approvers.approve(&world, &execution_id, FIRST_YES).await;
    approvers.approve(&world, &execution_id, SECOND_YES).await;
    ended(&world, &execution_id, "succeeded").await;

    let rules = classification::get(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert!(rules.rules.iter().any(|rule| rule.field_path == CARD_FIELD));
    let offered = workflows::apps(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert!(offered.is_empty(), "no app is open to workflows");
    for change in [
        "proxy.classification_rule_added",
        "routing.route_closed_to_workflows",
    ] {
        through_run(&world, change, &execution_id, pat.email()).await;
    }
    stack.stop().await.expect("the stack stops cleanly");
}
