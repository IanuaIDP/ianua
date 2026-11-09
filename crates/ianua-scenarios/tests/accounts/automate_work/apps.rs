//! Protected apps: a workflow calls Acme's orders app behind the gateway
//! as Pat, the person the run acts for, on a route Tess opened to
//! workflows. The app sees Pat, signed for it by the gateway, and never the
//! pass the call carried. A route left closed, a person the route's policy
//! does not let in, and anything but a pass on the workflow listener reach
//! the app not at all.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{Request, routing, workflows};
use ianua_scenarios::expect::eventually;
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::routes::{AppliedRoute, Placement, RouteSpec};
use ianua_scenarios::stack::{Presenting, Profile, Stack};
use ianua_scenarios::upstreams::{AssertionCheck, Echo};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::routing::{CustomPermission, RouteChange, RoutePolicy};
use ianua_scenarios::wire::workflows::{
    Execution, Graph, MappedField, Node, StartExecution, Step, Trigger,
};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{drafted, ended, pat, published, written};

/// The key of the step that reads the orders app.
const READ_STEP: &str = "read-order";

/// Acme's orders app behind the gateway, and the app itself, which keeps
/// every request forwarded to it.
struct OrdersApp {
    route: AppliedRoute,
    upstream: Echo,
    host: String,
}

/// Tess prepares the orders app at the chosen path, asking its policy of every caller.
async fn orders_app(world: &World<'_>, policy: RoutePolicy, path: &str) -> OrdersApp {
    let names = routing::hostnames(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let host = names.slug_subdomain.unwrap_or(names.uuid_subdomain);
    let upstream = Echo::start(world.stack(), &host)
        .await
        .expect("the orders app starts");
    let probe = Client::new(world.stack(), "a visitor of the orders app").expect("a client");
    let route = RouteSpec::public("orders-app", path)
        .asking(policy)
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
    OrdersApp {
        route,
        upstream,
        host,
    }
}

/// Publishes the final path after workflow access is set and waits for that route row.
/// The unauthenticated probe reaches no upstream and cannot succeed on the old path.
async fn publish_orders_path(world: &World<'_>, app: &OrdersApp) {
    let change = RouteChange {
        path_pattern: Some("/orders/*".to_owned()),
        ..RouteChange::default()
    };
    routing::change_route(world.tenant(), &app.route.route_id, &change)
        .send(world.admin().client())
        .await
        .ok();
    let probe =
        Client::new(world.stack(), "a visitor awaiting the orders route").expect("a client");
    let url = format!("https://{}/orders/probe", app.host);
    eventually("the gateway to serve the final orders route", || async {
        let answer = probe
            .attempt::<serde::de::IgnoredAny>(Call::get(url.as_str()))
            .await
            .ok()?;
        (answer.status() == Status::UNAUTHORIZED).then_some(())
    })
    .await;
}

/// A graph of one step reading order 7 from the orders app's route as the
/// run's person.
fn reading_order(route_id: &str) -> Graph {
    Graph {
        nodes: vec![Node {
            key: READ_STEP.to_owned(),
            name: "Read the order".to_owned(),
            step: Step::Action {
                integration: "apps".to_owned(),
                operation: "get".to_owned(),
                account_id: None,
                effect: "read".to_owned(),
                ceiling: "internal".to_owned(),
                inputs: vec![
                    MappedField {
                        field: "route".to_owned(),
                        source: written(route_id),
                    },
                    MappedField {
                        field: "path".to_owned(),
                        source: written("/orders/7"),
                    },
                ],
            },
        }],
        edges: vec![],
    }
}

/// Tess drafts the order read on `app`, Ann publishes it, Pat starts a run
/// and it ends as `expected` says.
async fn run_as_pat(
    world: &World<'_>,
    pat: &mut Person,
    app: &OrdersApp,
    expected: &str,
) -> Execution {
    let draft = drafted(world, Trigger::Manual, reading_order(&app.route.route_id)).await;
    let workflow = published(world, &draft).await;
    let start = StartExecution {
        input: json!({}),
        exposure: "internal".to_owned(),
    };
    let started = pat
        .send(workflows::start(world.tenant(), &workflow.id, &start))
        .await
        .ok();
    ended(world, &started.execution_id, expected).await
}

/// Tess opens the orders app to workflows; it is the one app the builder is
/// offered. Pat's run reads order 7 as Pat: the app sees one request on
/// `/orders/7`, the gateway's signed assertion naming Pat, and no
/// authorization header; the opening is recorded.
#[tokio::test]
async fn pat_s_run_reads_the_orders_app_as_pat() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let app = orders_app(&world, RoutePolicy::Authenticated, "/preparing-orders/*").await;
    let mut pat = pat(&world).await;

    routing::open_route_to_workflows(world.tenant(), &app.route.route_id)
        .send(world.admin().client())
        .await
        .ok();
    let offered = workflows::apps(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    publish_orders_path(&world, &app).await;
    run_as_pat(&world, &mut pat, &app, "succeeded").await;

    assert_eq!(offered.len(), 1, "the one open app is offered");
    assert_eq!(offered[0].id, app.route.route_id);
    check_pat_arrived(&app, &pat);
    assert_eq!(
        world
            .trail()
            .count("routing.route_opened_to_workflows")
            .await,
        1
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The app receives one request naming Pat through a signed assertion and no run pass.
fn check_pat_arrived(app: &OrdersApp, pat: &Person) {
    let arrivals = app.upstream.arrivals();
    assert_eq!(arrivals.len(), 1, "the app was called once");
    assert_eq!(arrivals[0].path, "/orders/7");
    assert!(
        !arrivals[0].has_header("authorization"),
        "the pass never reaches the app"
    );
    let AssertionCheck::Verified { caller } = &arrivals[0].assertion else {
        panic!("the gateway signed who the caller is");
    };
    assert_eq!(caller.kind, "user");
    assert!(caller.sub.contains(pat.id()), "the app sees Pat");
}

/// Pat's workflow read fails while Acme's orders app remains closed to
/// workflows, and no request reaches the app.
#[tokio::test]
async fn a_route_closed_to_workflows_refuses_the_run_s_call() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let app = orders_app(&world, RoutePolicy::Authenticated, "/orders/*").await;
    let mut pat = pat(&world).await;

    let run = run_as_pat(&world, &mut pat, &app, "failed").await;

    assert!(
        run.steps
            .iter()
            .any(|step| step.key == READ_STEP && step.phase == "failed"),
        "the read failed"
    );
    assert!(
        app.upstream.arrivals().is_empty(),
        "the app was not reached"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess declares the orders read permission and requires it on the route.
async fn orders_read_policy(world: &World<'_>) -> RoutePolicy {
    let declared: Request<serde_json::Value> = Request::of(
        Call::post(world.tenant().at("/resource-types")).json(&json!({
            "key": "orders",
            "display_name": "Orders",
            "actions": [{"key": "read", "display_name": "Read", "implies": []}],
            "data_class": "Internal",
        })),
    );
    declared.send(world.admin().client()).await.ok();
    RoutePolicy::RequireCustomPermission(vec![CustomPermission {
        resource: "orders".to_owned(),
        action: "read".to_owned(),
    }])
}

/// Tess requires `orders:read` for the orders app, and Pat does not hold it.
/// The open route refuses Pat's run with 403 without reaching the app.
#[tokio::test]
async fn the_app_s_own_policy_decides_for_the_run_s_person() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let policy = orders_read_policy(&world).await;
    let app = orders_app(&world, policy, "/preparing-orders/*").await;
    let mut pat = pat(&world).await;
    routing::open_route_to_workflows(world.tenant(), &app.route.route_id)
        .send(world.admin().client())
        .await
        .ok();

    publish_orders_path(&world, &app).await;
    let run = run_as_pat(&world, &mut pat, &app, "failed").await;

    check_orders_forbidden(&run);
    assert!(
        app.upstream.arrivals().is_empty(),
        "the app was not reached"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The read step records the gateway's authorization refusal rather than a bad credential.
fn check_orders_forbidden(run: &Execution) {
    let step = run
        .steps
        .iter()
        .find(|step| step.key == READ_STEP)
        .expect("the read step is recorded");
    assert_eq!(step.phase, "failed");
    let failure = step
        .failure
        .as_ref()
        .expect("the read explains its refusal");
    assert_eq!(failure.code, "reported");
    assert_eq!(failure.detail, "the address answered 403");
}

/// Mallory cannot call the workflow listener from inside the network. With
/// no certificate of the platform's, the handshake refuses her before any
/// request is read; plain HTTP gets no answer at all. Even with the
/// worker's own certificate, no pass and a made-up token are refused.
/// None of it reaches the orders app.
#[tokio::test]
async fn the_workflow_listener_takes_nothing_but_a_pass() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let app = orders_app(&world, RoutePolicy::Authenticated, "/orders/*").await;
    routing::open_route_to_workflows(world.tenant(), &app.route.route_id)
        .send(world.admin().client())
        .await
        .ok();
    refuse_listener_credentials(&stack).await;
    assert!(
        app.upstream.arrivals().is_empty(),
        "the app was not reached"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The listener refuses absent client certificates, cleartext calls and missing or forged run passes.
async fn refuse_listener_credentials(stack: &Stack) {
    let listener = format!("https://{}/orders/7", stack.gateway_workflows());
    let in_clear = format!("http://{}/orders/7", stack.gateway_workflows());
    let stranger = stack.internal_client(Presenting::Nothing);
    let worker = stack.internal_client(Presenting::WorkersCertificate);

    let without_certificate = stranger.get(&listener).send().await;
    let plain = reqwest::Client::new().get(&in_clear).send().await;
    let bare = worker.get(&listener).send().await.expect("an answer");
    let made_up = worker
        .get(&listener)
        .bearer_auth("a.made-up.token")
        .send()
        .await
        .expect("an answer");

    assert!(
        without_certificate.is_err(),
        "no handshake without a certificate"
    );
    assert!(plain.is_err(), "no answer in the clear");
    assert_eq!(bare.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(made_up.status(), reqwest::StatusCode::UNAUTHORIZED);
}
