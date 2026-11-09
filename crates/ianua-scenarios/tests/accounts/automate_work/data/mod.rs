//! Protected data: a workflow reaches Acme's own databases behind the
//! gateway as Pat, the person the run acts for, through a stream route Tess
//! opened to workflows with a login of the database. Each kind of database
//! has its own file; what they share is here.
//!
//! - `postgres`: rows come back, a query that writes is refused by the
//!   database itself, a closed route or one Pat may not use reads nothing,
//!   and a login asking for TLS refuses a database without it and reads
//!   one serving it.
//! - `mysql`, `redis`, `mongodb`: each read over TLS checked against the
//!   database's own authority, each refusing a read that would write.

mod mongodb;
mod mysql;
mod postgres;
mod redis;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{routing, workflows};
use ianua_scenarios::systems::{CompanySystem, LOGIN_PASSWORD};
use ianua_scenarios::wire::routing::{NewStreamRoute, StreamBackend, WorkflowLogin};
use ianua_scenarios::wire::workflows::{
    Execution, Graph, MappedField, Node, StartExecution, Step, Trigger,
};
use ianua_scenarios::world::World;
use serde_json::{Value, json};

use crate::support::{drafted, ended, published, written};

/// The key of the step that reaches the database.
pub(crate) const DATA_STEP: &str = "reach-orders";

/// The name the TLS databases' certificates are for: not the address the
/// gateway dials, so the login names it.
pub(crate) const SERVER_NAME: &str = "orders.acme.test";

/// A stream route to the database at `host` and `port`, letting in people
/// as `access` says; its id.
pub(crate) async fn data_route(world: &World<'_>, host: &str, port: u16, access: Value) -> String {
    routing::create_stream_route(
        world.tenant(),
        &NewStreamRoute {
            name: "orders-db".to_owned(),
            protocol: "tcp".to_owned(),
            listen_port: free_port(),
            policy: "tunnel".to_owned(),
            access,
            backends: vec![StreamBackend {
                host: host.to_owned(),
                port,
                weight: 1,
            }],
        },
    )
    .send(world.admin().client())
    .await
    .ok()
    .id
}

/// A loopback port nothing listens on now, for the stream route to claim.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .expect("a loopback port is free")
}

/// A route to `system`, letting in everyone signed in, opened to
/// workflows with its login over TLS checked against its own authority
/// and [`SERVER_NAME`]; the route's id.
pub(crate) async fn opened_over_tls(world: &World<'_>, system: &CompanySystem) -> String {
    let route = data_route(
        world,
        "127.0.0.1",
        system.port(),
        json!({"people": "Authenticated"}),
    )
    .await;
    open(
        world,
        &route,
        WorkflowLogin {
            login_user: system.user().to_owned(),
            login_password: LOGIN_PASSWORD.to_owned(),
            tls: None,
            tls_authority: system.authority_pem().map(str::to_owned),
            tls_server_name: Some(SERVER_NAME.to_owned()),
        },
    )
    .await;
    route
}

/// Tess opens `route` to workflows with `login`.
pub(crate) async fn open(world: &World<'_>, route: &str, login: WorkflowLogin) {
    routing::open_stream_route_to_workflows(world.tenant(), route, &login)
        .send(world.admin().client())
        .await
        .ok();
}

/// A graph of one step calling `operation` of `integration` on `route`
/// with `inputs`, as the run's person.
pub(crate) fn reaching(
    integration: &str,
    operation: &str,
    route: &str,
    inputs: &[(&str, Value)],
) -> Graph {
    let mut fields = vec![MappedField {
        field: "route".to_owned(),
        source: written(route),
    }];
    fields.extend(inputs.iter().map(|(field, value)| MappedField {
        field: (*field).to_owned(),
        source: written(value.clone()),
    }));
    Graph {
        nodes: vec![Node {
            key: DATA_STEP.to_owned(),
            name: "Reach the orders".to_owned(),
            step: Step::Action {
                integration: integration.to_owned(),
                operation: operation.to_owned(),
                account_id: None,
                effect: effect_of(operation).to_owned(),
                ceiling: "internal".to_owned(),
                inputs: fields,
            },
        }],
        edges: vec![],
    }
}

/// The effect a builder declares for `operation`.
fn effect_of(operation: &str) -> &'static str {
    match operation {
        "query" | "read" | "find" | "aggregate" => "read",
        _ => "write",
    }
}

/// Tess drafts `graph`, Ann publishes it, Pat starts a run and it ends as
/// `expected` says.
pub(crate) async fn run_as_pat(
    world: &World<'_>,
    pat: &mut Person,
    graph: Graph,
    expected: &str,
) -> Execution {
    let draft = drafted(world, Trigger::Manual, graph).await;
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

/// The output of the data step of `run`.
pub(crate) fn step_output(run: &Execution) -> Value {
    run.steps
        .iter()
        .find(|step| step.key == DATA_STEP)
        .and_then(|step| step.output.clone())
        .expect("the data step gave its output")
}

/// Whether the data step of `run` failed and read nothing.
pub(crate) fn failed_reading_nothing(run: &Execution) -> bool {
    run.steps
        .iter()
        .any(|step| step.key == DATA_STEP && step.phase == "failed" && step.output.is_none())
}
