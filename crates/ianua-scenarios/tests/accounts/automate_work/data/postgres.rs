//! Postgres: a workflow reads Acme's orders database as Pat. The rows come
//! back; a query that tries to change them is refused by the database
//! itself; a route left closed, and a person the route does not let in,
//! reach nothing. A login asking for TLS never speaks to a database
//! without it, and reads one serving it.

use ianua_scenarios::actors::Person;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::systems::{self, Serving};
use ianua_scenarios::wire::routing::WorkflowLogin;
use ianua_scenarios::wire::workflows::Graph;
use ianua_scenarios::world::World;
use serde_json::{Value, json};

use super::{
    data_route, failed_reading_nothing, open, opened_over_tls, reaching, run_as_pat, step_output,
};
use crate::support::pat;

/// The reader login's password: words, not a key.
const READER_PASSWORD: &str = "orders reader password";

/// Acme's orders database in the stack's own test database: its stream
/// route, and the table and reader login made for this scenario.
struct OrdersDatabase {
    route_id: String,
    database: String,
    table: String,
    reader: String,
}

/// Acme's orders database, with three orders and a login that may only
/// read them, behind a stream route letting in people as `access` says.
async fn orders_database(world: &World<'_>, access: Value) -> OrdersDatabase {
    let stack = world.stack();
    let suffix = uuid::Uuid::new_v4().simple().to_string()[..12].to_owned();
    let table = format!("acme_orders_{suffix}");
    let reader = format!("orders_reader_{suffix}");
    let company = stack.company_database();
    stack
        .as_database_owner(&format!(
            "CREATE ROLE {reader} LOGIN PASSWORD '{READER_PASSWORD}';
             CREATE TABLE {table} (id integer PRIMARY KEY, total integer NOT NULL);
             INSERT INTO {table} VALUES (1, 40), (2, 120), (3, 300);
             GRANT USAGE ON SCHEMA public TO {reader};
             GRANT SELECT ON {table} TO {reader};"
        ))
        .await;
    let route_id = data_route(world, &company.host, company.port, access).await;
    OrdersDatabase {
        route_id,
        database: company.name,
        table,
        reader,
    }
}

/// The reader login of `database`, over a connection protected as `tls`
/// says.
fn reader_login(database: &OrdersDatabase, tls: Option<&str>) -> WorkflowLogin {
    WorkflowLogin {
        login_user: database.reader.clone(),
        login_password: READER_PASSWORD.to_owned(),
        tls: tls.map(str::to_owned),
        tls_authority: None,
        tls_server_name: None,
    }
}

/// Tess opens `database` to workflows with its reader login, without TLS:
/// the stack's test database serves none.
async fn open_in_the_clear(world: &World<'_>, database: &OrdersDatabase) {
    open(
        world,
        &database.route_id,
        reader_login(database, Some("off")),
    )
    .await;
}

/// A graph querying `database` with `statement` and `parameters`.
fn querying(database: &OrdersDatabase, statement: &str, parameters: Value) -> Graph {
    reaching(
        "postgres",
        "query",
        &database.route_id,
        &[
            ("statement", json!(statement)),
            ("parameters", parameters),
            ("database", json!(database.database)),
        ],
    )
}

/// The orders over 100 in Acme's database, as the query reads them.
fn over_100(database: &OrdersDatabase) -> Graph {
    let statement = format!(
        "select id, total from {} where total > $1 order by id",
        database.table
    );
    querying(database, &statement, json!([100]))
}

/// Pat, and a stack with Acme's orders database letting in everyone signed
/// in.
async fn acme(world: &World<'_>) -> (OrdersDatabase, Person) {
    let database = orders_database(world, json!({"people": "Authenticated"})).await;
    (database, pat(world).await)
}

/// Tess opens the orders database to workflows; it is the one database
/// the builder is offered. Pat's run reads the orders over 100 as Pat:
/// both rows come back, with their values bound apart from the statement,
/// and the opening is recorded naming the login's user, never its
/// password.
#[tokio::test]
async fn pat_s_run_reads_the_orders_database_as_pat() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let (database, mut pat) = acme(&world).await;

    open_in_the_clear(&world, &database).await;
    let offered = ianua_scenarios::api::workflows::data(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let run = run_as_pat(&world, &mut pat, over_100(&database), "succeeded").await;

    assert_eq!(offered.len(), 1, "the one open database is offered");
    assert_eq!(offered[0].id, database.route_id);
    let output = step_output(&run);
    assert_eq!(output["row_count"], 2);
    assert_eq!(output["truncated"], false);
    assert_eq!(
        output["rows"],
        json!([{"id": 2, "total": 120}, {"id": 3, "total": 300}])
    );
    assert_eq!(
        world
            .trail()
            .count("routing.stream_route_opened_to_workflows")
            .await,
        1
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// A query step cannot delete orders through the reader login. The step
/// fails without output, and the next read still returns both orders over 100.
#[tokio::test]
async fn a_query_that_writes_is_refused_by_the_database() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let (database, mut pat) = acme(&world).await;
    open_in_the_clear(&world, &database).await;
    let deleting = format!("delete from {} where id > $1", database.table);

    let refused = run_as_pat(
        &world,
        &mut pat,
        querying(&database, &deleting, json!([0])),
        "failed",
    )
    .await;
    let after = run_as_pat(&world, &mut pat, over_100(&database), "succeeded").await;

    assert!(failed_reading_nothing(&refused), "the delete failed");
    assert_eq!(step_output(&after)["row_count"], 2, "no order was removed");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat's query fails without reading anything while Acme's orders database
/// remains closed to workflows.
#[tokio::test]
async fn a_stream_route_closed_to_workflows_refuses_the_run() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let (database, mut pat) = acme(&world).await;

    let run = run_as_pat(&world, &mut pat, over_100(&database), "failed").await;

    assert!(
        failed_reading_nothing(&run),
        "the query failed and read nothing"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The orders database requires `orders:read`, which Pat does not hold.
/// Opening it to workflows still leaves Pat's query refused without output.
#[tokio::test]
async fn the_route_s_own_access_decides_for_the_run_s_person() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let declared: ianua_scenarios::api::Request<Value> = ianua_scenarios::api::Request::of(
        ianua_scenarios::net::Call::post(world.tenant().at("/resource-types")).json(&json!({
            "key": "orders",
            "display_name": "Orders",
            "actions": [{"key": "read", "display_name": "Read", "implies": []}],
            "data_class": "Internal",
        })),
    );
    declared.send(world.admin().client()).await.ok();
    let access =
        json!({"people": {"RequireCustomPermission": [{"resource": "orders", "action": "read"}]}});
    let database = orders_database(&world, access).await;
    let mut pat = pat(&world).await;
    open_in_the_clear(&world, &database).await;

    let run = run_as_pat(&world, &mut pat, over_100(&database), "failed").await;

    assert!(
        failed_reading_nothing(&run),
        "the query was refused and read nothing"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess opens the orders database with TLS required, but the database
/// serves none. Pat's query fails without output rather than reading over
/// an unencrypted connection.
#[tokio::test]
async fn a_login_requiring_tls_never_speaks_in_the_clear() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let (database, mut pat) = acme(&world).await;
    open(&world, &database.route_id, reader_login(&database, None)).await;

    let run = run_as_pat(&world, &mut pat, over_100(&database), "failed").await;

    assert!(
        failed_reading_nothing(&run),
        "the query failed and read nothing"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Acme's own Postgres serves TLS with a certificate from Acme's own
/// authority for `orders.acme.test`. Tess opens it naming both; Pat's run
/// reads the orders over 100 through TLS from the worker to the database.
#[tokio::test]
async fn pat_s_run_reads_a_database_over_tls() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let orders = systems::postgres(Serving::Tls(super::SERVER_NAME)).await;
    let mut pat = pat(&world).await;
    let route = opened_over_tls(&world, &orders).await;

    let run = run_as_pat(&world, &mut pat, tls_order_query(&route), "succeeded").await;

    assert_eq!(
        step_output(&run)["rows"],
        json!([{"id": 2, "total": 120}, {"id": 3, "total": 300}])
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The TLS database query binds the threshold separately from its ordered row selection.
fn tls_order_query(route: &str) -> Graph {
    reaching(
        "postgres",
        "query",
        route,
        &[
            (
                "statement",
                json!("select id, total from orders where total > $1 order by id"),
            ),
            ("parameters", json!([100])),
            ("database", json!("postgres")),
        ],
    )
}
