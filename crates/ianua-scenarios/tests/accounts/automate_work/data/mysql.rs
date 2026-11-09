//! MySQL: Acme's own MySQL refuses any connection without TLS and serves
//! a certificate from Acme's own authority. Pat's run reads its orders
//! through TLS checked against that authority; a query that tries to
//! delete them is refused by MySQL itself, inside a read-only transaction.

use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::systems::{self, Serving};
use ianua_scenarios::wire::workflows::Graph;
use ianua_scenarios::world::World;
use serde_json::json;

use super::{failed_reading_nothing, opened_over_tls, reaching, run_as_pat, step_output};
use crate::support::pat;

/// A graph querying the orders on `route` with `statement`.
fn querying(route: &str, statement: &str) -> Graph {
    reaching(
        "mysql",
        "query",
        route,
        &[
            ("statement", json!(statement)),
            ("parameters", json!([100])),
            ("database", json!("acme")),
        ],
    )
}

/// Pat's run reads the orders over 100 from Acme's MySQL as Pat, over TLS.
/// A query that would delete them fails, and both orders are still there
/// for the next read.
#[tokio::test]
async fn pat_s_run_reads_mysql_over_tls_and_writes_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let orders = systems::mysql(Serving::Tls(super::SERVER_NAME)).await;
    let mut pat = pat(&world).await;
    let route = opened_over_tls(&world, &orders).await;
    let reading = "select id, total from orders where total > ? order by id";

    let read = run_as_pat(&world, &mut pat, querying(&route, reading), "succeeded").await;
    let deleting = querying(&route, "delete from orders where total > ?");
    let refused = run_as_pat(&world, &mut pat, deleting, "failed").await;
    let after = run_as_pat(&world, &mut pat, querying(&route, reading), "succeeded").await;

    assert_eq!(
        step_output(&read)["rows"],
        json!([{"id": 2, "total": 120}, {"id": 3, "total": 300}])
    );
    assert!(failed_reading_nothing(&refused), "the delete failed");
    assert_eq!(step_output(&after)["row_count"], 2, "no order was removed");

    stack.stop().await.expect("the stack stops cleanly");
}
