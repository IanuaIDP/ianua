//! MongoDB: Acme's own MongoDB serves a certificate from Acme's own
//! authority. Pat's run finds the large orders through TLS checked against
//! that authority, laid over the connection by the worker itself; an
//! aggregate that would copy the orders out with `$out` is refused.

use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::systems::{self, Serving};
use ianua_scenarios::wire::workflows::Graph;
use ianua_scenarios::world::World;
use serde_json::json;

use super::{failed_reading_nothing, opened_over_tls, reaching, run_as_pat, step_output};
use crate::support::pat;

/// Pat's run finds the orders over 100 as Pat, over TLS, sorted by id. An
/// aggregate copying every order to another collection fails.
#[tokio::test]
async fn pat_s_run_finds_in_mongodb_over_tls_and_copies_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let orders = systems::mongodb(Serving::Tls(super::SERVER_NAME)).await;
    let mut pat = pat(&world).await;
    let route = opened_over_tls(&world, &orders).await;
    let finding = find_large_orders(&route);
    let copying = copy_orders(&route);
    let found = run_as_pat(&world, &mut pat, finding, "succeeded").await;
    let refused = run_as_pat(&world, &mut pat, copying, "failed").await;

    assert_eq!(
        step_output(&found)["documents"],
        json!([{"_id": 2, "total": 120}, {"_id": 3, "total": 300}])
    );
    assert!(failed_reading_nothing(&refused), "the copy was refused");

    stack.stop().await.expect("the stack stops cleanly");
}

/// The read finds orders over one hundred in their id order.
fn find_large_orders(route: &str) -> Graph {
    reaching(
        "mongodb",
        "find",
        route,
        &[
            ("database", json!("acme")),
            ("collection", json!("orders")),
            ("filter", json!(r#"{"total": {"$gt": 100}}"#)),
            ("sort", json!(r#"{"_id": 1}"#)),
        ],
    )
}

/// An aggregate attempts to copy every order into another collection.
fn copy_orders(route: &str) -> Graph {
    reaching(
        "mongodb",
        "aggregate",
        route,
        &[
            ("database", json!("acme")),
            ("collection", json!("orders")),
            ("pipeline", json!(r#"[{"$match": {}}, {"$out": "copied"}]"#)),
        ],
    )
}
