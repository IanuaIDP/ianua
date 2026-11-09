//! Redis: Acme's own Redis speaks only TLS, with a certificate from Acme's
//! own authority. Pat's run reads the orders' totals through TLS checked
//! against that authority; a read asked to delete a key is refused before
//! Redis is reached; and a login naming another authority reaches nothing.

use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::systems::{self, LOGIN_PASSWORD, Serving, SystemCertificate};
use ianua_scenarios::wire::routing::WorkflowLogin;
use ianua_scenarios::wire::workflows::Graph;
use ianua_scenarios::world::World;
use serde_json::json;

use super::{
    data_route, failed_reading_nothing, open, opened_over_tls, reaching, run_as_pat, step_output,
};
use crate::support::pat;

/// Pat's run reads the totals of orders 2 and 3 as Pat, over TLS. A read
/// asked to delete them fails, and both are still there for the next read.
#[tokio::test]
async fn pat_s_run_reads_redis_over_tls_and_deletes_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let orders = systems::redis(Serving::Tls(super::SERVER_NAME)).await;
    let mut pat = pat(&world).await;
    let route = opened_over_tls(&world, &orders).await;
    let read = run_as_pat(&world, &mut pat, order_totals(&route, "MGET"), "succeeded").await;
    let deleting = order_totals(&route, "DEL");
    let refused = run_as_pat(&world, &mut pat, deleting, "failed").await;
    let after = run_as_pat(&world, &mut pat, order_totals(&route, "MGET"), "succeeded").await;

    assert_eq!(step_output(&read)["result"], json!(["120", "300"]));
    assert!(failed_reading_nothing(&refused), "the delete was refused");
    assert_eq!(step_output(&after)["result"], json!(["120", "300"]));

    stack.stop().await.expect("the stack stops cleanly");
}

/// The Redis read operation targets both order totals with the requested command.
fn order_totals(route: &str, command: &str) -> Graph {
    reaching(
        "redis",
        "read",
        route,
        &[
            ("command", json!(command)),
            ("arguments", json!(["order:2", "order:3"])),
        ],
    )
}

/// Mallory's Redis certificate comes from another authority than the one
/// named in Acme's workflow login. Pat's run fails and reads nothing.
#[tokio::test]
async fn a_certificate_from_another_authority_reaches_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let impostor = systems::redis(Serving::Tls(super::SERVER_NAME)).await;
    let acme_authority = SystemCertificate::for_name(super::SERVER_NAME);
    let mut pat = pat(&world).await;
    let route = data_route(
        &world,
        "127.0.0.1",
        impostor.port(),
        json!({"people": "Authenticated"}),
    )
    .await;
    open(
        &world,
        &route,
        foreign_login(impostor.user(), &acme_authority),
    )
    .await;

    let run = run_as_pat(&world, &mut pat, single_order(&route), "failed").await;

    assert!(failed_reading_nothing(&run), "the read reached nothing");

    stack.stop().await.expect("the stack stops cleanly");
}

/// The login trusts Acme's authority while connecting to the impostor's database.
fn foreign_login(user: &str, acme_authority: &SystemCertificate) -> WorkflowLogin {
    WorkflowLogin {
        login_user: user.to_owned(),
        login_password: LOGIN_PASSWORD.to_owned(),
        tls: None,
        tls_authority: Some(acme_authority.authority_pem().to_owned()),
        tls_server_name: Some(super::SERVER_NAME.to_owned()),
    }
}

/// The certificate refusal attempts to read only order 2 through the configured route.
fn single_order(route: &str) -> Graph {
    reaching(
        "redis",
        "read",
        route,
        &[("command", json!("GET")), ("arguments", json!(["order:2"]))],
    )
}
