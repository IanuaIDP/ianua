//! The platform starts: the API answers through the ingress over TLS, its
//! internal listener says every part it depends on answers, and it stops
//! cleanly.

use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use serde::de::IgnoredAny;

/// The platform starts and is ready: the API answers through the ingress
/// over TLS, and its internal listener says the database, the bus and the
/// cache all answer. It then stops cleanly.
#[tokio::test]
async fn the_platform_starts_ready_and_stops_cleanly() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let visitor = Client::new(&stack, "a visitor").expect("a client for a visitor");

    let health = visitor.get::<IgnoredAny>("/health").await;
    assert_eq!(
        health.status(),
        Status::OK,
        "the API answers through the ingress"
    );

    let ready = reqwest::get(format!("http://{}/health/ready", stack.internal_api()))
        .await
        .expect("the internal listener answers");
    assert_eq!(
        ready.status(),
        Status::OK,
        "the database, the bus and the cache all answer"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
