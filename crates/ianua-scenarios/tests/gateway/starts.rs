//! The gateway starts beside the platform: its status listener says it
//! holds every tenant's configuration and reaches the database, the bus
//! and the cache; a visitor asking for a host no tenant serves is refused
//! over TLS from the platform's own certificate; and the whole stack stops
//! cleanly.

use ianua_scenarios::expect::eventually;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use serde::de::IgnoredAny;

/// The gateway starts and is ready once its first full read of every
/// tenant is done. A visitor asks for a host under the apps domain that no
/// tenant serves: the gateway answers over TLS that it serves nothing
/// there, forwarding to nobody. The stack stops cleanly.
#[tokio::test]
async fn the_gateway_starts_ready_and_stops_cleanly() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let status = format!("http://{}/health/ready", stack.gateway_status());
    eventually("the gateway to be ready", || async {
        let ready = reqwest::get(&status).await.ok()?;
        (ready.status() == Status::OK).then_some(())
    })
    .await;
    let visitor = Client::new(&stack, "a visitor").expect("a client for a visitor");

    let nowhere = format!("https://nobody-here.{}/", stack.apps_domain());
    let answer = visitor.get::<IgnoredAny>(&nowhere).await;
    assert_eq!(
        answer.status(),
        Status::NOT_FOUND,
        "a host no tenant serves is answered with nothing served there: {}",
        answer.summary()
    );

    stack.stop().await.expect("the stack stops cleanly");
}
