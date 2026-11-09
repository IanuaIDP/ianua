//! The cache server the cache adapters' tests run against, started once
//! for the run by the `cache` setup script.

use std::time::Duration;

use crate::cache::ServerState;
use crate::namespace::Namespace;

/// State on the test cache server, under the default namespace.
///
/// # Panics
///
/// When the setup script did not run or the server does not answer: no
/// cache test can go on without it.
pub async fn test_server() -> ServerState {
    test_server_in(&Namespace::default()).await
}

/// State on the test cache server, every key under `namespace`.
///
/// # Panics
///
/// When the setup script did not run or the server does not answer: no
/// cache test can go on without it.
pub async fn test_server_in(namespace: &Namespace) -> ServerState {
    let port = std::env::var("IANUA_TEST_CACHE_PORT")
        .expect("the cache setup script names the test cache's port");
    ServerState::connect(
        &format!("redis://127.0.0.1:{port}"),
        namespace,
        Duration::from_secs(2),
    )
    .await
    .expect("the test cache answers")
}
