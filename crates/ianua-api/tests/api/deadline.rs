//! The request deadline: it bounds the handler, never the commit after it.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, deps, router_over};
use ianua_app::ports::runtime::{Settlement, UnitOfWork, UnitWork};
use ianua_assembly::deps::Adapters;
use ianua_domain::shared::errors::DomainError;
use serde_json::json;

/// How long a handler may take in these tests.
const HANDLER_LIMIT: Duration = Duration::from_millis(100);

/// A unit of work whose commit takes longer than a handler may.
struct SlowCommit;

#[async_trait]
impl UnitOfWork for SlowCommit {
    async fn run_apart<'a>(&'a self, work: UnitWork<'a>) -> Result<(), DomainError> {
        self.run(work).await
    }

    async fn run<'a>(&'a self, work: UnitWork<'a>) -> Result<(), DomainError> {
        if work.await == Settlement::Commit {
            tokio::time::sleep(HANDLER_LIMIT * 3).await;
        }
        Ok(())
    }
}

/// A server whose handlers get [`HANDLER_LIMIT`] and whose commits are slow.
fn slow_to_commit() -> TestServer {
    let mut deps = deps(Adapters {
        unit_of_work: Arc::new(SlowCommit),
        ..adapters()
    });
    deps.http.public_listener.timeout = HANDLER_LIMIT;
    TestServer::new(router_over(&deps)).unwrap()
}

/// Ann creates a role. Her handler finishes at once, and the database
/// takes three times the handler's limit to commit it. She is answered
/// `201`, not `504`: the role was kept, and a timeout would have her try
/// again and make it twice.
#[tokio::test]
async fn a_handler_finished_in_time_is_answered_however_long_the_commit_takes() {
    let server = slow_to_commit();

    let response = server
        .post(&format!(
            "/api/v1/organizations/{ORG}/tenants/{TENANT}/authorization/roles"
        ))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "Support"}))
        .await;

    response.assert_status(StatusCode::CREATED);
}
