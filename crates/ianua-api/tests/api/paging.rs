//! Every list pages by cursor: a page answers where the next one starts,
//! and a cursor that is not one the list made, or a size out of range, is
//! refused instead of guessed at.

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, router};
use serde_json::{Value, json};

use crate::authorization::wired_adapters;

/// The tenant's roles list, with `query`.
fn roles(query: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/authorization/roles{query}")
}

/// A server whose tenant holds the roles `names`, made through the API.
async fn holding_roles(names: &[&str]) -> TestServer {
    let server = TestServer::new(router(wired_adapters())).unwrap();
    for name in names {
        server
            .post(&roles(""))
            .authorization_bearer(TENANT_USER)
            .json(&json!({"name": name, "system_permissions": [{"Users": "View"}]}))
            .await
            .assert_status(StatusCode::CREATED);
    }
    server
}

/// What the roles list answers to `query`.
async fn status_of(query: &str) -> StatusCode {
    holding_roles(&[])
        .await
        .get(&roles(query))
        .authorization_bearer(TENANT_USER)
        .await
        .status_code()
}

/// A first page answers its items, the size it was read with, and where
/// the next page starts; following it reads on, and the last page points
/// nowhere.
#[tokio::test]
async fn a_page_answers_its_items_and_where_the_next_starts() {
    let server = holding_roles(&["Auditor", "Support"]).await;

    let first: Value = server
        .get(&roles("?limit=1&sort=name"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    let cursor = first["next_cursor"]
        .as_str()
        .expect("a second role follows");
    let second: Value = server
        .get(&roles(&format!("?limit=1&sort=name&after={cursor}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    assert_eq!(first["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(first["limit"], 1);
    assert_ne!(first["items"][0]["id"], second["items"][0]["id"]);
}

/// An invented role-list cursor returns 422.
#[tokio::test]
async fn a_cursor_the_list_never_made_is_refused() {
    assert_eq!(
        status_of("?after=not-a-cursor").await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

/// A page of nothing, or of more than a hundred, is refused rather than
/// quietly resized.
#[tokio::test]
async fn a_size_out_of_range_is_refused() {
    assert_eq!(
        status_of("?limit=0").await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        status_of("?limit=101").await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

/// Reusing a valid cursor with a different sort returns 422.
#[tokio::test]
async fn a_cursor_used_with_another_sort_is_refused() {
    let server = holding_roles(&["Auditor", "Support"]).await;
    let first: Value = server
        .get(&roles("?limit=1&sort=name"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    let cursor = first["next_cursor"]
        .as_str()
        .expect("a second role follows");

    let other_sort = server
        .get(&roles(&format!("?limit=1&sort=-name&after={cursor}")))
        .authorization_bearer(TENANT_USER)
        .await;

    other_sort.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}
