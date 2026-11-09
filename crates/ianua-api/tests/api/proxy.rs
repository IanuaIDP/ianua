//! The proxy endpoints: pipelines, their stages, canary tokens and WASM
//! modules, the request records the gateway kept and the log targets they
//! are shipped to, and the shape each answers in.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, router};
use ianua_app::test_support::RejectingLimitEnforcer;
use ianua_app::test_support::acting::{FakeTenantAuthorities, Refusal};
use ianua_app::test_support::proxy::{FakeRequestLog, rate_limit_stage, test_request_record};
use ianua_domain::domains::proxy::observation::{
    DecidingRule, DecidingStage, GatewayCheck, RequestOutcome,
};
use serde_json::{Value, json};

/// The test tenant's pipeline address, followed by `rest`.
fn pipelines(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/pipelines{rest}")
}

/// A server over the default fake adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// Ann creates a pipeline and answers with its id.
async fn created_pipeline(server: &TestServer, name: &str) -> String {
    let response = server
        .post(&pipelines(""))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": name}))
        .await;
    response.assert_status(StatusCode::CREATED);
    response.json::<Value>()["id"].as_str().unwrap().to_owned()
}

/// The pipeline with this id, as Ann reads it.
async fn pipeline(server: &TestServer, id: &str) -> Value {
    let response = server
        .get(&pipelines(&format!("/{id}")))
        .authorization_bearer(TENANT_USER)
        .await;
    response.assert_status_ok();
    response.json()
}

/// A new pipeline is a draft running the two mandatory stages, Identity
/// first, each in the shape the dashboard reads.
#[tokio::test]
async fn a_new_pipeline_is_a_draft_with_the_mandatory_stages() {
    let server = server();
    let id = created_pipeline(&server, "edge").await;

    let body = pipeline(&server, &id).await;

    assert_eq!(body["name"], "edge");
    assert_eq!(body["status"], "Draft");
    let stages = body["stages"].as_array().unwrap();
    assert_eq!(stages.len(), 2);
    assert_eq!(stages[0]["kind"], "Identity");
    assert_eq!(stages[1]["kind"], "Policy");
    assert_eq!(stages[0]["mandatory"], true);
    assert_eq!(stages[0]["enabled"], true);
}

/// The listing says how many routes run each pipeline.
#[tokio::test]
async fn the_listing_counts_the_routes_of_each_pipeline() {
    let server = server();
    created_pipeline(&server, "edge").await;

    let response = server
        .get(&pipelines(""))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let listed: Vec<Value> = response.json();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["stage_count"], 2);
    assert_eq!(listed[0]["route_count"], 0);
}

/// Ann renames a pipeline; it reads back under the new name.
#[tokio::test]
async fn a_pipeline_is_renamed() {
    let server = server();
    let id = created_pipeline(&server, "edge").await;

    server
        .patch(&pipelines(&format!("/{id}")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "edge-v2"}))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    assert_eq!(pipeline(&server, &id).await["name"], "edge-v2");
}

/// A stage is appended to the end, and the order is replaced as a whole.
/// Moving it ahead of Policy does not move it: Identity and Policy always
/// run first, so nothing filters traffic before the caller is known.
#[tokio::test]
async fn a_stage_is_added_at_the_end_and_stays_behind_the_mandatory_ones() {
    let server = server();
    let id = created_pipeline(&server, "edge").await;
    let kind = serde_json::to_value(rate_limit_stage(300).kind()).unwrap();

    server
        .post(&pipelines(&format!("/{id}/stages")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"kind": kind}))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let stages = pipeline(&server, &id).await["stages"].clone();
    let ids: Vec<Value> = stages
        .as_array()
        .unwrap()
        .iter()
        .map(|stage| stage["id"].clone())
        .collect();
    assert_eq!(ids.len(), 3);

    let reordered = json!({"stage_ids": [ids[0], ids[2], ids[1]]});
    server
        .put(&pipelines(&format!("/{id}/stages/order")))
        .authorization_bearer(TENANT_USER)
        .json(&reordered)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let after = pipeline(&server, &id).await;
    assert_eq!(after["stages"][0]["kind"], "Identity");
    assert_eq!(after["stages"][1]["kind"], "Policy");
    assert_eq!(after["stages"][2]["id"], ids[2]);
}

/// An order that leaves a stage out is refused rather than applied.
#[tokio::test]
async fn a_partial_order_is_refused() {
    let server = server();
    let id = created_pipeline(&server, "edge").await;
    let first = pipeline(&server, &id).await["stages"][0]["id"].clone();

    let response = server
        .put(&pipelines(&format!("/{id}/stages/order")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"stage_ids": [first]}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A canary token is a decoy credential handed back once.
#[tokio::test]
async fn a_canary_token_is_generated() {
    let server = server();

    let response = server
        .post(&pipelines("/canary-tokens/generate"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::CREATED);
    assert!(response.json::<Value>()["token"].is_string());
}

/// Bytecode that is not base64 is refused before it is stored.
#[tokio::test]
async fn a_wasm_module_that_is_not_base64_is_refused() {
    let server = server();

    let response = server
        .post(&pipelines("/wasm-modules"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"bytecode_base64": "not base64!"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Ann lowers a rate limit stage's budget in place. The stage keeps its id
/// and place, and reads back with the new settings.
#[tokio::test]
async fn a_stage_takes_new_settings_in_place() {
    let server = server();
    let id = created_pipeline(&server, "edge").await;
    let kind = serde_json::to_value(rate_limit_stage(300).kind()).unwrap();
    server
        .post(&pipelines(&format!("/{id}/stages")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"kind": kind}))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let stage = pipeline(&server, &id).await["stages"][2].clone();
    let mut lowered = stage["kind"].clone();
    lowered["RateLimit"]["max_requests"] = json!(50);

    server
        .patch(&pipelines(&format!(
            "/{id}/stages/{}",
            stage["id"].as_str().unwrap()
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"kind": lowered}))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let after = pipeline(&server, &id).await["stages"][2].clone();
    assert_eq!(after["id"], stage["id"]);
    assert_eq!(after["kind"]["RateLimit"]["max_requests"], 50);
}

/// Replacing an Identity stage's settings with a rate-limit kind produces
/// a client error.
#[tokio::test]
async fn a_mandatory_stage_takes_no_new_settings() {
    let server = server();
    let id = created_pipeline(&server, "edge").await;
    let identity = pipeline(&server, &id).await["stages"][0]["id"].clone();
    let kind = serde_json::to_value(rate_limit_stage(300).kind()).unwrap();

    let response = server
        .patch(&pipelines(&format!(
            "/{id}/stages/{}",
            identity.as_str().unwrap()
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"kind": kind}))
        .await;

    assert!(response.status_code().is_client_error());
}

/// Creating a pipeline without tenant authority returns 403.
#[tokio::test]
async fn a_caller_the_app_refuses_cannot_create_a_pipeline() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .post(&pipelines(""))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "edge"}))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// The test tenant's gateway address, followed by `rest`.
fn gateway(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/gateway{rest}")
}

/// A refusal by the gateway because the route's pipeline is off.
fn pipeline_off_refusal() -> RequestOutcome {
    RequestOutcome::Denied {
        status: 503,
        reason: "the route's pipeline is off".to_owned(),
        decided_by: DecidingStage::Gateway(GatewayCheck::PipelineOff),
        rule: DecidingRule::Unnamed,
    }
}

/// A server whose request log holds one allowed request and one refusal.
fn server_with_records() -> TestServer {
    let log = FakeRequestLog::holding(vec![
        test_request_record(RequestOutcome::Allowed {
            upstream_status: 200,
        }),
        test_request_record(pipeline_off_refusal()),
    ]);
    TestServer::new(router(ianua_assembly::deps::Adapters {
        proxy_request_log: Arc::new(log),
        ..adapters()
    }))
    .unwrap()
}

/// Ann searches for refusals and reads which gateway check made each, and
/// why.
#[tokio::test]
async fn a_refusal_search_names_the_check_that_refused() {
    let server = server_with_records();

    let response = server
        .get(&gateway(
            "/requests?decision=refused&gateway_check=pipeline_off",
        ))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let page: Value = response.json();
    assert_eq!(page["items"].as_array().map(Vec::len), Some(1));
    let record = &page["items"][0];
    assert_eq!(record["decision"], "refused");
    assert_eq!(record["status"], 503);
    assert_eq!(record["reason"], "the route's pipeline is off");
    assert_eq!(record["decided_by"]["kind"], "gateway");
    assert_eq!(record["decided_by"]["name"], "pipeline_off");
    assert_eq!(record["rule"], Value::Null);
}

/// Searching gateway records by an unsupported stage kind returns 422.
#[tokio::test]
async fn a_search_by_an_unknown_stage_kind_is_refused() {
    let server = server_with_records();

    let response = server
        .get(&gateway("/requests?stage_kind=firewall"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Searching gateway request records without tenant authority returns 403.
#[tokio::test]
async fn a_caller_the_app_refuses_cannot_search_the_records() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&gateway("/requests"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// Ann's SIEM collector, with its API key.
fn siem_target() -> Value {
    json!({
        "name": "siem",
        "destination": {"https": "https://siem.example.com/ingest"},
        "credential": "siem-key-1",
    })
}

/// Ann adds her SIEM as a log target. It answers active, saying a
/// credential is set but never showing it, and lists the same way.
#[tokio::test]
async fn a_created_log_target_never_shows_its_credential() {
    let server = server();

    let created = server
        .post(&gateway("/log-targets"))
        .authorization_bearer(TENANT_USER)
        .json(&siem_target())
        .await;
    created.assert_status(StatusCode::CREATED);
    let listed = server
        .get(&gateway("/log-targets"))
        .authorization_bearer(TENANT_USER)
        .await;

    let target: Value = created.json();
    assert_eq!(target["status"], "Active");
    assert_eq!(target["has_credential"], true);
    assert_eq!(target["records"], "all");
    assert_eq!(target["format"], "json_lines");
    assert!(!created.text().contains("siem-key-1"));
    assert!(!listed.text().contains("siem-key-1"));
    assert_eq!(listed.json::<Vec<Value>>().len(), 1);
}

/// A paused target reads back paused, and resumes.
#[tokio::test]
async fn a_log_target_is_paused_and_resumed() {
    let server = server();
    let created: Value = server
        .post(&gateway("/log-targets"))
        .authorization_bearer(TENANT_USER)
        .json(&siem_target())
        .await
        .json();
    let target = gateway(&format!("/log-targets/{}", created["id"].as_str().unwrap()));

    server
        .post(&format!("{target}/pause"))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let paused: Value = server
        .get(&target)
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    server
        .post(&format!("{target}/resume"))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let resumed: Value = server
        .get(&target)
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    assert_eq!(paused["status"], "Paused");
    assert_eq!(resumed["status"], "Active");
}

/// Changing a target with its credential set to `null` ships without one
/// from then on.
#[tokio::test]
async fn a_change_can_remove_the_credential() {
    let server = server();
    let created: Value = server
        .post(&gateway("/log-targets"))
        .authorization_bearer(TENANT_USER)
        .json(&siem_target())
        .await
        .json();

    let changed = server
        .put(&gateway(&format!(
            "/log-targets/{}",
            created["id"].as_str().unwrap()
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "destination": {"https": "https://siem.example.com/ingest"},
            "credential": null,
            "records": "denied_only",
            "format": "json_lines",
        }))
        .await;

    changed.assert_status_ok();
    let target: Value = changed.json();
    assert_eq!(target["has_credential"], false);
    assert_eq!(target["records"], "denied_only");
}

/// Creating a Datadog log target without its credential returns 422.
#[tokio::test]
async fn a_datadog_target_without_a_credential_is_refused() {
    let server = server();

    let response = server
        .post(&gateway("/log-targets"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "dd", "destination": {"datadog": "eu1"}}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A plan refusal makes log-target creation return 403.
#[tokio::test]
async fn a_log_target_over_the_plan_limit_is_refused() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        limit_enforcer: Arc::new(RejectingLimitEnforcer),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .post(&gateway("/log-targets"))
        .authorization_bearer(TENANT_USER)
        .json(&siem_target())
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}
