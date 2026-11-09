//! The audit endpoints: the audit logs, their exports written in the
//! background, and the last verdict on a tenant's audit chain.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{OPERATOR, ORG, ORG_MEMBER, TENANT, TENANT_USER, adapters, router};
use ianua_app::test_support::acting::{FakeOrgActors, FakeTenantAuthorities, Refusal};
use ianua_app::test_support::audit::{
    FakeAuditExportStore, FakeChainVerdictStore, WatchedAuditLog, chain_link, pending_export_of,
    written_export_of,
};
use ianua_app::test_support::test_ctx;
use ianua_domain::domains::audit::access::AuditLogOf;
use ianua_domain::domains::audit::checkpoint::ChainStart;
use ianua_domain::domains::audit::verdict::{ChainVerdict, ChainVerdictRow};
use ianua_domain::domains::audit::walk::ChainStanding;
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::shared::clock;
use ianua_domain::types::{ActorRef, AuditExportId, TenantId};
use serde_json::{Value, json};

/// A server over the default fake adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// An empty audit log answers an empty page of 50.
#[tokio::test]
async fn an_empty_log_answers_an_empty_page() {
    let server = server();

    let response = server
        .get(&format!("/api/v1/organizations/{ORG}/audit-log"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_json(&json!({
        "items": [],
        "next_cursor": null,
        "limit": 20,
    }));
}

/// Olga asks for her organization's log as JSON. The export is accepted,
/// pending, with the id to poll it by.
#[tokio::test]
async fn an_organization_export_is_accepted_pending() {
    let response = server()
        .post(&format!("/api/v1/organizations/{ORG}/audit-log/exports"))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"format": "json", "event_type": "organization.org_user"}))
        .await;

    response.assert_status(StatusCode::ACCEPTED);
    let accepted: Value = response.json();
    assert_eq!(accepted["status"], "pending");
    assert!(accepted["id"].is_string());
}

/// The synchronous download that cut the log at 10,000 entries is gone.
#[tokio::test]
async fn the_old_export_download_is_gone() {
    let response = server()
        .get(&format!("/api/v1/organizations/{ORG}/audit-log/export"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// A timestamp that is not RFC 3339 is refused before the app sees it.
#[tokio::test]
async fn a_malformed_timestamp_is_refused() {
    let server = server();

    let response = server
        .get(&format!(
            "/api/v1/organizations/{ORG}/audit-log?after=yesterday"
        ))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// The tenant's chain verify address.
fn verify_path() -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/audit/verify")
}

/// Before the first sweep, the chain is not verified yet; it is never
/// reported intact unseen.
#[tokio::test]
async fn a_chain_no_sweep_walked_is_not_verified_yet() {
    let response = server()
        .get(&verify_path())
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    response.assert_json(&json!({
        "status": "not_verified_yet",
        "verified_at": null,
        "checked_through_seq": null,
        "broken_at_seq": null,
    }));
}

/// Last night's sweep verified the chain through record 500. The answer is
/// that verdict, with when it was found.
#[tokio::test]
async fn the_last_sweeps_verdict_is_answered() {
    let verdicts = Arc::new(FakeChainVerdictStore::default());
    let verdict = ChainVerdict::reconstitute(ChainVerdictRow {
        verified_at: clock::now(),
        standing: ChainStanding::Intact,
        checkpoint: ChainStart::After(chain_link(500)),
    })
    .unwrap();
    verdicts.keep(test_ctx().tenant_id(), verdict);
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        audit_chain_verdict_store: verdicts,
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&verify_path())
        .authorization_bearer(TENANT_USER)
        .await;

    let verdict: Value = response.json();
    assert_eq!(verdict["status"], "intact");
    assert_eq!(verdict["checked_through_seq"], 500);
    assert!(verdict["verified_at"].is_string());
}

/// Denied organization audit authority becomes a 403 response.
#[tokio::test]
async fn a_member_the_app_refuses_is_forbidden() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        org_actors: Arc::new(FakeOrgActors::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&format!("/api/v1/organizations/{ORG}/audit-log"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// The test tenant's audit log, followed by `rest`.
fn tenant_log(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/audit-log{rest}")
}

/// A server whose tenant and platform audit logs are `log`.
fn watched(log: &Arc<WatchedAuditLog>) -> TestServer {
    TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_audit_log_store: log.clone(),
        platform_audit_log_store: log.clone(),
        ..adapters()
    }))
    .unwrap()
}

/// Ann reads her tenant's log narrowed to one actor and one address; the
/// app reads the tenant's own log with both filters.
#[tokio::test]
async fn a_tenant_admin_reads_their_tenants_log_filtered() {
    let log = Arc::new(WatchedAuditLog::default());
    let server = watched(&log);
    let user = uuid::Uuid::now_v7();

    let response = server
        .get(&tenant_log(&format!(
            "?actor=user:{user}&ip_address=10.0.0.1"
        )))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let asked = log.asked();
    assert_eq!(asked.len(), 1);
    let (tenant, filter) = &asked[0];
    assert_eq!(*tenant, Some(test_ctx().tenant_id()));
    assert!(matches!(filter.actor, Some(ActorRef::User(id)) if *id.as_uuid() == user));
    assert!(filter.ip_address.is_some());
}

/// An actor the query cannot name is refused before the app sees it.
#[tokio::test]
async fn an_unknown_actor_is_refused() {
    let response = server()
        .get(&tenant_log("?actor=robot:1"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A server whose audit exports are kept in `exports`.
fn exporting(exports: &Arc<FakeAuditExportStore>) -> TestServer {
    TestServer::new(router(ianua_assembly::deps::Adapters {
        audit_export_store: exports.clone(),
        ..adapters()
    }))
    .unwrap()
}

/// Ann asks for her tenant's log with no body. The export is accepted and
/// kept for her tenant's own log.
#[tokio::test]
async fn a_tenant_export_is_accepted_and_kept() {
    let exports = Arc::new(FakeAuditExportStore::default());

    let response = exporting(&exports)
        .post(&tenant_log("/exports"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::ACCEPTED);
    let accepted: Value = response.json();
    let id = AuditExportId::from_uuid(accepted["id"].as_str().unwrap().parse().unwrap());
    assert_eq!(
        exports.stored(&id).unwrap().log(),
        AuditLogOf::Tenant(test_ctx().tenant_id())
    );
}

/// An event type in capitals names no event type. It is refused before the
/// app keeps anything.
#[tokio::test]
async fn an_export_with_a_malformed_event_type_is_refused() {
    let exports = Arc::new(FakeAuditExportStore::default());

    let response = exporting(&exports)
        .post(&tenant_log("/exports"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"event_type": "Tenant Created"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(exports.count(), 0);
}

/// Ann's tenant has three exports waiting, as many as it may. A fourth is
/// refused with `429`.
#[tokio::test]
async fn a_fourth_waiting_export_is_refused() {
    let exports = Arc::new(FakeAuditExportStore::default());
    let server = exporting(&exports);
    for _ in 0..3 {
        server
            .post(&tenant_log("/exports"))
            .authorization_bearer(TENANT_USER)
            .await
            .assert_status(StatusCode::ACCEPTED);
    }

    let response = server
        .post(&tenant_log("/exports"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::TOO_MANY_REQUESTS);
}

/// The worker is still writing Ann's export. She sees it pending, with no
/// link.
#[tokio::test]
async fn a_pending_export_has_no_link() {
    let export = pending_export_of(AuditLogOf::Tenant(test_ctx().tenant_id()));
    let id = *export.id();
    let exports = Arc::new(FakeAuditExportStore::holding(export));

    let response = exporting(&exports)
        .get(&tenant_log(&format!("/exports/{id}")))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let answer: Value = response.json();
    assert_eq!(answer["status"], "pending");
    assert_eq!(answer["download_url"], Value::Null);
}

/// Ann's export is written. She sees how many entries it holds and gets a
/// link to its file.
#[tokio::test]
async fn a_written_export_answers_a_link() {
    let export = written_export_of(AuditLogOf::Tenant(test_ctx().tenant_id()));
    let id = *export.id();
    let exports = Arc::new(FakeAuditExportStore::holding(export));

    let response = exporting(&exports)
        .get(&tenant_log(&format!("/exports/{id}")))
        .authorization_bearer(TENANT_USER)
        .await;

    let answer: Value = response.json();
    assert_eq!(answer["status"], "ready");
    assert_eq!(answer["rows"], 3);
    assert!(
        answer["download_url"]
            .as_str()
            .unwrap()
            .starts_with("https://")
    );
}

/// An export belonging to another tenant returns 404.
#[tokio::test]
async fn another_tenants_export_is_not_found() {
    let export = written_export_of(AuditLogOf::Tenant(TenantId::new()));
    let id = *export.id();
    let exports = Arc::new(FakeAuditExportStore::holding(export));

    let response = exporting(&exports)
        .get(&tenant_log(&format!("/exports/{id}")))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// A tenant user denied audit authority receives 403 when requesting an export.
#[tokio::test]
async fn a_tenant_user_the_app_refuses_exports_nothing() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .post(&tenant_log("/exports"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// View-only audit access permits reading the log but returns 403 for an
/// export request and leaves the export store empty.
#[tokio::test]
async fn a_tenant_user_who_may_only_view_the_log_exports_nothing() {
    let exports = Arc::new(FakeAuditExportStore::default());
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
            SystemPermission::ViewAuditLog,
        ])),
        audit_export_store: exports.clone(),
        ..adapters()
    }))
    .unwrap();

    let read = server
        .get(&tenant_log(""))
        .authorization_bearer(TENANT_USER)
        .await;
    let exported = server
        .post(&tenant_log("/exports"))
        .authorization_bearer(TENANT_USER)
        .await;

    read.assert_status_ok();
    exported.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(exports.count(), 0);
}

/// An operator asks for the platform's log. The export is accepted.
#[tokio::test]
async fn an_operator_exports_the_platforms_log() {
    let response = server()
        .post("/api/v1/audit-log/exports")
        .authorization_bearer(OPERATOR)
        .json(&json!({"format": "csv"}))
        .await;

    response.assert_status(StatusCode::ACCEPTED);
}

/// A tenant credential receives 403 when exporting the platform audit log.
#[tokio::test]
async fn a_tenant_user_exports_no_platform_log() {
    let response = server()
        .post("/api/v1/audit-log/exports")
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// Denied tenant audit authority returns 403 from the log endpoint.
#[tokio::test]
async fn a_tenant_user_the_app_refuses_reads_no_log() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&tenant_log(""))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// An operator reads the platform's log, narrowed to one tenant.
#[tokio::test]
async fn an_operator_reads_the_platforms_log() {
    let log = Arc::new(WatchedAuditLog::default());
    let server = watched(&log);
    let tenant = test_ctx().tenant_id();

    let response = server
        .get(&format!("/api/v1/audit-log?tenant_id={tenant}"))
        .authorization_bearer(OPERATOR)
        .await;

    response.assert_status_ok();
    let asked = log.asked();
    assert_eq!(asked[0].0, None);
    assert_eq!(asked[0].1.tenant_id, Some(tenant));
}

/// Reading the platform audit log with a tenant credential returns 403.
#[tokio::test]
async fn a_tenant_user_reads_no_platform_log() {
    let response = server()
        .get("/api/v1/audit-log")
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}
