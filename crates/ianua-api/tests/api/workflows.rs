//! The workflow endpoints: accounts, definitions, executions and raised
//! risks, and the shape each answers in.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, router};
use ianua_app::test_support::RejectingLimitEnforcer;
use ianua_app::test_support::acting::{FakeTenantAuthorities, Refusal};
use ianua_app::test_support::workflows::{
    FakeAccountVerifier, FakeIntegrationCatalog, FakeWorkflowExecutionStore, SHEETS, append_row,
    awaiting_approval_at, person,
};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
use ianua_domain::types::{ActionClass, UntrustedText};
use serde_json::{Value, json};

/// The test tenant's workflow address, followed by `rest`.
fn path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/workflows{rest}")
}

/// A server over the default fake adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// A workflow started by hand: it copies the trigger's flag, checks it, and
/// waits a minute when it holds.
fn weekly_report() -> Value {
    json!({
        "name": "Weekly report",
        "trigger": {"type": "manual"},
        "run_limit_seconds": 3600,
        "graph": {
            "nodes": [
                {
                    "key": "collect",
                    "name": "Collect",
                    "kind": "transform",
                    "fields": [
                        {"field": "ok", "from": "input", "path": "trigger.ok"},
                        {"field": "source", "from": "literal", "value": "weekly"}
                    ]
                },
                {
                    "key": "check",
                    "name": "Check",
                    "kind": "condition",
                    "matching": "all",
                    "clauses": [{"path": "collect.ok", "test": "exists"}]
                },
                {"key": "pause", "name": "Pause", "kind": "wait", "duration_seconds": 60}
            ],
            "edges": [
                {"from": "collect", "to": "check"},
                {"from": "check", "port": "when_true", "to": "pause"}
            ]
        }
    })
}

/// The weekly report as Ann drafts it, in the shape the answer gives.
async fn created(server: &TestServer) -> Value {
    let response = server
        .post(&path(""))
        .authorization_bearer(TENANT_USER)
        .json(&weekly_report())
        .await;
    response.assert_status(StatusCode::CREATED);
    response.json()
}

/// The weekly report drafted and then published, as the publish answer
/// gives it.
async fn published(server: &TestServer) -> Value {
    let draft = created(server).await;
    let response = server
        .post(&path(&format!(
            "/{}/publish",
            draft["id"].as_str().unwrap()
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"revision": draft["revision"]}))
        .await;
    response.assert_status_ok();
    response.json()
}

/// Ann drafts the weekly report. The draft comes back in the shape she
/// sent, with its status, revision and who wrote it.
#[tokio::test]
async fn a_draft_comes_back_in_the_shape_it_was_sent() {
    let server = server();

    let draft = created(&server).await;

    assert_eq!(draft["version"], 1);
    assert_eq!(draft["status"], "draft");
    assert_eq!(draft["trigger"], json!({"type": "manual"}));
    assert_eq!(draft["run_limit_seconds"], 3600);
    let graph = &draft["graph"];
    assert_eq!(graph["nodes"][0]["kind"], "transform");
    assert_eq!(graph["nodes"][0]["join"], "all");
    assert_eq!(
        graph["nodes"][0]["fields"][1],
        json!({"field": "source", "from": "literal", "value": "weekly"})
    );
    assert_eq!(
        graph["nodes"][1]["clauses"][0],
        json!({"path": "collect.ok", "test": "exists"})
    );
    assert_eq!(
        graph["edges"][0],
        json!({"from": "collect", "port": "next", "to": "check"})
    );
    assert!(draft["revision"].is_string());
    assert!(draft["created_by"].as_str().unwrap().contains(':'));
    assert!(draft.get("published_by").is_none());
}

/// Reading the workflow back and renaming its draft answers the latest
/// version, renamed.
#[tokio::test]
async fn a_draft_is_read_and_renamed() {
    let server = server();
    let draft = created(&server).await;
    let id = draft["id"].as_str().unwrap();

    server
        .get(&path(&format!("/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status_ok();
    let renamed = server
        .patch(&path(&format!("/{id}/draft")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"edit": "rename", "name": "Monday report"}))
        .await;

    renamed.assert_status_ok();
    assert_eq!(renamed.json::<Value>()["name"], "Monday report");
}

/// Ann publishes the draft she reviewed. It is the version in service.
#[tokio::test]
async fn a_reviewed_draft_is_published() {
    let server = server();

    let workflow = published(&server).await;

    assert_eq!(workflow["status"], "published");
    assert!(workflow["published_by"].is_string());
}

/// The list holds the latest version of each workflow, in a page.
#[tokio::test]
async fn workflows_are_listed_in_a_page() {
    let server = server();
    created(&server).await;

    let response = server
        .get(&path(""))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>()["items"].as_array().map(Vec::len),
        Some(1)
    );
}

/// A step may not be called `trigger`, which names the trigger's data. The
/// draft is refused, not stored.
#[tokio::test]
async fn a_step_named_trigger_is_refused() {
    let server = server();
    let mut body = weekly_report();
    body["graph"]["nodes"][0]["key"] = json!("trigger");

    let response = server
        .post(&path(""))
        .authorization_bearer(TENANT_USER)
        .json(&body)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Listing workflows without tenant authority returns 403.
#[tokio::test]
async fn a_caller_the_app_refuses_is_forbidden() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&path(""))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// Ann starts the published report by hand, reads where it stands, and
/// stops it.
#[tokio::test]
async fn an_execution_is_started_read_and_cancelled() {
    let server = server();
    let workflow = published(&server).await;
    let workflow_id = workflow["id"].as_str().unwrap();

    let started = server
        .post(&path(&format!("/{workflow_id}/executions")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"input": {"ok": true}, "exposure": "internal"}))
        .await;
    started.assert_status(StatusCode::CREATED);
    let started: Value = started.json();
    assert_eq!(started["status"], "running");
    let execution_id = started["execution_id"].as_str().unwrap();

    let read = server
        .get(&path(&format!("/executions/{execution_id}")))
        .authorization_bearer(TENANT_USER)
        .await;
    read.assert_status_ok();
    let read: Value = read.json();
    assert_eq!(read["workflow_id"], workflow_id);
    assert_eq!(read["cause"], "manual");
    assert_eq!(read["input"], json!({"ok": true}));
    assert_eq!(read["steps"].as_array().unwrap().len(), 3);
    assert_eq!(read["steps"][0]["key"], "collect");

    let cancelled = server
        .post(&path(&format!("/executions/{execution_id}/cancel")))
        .authorization_bearer(TENANT_USER)
        .await;
    cancelled.assert_status_ok();
    assert_eq!(cancelled.json::<Value>()["status"], "cancelled");
}

/// A server whose store holds an execution waiting at its `check` step for
/// a decision on a `class` action, and that step's path.
fn waiting_for_approval(class: ActionClass) -> (TestServer, String) {
    let execution = awaiting_approval_at(
        &person("author@acme.test"),
        &person("ann@acme.test"),
        class,
        DataClassLevel::Internal,
    );
    let step = path(&format!(
        "/executions/{}/approvals/check",
        execution.id().as_uuid()
    ));
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        workflow_execution_store: Arc::new(FakeWorkflowExecutionStore::holding(&execution)),
        ..adapters()
    }))
    .unwrap();
    (server, step)
}

/// Bob opens the sign-off and approves exactly what he was shown.
#[tokio::test]
async fn an_approver_approves_what_they_were_shown() {
    let (server, step) = waiting_for_approval(ActionClass::Read);

    let shown = server.get(&step).authorization_bearer(TENANT_USER).await;
    shown.assert_status_ok();
    let shown: Value = shown.json();

    let approved = server
        .post(&format!("{step}/approve"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"shown": shown["shown"]}))
        .await;

    approved.assert_status_ok();
    assert!(approved.json::<Value>()["execution_id"].is_string());
}

/// Bob refuses the sign-off, and the execution fails.
#[tokio::test]
async fn denying_a_step_fails_the_execution() {
    let (server, step) = waiting_for_approval(ActionClass::Communicate);

    let response = server
        .post(&format!("{step}/deny"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    assert_eq!(response.json::<Value>()["status"], "failed");
}

/// Ann connects the tenant's spreadsheet account. Its credential is never
/// given back, and it is listed.
#[tokio::test]
async fn an_account_is_connected_without_showing_its_credential() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        integration_catalog: Arc::new(FakeIntegrationCatalog::offering(vec![append_row(
            ActionClass::Write,
        )])),
        ..adapters()
    }))
    .unwrap();

    let connected = server
        .post(&path("/accounts"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"integration": SHEETS, "name": "Reports sheet", "credential": "s3cret"}))
        .await;
    connected.assert_status(StatusCode::CREATED);
    let account: Value = connected.json();
    assert_eq!(account["integration"], SHEETS);
    assert_eq!(account["sharing"], "owner_only");
    assert_eq!(account["status"], "active");
    assert!(account["operations"].is_null());
    assert!(!connected.text().contains("s3cret"));

    let listed = server
        .get(&path("/accounts"))
        .authorization_bearer(TENANT_USER)
        .await;
    listed.assert_status_ok();
    assert_eq!(
        listed.json::<Value>()["items"].as_array().map(Vec::len),
        Some(1)
    );
}

/// Ann raises the spreadsheet's append operation to financial, then lists
/// what the tenant raised.
#[tokio::test]
async fn a_risk_is_raised_and_listed() {
    let server = server();

    let raised = server
        .post(&path("/risks"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"integration": SHEETS, "operation": "append-row", "effect": "financial"}))
        .await;
    raised.assert_status(StatusCode::CREATED);
    assert_eq!(raised.json::<Value>()["effect"], "financial");

    let listed = server
        .get(&path("/risks"))
        .authorization_bearer(TENANT_USER)
        .await;
    listed.assert_status_ok();
    assert_eq!(listed.json::<Vec<Value>>().len(), 1);
}

/// An effect that is no action class is refused.
#[tokio::test]
async fn an_unknown_effect_is_refused() {
    let server = server();

    let response = server
        .post(&path("/risks"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"integration": SHEETS, "operation": "append-row", "effect": "spooky"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// The catalog lists each operation the installed integrations offer, as
/// a builder needs it.
#[tokio::test]
async fn the_catalog_lists_what_a_builder_may_use() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        integration_catalog: Arc::new(FakeIntegrationCatalog::offering(vec![append_row(
            ActionClass::Write,
        )])),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&path("/operations"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let operations: Vec<Value> = response.json();
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0]["integration"], SHEETS);
    assert_eq!(operations[0]["operation"], "append-row");
    assert_eq!(operations[0]["effect"], "write");
    assert!(
        operations[0]["title"].is_string(),
        "an operation has a title"
    );
    assert!(operations[0]["description"].is_string());
    assert!(
        operations[0]["inputs"][0]["description"].is_string(),
        "each input says what it means"
    );
    assert!(
        operations[0]["outputs"][0]["path"].is_string(),
        "an operation says what it gives back"
    );
}

/// The catalog lists each integration installed once, with its title,
/// description and icon.
#[tokio::test]
async fn the_catalog_lists_each_integration_with_its_profile() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        integration_catalog: Arc::new(FakeIntegrationCatalog::offering(vec![append_row(
            ActionClass::Write,
        )])),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&path("/integrations"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let integrations: Vec<Value> = response.json();
    assert_eq!(integrations.len(), 1);
    assert_eq!(integrations[0]["key"], SHEETS);
    for field in ["title", "description", "icon"] {
        assert!(integrations[0][field].is_string(), "{field} is given");
    }
}

/// Rejected credentials return 422 and an unreachable verifier returns 502;
/// neither attempt leaves a connected account in the list.
#[tokio::test]
async fn a_credential_the_service_refuses_or_cannot_check_is_not_connected() {
    for (check, status) in [
        (
            AccountCheck::Refused(UntrustedText::record("bad credentials")),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (AccountCheck::Unreachable, StatusCode::BAD_GATEWAY),
    ] {
        let server = TestServer::new(router(ianua_assembly::deps::Adapters {
            integration_catalog: Arc::new(FakeIntegrationCatalog::offering(vec![append_row(
                ActionClass::Write,
            )])),
            account_verifier: Arc::new(FakeAccountVerifier::answering(check)),
            ..adapters()
        }))
        .unwrap();

        let refused = server
            .post(&path("/accounts"))
            .authorization_bearer(TENANT_USER)
            .json(&json!({"integration": SHEETS, "name": "Reports sheet", "credential": "s3cret"}))
            .await;

        refused.assert_status(status);
        let listed = server
            .get(&path("/accounts"))
            .authorization_bearer(TENANT_USER)
            .await;
        assert_eq!(
            listed.json::<Value>()["items"].as_array().map(Vec::len),
            Some(0)
        );
    }
}

/// The weekly report started on its webhook, published by Ann, with its
/// secret issued: the trigger id and the secret, as the issue answer gives
/// them.
async fn hooked(server: &TestServer) -> Value {
    let mut report = weekly_report();
    report["trigger"] = json!({"type": "webhook"});
    let draft: Value = server
        .post(&path(""))
        .authorization_bearer(TENANT_USER)
        .json(&report)
        .await
        .json();
    let id = draft["id"].as_str().unwrap();
    server
        .post(&path(&format!("/{id}/publish")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"revision": draft["revision"]}))
        .await
        .assert_status_ok();
    let issued = server
        .post(&path(&format!("/{id}/trigger-secret")))
        .authorization_bearer(TENANT_USER)
        .await;
    issued.assert_status(StatusCode::CREATED);
    issued.json()
}

/// Whatever was handed the webhook's secret calls it without a session,
/// and the call is taken.
#[tokio::test]
async fn a_webhook_called_with_its_secret_is_taken() {
    let server = server();
    let issued = hooked(&server).await;

    let response = server
        .post(&path(&format!(
            "/triggers/{}",
            issued["trigger_id"].as_str().unwrap()
        )))
        .add_header("ianua-trigger-secret", issued["secret"].as_str().unwrap())
        .json(&json!({"ok": true}))
        .await;

    response.assert_status(StatusCode::ACCEPTED);
    let status = response.json::<Value>()["status"].clone();
    assert!(status == "started" || status == "refused");
}

/// A workflow webhook called with an incorrect secret returns 401.
#[tokio::test]
async fn a_webhook_called_with_a_wrong_secret_is_refused() {
    let server = server();
    let issued = hooked(&server).await;

    let response = server
        .post(&path(&format!(
            "/triggers/{}",
            issued["trigger_id"].as_str().unwrap()
        )))
        .add_header("ianua-trigger-secret", "hook-secret-guessed")
        .json(&json!({"ok": true}))
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// A workflow webhook called without a secret returns 401.
#[tokio::test]
async fn a_webhook_called_without_a_secret_is_refused() {
    let server = server();

    let response = server
        .post(&path(&format!("/triggers/{}", uuid::Uuid::now_v7())))
        .json(&json!({"ok": true}))
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// An execution started by hand is listed among the tenant's executions,
/// and one still running is not run again.
#[tokio::test]
async fn executions_are_listed_across_workflows() {
    let server = server();
    let workflow = published(&server).await;
    let started: Value = server
        .post(&path(&format!(
            "/{}/executions",
            workflow["id"].as_str().unwrap()
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"input": {"ok": true}, "exposure": "internal"}))
        .await
        .json();

    let listed: Value = server
        .get(&path("/executions"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(listed["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(listed["items"][0]["id"], started["execution_id"]);

    server
        .post(&path(&format!(
            "/executions/{}/rerun",
            started["execution_id"].as_str().unwrap()
        )))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::CONFLICT);
}

/// The tenant's agent flow address, followed by `rest`.
fn flows_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/flows{rest}")
}

/// One run of a flow, as the dashboard's builder lays it out.
fn flow_run() -> Value {
    json!({
        "agent_id": uuid::Uuid::now_v7(),
        "provider_id": uuid::Uuid::now_v7(),
        "goal": "summarise the open incidents",
        "purpose": ["read"],
    })
}

/// Two runs side by side, then one, as the dashboard sends a new flow.
fn incident_digest() -> Value {
    json!({
        "name": "Incident digest",
        "description": null,
        "stages": [[flow_run(), flow_run()], [flow_run()]],
    })
}

/// Ann makes a flow of two stages. It starts at once, every run pending,
/// and reads back running, in the shape the flow pages read.
#[tokio::test]
async fn a_flow_is_made_started_and_read() {
    let server = server();

    let created = server
        .post(&flows_path(""))
        .authorization_bearer(TENANT_USER)
        .json(&incident_digest())
        .await;
    created.assert_status(StatusCode::CREATED);
    let created: Value = created.json();
    assert_eq!(created["status"], "Running");
    assert_eq!(created["stages"][0].as_array().unwrap().len(), 2);
    assert_eq!(created["stages"][1][0]["status"], "Pending");
    assert_eq!(created["stages"][0][0]["max_steps"], 10);

    let read = server
        .get(&flows_path(&format!(
            "/{}",
            created["id"].as_str().unwrap()
        )))
        .authorization_bearer(TENANT_USER)
        .await;
    read.assert_status_ok();
    let read: Value = read.json();
    assert_eq!(read["name"], "Incident digest");
    assert_eq!(read["status"], "Running");
    assert_eq!(read["current_stage"], 0);
    assert_eq!(read["stages"].as_array().unwrap().len(), 2);
}

/// Ann lists the tenant's flows. Each one carries where its run stands, in
/// the shape the flow pages read, so the list shows her flow running
/// without opening it.
#[tokio::test]
async fn a_listed_flow_carries_where_its_run_stands() {
    let server = server();
    server
        .post(&flows_path(""))
        .authorization_bearer(TENANT_USER)
        .json(&incident_digest())
        .await
        .assert_status(StatusCode::CREATED);

    let listed = server
        .get(&flows_path(""))
        .authorization_bearer(TENANT_USER)
        .await;

    listed.assert_status_ok();
    let page: Value = listed.json();
    let flow = &page["items"][0];
    assert_eq!(flow["status"], "Running");
    assert_eq!(flow["current_stage"], 0);
    assert!(flow["stages"][0][0]["status"].is_string());
}

/// A running flow is not deleted; once stopped, it is.
#[tokio::test]
async fn a_flow_is_stopped_before_it_is_deleted() {
    let server = server();
    let created: Value = server
        .post(&flows_path(""))
        .authorization_bearer(TENANT_USER)
        .json(&incident_digest())
        .await
        .json();
    let flow = flows_path(&format!("/{}", created["id"].as_str().unwrap()));

    server
        .delete(&flow)
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::CONFLICT);
    let cancelled = server
        .post(&format!("{flow}/cancel"))
        .authorization_bearer(TENANT_USER)
        .await;
    cancelled.assert_status_ok();
    let cancelled: Value = cancelled.json();
    assert_eq!(cancelled["status"], "Canceled");
    assert_eq!(cancelled["name"], "Incident digest");
    assert_eq!(cancelled["stages"].as_array().unwrap().len(), 2);
    server
        .delete(&flow)
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);
}

/// A plan refusal makes agent-flow creation return 403.
#[tokio::test]
async fn a_flow_past_the_plan_limit_is_refused() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        limit_enforcer: Arc::new(RejectingLimitEnforcer),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .post(&flows_path(""))
        .authorization_bearer(TENANT_USER)
        .json(&incident_digest())
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// An agent flow containing an empty stage returns 422.
#[tokio::test]
async fn a_flow_with_an_empty_stage_is_refused() {
    let server = server();
    let mut body = incident_digest();
    body["stages"] = json!([[flow_run()], []]);

    let response = server
        .post(&flows_path(""))
        .authorization_bearer(TENANT_USER)
        .json(&body)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}
