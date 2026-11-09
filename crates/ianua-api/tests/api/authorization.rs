//! The authorization endpoints: roles and who holds them, groups, the
//! access policy and its versions, the permission catalogue, separation of
//! duties, access requests and reviews, relationships, access checks and
//! clearance, and in what shape they answer.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, router};
use ianua_app::test_support::acting::{FakeTenantAuthorities, Refusal};
use ianua_app::test_support::authorization::{
    AccessSources, FakeAccessRecordStore, FakeAccessReviewStore, FakeRoleHolderQueries,
    open_review_of,
};
use ianua_app::test_support::test_ctx;
use ianua_assembly::deps::Adapters;
use ianua_domain::domains::authorization::access_review::ReviewScope;
use ianua_domain::shared::clock;
use ianua_domain::types::{AccessReviewId, PrincipalRef, RoleId, TenantId, UserId};
use serde_json::{Value, json};
use time::Duration;

/// A user of the test tenant other than the caller.
const ANN: &str = "6f1c1f0e-3b7a-4c55-9a77-0c2b1d2e3f40";
/// A second user of the test tenant.
const BOB: &str = "0b9d6a51-4e1f-4c2a-8f3e-7a6b5c4d3e21";
/// A third user of the test tenant.
const CAROL: &str = "c4a1e7d2-9b3f-4a6c-8e5d-1f2a3b4c5d60";

/// The test tenant's authorization address, followed by `rest`.
fn authz(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/authorization{rest}")
}

/// A server over the default fake adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// Ann creates a role, and the list shows it in the shape the role editor
/// reads: its permissions by value, whether new users get it, and how many
/// hold it.
#[tokio::test]
async fn a_created_role_is_listed() {
    let server = server();

    let created = server
        .post(&authz("/roles"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "Support", "system_permissions": [{"Users": "View"}]}))
        .await;
    created.assert_status(StatusCode::CREATED);
    let id = created.json::<Value>()["id"].clone();

    let listed = server
        .get(&authz("/roles"))
        .authorization_bearer(TENANT_USER)
        .await;

    listed.assert_status_ok();
    let page: Value = listed.json();
    let role = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|role| role["id"] == id)
        .unwrap();
    assert_eq!(role["name"], "Support");
    assert_eq!(role["system_permissions"], json!([{"Users": "View"}]));
    assert_eq!(role["is_default"], false);
    assert_eq!(role["assigned_user_count"], 0);
}

/// A role with a blank name is refused before the app sees it.
#[tokio::test]
async fn a_role_without_a_name_is_refused() {
    let server = server();

    let response = server
        .post(&authz("/roles"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": ""}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// The permission picker reads every built-in permission, grouped by area,
/// each with the value a role takes and a label.
#[tokio::test]
async fn the_permission_catalogue_lists_every_area() {
    let server = server();

    let response = server
        .get(&authz("/permissions"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let areas: Vec<Value> = response.json();
    assert!(!areas.is_empty());
    let first = &areas[0]["permissions"][0];
    assert!(first.get("value").is_some());
    assert!(first["label"].as_str().unwrap().starts_with("idp:"));
}

/// A group created under no parent reads back at the top of the tree.
#[tokio::test]
async fn a_created_group_reads_back() {
    let server = server();

    let created = server
        .post(&authz("/groups"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "Support desk"}))
        .await;
    created.assert_status(StatusCode::CREATED);
    let id = created.json::<Value>()["id"].as_str().unwrap().to_owned();

    let group: Value = server
        .get(&authz(&format!("/groups/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    assert_eq!(group["name"], "Support desk");
    assert_eq!(group["parent_id"], Value::Null);
    assert_eq!(group["role_ids"], json!([]));
}

/// A tenant that never started a policy has none to read; once Ann starts
/// a blank draft and adds a rule, the policy answers with it.
#[tokio::test]
async fn a_policy_is_built_one_step_at_a_time() {
    let server = server();

    server
        .get(&authz("/policy"))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NOT_FOUND);

    let draft = server
        .post(&authz("/policy/draft"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"from": "blank", "default_action": {"Deny": {"reason": "denied"}}}))
        .await;
    draft.assert_status(StatusCode::CREATED);
    assert_eq!(draft.json::<Value>()["status"], "Draft");
    assert_eq!(draft.json::<Value>()["editable"], true);

    let with_rule = server
        .post(&authz("/policy/rules"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "allow-all", "action": "Allow", "priority": 10}))
        .await;

    with_rule.assert_status_ok();
    let rules = &with_rule.json::<Value>()["rules"];
    assert_eq!(rules[0]["name"], "allow-all");
    assert_eq!(rules[0]["enabled"], true);
}

/// A declared resource type is listed with its data class and each
/// action's ladder walked.
#[tokio::test]
async fn a_declared_resource_type_is_listed_with_its_ladder() {
    let server = server();

    declare_resource_type(
        &server,
        &json!({
            "key": "invoice",
            "display_name": "Invoice",
            "data_class": "Confidential",
            "actions": [
                {"key": "write", "display_name": "Write", "implies": ["read"]},
                {"key": "read", "display_name": "Read"}
            ]
        }),
    )
    .await;

    let page: Value = server
        .get(&format!(
            "/api/v1/organizations/{ORG}/tenants/{TENANT}/resource-types"
        ))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    assert_invoice_ladder(&page["items"][0]);
}

/// Declares the resource type through the API and verifies creation succeeds.
async fn declare_resource_type(server: &TestServer, resource: &Value) {
    server
        .post(&format!(
            "/api/v1/organizations/{ORG}/tenants/{TENANT}/resource-types"
        ))
        .authorization_bearer(TENANT_USER)
        .json(resource)
        .await
        .assert_status(StatusCode::CREATED);
}

/// Checks the invoice's classification and the permission implied by writing it.
fn assert_invoice_ladder(invoice: &Value) {
    assert_eq!(invoice["key"], "invoice");
    assert_eq!(invoice["data_class"], "Confidential");
    let write = invoice["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|action| action["key"] == "write")
        .unwrap();
    assert!(
        write["grants"]
            .as_array()
            .unwrap()
            .contains(&json!("invoice:read"))
    );
}

/// Listing roles without tenant authority returns 403.
#[tokio::test]
async fn a_caller_the_app_refuses_is_forbidden() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&authz("/roles"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// The default fakes, with the access records read from the same role,
/// group and catalogue stores the endpoints write, as one database holds
/// them all.
pub(crate) fn wired_adapters() -> Adapters {
    let sources = AccessSources::default();
    let holders = FakeRoleHolderQueries {
        assignments: sources.assignments.clone(),
        groups: sources.groups.clone(),
    };
    Adapters {
        role_holder_queries: Arc::new(holders),
        role_store: sources.roles.clone(),
        role_assignment_store: sources.assignments.clone(),
        group_store: sources.groups.clone(),
        group_membership_store: sources.memberships.clone(),
        resource_type_store: sources.catalogue.clone(),
        access_record_store: Arc::new(FakeAccessRecordStore::reading(sources)),
        ..adapters()
    }
}

/// Creates a role named `name` with no permissions, and answers its id.
async fn created_role(server: &TestServer, name: &str) -> String {
    let created = server
        .post(&authz("/roles"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": name}))
        .await;
    created.assert_status(StatusCode::CREATED);
    created.json::<Value>()["id"].as_str().unwrap().to_owned()
}

/// Starts a blank draft that denies what no rule allows.
async fn started_draft(server: &TestServer) {
    server
        .post(&authz("/policy/draft"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"from": "blank", "default_action": {"Deny": {"reason": "denied"}}}))
        .await
        .assert_status(StatusCode::CREATED);
}

/// Adds the allowing rule `name` at `priority` to the draft.
async fn added_rule(server: &TestServer, name: &str, priority: u16) {
    server
        .post(&authz("/policy/rules"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": name, "action": "Allow", "priority": priority}))
        .await
        .assert_status_ok();
}

/// Ann is given a role until a set time. Her access reads the role with
/// that end, and the role's holders name her.
#[tokio::test]
async fn a_role_given_until_a_time_reads_back_with_its_end() {
    let server = TestServer::new(router(wired_adapters())).unwrap();
    let role = created_role(&server, "On call").await;

    server
        .post(&authz(&format!("/roles/{role}/assignments")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"user_id": ANN, "until": "2999-01-01T00:00:00Z"}))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let access: Value = server
        .get(&authz(&format!("/principals/user/{ANN}/access")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    let holders: Value = server
        .get(&authz(&format!("/roles/{role}/holders")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    assert_eq!(access["direct_roles"][0]["role"]["name"], "On call");
    assert!(!access["direct_roles"][0]["until"].is_null());
    assert_eq!(holders["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(holders["items"][0]["via"], "direct");
    assert_eq!(holders["items"][0]["principal"]["kind"], "user");
    assert_eq!(holders["items"][0]["principal"]["id"], ANN);
}

/// Three people are given a role and Ann reads its holders two at a time.
/// The first page holds two and points to the next; the next holds the
/// third and points nowhere.
#[tokio::test]
async fn role_holders_are_answered_a_page_at_a_time() {
    let server = TestServer::new(router(wired_adapters())).unwrap();
    let role = created_role(&server, "Reviewer").await;
    for user in [ANN, BOB, CAROL] {
        server
            .post(&authz(&format!("/roles/{role}/assignments")))
            .authorization_bearer(TENANT_USER)
            .json(&json!({"user_id": user}))
            .await
            .assert_status(StatusCode::NO_CONTENT);
    }

    let pages = pages_of(&server, &authz(&format!("/roles/{role}/holders"))).await;

    assert_eq!(pages, [2, 1]);
}

/// The size of each page of the list at `path`, read two at a time by
/// following `next_cursor` until it runs out.
async fn pages_of(server: &TestServer, path: &str) -> Vec<usize> {
    let mut sizes = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let query = after.as_ref().map_or_else(
            || "?limit=2".to_owned(),
            |cursor| format!("?limit=2&after={cursor}"),
        );
        let page: Value = server
            .get(&format!("{path}{query}"))
            .authorization_bearer(TENANT_USER)
            .await
            .json();
        sizes.push(page["items"].as_array().map_or(0, Vec::len));
        let Some(next) = page["next_cursor"].as_str() else {
            return sizes;
        };
        after = Some(next.to_owned());
    }
}

/// Three people join a group and Ann reads its members two at a time. The
/// first page holds two and points to the next; the next holds the third
/// and points nowhere.
#[tokio::test]
async fn group_members_are_answered_a_page_at_a_time() {
    let server = TestServer::new(router(wired_adapters())).unwrap();
    let created = server
        .post(&authz("/groups"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "Reviewers"}))
        .await;
    created.assert_status(StatusCode::CREATED);
    let group = created.json::<Value>()["id"].as_str().unwrap().to_owned();
    for user in [ANN, BOB, CAROL] {
        server
            .post(&authz(&format!("/groups/{group}/members")))
            .authorization_bearer(TENANT_USER)
            .json(&json!({"kind": "user", "id": user}))
            .await
            .assert_status(StatusCode::NO_CONTENT);
    }

    let pages = pages_of(&server, &authz(&format!("/groups/{group}/members"))).await;

    assert_eq!(pages, [2, 1]);
}

/// A draft opened while nothing is live reads as the draft, not as the
/// live version, and is the policy's first version.
#[tokio::test]
async fn the_draft_is_read_apart_from_the_live_version() {
    let server = server();
    started_draft(&server).await;

    let live = server
        .get(&authz("/policy/live"))
        .authorization_bearer(TENANT_USER)
        .await;
    let draft = server
        .get(&authz("/policy/draft"))
        .authorization_bearer(TENANT_USER)
        .await;
    let versions: Value = server
        .get(&authz("/policy/versions"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    live.assert_status(StatusCode::NOT_FOUND);
    draft.assert_status_ok();
    assert_eq!(draft.json::<Value>()["version"], 1);
    assert_eq!(draft.json::<Value>()["based_on"], "blank");
    assert_eq!(versions.as_array().unwrap().len(), 1);
}

/// A draft rule is rewritten in place, and the rules are put in a new
/// order by name.
#[tokio::test]
async fn draft_rules_are_changed_and_reordered() {
    let server = server();
    started_draft(&server).await;
    added_rule(&server, "first", 10).await;
    added_rule(&server, "second", 20).await;

    server
        .put(&authz("/policy/rules/first"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "first", "action": "AuditOnly", "priority": 10}))
        .await
        .assert_status_ok();
    let reordered = server
        .put(&authz("/policy/rule-order"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"names": ["second", "first"]}))
        .await;

    reordered.assert_status_ok();
    let rules = &reordered.json::<Value>()["rules"];
    assert_eq!(rules[0]["name"], "second");
    assert_eq!(rules[1]["action"], "AuditOnly");
}

/// The draft is tried before it goes live: it answers with its own rules
/// and number, while the live version, which does not exist yet, is `404`.
#[tokio::test]
async fn a_draft_is_simulated_before_it_goes_live() {
    let server = server();
    started_draft(&server).await;
    added_rule(&server, "allow-all", 10).await;
    let scenario = |version: &str| json!({"version": version, "path": "/admin", "risk": "Low", "current_aal": "Aal1"});

    let draft = server
        .post(&authz("/simulate"))
        .authorization_bearer(TENANT_USER)
        .json(&scenario("draft"))
        .await;
    let live = server
        .post(&authz("/simulate"))
        .authorization_bearer(TENANT_USER)
        .json(&scenario("live"))
        .await;

    draft.assert_status_ok();
    assert_eq!(draft.json::<Value>()["action"], "Allow");
    assert_eq!(draft.json::<Value>()["policy_version"], 1);
    live.assert_status(StatusCode::NOT_FOUND);
}

/// A separation-of-duties rule is declared between two roles, listed, and
/// lifted.
#[tokio::test]
async fn a_separation_rule_is_declared_listed_and_lifted() {
    let server = server();
    let payments = created_role(&server, "Payments").await;
    let approvals = created_role(&server, "Approvals").await;

    let declared = server
        .post(&authz("/separation-rules"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "name": "payments-vs-approvals",
            "first_role_id": payments,
            "second_role_id": approvals
        }))
        .await;
    declared.assert_status(StatusCode::CREATED);
    let id = declared.json::<Value>()["id"].as_str().unwrap().to_owned();
    let listed: Value = server
        .get(&authz("/separation-rules"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    let lifted = server
        .delete(&authz(&format!("/separation-rules/{id}")))
        .authorization_bearer(TENANT_USER)
        .await;

    assert_eq!(listed[0]["name"], "payments-vs-approvals");
    lifted.assert_status(StatusCode::NO_CONTENT);
}

/// Self-approval returns 403 and leaves the access request pending.
#[tokio::test]
async fn nobody_approves_their_own_access_request() {
    let server = server();
    let role = created_role(&server, "Deployer").await;

    let asked = server
        .post(&authz("/access-requests"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "asked": {"kind": "role", "id": role},
            "reason": "release tonight",
            "length_seconds": 3600
        }))
        .await;
    asked.assert_status(StatusCode::CREATED);
    let id = asked.json::<Value>()["id"].as_str().unwrap().to_owned();
    let approved = server
        .post(&authz(&format!("/access-requests/{id}/approve")))
        .authorization_bearer(TENANT_USER)
        .await;
    let pending: Value = server
        .get(&authz("/access-requests?status=pending"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    approved.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(pending["items"][0]["status"], "pending");
    assert_eq!(pending["items"][0]["asked"]["kind"], "role");
}

/// The tenant's limit on access requests reads the widest a month allows
/// until it is set, and the set limit after.
#[tokio::test]
async fn the_access_request_limit_is_read_and_changed() {
    let server = server();

    let before: Value = server
        .get(&authz("/access-request-policy"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    let changed = server
        .put(&authz("/access-request-policy"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"longest_seconds": 3600}))
        .await;

    assert_eq!(before["longest_seconds"], 30 * 86_400);
    changed.assert_status_ok();
    assert_eq!(changed.json::<Value>()["longest_seconds"], 3600);
}

/// An undeclared resource type yields an unknown-resource denial that is
/// retained in the searchable access decisions.
#[tokio::test]
async fn an_access_check_on_an_undeclared_type_is_denied_and_recorded() {
    let server = server();

    let answer = server
        .post(&authz("/check"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "subject": {"kind": "user", "id": ANN},
            "action": "read",
            "resource_type": "document",
            "object_key": "42"
        }))
        .await;
    let records: Value = server
        .get(&authz("/decisions?verdict=denied"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    answer.assert_status_ok();
    assert_eq!(answer.json::<Value>()["decision"], "denied");
    assert_eq!(answer.json::<Value>()["reason"], "unknown_resource_type");
    assert_eq!(records["items"][0]["basis"]["kind"], "app_check");
    assert_eq!(records["items"][0]["subject"]["id"], ANN);
}

/// A two-question access batch returns two decisions, including a denial
/// for the second question.
#[tokio::test]
async fn a_batch_check_answers_every_question_in_order() {
    let server = server();

    let answers = server
        .post(&authz("/check/batch"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "subject": {"kind": "agent", "id": ANN},
            "checks": [
                {"action": "read", "resource_type": "document"},
                {"action": "write", "resource_type": "invoice", "object_key": "7"}
            ]
        }))
        .await;

    answers.assert_status_ok();
    let decisions = answers.json::<Value>()["decisions"].clone();
    assert_eq!(decisions.as_array().unwrap().len(), 2);
    assert_eq!(decisions[1]["decision"], "denied");
}

/// Ann is made a viewer of one document of a declared type, and listing
/// that document's relationships shows it.
#[tokio::test]
async fn a_relationship_on_an_object_is_written_and_listed() {
    let server = TestServer::new(router(wired_adapters())).unwrap();
    declare_resource_type(
        &server,
        &json!({
            "key": "document",
            "display_name": "Document",
            "data_class": "Internal",
            "actions": [{"key": "viewer", "display_name": "Viewer"}]
        }),
    )
    .await;

    server
        .post(&authz("/relationships"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "object": {"resource_type": "document", "key": "42"},
            "link": {"holds": {"relation": "viewer", "subject": {"kind": "user", "id": ANN}}}
        }))
        .await
        .assert_status(StatusCode::CREATED);
    let listed: Value = server
        .get(&authz("/relationships?object_type=document&object_key=42"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    let link = &listed["items"][0]["link"]["holds"];
    assert_eq!(link["relation"], "viewer");
    assert_eq!(link["subject"]["id"], ANN);
}

/// A clearance rule is added for an app permission and read back with the
/// level it clears for.
#[tokio::test]
async fn a_clearance_rule_is_added_and_read_back() {
    let server = server();

    server
        .post(&authz("/clearance-rules"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "permission": {"resource": "payroll", "action": "read"},
            "up_to": "Restricted"
        }))
        .await
        .assert_status(StatusCode::CREATED);
    let rules: Value = server
        .get(&authz("/clearance-rules"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    assert_eq!(rules["rules"][0]["up_to"], "Restricted");
    assert_eq!(rules["rules"][0]["permission"]["resource"], "payroll");
}

/// Reviewing an unknown role returns 404 and leaves the review list empty.
#[tokio::test]
async fn a_review_of_an_unknown_role_is_refused() {
    let server = server();

    let started = server
        .post(&authz("/access-reviews"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "name": "Quarterly",
            "scope": {"kind": "role", "id": ANN},
            "reviewer_ids": [ANN],
            "due": "2999-01-01T00:00:00Z",
            "unanswered": "keep_access"
        }))
        .await;
    let listed: Value = server
        .get(&authz("/access-reviews"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();

    started.assert_status(StatusCode::NOT_FOUND);
    assert_eq!(listed["items"], json!([]));
}

/// Denied tenant authority returns 403 from the access-check endpoint.
#[tokio::test]
async fn a_refused_caller_gets_no_access_answer() {
    let server = TestServer::new(router(Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .post(&authz("/check"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "subject": {"kind": "user", "id": ANN},
            "action": "read",
            "resource_type": "document"
        }))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A subject filter with an identifier but no kind returns 422.
#[tokio::test]
async fn half_a_subject_filter_is_refused() {
    let server = server();

    let response = server
        .get(&authz(&format!("/decisions?subject_id={ANN}")))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Seeds twenty-one pending holders separately from their review header.
fn review_server(reviewer: &str, tenant: TenantId) -> (TestServer, AccessReviewId) {
    let holders: Vec<_> = (0..21).map(|_| PrincipalRef::User(UserId::new())).collect();
    let review = open_review_of(
        ReviewScope::Role(RoleId::new()),
        &holders,
        reviewer,
        clock::now() + Duration::days(7),
    );
    let id = *review.id();
    let store = FakeAccessReviewStore::holding(tenant, [review]);
    store.seed_items(tenant, &store.stored(tenant, &id).unwrap(), &holders);
    let server = TestServer::new(router(Adapters {
        access_review_store: Arc::new(store),
        tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
        ..adapters()
    }))
    .unwrap();
    (server, id)
}

/// A reviewer reads a constant-size header then follows immutable holder
/// positions across the default page boundary without embedding all holders.
#[tokio::test]
async fn review_headers_and_holder_pages_are_separate() {
    let (server, id) = review_server("caller@example.test", test_ctx().tenant_id());
    let header = review_page(&server, id, "").await;
    assert!(header.get("items").is_none());
    assert_eq!(header["holder_count"], 21);
    assert_eq!(header["pending_count"], 21);
    assert_eq!(header["remove_count"], 0);
    let first = review_page(&server, id, "/items").await;
    assert_eq!(first["limit"], 20);
    assert_eq!(first["items"].as_array().unwrap().len(), 20);
    assert_eq!(first["items"][0]["position"], 1);
    assert_eq!(first["items"][19]["position"], 20);
    assert!(first["items"][0].get("choice").is_none());
    let cursor = first["next_cursor"].as_str().unwrap();
    let last = review_page(&server, id, &format!("/items?after={cursor}")).await;
    assert_eq!(last["items"].as_array().unwrap().len(), 1);
    assert_eq!(last["items"][0]["position"], 21);
    assert!(last["next_cursor"].is_null());
}

/// Reads an authorized review header or holder page and checks it is available.
async fn review_page(server: &TestServer, id: AccessReviewId, suffix: &str) -> Value {
    let response = server
        .get(&authz(&format!("/access-reviews/{id}{suffix}")))
        .authorization_bearer(TENANT_USER)
        .await;
    response.assert_status_ok();
    response.json()
}

/// Another tenant or an unauthorized reviewer receives 404 for both the
/// review header and its holder page.
#[tokio::test]
async fn unreadable_review_pages_do_not_reveal_holders() {
    for (reviewer, tenant) in [
        ("someone@example.test", test_ctx().tenant_id()),
        ("caller@example.test", TenantId::new()),
    ] {
        let (server, id) = review_server(reviewer, tenant);
        for suffix in ["", "/items"] {
            server
                .get(&authz(&format!("/access-reviews/{id}{suffix}")))
                .authorization_bearer(TENANT_USER)
                .await
                .assert_status(StatusCode::NOT_FOUND);
        }
    }
}

/// An authorized review reader still receives 422 for invalid page sizes
/// and an invented cursor.
#[tokio::test]
async fn review_holder_pages_refuse_invalid_parameters() {
    let (server, id) = review_server("caller@example.test", test_ctx().tenant_id());
    for query in ["limit=0", "limit=101", "after=not-a-cursor"] {
        server
            .get(&authz(&format!("/access-reviews/{id}/items?{query}")))
            .authorization_bearer(TENANT_USER)
            .await
            .assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    }
}
