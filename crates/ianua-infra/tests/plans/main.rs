//! Every query, as Postgres would run it: a query that can only be answered
//! by reading a whole table fails here, naming the query and the table.
//!
//! Each file under `queries/` is planned against the migrated schema for
//! any values of its parameters, with whole-table scans made a last resort.
//! Postgres then picks one only when no index can answer the query, so a
//! scan in the plan is a missing index, not a guess about table sizes.
//!
//! A small table whose every row is always read may be scanned whole, but
//! only when listed below with its reason.

use std::fs;
use std::path::Path;

use ianua_infra::test_support::TestDb;
use serde_json::Value;

/// Queries that may read a table whole, by file and table, with the reason.
const WHOLE_TABLE_READS: &[(&str, &str, &str)] = &[
    (
        "queries/tenant_metric_snapshots/capture_shared.sql",
        "tenants",
        "the capture counts every live tenant of the platform database",
    ),
    (
        "queries/platform_certificates/prune.sql",
        "platform_certificates",
        "reconciliation compares every held root against the complete desired catalog",
    ),
];

/// Every query file under `queries/`, by its path from the crate's root.
fn query_files() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    collect(root, &root.join("queries"), &mut found);
    found.sort();
    found
}

fn collect(root: &Path, dir: &Path, found: &mut Vec<(String, String)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for path in entries.flatten().map(|entry| entry.path()) {
        if path.is_dir() {
            collect(root, &path, found);
            continue;
        }
        if path.extension().is_some_and(|extension| extension == "sql") {
            found.push((relative(root, &path), read(&path)));
        }
    }
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Reads a query fixture whose plan this test must inspect.
// An unreadable query must fail the test rather than skip its plan check.
#[allow(clippy::expect_used)]
fn read(path: &Path) -> String {
    fs::read_to_string(path).expect("a query file is readable")
}

/// The tables a plan reads whole.
fn scanned_tables(plan: &Value) -> Vec<String> {
    let mut found = Vec::new();
    walk(plan, &mut found);
    found
}

fn walk(node: &Value, found: &mut Vec<String>) {
    match node {
        Value::Array(items) => items.iter().for_each(|item| walk(item, found)),
        Value::Object(fields) => {
            let scans = fields.get("Node Type").and_then(Value::as_str) == Some("Seq Scan");
            if let Some(table) = fields
                .get("Relation Name")
                .and_then(Value::as_str)
                .filter(|_| scans)
            {
                found.push(table.to_owned());
            }
            fields.values().for_each(|value| walk(value, found));
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// Query plans contain no sequential table scans except those explicitly
/// allowed for the query and table.
#[tokio::test]
async fn every_query_can_use_an_index() {
    let db = TestDb::fresh().await;
    let mut findings = Vec::new();
    for (path, sql) in query_files() {
        for table in scanned_tables(&db.plan(&sql).await) {
            if !WHOLE_TABLE_READS
                .iter()
                .any(|(query, allowed, _)| *query == path && *allowed == table)
            {
                findings.push(format!("{path}: reads all of `{table}`; give it an index"));
            }
        }
    }
    assert!(
        findings.is_empty(),
        "queries no index can answer:\n{}",
        findings.join("\n")
    );
}

/// Finds the index condition of the named index anywhere in a PostgreSQL plan.
fn index_condition<'a>(plan: &'a Value, index: &str) -> Option<&'a str> {
    match plan {
        Value::Array(items) => items.iter().find_map(|item| index_condition(item, index)),
        Value::Object(fields) => {
            if fields.get("Index Name").and_then(Value::as_str) == Some(index) {
                return fields.get("Index Cond").and_then(Value::as_str);
            }
            fields
                .values()
                .find_map(|item| index_condition(item, index))
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => None,
    }
}

/// A user page resolves each invitee's latest pending invitation through the
/// per-user ordered index instead of scanning the tenant's open invitations.
#[tokio::test]
async fn invitation_page_enrichment_uses_the_requested_users_index() {
    let db = TestDb::fresh().await;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sql = read(&root.join("queries/invitations/latest_pending_for_users.sql"));
    let plan = db.plan(&sql).await;
    let condition = index_condition(&plan, "invitations_pending_of_user")
        .unwrap_or_else(|| panic!("per-user invitation index absent: {plan}"));
    assert!(
        condition.contains("tenant_id"),
        "tenant missing from seek: {condition}"
    );
    assert!(
        condition.contains("user_id"),
        "invitee missing from seek: {condition}"
    );
}

/// Later expiry batches seek on the whole composite key even with a generic
/// prepared plan, avoiding repeated scans through already attempted rows.
#[tokio::test]
async fn holding_sweeps_seek_on_complete_keys_in_generic_plans() {
    let db = TestDb::fresh().await;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (table, resource) in [
        ("role_assignments", "role_id"),
        ("group_memberships", "group_id"),
    ] {
        let sql = read(&root.join(format!("queries/{table}/lapsed_after.sql")));
        let plan = db.plan(&sql).await;
        let index = format!("{table}_sweep");
        let condition =
            index_condition(&plan, &index).unwrap_or_else(|| panic!("{index} absent: {plan}"));
        for component in ["expires_at", resource, "principal_kind", "principal_id"] {
            assert!(
                condition.contains(component),
                "{component} missing from indexed seek: {condition}"
            );
        }
        assert!(condition.contains('>'), "no keyset seek: {condition}");
    }
}

/// Whether a plan sorts rows before it can return the next bounded page.
fn sorts_rows(plan: &Value) -> bool {
    match plan {
        Value::Array(items) => items.iter().any(sorts_rows),
        Value::Object(fields) => {
            matches!(
                fields.get("Node Type").and_then(Value::as_str),
                Some("Sort" | "Incremental Sort")
            ) || fields.values().any(sorts_rows)
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

/// The plan check detects both kinds of sorting even below a Limit node,
/// and leaves an index-only plan alone.
#[test]
fn planted_sort_nodes_are_detected() {
    for kind in ["Sort", "Incremental Sort"] {
        let plan = serde_json::json!([{
            "Plan": { "Node Type": "Limit", "Plans": [{ "Node Type": kind }] }
        }]);
        assert!(sorts_rows(&plan));
    }
    let indexed = serde_json::json!([{
        "Plan": { "Node Type": "Limit", "Plans": [{ "Node Type": "Index Only Scan" }] }
    }]);
    assert!(!sorts_rows(&indexed));
}

/// A representative overdue keyset query proves the index can seek past
/// deadline and id without sorting under generic parameter planning. This
/// checks index capability rather than capturing the runtime query.
#[tokio::test]
async fn overdue_review_pages_seek_the_complete_due_position_without_sorting() {
    let db = TestDb::fresh().await;
    let plan = db
        .plan(
            "SELECT id FROM access_reviews
         WHERE tenant_id = $1 AND status = 'open' AND due <= $2
           AND (due, id) > ($3, $4)
         ORDER BY due, id LIMIT $5",
        )
        .await;
    let condition = index_condition(&plan, "access_reviews_open_by_due")
        .unwrap_or_else(|| panic!("overdue review index absent: {plan}"));

    assert!(
        condition.contains("tenant_id"),
        "tenant missing from seek: {condition}"
    );
    assert!(
        condition.contains("due")
            && condition.contains("id")
            && condition.contains("$3")
            && condition.contains("$4"),
        "deadline or tie position missing from seek: {condition}"
    );
    assert!(!sorts_rows(&plan), "overdue pages sort the backlog: {plan}");
}

/// The check finds a whole-table read planted for it, so a check that
/// silently matches nothing fails here.
#[tokio::test]
async fn a_planted_whole_table_read_is_found() {
    let db = TestDb::fresh().await;

    let plan = db
        .plan("SELECT id FROM tenants WHERE contact_email = $1")
        .await;

    assert_eq!(scanned_tables(&plan), ["tenants"]);
}
