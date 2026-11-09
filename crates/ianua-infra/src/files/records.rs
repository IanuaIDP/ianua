//! Audit records as an export file writes them: a CSV row under the
//! columns the domain names, or a JSON object as the audit log list shows
//! it. The audit log export and the activity in a person's data export
//! write them alike.
//!
//! A CSV cell that a spreadsheet would run as a formula, such as an
//! address typed as `=HYPERLINK(..)` into a failed sign-in, is written
//! with a leading `'`, so opening the file runs nothing. A cell holding a
//! `;` is quoted too, for spreadsheets that split cells there.

use ianua_app::ports::audit::AuditLogEntry;
use ianua_domain::domains::audit::builder::ActedThrough;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::data::{EventData, FieldValue};
use ianua_domain::types::{DisplayName, IpAddress, TenantSlug};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// The first line of a CSV export: its columns, as the domain names them.
pub(crate) const CSV_HEADER: &str =
    "id,event_type,actor,tenant,target_id,ip_address,occurred_at,acted_through,through_id\n";

/// The characters a spreadsheet reads a cell starting with as a formula.
const FORMULA_STARTS: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

/// `at` as RFC 3339 text.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the moment cannot be
/// written, which no moment `time` holds causes.
pub(crate) fn moment(at: OffsetDateTime) -> Result<String, DomainError> {
    at.format(&Rfc3339).map_err(DomainError::infra)
}

/// `entries` as CSV rows, one line each.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a moment cannot be written.
pub(crate) fn csv_rows(entries: &[AuditLogEntry]) -> Result<String, DomainError> {
    let mut text = String::new();
    for entry in entries {
        let cells = [
            entry.id.as_uuid().to_string(),
            entry.event_type.as_str().to_owned(),
            entry.actor_display.clone(),
            entry
                .tenant_id
                .map(|tenant| tenant.as_uuid().to_string())
                .unwrap_or_default(),
            entry.target.id().unwrap_or_default().to_owned(),
            entry
                .ip_address
                .as_ref()
                .map(|ip| ip.as_str().to_owned())
                .unwrap_or_default(),
            moment(entry.occurred_at)?,
            entry.acted_through.kind().to_owned(),
            through_id(&entry.acted_through),
        ];
        let row: Vec<String> = cells.iter().map(|cell| csv_cell(cell)).collect();
        text.push_str(&row.join(","));
        text.push('\n');
    }
    Ok(text)
}

/// `cell` as one CSV cell: defused when a spreadsheet would run it, and
/// quoted when it holds a comma, a semicolon, a quote or a line break. A
/// spreadsheet set to a language that splits cells at `;` would otherwise
/// start a new cell after it, one the defusing never saw.
fn csv_cell(cell: &str) -> String {
    let defused = match cell.chars().next() {
        Some(first) if FORMULA_STARTS.contains(&first) => format!("'{cell}"),
        Some(_) | None => cell.to_owned(),
    };
    if !defused.contains([',', ';', '"', '\n', '\r']) {
        return defused;
    }
    format!("\"{}\"", defused.replace('"', "\"\""))
}

/// `entries` as JSON objects, each after a comma unless it is the first
/// of the array, `already` being how many the array holds before them.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when an entry cannot be written.
pub(crate) fn json_items(entries: &[AuditLogEntry], already: u64) -> Result<String, DomainError> {
    let mut text = String::new();
    for (at, entry) in entries.iter().enumerate() {
        if already > 0 || at > 0 {
            text.push(',');
        }
        text.push('\n');
        let item = serde_json::to_string(&json_record(entry)?).map_err(DomainError::infra)?;
        text.push_str(&item);
    }
    Ok(text)
}

/// One record as the audit log list shows it.
fn json_record(entry: &AuditLogEntry) -> Result<Value, DomainError> {
    Ok(json!({
        "id": entry.id.as_uuid().to_string(),
        "event_type": entry.event_type.as_str(),
        "actor": entry.actor_display,
        "tenant_id": entry.tenant_id.map(|tenant| tenant.as_uuid().to_string()),
        "tenant_slug": entry.tenant_slug.as_ref().map(TenantSlug::as_str),
        "tenant_name": entry.tenant_name.as_ref().map(DisplayName::as_str),
        "target_id": entry.target.id(),
        "ip_address": entry.ip_address.as_ref().map(IpAddress::as_str),
        "details": details(&entry.payload),
        "occurred_at": moment(entry.occurred_at)?,
        "acted_through": acted_through(&entry.acted_through),
    }))
}

/// Whom or what the actor acted through, with the ids its kind names, or
/// `null` when they acted in their own name.
fn acted_through(through: &ActedThrough) -> Value {
    match through {
        ActedThrough::Directly => Value::Null,
        ActedThrough::Impersonation {
            operator_id,
            as_user,
        } => json!({
            "kind": through.kind(),
            "operator_id": operator_id.as_uuid().to_string(),
            "as_user_id": as_user.as_uuid().to_string(),
        }),
        ActedThrough::SupportImpersonation {
            as_user,
            impersonation,
            ..
        } => json!({
            "kind": through.kind(),
            "as_user_id": as_user.as_uuid().to_string(),
            "impersonation_id": impersonation.as_uuid().to_string(),
        }),
        ActedThrough::WorkflowRun { execution } => json!({
            "kind": through.kind(),
            "execution_id": execution.as_uuid().to_string(),
        }),
    }
}

/// The one id a CSV row keeps of whom the actor acted through: the run,
/// the support impersonation or the operator; empty when they acted
/// directly.
fn through_id(through: &ActedThrough) -> String {
    match through {
        ActedThrough::Directly => String::new(),
        ActedThrough::Impersonation { operator_id, .. } => operator_id.as_uuid().to_string(),
        ActedThrough::SupportImpersonation { impersonation, .. } => {
            impersonation.as_uuid().to_string()
        }
        ActedThrough::WorkflowRun { execution } => execution.as_uuid().to_string(),
    }
}

/// What happened, by field: text as a string, a reference or a change as
/// an object.
fn details(data: &EventData) -> Value {
    let fields: Map<String, Value> = data
        .fields()
        .iter()
        .map(|(key, value)| (key.clone(), field(value)))
        .collect();
    Value::Object(fields)
}

/// One detail as JSON.
fn field(value: &FieldValue) -> Value {
    match value {
        FieldValue::Text(text) => Value::String(text.clone()),
        FieldValue::Reference(reference) => json!({
            "kind": reference.kind().as_str(),
            "id": reference.id(),
            "label": reference.label(),
        }),
        FieldValue::Change(change) => json!({
            "change": { "from": change.from(), "to": change.to() },
        }),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::record::AuditTarget;
    use ianua_domain::types::{AuditRecordId, EventType};

    use super::*;
    use crate::test_support::rows::at;

    /// A failed sign-in where Mallory typed a formula as her address.
    fn typed_formula() -> AuditLogEntry {
        AuditLogEntry {
            id: AuditRecordId::new(),
            event_type: EventType::parse("authentication.login_failed").unwrap(),
            actor_display: "=HYPERLINK(\"https://evil.test\",\"Help\")".to_owned(),
            tenant_id: None,
            tenant_slug: None,
            tenant_name: None,
            target: AuditTarget::Entity("user-7".to_owned()),
            ip_address: Some(IpAddress::new("203.0.113.7").unwrap()),
            payload: EventData::new().field("reason", "bad_password"),
            acted_through: ActedThrough::Directly,
            occurred_at: at(1),
        }
    }

    /// A formula-like actor name is prefixed with a quote and escaped as one
    /// CSV cell.
    #[test]
    fn a_formula_is_written_as_text() {
        let rows = csv_rows(&[typed_formula()]).unwrap();

        assert!(rows.contains(",\"'=HYPERLINK(\"\"https://evil.test\"\",\"\"Help\"\")\","));
    }

    /// An actor name containing semicolons and formula text stays quoted in one
    /// CSV cell.
    #[test]
    fn a_formula_after_a_semicolon_stays_in_its_cell() {
        let mut entry = typed_formula();
        entry.actor_display = "x;=cmd|' /C calc'!A0; (ann@acme.test)".to_owned();

        let rows = csv_rows(&[entry]).unwrap();

        assert!(rows.contains(",\"x;=cmd|' /C calc'!A0; (ann@acme.test)\","));
    }

    /// A row holds the columns the header names, in its order.
    #[test]
    fn a_row_holds_the_headers_columns() {
        let mut entry = typed_formula();
        entry.actor_display = "System".to_owned();

        let rows = csv_rows(&[entry]).unwrap();

        let cells: Vec<&str> = rows.trim_end().split(',').collect();
        assert_eq!(cells.len(), CSV_HEADER.trim_end().split(',').count());
        assert_eq!(cells[1], "authentication.login_failed");
        assert_eq!(cells[4], "user-7");
        assert_eq!(cells[5], "203.0.113.7");
    }

    /// Records in JSON are separated by commas across pages, so the pages
    /// make one array.
    #[test]
    fn items_across_pages_make_one_array() {
        let first = json_items(&[typed_formula()], 0).unwrap();
        let second = json_items(&[typed_formula(), typed_formula()], 1).unwrap();

        let array: Value = serde_json::from_str(&format!("[{first}{second}]")).unwrap();

        assert_eq!(array.as_array().unwrap().len(), 3);
        assert_eq!(array[0]["details"]["reason"], "bad_password");
        assert_eq!(array[0]["target_id"], "user-7");
    }
}
