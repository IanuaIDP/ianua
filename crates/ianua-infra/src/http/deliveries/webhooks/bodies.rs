//! The body an event is sent to webhooks as: its wire form, the same for
//! every subscription that receives it.
//!
//! A body names the audit record the event was kept as, so a receiver can
//! match a delivery to the trail, then the event's type, when it happened,
//! its tenant and its details. The details come from the record's payload:
//! a scalar as text, a reference to an entity as `{kind, id, label}`, a
//! transition as `{from, to}`. A field whose name marks a secret is left
//! out, so a payload built carelessly still sends none.

use std::collections::BTreeMap;

use ianua_app::ports::shared::PublishedEvent;
use ianua_app::ports::webhooks::WebhookBodies;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::data::{EventData, FieldValue, is_sensitive_key};
use serde::Serialize;
use time::OffsetDateTime;

/// Writes events as the JSON bodies webhooks receive.
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpWebhookBodies;

impl WebhookBodies for HttpWebhookBodies {
    fn body(&self, event: &PublishedEvent) -> Result<Vec<u8>, DomainError> {
        let record = event.record();
        let body = Body {
            id: record.id.to_string(),
            event_type: record.event_type.as_str(),
            occurred_at: record.occurred_at,
            tenant_id: record.scope.tenant_id().map(ToString::to_string),
            data: details(&record.payload),
        };
        serde_json::to_vec(&body).map_err(DomainError::infra)
    }
}

/// One event as a webhook receives it.
#[derive(Serialize)]
struct Body<'a> {
    id: String,
    #[serde(rename = "type")]
    event_type: &'a str,
    #[serde(with = "time::serde::rfc3339")]
    occurred_at: OffsetDateTime,
    tenant_id: Option<String>,
    data: BTreeMap<&'a str, Detail<'a>>,
}

/// One detail of an event as it is sent.
#[derive(Serialize)]
#[serde(untagged)]
enum Detail<'a> {
    Text(&'a str),
    Reference {
        kind: &'a str,
        id: &'a str,
        label: &'a str,
    },
    Change {
        #[serde(skip_serializing_if = "Option::is_none")]
        from: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        to: Option<&'a str>,
    },
}

/// The details of `payload` by name, leaving out any that names a secret.
fn details(payload: &EventData) -> BTreeMap<&str, Detail<'_>> {
    payload
        .fields()
        .iter()
        .filter(|(key, _)| !is_sensitive_key(key))
        .map(|(key, value)| (key.as_str(), detail(value)))
        .collect()
}

/// `value` as it is sent.
fn detail(value: &FieldValue) -> Detail<'_> {
    match value {
        FieldValue::Text(text) => Detail::Text(text),
        FieldValue::Reference(reference) => Detail::Reference {
            kind: reference.kind().as_str(),
            id: reference.id(),
            label: reference.label(),
        },
        FieldValue::Change(change) => Detail::Change {
            from: change.from(),
            to: change.to(),
        },
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::shared::events::data::{RefKind, Reference};
    use ianua_domain::test_support::events::sample_event_about;
    use ianua_domain::types::{AuditRecordId, TenantId, UserId};
    use serde_json::{Value, json};

    use super::*;

    fn published(tenant: TenantId) -> PublishedEvent {
        PublishedEvent {
            id: AuditRecordId::new(),
            event: sample_event_about(tenant, UserId::new()),
            context: AuditContext::system(),
        }
    }

    /// A user's status change is sent with the record's id, its type, its
    /// time, its tenant and its details.
    #[test]
    fn a_body_names_the_record_type_time_tenant_and_details() {
        let tenant = TenantId::new();
        let event = published(tenant);

        let body: Value = serde_json::from_slice(&HttpWebhookBodies.body(&event).unwrap()).unwrap();

        assert_eq!(body["id"], json!(event.id.to_string()));
        assert_eq!(body["type"], json!(event.record().event_type.as_str()));
        assert_eq!(body["tenant_id"], json!(tenant.to_string()));
        assert!(
            body["occurred_at"]
                .as_str()
                .is_some_and(|at| at.contains('T'))
        );
        assert!(body["data"].is_object());
    }

    /// Each kind of detail keeps its shape: text as a string, a reference
    /// as kind, id and label, a change as from and to.
    #[test]
    fn each_kind_of_detail_keeps_its_shape() {
        let payload = EventData::new()
            .field("status", "active")
            .reference("user", Reference::new(RefKind::USER, "u1", "ada@acme.test"))
            .change_between("role", None, Some("admin".to_owned()));

        let sent = serde_json::to_value(details(&payload)).unwrap();

        assert_eq!(
            sent,
            json!({
                "status": "active",
                "user": {"kind": RefKind::USER.as_str(), "id": "u1", "label": "ada@acme.test"},
                "role": {"to": "admin"},
            })
        );
    }

    /// Serializing event details omits the signing-secret value while
    /// retaining the active status.
    #[test]
    fn a_field_naming_a_secret_is_left_out() {
        let payload = EventData::from_pairs(vec![
            ("signing_secret".to_owned(), "whsec_live".to_owned()),
            ("status".to_owned(), "active".to_owned()),
        ]);

        let sent = serde_json::to_string(&details(&payload)).unwrap();

        assert!(!sent.contains("whsec_live"), "{sent}");
        assert!(sent.contains("active"), "{sent}");
    }
}
