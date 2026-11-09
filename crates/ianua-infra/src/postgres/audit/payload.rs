//! An audit record's payload as its `payload` column keeps it: one JSON
//! object by field name, each value a string for a scalar, `{kind, id,
//! label}` for a reference to an entity, or `{change: {from, to}}` for a
//! transition. The domain's `EventData` is written out and read back here
//! only, so the trail, the logs and the evidence agree on it.

use std::collections::BTreeMap;

use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::data::{Change, EventData, FieldValue, RefKind, Reference};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::postgres::foundation::envelope::Kept;

/// The payload column of an audit record.
pub(crate) const PAYLOAD: Kept = Kept {
    entity: "audit record",
    column: "payload",
    shape: 1,
};

/// The kinds of entity a reference may name, as the domain defines them.
/// A stored kind outside the list is a row this release cannot read.
const REF_KINDS: &[RefKind] = &[
    RefKind::USER,
    RefKind::ORG_USER,
    RefKind::OPERATOR,
    RefKind::ORGANIZATION,
    RefKind::TENANT,
    RefKind::ROLE,
    RefKind::GROUP,
    RefKind::USER_ATTRIBUTE,
    RefKind::AGENT,
    RefKind::CLIENT,
    RefKind::CONNECTION,
    RefKind::KEY,
    RefKind::DELEGATION,
    RefKind::CREDENTIAL,
    RefKind::ROUTE,
    RefKind::CONSUMER,
    RefKind::SERVICE,
    RefKind::STREAM_ROUTE,
    RefKind::RESOURCE_TYPE,
    RefKind::WEBHOOK,
    RefKind::SCHEMA,
    RefKind::SESSION,
    RefKind::SUBSCRIPTION,
    RefKind::RUN,
    RefKind::APPROVAL,
    RefKind::PROVIDER,
    RefKind::TOOL,
    RefKind::new("agent_channel"),
    RefKind::new("agent_sighting"),
    RefKind::new("api_key"),
    RefKind::new("image_registry"),
    RefKind::new("integration_account"),
    RefKind::new("log_target"),
    RefKind::new("memory"),
    RefKind::new("notification"),
    RefKind::new("notification_destination"),
    RefKind::new("operation_risk_override"),
    RefKind::new("pipeline"),
    RefKind::new("saml_service_provider"),
    RefKind::new("sandbox"),
    RefKind::new("sandbox_version"),
    RefKind::new("service_account"),
    RefKind::new("signal_stream"),
    RefKind::new("topic"),
    RefKind::new("topic_subscription"),
    RefKind::new("workflow"),
    RefKind::new("workflow_evaluation"),
    RefKind::new("workflow_execution"),
];

/// One field's value as it is stored.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum StoredValue {
    Text(String),
    Reference {
        kind: String,
        id: String,
        label: String,
    },
    Change {
        change: StoredChange,
    },
}

/// A transition as it is stored, either side left out when absent.
#[derive(Serialize, Deserialize)]
struct StoredChange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    to: Option<String>,
}

impl StoredValue {
    fn of(value: &FieldValue) -> Self {
        match value {
            FieldValue::Text(text) => Self::Text(text.clone()),
            FieldValue::Reference(reference) => Self::Reference {
                kind: reference.kind().as_str().to_owned(),
                id: reference.id().to_owned(),
                label: reference.label().to_owned(),
            },
            FieldValue::Change(change) => Self::Change {
                change: StoredChange {
                    from: change.from().map(str::to_owned),
                    to: change.to().map(str::to_owned),
                },
            },
        }
    }

    fn into_value(self) -> Result<FieldValue, DomainError> {
        match self {
            Self::Text(text) => Ok(FieldValue::Text(text)),
            Self::Reference { kind, id, label } => Ok(FieldValue::Reference(Reference::new(
                ref_kind(&kind)?,
                id,
                label,
            ))),
            Self::Change { change } => {
                Ok(FieldValue::Change(Change::between(change.from, change.to)))
            }
        }
    }
}

/// The kind `word` names.
fn ref_kind(word: &str) -> Result<RefKind, DomainError> {
    REF_KINDS
        .iter()
        .copied()
        .find(|kind| kind.as_str() == word)
        .ok_or_else(|| DomainError::corrupt_row(PAYLOAD.entity, "a reference to an unknown kind"))
}

/// `data` ready to bind to the payload column.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when it cannot be written out.
pub(crate) fn sealed(data: &EventData) -> Result<Value, DomainError> {
    let fields: BTreeMap<&str, StoredValue> = data
        .fields()
        .iter()
        .map(|(key, value)| (key.as_str(), StoredValue::of(value)))
        .collect();
    PAYLOAD.seal(&fields)
}

/// The payload `stored` holds, its fields by name.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when it does not read, or names a
/// kind of entity this release does not know.
pub(crate) fn opened(stored: Value) -> Result<EventData, DomainError> {
    let fields: BTreeMap<String, StoredValue> = PAYLOAD.open(stored)?;
    fields
        .into_iter()
        .map(|(key, value)| value.into_value().map(|value| (key, value)))
        .collect::<Result<Vec<_>, _>>()
        .map(EventData::from_fields)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// A payload of a scalar, a reference and a change.
    fn payload() -> EventData {
        EventData::new()
            .field("status", "active")
            .reference("role", Reference::new(RefKind::ROLE, "r-1", "viewer"))
            .change("name", "old", "new")
    }

    /// The payload in the shape the column keeps.
    fn stored() -> Value {
        json!({"v": 1, "value": {
            "name": {"change": {"from": "old", "to": "new"}},
            "role": {"kind": "role", "id": "r-1", "label": "viewer"},
            "status": "active"
        }})
    }

    /// A payload is stored in the shape pinned here, and reads back with
    /// every field, its fields by name.
    #[test]
    fn a_payload_is_stored_in_its_pinned_shape() {
        assert_eq!(sealed(&payload()).unwrap(), stored());
        assert_eq!(
            PAYLOAD.seal(&json!({})).unwrap(),
            json!({"v": 1, "value": {}})
        );

        let read = opened(stored()).unwrap();

        assert_eq!(read.get("status"), Some("active"));
        assert_eq!(read.get("role"), Some("r-1"));
        assert_eq!(read.get("name"), Some("new"));
    }

    /// Opening a payload with an unknown reference kind returns a corruption
    /// error.
    #[test]
    fn a_reference_to_an_unknown_kind_is_refused() {
        let stored = json!({"v": 1, "value": {"x": {"kind": "wizard", "id": "1", "label": "l"}}});

        assert!(matches!(
            opened(stored),
            Err(DomainError::Infrastructure(_))
        ));
    }

    /// A change with no side before it, as a creation is, reads back
    /// without one.
    #[test]
    fn a_change_from_nothing_reads_back_from_nothing() {
        let data = EventData::new().change_between("name", None, Some("new".to_owned()));

        let read = opened(sealed(&data).unwrap()).unwrap();

        let Some(FieldValue::Change(change)) = read.value("name") else {
            panic!("the change did not read back");
        };
        assert_eq!(change.from(), None);
        assert_eq!(change.to(), Some("new"));
    }
}
