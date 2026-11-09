//! An audit record as a security team's SIEM receives it: one JSON object
//! naming the event, who did it, where it belongs, from where, and its
//! details field by field.
//!
//! Every destination gets the same object, so a team moving from one SIEM
//! to another searches the same fields. The details are written as the
//! trail keeps them: a scalar as text, a reference as its kind, id and
//! label, a change as its two sides.

use std::collections::BTreeMap;

use ianua_domain::domains::audit::builder::ActedThrough;
use ianua_domain::domains::audit::record::AuditRecord;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::data::{EventData, FieldValue, is_sensitive_key};
use ianua_domain::types::{IpAddress, UserAgent};
use serde::Serialize;
use time::format_description::well_known::Rfc3339;

/// One audit record as it is sent.
#[derive(Serialize)]
pub(super) struct RecordJson<'a> {
    id: String,
    event_type: &'static str,
    occurred_at: String,
    actor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_address: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<&'a str>,
    acted_through: Acted,
    details: BTreeMap<&'a str, Field<'a>>,
}

/// How the action was carried out.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Acted {
    Directly,
    Impersonation {
        operator_id: String,
        as_user: String,
    },
    SupportImpersonation {
        admin: String,
        as_user: String,
        impersonation: String,
    },
    WorkflowRun {
        execution: String,
    },
}

/// One detail, as the trail keeps it.
#[derive(Serialize)]
#[serde(untagged)]
enum Field<'a> {
    Text(&'a str),
    Reference {
        kind: &'static str,
        id: &'a str,
        label: &'a str,
    },
    Change {
        change: Sides<'a>,
    },
}

/// The two sides of a change, either left out when absent.
#[derive(Serialize)]
struct Sides<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<&'a str>,
}

impl<'a> RecordJson<'a> {
    /// The object `record` is sent as.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when its time cannot be
    /// written out.
    pub(super) fn of(record: &'a AuditRecord) -> Result<Self, DomainError> {
        Ok(Self {
            id: record.id.to_string(),
            event_type: record.event_type.as_str(),
            occurred_at: record
                .occurred_at
                .format(&Rfc3339)
                .map_err(DomainError::infra)?,
            actor: record.actor.audit_label(),
            organization_id: record.scope.organization_id().map(ToString::to_string),
            tenant_id: record.scope.tenant_id().map(ToString::to_string),
            target: record.target.id(),
            ip_address: record.ip_address.known().map(IpAddress::as_str),
            user_agent: record.user_agent.known().map(UserAgent::as_str),
            acted_through: acted(record.acted_through),
            details: details(&record.payload),
        })
    }

    /// The record's event type, which a destination may file it under.
    pub(super) fn event_type(&self) -> &'static str {
        self.event_type
    }
}

/// `record` written out as its JSON object.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when it cannot be written out.
pub(super) fn json(record: &AuditRecord) -> Result<Vec<u8>, DomainError> {
    serde_json::to_vec(&RecordJson::of(record)?).map_err(DomainError::infra)
}

fn acted(through: ActedThrough) -> Acted {
    match through {
        ActedThrough::Directly => Acted::Directly,
        ActedThrough::Impersonation {
            operator_id,
            as_user,
        } => Acted::Impersonation {
            operator_id: operator_id.to_string(),
            as_user: as_user.to_string(),
        },
        ActedThrough::SupportImpersonation {
            admin,
            as_user,
            impersonation,
        } => Acted::SupportImpersonation {
            admin: admin.to_string(),
            as_user: as_user.to_string(),
            impersonation: impersonation.to_string(),
        },
        ActedThrough::WorkflowRun { execution } => Acted::WorkflowRun {
            execution: execution.to_string(),
        },
    }
}

/// The details of `payload` by name, leaving out any that names a secret.
/// A tenant's SIEM is read by more people than the trail, so a secret that
/// slipped into a payload stops here.
fn details(payload: &EventData) -> BTreeMap<&str, Field<'_>> {
    payload
        .fields()
        .iter()
        .filter(|(name, _)| !is_sensitive_key(name))
        .map(|(name, value)| (name.as_str(), field(value)))
        .collect()
}

fn field(value: &FieldValue) -> Field<'_> {
    match value {
        FieldValue::Text(text) => Field::Text(text),
        FieldValue::Reference(reference) => Field::Reference {
            kind: reference.kind().as_str(),
            id: reference.id(),
            label: reference.label(),
        },
        FieldValue::Change(change) => Field::Change {
            change: Sides {
                from: change.from(),
                to: change.to(),
            },
        },
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use ianua_domain::domains::audit::record::{AuditScope, AuditTarget};
    use ianua_domain::shared::events::data::EventData;
    use ianua_domain::types::{ActorRef, AuditRecordId, EventType, Fact, TenantId};
    use serde_json::{Value, json};
    use time::OffsetDateTime;

    use super::*;

    /// A tenant record of the first event type there is, from an address,
    /// with one detail.
    pub(crate) fn record() -> AuditRecord {
        AuditRecord {
            id: AuditRecordId::new(),
            scope: AuditScope::Tenant {
                organization: Fact::Unknown,
                tenant: TenantId::new(),
            },
            actor: ActorRef::System,
            event_type: EventType::all().next().unwrap(),
            target: AuditTarget::Untargeted,
            ip_address: Fact::Known(IpAddress::new("203.0.113.9").unwrap()),
            user_agent: Fact::Unknown,
            payload: EventData::new().field("status", "active"),
            acted_through: ActedThrough::Directly,
            occurred_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        }
    }

    /// A record is sent with its type, time, actor, tenant, address and
    /// details, and leaves out what it does not know.
    #[test]
    fn a_record_is_sent_with_its_facts_and_details() {
        let record = record();

        let sent: Value = serde_json::from_slice(&json(&record).unwrap()).unwrap();

        assert_eq!(sent["event_type"], json!(record.event_type.as_str()));
        assert_eq!(sent["occurred_at"], json!("2023-11-14T22:13:20Z"));
        assert_eq!(sent["actor"], json!(record.actor.audit_label()));
        assert_eq!(sent["ip_address"], json!("203.0.113.9"));
        assert_eq!(sent["acted_through"], json!({"kind": "directly"}));
        assert_eq!(sent["details"], json!({"status": "active"}));
        assert!(sent.get("user_agent").is_none());
    }

    /// Serializing an audit record omits its refresh-token value while
    /// retaining the active status.
    #[test]
    fn a_field_naming_a_secret_is_left_out() {
        let record = AuditRecord {
            payload: EventData::from_pairs(vec![
                ("refresh_token".to_owned(), "rt_live_secret".to_owned()),
                ("status".to_owned(), "active".to_owned()),
            ]),
            ..record()
        };

        let sent = String::from_utf8(json(&record).unwrap()).unwrap();

        assert!(!sent.contains("rt_live_secret"), "{sent}");
        assert!(sent.contains("active"), "{sent}");
    }
}
