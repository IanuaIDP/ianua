//! What the audit trail holds about an agent: its activity timeline, and its
//! records as evidence with their place in the tenant's hash chain.

use ianua_app::listing::{PageRequest, SortOrder};
use ianua_app::ports::audit::{AuditLogEntry, AuditLogFilter, AuditLogSortField};
use ianua_app::use_cases::agents::evidence::{
    EvidencePage, GetAgentActivityRequest, GetAgentRequest,
};
use ianua_domain::domains::audit::evidence::EvidenceRecord;
use ianua_domain::shared::events::data::{EventData, FieldValue};
use ianua_domain::types::AgentId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::audit::AuditChainVerificationResponse;
use crate::error::ApiError;
use crate::extractors::time::parse_rfc3339;

/// Query parameters for an agent's activity timeline.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ActivityQueryParams {
    /// Only events whose type starts with this, such as `agents.delegation`.
    pub event_type: Option<String>,
    /// Only events after this RFC 3339 timestamp. Named `since` because
    /// `after` is the page cursor.
    pub since: Option<String>,
    /// Only events before this RFC 3339 timestamp.
    pub before: Option<String>,
}

impl ActivityQueryParams {
    /// The timeline of `agent_id` this query asks for, in `sort` order.
    ///
    /// # Errors
    ///
    /// - A validation error when `since` or `before` is not an RFC 3339
    ///   timestamp.
    pub(crate) fn listing(
        self,
        agent_id: AgentId,
        sort: SortOrder<AuditLogSortField>,
        page: PageRequest,
    ) -> Result<GetAgentActivityRequest, ApiError> {
        Ok(GetAgentActivityRequest {
            agent_id,
            filter: AuditLogFilter {
                event_type: self.event_type,
                after: self.since.as_deref().map(parse_rfc3339).transpose()?,
                before: self.before.as_deref().map(parse_rfc3339).transpose()?,
                ..AuditLogFilter::default()
            },
            sort,
            page,
        })
    }
}

/// One record of an agent's activity.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AgentActivityEntryResponse {
    /// Unique record ID.
    pub id: Uuid,
    /// The stable name identifying which action was recorded.
    pub event_type: String,
    /// Who performed the action.
    pub actor: String,
    /// The tenant the event occurred in.
    pub tenant_id: Option<Uuid>,
    /// The tenant's URL slug.
    pub tenant_slug: Option<String>,
    /// The tenant's display name.
    pub tenant_name: Option<String>,
    /// Target entity ID, if any.
    pub target_id: Option<String>,
    /// Source IP address.
    pub ip_address: Option<String>,
    /// What happened: named values, each a scalar, an entity reference
    /// (`{ kind, id, label }`), or a change (`{ change: { from, to } }`).
    #[schema(value_type = Object)]
    pub details: serde_json::Value,
    /// When the event occurred.
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
}

impl From<AuditLogEntry> for AgentActivityEntryResponse {
    fn from(entry: AuditLogEntry) -> Self {
        Self {
            id: *entry.id.as_uuid(),
            event_type: entry.event_type.as_str().to_owned(),
            actor: entry.actor_display,
            tenant_id: entry.tenant_id.map(|t| *t.as_uuid()),
            tenant_slug: entry.tenant_slug.map(|slug| slug.as_str().to_owned()),
            tenant_name: entry.tenant_name.map(|name| name.as_str().to_owned()),
            target_id: entry.target.id().map(str::to_owned),
            ip_address: entry.ip_address.map(|ip| ip.as_str().to_owned()),
            details: details(&entry.payload),
            occurred_at: entry.occurred_at,
        }
    }
}

/// An audit payload as a flat JSON object: a string for a scalar,
/// `{ kind, id, label }` for a reference, `{ change: { from, to } }` for a
/// change.
fn details(data: &EventData) -> serde_json::Value {
    let fields = data
        .fields()
        .iter()
        .map(|(key, value)| (key.clone(), field_json(value)))
        .collect();
    serde_json::Value::Object(fields)
}

/// One payload field as JSON: a string, a `{ kind, id, label }` reference,
/// or a `{ change: { from, to } }` that leaves out a missing side.
fn field_json(value: &FieldValue) -> serde_json::Value {
    match value {
        FieldValue::Text(text) => serde_json::Value::String(text.clone()),
        FieldValue::Reference(reference) => serde_json::json!({
            "kind": reference.kind().as_str(),
            "id": reference.id(),
            "label": reference.label(),
        }),
        FieldValue::Change(change) => {
            let mut inner = serde_json::Map::new();
            if let Some(from) = change.from() {
                inner.insert("from".to_owned(), from.into());
            }
            if let Some(to) = change.to() {
                inner.insert("to".to_owned(), to.into());
            }
            serde_json::json!({ "change": inner })
        }
    }
}

/// Query parameters for paging evidence.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct EvidenceParams {
    /// Return records after this chain position (default: from the start).
    #[serde(default)]
    pub after_seq: i64,
    /// How many records at most (default 50, at most 200).
    #[serde(default = "default_evidence_limit")]
    pub limit: u32,
}

/// How many evidence records a page holds when the caller does not say.
fn default_evidence_limit() -> u32 {
    50
}

impl EvidenceParams {
    /// The page of `agent_id`'s evidence asked for.
    #[must_use]
    pub(crate) fn for_agent(&self, agent_id: AgentId) -> GetAgentRequest {
        GetAgentRequest {
            agent_id,
            after_seq: self.after_seq,
            limit: self.limit,
        }
    }
}

/// One audit record with its place in the tenant's chain.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct EvidenceRecordResponse {
    /// The record's position in the chain: what a verdict cites.
    pub seq: i64,
    /// The record's id.
    pub id: Uuid,
    /// What happened.
    pub event_type: String,
    /// The event's details.
    #[schema(value_type = Object)]
    pub details: serde_json::Value,
    /// When it happened.
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    /// The record's link, hex.
    pub entry_hash: String,
    /// The link it follows, hex.
    pub prev_hash: String,
}

impl From<EvidenceRecord> for EvidenceRecordResponse {
    fn from(record: EvidenceRecord) -> Self {
        Self {
            seq: record.seq,
            id: *record.id.as_uuid(),
            event_type: record.event_type.as_str().to_owned(),
            details: details(&record.payload),
            occurred_at: record.occurred_at,
            entry_hash: hex(&record.entry_hash),
            prev_hash: hex(&record.prev_hash),
        }
    }
}

/// A page of an agent's evidence and the state of the chain it sits in.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct EvidencePageResponse {
    /// The records, oldest first.
    pub records: Vec<EvidenceRecordResponse>,
    /// The scheduled sweep's last verdict on the tenant's chain. Records
    /// from a chain that does not verify prove nothing.
    pub chain: AuditChainVerificationResponse,
}

impl From<EvidencePage> for EvidencePageResponse {
    fn from(page: EvidencePage) -> Self {
        Self {
            records: page
                .records
                .into_iter()
                .map(EvidenceRecordResponse::from)
                .collect(),
            chain: AuditChainVerificationResponse::from(page.chain),
        }
    }
}

/// Lowercase hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
