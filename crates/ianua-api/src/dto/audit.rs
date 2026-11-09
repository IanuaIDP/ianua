//! Audit bodies: the audit log of an organization, a tenant or the whole
//! platform as a page, exports of it written in the background, and the
//! last verdict on a tenant's audit chain.

use ianua_app::error::AppError;
use ianua_app::listing::{PageRequest, SortOrder};
use ianua_app::ports::audit::{AuditLogEntry, AuditLogFilter, AuditLogSortField};
use ianua_app::use_cases::audit::ListForOrgRequest;
use ianua_app::use_cases::audit::exports::{ExportAnswer, Selection};
use ianua_domain::domains::audit::builder::ActedThrough;
use ianua_domain::domains::audit::export::filter::{
    AuditExportFilter, AuditExportFilterParts, AuditExportFormat, AuditTargetId, EventTypePrefix,
};
use ianua_domain::domains::audit::export::state::AuditExportState;
use ianua_domain::domains::audit::verdict::ChainVerdict;
use ianua_domain::domains::audit::walk::ChainStanding;
use ianua_domain::shared::events::data::{EventData, FieldValue};
use ianua_domain::types::{AuditExportId, IpAddress, TenantId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;
use crate::extractors::audit::actor_named;
use crate::extractors::time::parse_rfc3339;

/// Which audit entries to read.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct AuditLogQueryParams {
    /// Only events whose type starts with this, such as
    /// `organization.org_user`.
    pub event_type: Option<String>,
    /// Only events after this RFC 3339 timestamp. Named `since` because
    /// `after` is the page cursor.
    pub since: Option<String>,
    /// Only events before this RFC 3339 timestamp.
    pub before: Option<String>,
    /// Only events this actor performed: `system`, `anonymous`, or
    /// `<kind>:<uuid>` with kind `user`, `org_user`, `operator`, `api_key`,
    /// `oauth_client` or `service`.
    pub actor: Option<String>,
    /// Only events in this tenant. A tenant's own log is always its own,
    /// whatever this says.
    pub tenant_id: Option<Uuid>,
    /// Only events about the entity with this id.
    pub target: Option<String>,
    /// Only events from this client address.
    pub ip_address: Option<String>,
}

impl AuditLogQueryParams {
    /// The page `page` of entries asked for, in `sort` order.
    ///
    /// # Errors
    ///
    /// A validation error for a timestamp that is not RFC 3339.
    pub(crate) fn listing(
        &self,
        sort: SortOrder<AuditLogSortField>,
        page: PageRequest,
    ) -> Result<ListForOrgRequest, ApiError> {
        Ok(ListForOrgRequest {
            filter: self.filter()?,
            sort,
            page,
        })
    }

    /// The event type, time bounds, actor, tenant, target and address asked
    /// for, refused when a timestamp is not RFC 3339, the actor names no
    /// actor or the address is no IP address.
    fn filter(&self) -> Result<AuditLogFilter, ApiError> {
        Ok(AuditLogFilter {
            event_type: self.event_type.clone(),
            after: self.since.as_deref().map(parse_rfc3339).transpose()?,
            before: self.before.as_deref().map(parse_rfc3339).transpose()?,
            actor: self.actor.as_deref().map(actor_named).transpose()?,
            tenant_id: self.tenant_id.map(TenantId::from_uuid),
            target: self.target.clone(),
            ip_address: self
                .ip_address
                .clone()
                .map(IpAddress::new)
                .transpose()
                .map_err(ApiError::validation)?,
            names: None,
            sign_ins_of: None,
            acting_as: None,
        })
    }
}

/// A recorded action with its actor, scope, affected entity and details.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AuditLogEntryResponse {
    /// The record's id.
    pub id: Uuid,
    /// The event type, such as `tenant.provisioned`.
    pub event_type: &'static str,
    /// Who performed the action.
    pub actor: String,
    /// The tenant the event occurred in, `null` for organization- or
    /// platform-level events.
    pub tenant_id: Option<Uuid>,
    /// The tenant's URL slug, when the event is tenant-scoped.
    pub tenant_slug: Option<String>,
    /// The tenant's name, when the event is tenant-scoped.
    pub tenant_name: Option<String>,
    /// The entity the event affected, if any.
    pub target_id: Option<String>,
    /// The client's address.
    pub ip_address: Option<String>,
    /// What happened: named values, each a scalar, an entity reference
    /// (`{ kind, id, label }`), or a change (`{ change: { from, to } }`).
    #[schema(value_type = Object)]
    pub details: serde_json::Value,
    /// When the event occurred.
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    /// Whom or what the actor acted through; `null` when they acted in
    /// their own name.
    pub acted_through: Option<ActedThroughResponse>,
}

/// Whom or what an actor acted through, with the ids its kind names.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ActedThroughResponse {
    /// `impersonation` (an operator acting as a user),
    /// `support_impersonation` (a tenant admin acting as one of its people)
    /// or `workflow_run` (a workflow run acting as the person it is for).
    pub kind: &'static str,
    /// The operator, for `impersonation`.
    pub operator_id: Option<Uuid>,
    /// The person acted as, for either impersonation.
    pub as_user_id: Option<Uuid>,
    /// The support impersonation, for `support_impersonation`.
    pub impersonation_id: Option<Uuid>,
    /// The workflow run, for `workflow_run`.
    pub execution_id: Option<Uuid>,
}

impl ActedThroughResponse {
    /// Names the origin with all kind-specific identifiers absent until they are mapped.
    fn named(kind: &'static str) -> Self {
        Self {
            kind,
            operator_id: None,
            as_user_id: None,
            impersonation_id: None,
            execution_id: None,
        }
    }

    /// What `through` names, or `None` when the actor acted directly.
    fn of(through: ActedThrough) -> Option<Self> {
        let named = Self::named(through.kind());
        match through {
            ActedThrough::Directly => None,
            ActedThrough::Impersonation {
                operator_id,
                as_user,
            } => Some(Self {
                operator_id: Some(*operator_id.as_uuid()),
                as_user_id: Some(*as_user.as_uuid()),
                ..named
            }),
            ActedThrough::SupportImpersonation {
                as_user,
                impersonation,
                ..
            } => Some(Self {
                as_user_id: Some(*as_user.as_uuid()),
                impersonation_id: Some(*impersonation.as_uuid()),
                ..named
            }),
            ActedThrough::WorkflowRun { execution } => Some(Self {
                execution_id: Some(*execution.as_uuid()),
                ..named
            }),
        }
    }
}

impl From<AuditLogEntry> for AuditLogEntryResponse {
    fn from(entry: AuditLogEntry) -> Self {
        Self {
            id: *entry.id.as_uuid(),
            event_type: entry.event_type.as_str(),
            actor: entry.actor_display,
            tenant_id: entry.tenant_id.map(|tenant| *tenant.as_uuid()),
            tenant_slug: entry.tenant_slug.map(|slug| slug.as_str().to_owned()),
            tenant_name: entry.tenant_name.map(|name| name.as_str().to_owned()),
            target_id: entry.target.id().map(ToOwned::to_owned),
            ip_address: entry.ip_address.map(|ip| ip.as_str().to_owned()),
            details: details(&entry.payload),
            occurred_at: entry.occurred_at,
            acted_through: ActedThroughResponse::of(entry.acted_through),
        }
    }
}

/// The format an audit log export is written in.
#[derive(Deserialize, Default, Clone, Copy, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AuditExportFormatBody {
    /// One row per entry, the columns
    /// `id,event_type,actor,tenant,target_id,ip_address,occurred_at,acted_through,through_id`.
    #[default]
    Csv,
    /// A JSON array of entries, each as the list shows it.
    Json,
}

impl From<AuditExportFormatBody> for AuditExportFormat {
    fn from(format: AuditExportFormatBody) -> Self {
        match format {
            AuditExportFormatBody::Csv => Self::Csv,
            AuditExportFormatBody::Json => Self::Json,
        }
    }
}

/// Which audit entries an export holds, with the list's filters, and how
/// its file is written. Every field may be left out.
#[derive(Deserialize, Default, utoipa::ToSchema)]
pub(crate) struct AuditExportBody {
    /// `csv` (the default) or `json`.
    #[serde(default)]
    pub format: Option<AuditExportFormatBody>,
    /// Only events whose type starts with this, such as
    /// `organization.org_user`.
    #[serde(default)]
    pub event_type: Option<String>,
    /// Only events after this instant (RFC 3339).
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub after: Option<OffsetDateTime>,
    /// Only events before this instant (RFC 3339).
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub before: Option<OffsetDateTime>,
    /// Only events this actor performed, named as the list's `actor`.
    #[serde(default)]
    pub actor: Option<String>,
    /// Only events in this tenant. A tenant's own export is always of its
    /// own log, whatever this says.
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    /// Only events about the entity with this id.
    #[serde(default)]
    pub target: Option<String>,
    /// Only events from this client address.
    #[serde(default)]
    pub ip_address: Option<String>,
}

impl AuditExportBody {
    /// The export `body` asks for; no body asks for every entry as CSV.
    ///
    /// # Errors
    ///
    /// A validation error for an event type that is no dotted lowercase
    /// name, an actor that names no actor, an address that is no IP
    /// address, a target that is empty or too long, or `after` not before
    /// `before`.
    pub(crate) fn request(body: Option<Self>) -> Result<Selection, ApiError> {
        let body = body.unwrap_or_default();
        let parts = AuditExportFilterParts {
            event_type: body
                .event_type
                .map(EventTypePrefix::new)
                .transpose()
                .map_err(ApiError::validation)?,
            after: body.after,
            before: body.before,
            actor: body.actor.as_deref().map(actor_named).transpose()?,
            tenant_id: body.tenant_id.map(TenantId::from_uuid),
            target: body
                .target
                .map(AuditTargetId::new)
                .transpose()
                .map_err(ApiError::validation)?,
            ip_address: body
                .ip_address
                .map(IpAddress::new)
                .transpose()
                .map_err(ApiError::validation)?,
        };
        let filter = AuditExportFilter::new(parts).map_err(AppError::from_domain)?;
        Ok(Selection {
            filter,
            format: body.format.unwrap_or_default().into(),
        })
    }
}

/// The export asked for, being written.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AuditExportAcceptedResponse {
    /// The export's id, to ask for its status by.
    pub id: Uuid,
    /// Always `pending`: the worker writes the file next.
    pub status: &'static str,
}

impl From<AuditExportId> for AuditExportAcceptedResponse {
    fn from(id: AuditExportId) -> Self {
        Self {
            id: *id.as_uuid(),
            status: "pending",
        }
    }
}

/// One export of an audit log: where it stands, and once written, how much
/// it holds and a link to its file.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AuditExportResponse {
    /// The export's id.
    pub id: Uuid,
    /// `pending` while the worker writes the file, `ready` to download,
    /// `failed` when it was not written within a day, `expired` once its
    /// week is over and the file is gone.
    pub status: &'static str,
    /// `csv` or `json`.
    pub format: &'static str,
    /// When it was asked for.
    #[serde(with = "time::serde::rfc3339")]
    pub requested_at: OffsetDateTime,
    /// When the file was written, once it is.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub ready_at: Option<OffsetDateTime>,
    /// Until when the file may be downloaded, while it is ready.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub available_until: Option<OffsetDateTime>,
    /// How many entries the file holds, once written. Never cut short.
    pub rows: Option<u64>,
    /// The SHA-256 of the file in lower-case hex, while it is ready, to
    /// compare with `sha256sum` of the downloaded file.
    pub sha256: Option<String>,
    /// For a tenant's log, while the file is ready: a compact JWS typed
    /// `ianua-audit-seal+jwt`, signed with the tenant's signing key, naming
    /// the export as `jti`, the tenant as `sub` and the file's `sha256`,
    /// `rows`, `format` and `covers_until`. Check it against the tenant's
    /// published keys. An organization's or the platform's export has none.
    pub seal: Option<String>,
    /// A signed link that downloads the file once and works for a few
    /// minutes, while it is ready. Each request for the export hands out a
    /// fresh one and records the download.
    pub download_url: Option<String>,
}

impl From<ExportAnswer> for AuditExportResponse {
    fn from(answer: ExportAnswer) -> Self {
        let export = &answer.export;
        let (ready_at, available_until, rows, sha256) = match export.state() {
            AuditExportState::Ready {
                at,
                available_until,
                rows,
                digest,
            } => (
                Some(at),
                Some(available_until),
                Some(rows),
                Some(digest.hex()),
            ),
            AuditExportState::Pending
            | AuditExportState::Failed { .. }
            | AuditExportState::Expired => (None, None, None, None),
        };
        Self {
            id: *export.id().as_uuid(),
            status: export.status().as_str(),
            format: export.format().as_str(),
            requested_at: export.requested_at(),
            ready_at,
            available_until,
            rows,
            sha256,
            seal: export.seal().map(|seal| seal.as_str().to_owned()),
            download_url: answer.download.map(|url| url.as_str().to_owned()),
        }
    }
}

/// The last verdict on a tenant's tamper-evident audit chain, as the
/// scheduled sweep found it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AuditChainVerificationResponse {
    /// `intact` when every record verified up to the signed head,
    /// `intact_so_far` when every record walked verified but the sweep has
    /// more to walk, `broken` when a record did not verify, and
    /// `not_verified_yet` before the first sweep.
    pub status: &'static str,
    /// When the sweep walked the chain; `null` before the first sweep.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub verified_at: Option<OffsetDateTime>,
    /// The sequence number of the last record verified; `null` when none
    /// was.
    pub checked_through_seq: Option<i64>,
    /// The sequence number of the first tampered record, when the chain is
    /// broken.
    pub broken_at_seq: Option<i64>,
}

impl From<Option<ChainVerdict>> for AuditChainVerificationResponse {
    fn from(verdict: Option<ChainVerdict>) -> Self {
        let Some(verdict) = verdict else {
            return Self {
                status: "not_verified_yet",
                verified_at: None,
                checked_through_seq: None,
                broken_at_seq: None,
            };
        };
        let broken_at_seq = match verdict.standing() {
            ChainStanding::BrokenAt(seq) => Some(seq),
            ChainStanding::Intact | ChainStanding::IntactSoFar => None,
        };
        Self {
            status: verdict.standing().as_str(),
            verified_at: Some(verdict.verified_at()),
            checked_through_seq: verdict.checkpoint().verified_through(),
            broken_at_seq,
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

/// One detail field as JSON: text as a string, a reference or a change as
/// an object.
fn field_json(value: &FieldValue) -> serde_json::Value {
    match value {
        FieldValue::Text(text) => serde_json::Value::String(text.clone()),
        FieldValue::Reference(reference) => serde_json::json!({
            "kind": reference.kind().as_str(),
            "id": reference.id(),
            "label": reference.label(),
        }),
        FieldValue::Change(change) => {
            let mut moved = serde_json::Map::new();
            if let Some(from) = change.from() {
                moved.insert("from".to_owned(), serde_json::Value::from(from));
            }
            if let Some(to) = change.to() {
                moved.insert("to".to_owned(), serde_json::Value::from(to));
            }
            serde_json::json!({ "change": moved })
        }
    }
}
