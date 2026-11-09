//! An audit log export as its row holds it: read back into the aggregate,
//! and written out from it.

use ianua_domain::domains::audit::access::{AuditLogOf, LogReach};
use ianua_domain::domains::audit::export::filter::{
    AuditExportFilter, AuditExportFilterParts, AuditTargetId, EventTypePrefix,
};
use ianua_domain::domains::audit::export::seal::{ExportSeal, FileDigest};
use ianua_domain::domains::audit::export::state::{AuditExportState, AuditExportStatus};
use ianua_domain::domains::audit::export::{AuditLogExport, AuditLogExportRow};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ActorRef, AuditExportId, IpAddress, OrganizationId, TenantId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const EXPORT: Stored = Stored("audit log export");

const RECORD_FILTER: Kept = Kept {
    entity: EXPORT.0,
    column: "record_filter",
    shape: 1,
};

/// Which records an export holds, as the column keeps it: each part left
/// out narrows nothing, the actor by the label of one principal, and
/// `reach` the only tenants whose records it holds, left out for every
/// tenant.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct StoredFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    event_type: Option<String>,
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    after: Option<OffsetDateTime>,
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    before: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ip_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reach: Option<Vec<Uuid>>,
}

/// `reach` as the column keeps it: no list for every tenant.
fn stored_reach(reach: &LogReach) -> Option<Vec<Uuid>> {
    match reach {
        LogReach::Every => None,
        LogReach::Tenants(tenants) => Some(tenants.iter().map(|t| *t.as_uuid()).collect()),
    }
}

/// The reach `tenants` keeps: every tenant when it is no list.
fn read_reach(tenants: Option<Vec<Uuid>>) -> LogReach {
    tenants.map_or(LogReach::Every, |tenants| {
        LogReach::Tenants(tenants.into_iter().map(TenantId::from_uuid).collect())
    })
}

impl StoredFilter {
    fn of(filter: &AuditExportFilter) -> Self {
        let parts = filter.parts();
        Self {
            event_type: parts.event_type.as_ref().map(|p| p.as_str().to_owned()),
            after: parts.after,
            before: parts.before,
            actor: parts.actor.as_ref().map(ActorRef::audit_label),
            tenant_id: parts.tenant_id.map(|tenant| *tenant.as_uuid()),
            target: parts.target.as_ref().map(|t| t.as_str().to_owned()),
            ip_address: parts.ip_address.as_ref().map(|ip| ip.as_str().to_owned()),
            reach: stored_reach(filter.reach()),
        }
    }

    fn into_filter(self) -> Result<AuditExportFilter, DomainError> {
        let reach = read_reach(self.reach);
        let parts = AuditExportFilterParts {
            event_type: self
                .event_type
                .map(|p| EXPORT.value("event type", EventTypePrefix::new(p)))
                .transpose()?,
            after: self.after,
            before: self.before,
            actor: self
                .actor
                .map(|label| ActorRef::from_audit_label(&label))
                .transpose()?,
            tenant_id: self.tenant_id.map(TenantId::from_uuid),
            target: self
                .target
                .map(|t| EXPORT.value("target", AuditTargetId::new(t)))
                .transpose()?,
            ip_address: self
                .ip_address
                .map(|ip| EXPORT.value("ip address", IpAddress::new(ip)))
                .transpose()?,
        };
        AuditExportFilter::from_stored(parts, reach)
    }
}

/// An export as it is read. The store's checked queries fill it.
pub(super) struct ExportRecord {
    pub(super) id: Uuid,
    pub(super) log: String,
    pub(super) organization_id: Option<Uuid>,
    pub(super) tenant_id: Option<Uuid>,
    pub(super) requested_by: String,
    pub(super) record_filter: Value,
    pub(super) format: String,
    pub(super) status: String,
    pub(super) state_at: Option<OffsetDateTime>,
    pub(super) available_until: Option<OffsetDateTime>,
    pub(super) row_count: Option<i64>,
    pub(super) requested_at: OffsetDateTime,
    pub(super) file_sha256: Option<Vec<u8>>,
    pub(super) seal: Option<String>,
}

impl ExportRecord {
    /// The export the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the export
    /// keeps.
    pub(super) fn into_export(self) -> Result<AuditLogExport, DomainError> {
        let state = self.state()?;
        let filter: StoredFilter = RECORD_FILTER.open(self.record_filter)?;
        AuditLogExport::reconstitute(AuditLogExportRow {
            id: AuditExportId::from_uuid(self.id),
            log: log_of(&self.log, self.organization_id, self.tenant_id)?,
            requested_by: ActorRef::from_audit_label(&self.requested_by)?,
            filter: filter.into_filter()?,
            format: EXPORT.choice(&self.format)?,
            state,
            seal: self
                .seal
                .map(|seal| EXPORT.value("seal", ExportSeal::new(seal)))
                .transpose()?,
            requested_at: self.requested_at,
        })
    }

    /// The state the status column and its parts make.
    fn state(&self) -> Result<AuditExportState, DomainError> {
        let status: AuditExportStatus = EXPORT.choice(&self.status)?;
        let parts = (
            self.state_at,
            self.available_until,
            self.row_count,
            self.file_sha256.as_deref(),
        );
        match (status, parts) {
            (AuditExportStatus::Pending, (None, None, None, None)) => Ok(AuditExportState::Pending),
            (
                AuditExportStatus::Ready,
                (Some(at), Some(available_until), Some(rows), Some(digest)),
            ) => Ok(AuditExportState::Ready {
                at,
                available_until,
                rows: u64::try_from(rows)
                    .map_err(|_| DomainError::corrupt_row(EXPORT.0, "a count below zero"))?,
                digest: FileDigest::from_bytes(digest)?,
            }),
            (AuditExportStatus::Failed, (Some(at), None, None, None)) => {
                Ok(AuditExportState::Failed { at })
            }
            (AuditExportStatus::Expired, (None, None, None, None)) => Ok(AuditExportState::Expired),
            _ => Err(DomainError::corrupt_row(
                EXPORT.0,
                "a state missing its parts",
            )),
        }
    }
}

/// The log the columns name.
fn log_of(
    word: &str,
    organization: Option<Uuid>,
    tenant: Option<Uuid>,
) -> Result<AuditLogOf, DomainError> {
    match (word, organization, tenant) {
        ("platform", None, None) => Ok(AuditLogOf::Platform),
        ("organization", Some(organization), None) => Ok(AuditLogOf::Organization(
            OrganizationId::from_uuid(organization),
        )),
        ("tenant", None, Some(tenant)) => Ok(AuditLogOf::Tenant(TenantId::from_uuid(tenant))),
        _ => Err(DomainError::corrupt_row(EXPORT.0, "an unknown log")),
    }
}

/// The scope columns of `log`: its organization or its tenant.
pub(super) fn scope_of(log: AuditLogOf) -> (Option<Uuid>, Option<Uuid>) {
    match log {
        AuditLogOf::Platform => (None, None),
        AuditLogOf::Organization(organization) => (Some(*organization.as_uuid()), None),
        AuditLogOf::Tenant(tenant) => (None, Some(*tenant.as_uuid())),
    }
}

/// An export's columns, as they are written.
pub(super) struct ExportColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) log: &'static str,
    pub(super) organization_id: Option<Uuid>,
    pub(super) tenant_id: Option<Uuid>,
    pub(super) requested_by: String,
    pub(super) record_filter: Value,
    pub(super) format: &'static str,
    pub(super) status: &'static str,
    pub(super) state_at: Option<OffsetDateTime>,
    pub(super) available_until: Option<OffsetDateTime>,
    pub(super) row_count: Option<i64>,
    pub(super) requested_at: OffsetDateTime,
    pub(super) file_sha256: Option<Vec<u8>>,
    pub(super) seal: Option<&'a str>,
}

impl<'a> ExportColumns<'a> {
    /// The columns `export` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the filter cannot be
    /// written out.
    pub(super) fn of(export: &'a AuditLogExport) -> Result<Self, DomainError> {
        let (organization_id, tenant_id) = scope_of(export.log());
        let written = Written::of(export.state());
        Ok(Self {
            id: export.id().as_uuid(),
            log: export.log().as_str(),
            organization_id,
            tenant_id,
            requested_by: export.requested_by().audit_label(),
            record_filter: RECORD_FILTER.seal(&StoredFilter::of(export.filter()))?,
            format: export.format().word(),
            status: export.status().word(),
            state_at: export.state().since(),
            available_until: written.map(|file| file.available_until),
            row_count: written.map(|file| i64::try_from(file.rows).unwrap_or(i64::MAX)),
            requested_at: export.requested_at(),
            file_sha256: written.map(|file| file.digest.as_bytes().to_vec()),
            seal: export.seal().map(ExportSeal::as_str),
        })
    }
}

/// What a ready export's columns keep of its file.
#[derive(Clone, Copy)]
struct Written {
    available_until: OffsetDateTime,
    rows: u64,
    digest: FileDigest,
}

impl Written {
    /// The file `state` has, once it is ready.
    fn of(state: AuditExportState) -> Option<Self> {
        let AuditExportState::Ready {
            available_until,
            rows,
            digest,
            ..
        } = state
        else {
            return None;
        };
        Some(Self {
            available_until,
            rows,
            digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::UserId;
    use serde_json::json;

    use super::*;
    use crate::test_support::rows::{at, pinned};

    /// A filter by event type, window and actor, in the shape the column
    /// keeps.
    fn stored_filter(actor: &ActorRef) -> Value {
        json!({"v": 1, "value": {
            "event_type": "authentication.",
            "after": "2027-01-15T08:00:00Z",
            "before": "2027-01-15T08:00:10Z",
            "actor": actor.audit_label()
        }})
    }

    /// A filter stored in the shape pinned here reads back, and is written
    /// again in the same shape; an empty one keeps nothing.
    #[test]
    fn a_filter_is_stored_in_its_pinned_shape() {
        let ann = ActorRef::User(UserId::new());
        let read: StoredFilter = RECORD_FILTER.open(stored_filter(&ann)).unwrap();
        let filter = read.into_filter().unwrap();

        assert_eq!(filter.parts().after, Some(pinned(0)));
        assert_eq!(
            RECORD_FILTER.seal(&StoredFilter::of(&filter)).unwrap(),
            stored_filter(&ann)
        );
        assert_eq!(
            RECORD_FILTER
                .seal(&StoredFilter::of(&AuditExportFilter::default()))
                .unwrap(),
            json!({"v": 1, "value": {}})
        );
    }

    /// A reach naming no tenant stays one that shows none when read back:
    /// an empty list is a viewer's export, not an owner's.
    #[test]
    fn a_reach_of_no_tenant_is_kept_apart_from_every_tenant() {
        let none = StoredFilter {
            reach: Some(Vec::new()),
            ..StoredFilter::default()
        };
        let tenant = TenantId::new();
        let one = StoredFilter {
            reach: Some(vec![*tenant.as_uuid()]),
            ..StoredFilter::default()
        };

        assert_eq!(
            *none.into_filter().unwrap().reach(),
            LogReach::Tenants(Vec::new())
        );
        assert_eq!(
            *one.into_filter().unwrap().reach(),
            LogReach::Tenants(vec![tenant])
        );
        assert_eq!(
            *StoredFilter::default().into_filter().unwrap().reach(),
            LogReach::Every
        );
    }

    /// A stored export filter whose end precedes its start is rejected as
    /// corrupt.
    #[test]
    fn a_filter_whose_window_runs_backwards_is_refused() {
        let backwards = StoredFilter {
            after: Some(at(10)),
            before: Some(at(0)),
            ..StoredFilter::default()
        };

        assert!(matches!(
            backwards.into_filter(),
            Err(DomainError::Infrastructure(_))
        ));
    }
}
