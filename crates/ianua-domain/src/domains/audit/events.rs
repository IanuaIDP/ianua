//! Events of audit log exports: one was asked for, and its file was handed
//! out.
//!
//! Each log has its own scope, so each event comes in the scope of the log
//! it exports: a tenant's, an organization's or the platform's. Writing the
//! file and expiring it are the worker's bookkeeping; the export's status
//! shows those, and the audit trail records who took the records out.

use time::OffsetDateTime;

use crate::domains::audit::export::filter::AuditExportFormat;
use crate::shared::events::data::EventData;
use crate::shared::events::event::{organization_event, platform_event, tenant_event};
use crate::types::{AuditExportId, OrganizationId};

/// The payload every request event writes: the export and its format.
fn requested(export_id: &AuditExportId, format: AuditExportFormat) -> EventData {
    EventData::new()
        .field("export_id", export_id.to_string())
        .field("format", format.as_str())
}

/// The payload every hand-out event writes: the export and how many records
/// its file holds.
fn handed_out(export_id: &AuditExportId, rows: u64) -> EventData {
    EventData::new()
        .field("export_id", export_id.to_string())
        .field("rows", rows.to_string())
}

/// An export of a tenant's audit log was asked for.
#[derive(Debug)]
pub(crate) struct TenantAuditExportRequested {
    /// The requested artifact containing the tenant's filtered audit records.
    pub(crate) export_id: AuditExportId,
    /// The format its file is written in.
    pub(crate) format: AuditExportFormat,
    /// When it was asked for.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantAuditExportRequested => crate::types::event_type::TenantEvent::AuditLogExportRequested,
    fn payload(&self) -> EventData {
        requested(&self.export_id, self.format)
    }
}

/// The file of an export of a tenant's audit log was handed out.
#[derive(Debug)]
pub(crate) struct TenantAuditExportDownloaded {
    /// The artifact whose download link was issued.
    pub(crate) export_id: AuditExportId,
    /// How many records the file holds.
    pub(crate) rows: u64,
    /// When the link was handed out.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantAuditExportDownloaded => crate::types::event_type::TenantEvent::AuditLogExportDownloaded,
    fn payload(&self) -> EventData {
        handed_out(&self.export_id, self.rows)
    }
}

/// An export of an organization's audit log was asked for.
#[derive(Debug)]
pub(crate) struct OrgAuditExportRequested {
    /// The organization whose log is exported.
    pub(crate) organization_id: OrganizationId,
    /// The requested artifact containing the organization's filtered audit records.
    pub(crate) export_id: AuditExportId,
    /// The format its file is written in.
    pub(crate) format: AuditExportFormat,
    /// When it was asked for.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgAuditExportRequested => crate::types::event_type::OrganizationEvent::AuditLogExportRequested,
    fn payload(&self) -> EventData {
        requested(&self.export_id, self.format)
    }
}

/// The file of an export of an organization's audit log was handed out.
#[derive(Debug)]
pub(crate) struct OrgAuditExportDownloaded {
    /// The organization whose log was exported.
    pub(crate) organization_id: OrganizationId,
    /// The organization's artifact whose download link was issued.
    pub(crate) export_id: AuditExportId,
    /// How many records the file holds.
    pub(crate) rows: u64,
    /// When the link was handed out.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgAuditExportDownloaded => crate::types::event_type::OrganizationEvent::AuditLogExportDownloaded,
    fn payload(&self) -> EventData {
        handed_out(&self.export_id, self.rows)
    }
}

/// An export of the platform's audit log was asked for, by an operator.
#[derive(Debug)]
pub(crate) struct PlatformAuditExportRequested {
    /// The requested artifact containing the platform's filtered audit records.
    pub(crate) export_id: AuditExportId,
    /// The format its file is written in.
    pub(crate) format: AuditExportFormat,
    /// When it was asked for.
    pub(crate) occurred_at: OffsetDateTime,
}

platform_event! {
    PlatformAuditExportRequested => crate::types::event_type::OperatorEvent::AuditLogExportRequested,
    fn payload(&self) -> EventData {
        requested(&self.export_id, self.format)
    }
}

/// The file of an export of the platform's audit log was handed out.
#[derive(Debug)]
pub(crate) struct PlatformAuditExportDownloaded {
    /// The platform artifact whose download link was issued.
    pub(crate) export_id: AuditExportId,
    /// How many records the file holds.
    pub(crate) rows: u64,
    /// When the link was handed out.
    pub(crate) occurred_at: OffsetDateTime,
}

platform_event! {
    PlatformAuditExportDownloaded => crate::types::event_type::OperatorEvent::AuditLogExportDownloaded,
    fn payload(&self) -> EventData {
        handed_out(&self.export_id, self.rows)
    }
}
