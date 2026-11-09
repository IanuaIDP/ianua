//! An export request as its row holds it: read back into the aggregate,
//! and written out from it.

use ianua_domain::domains::identity::privacy::export::{DataExportRequest, DataExportRequestRow};
use ianua_domain::domains::identity::privacy::export_state::{ExportState, ExportStatus};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DataExportId, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const EXPORT: Stored = Stored("data export request");

/// An export request as it is read. The store's checked queries fill it.
pub(super) struct ExportRecord {
    pub(super) id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) scope: String,
    pub(super) asked_by: String,
    pub(super) status: String,
    pub(super) ready_at: Option<OffsetDateTime>,
    pub(super) available_until: Option<OffsetDateTime>,
    pub(super) requested_at: OffsetDateTime,
}

impl ExportRecord {
    /// The request the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a word is unknown, or the
    /// row breaks a rule the request keeps.
    pub(super) fn into_request(self) -> Result<DataExportRequest<ResolvedTenant>, DomainError> {
        let status: ExportStatus = EXPORT.choice(&self.status)?;
        DataExportRequest::reconstitute(DataExportRequestRow {
            id: DataExportId::from_uuid(self.id),
            user_id: UserId::from_uuid(self.user_id),
            scope: EXPORT.choice(&self.scope)?,
            asked_by: EXPORT.choice(&self.asked_by)?,
            state: ExportState::from_stored(status, self.ready_at, self.available_until)?,
            requested_at: self.requested_at,
        })
    }
}

/// An export request's columns, as they are written.
pub(super) struct ExportColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) user_id: &'a Uuid,
    pub(super) scope: &'static str,
    pub(super) asked_by: &'static str,
    pub(super) status: &'static str,
    pub(super) ready_at: Option<OffsetDateTime>,
    pub(super) available_until: Option<OffsetDateTime>,
    pub(super) requested_at: OffsetDateTime,
}

impl<'a> ExportColumns<'a> {
    /// The columns `request` is written to.
    pub(super) fn of(request: &'a DataExportRequest<ResolvedTenant>) -> Self {
        Self {
            id: request.id().as_uuid(),
            user_id: request.user_id().as_uuid(),
            scope: request.scope().word(),
            asked_by: request.asked_by().word(),
            status: request.status().word(),
            ready_at: request.state().ready_at(),
            available_until: request.state().available_until(),
            requested_at: request.requested_at(),
        }
    }
}
