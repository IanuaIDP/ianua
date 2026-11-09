//! The audit log export a request names.

use ianua_domain::types::AuditExportId;
use serde::Deserialize;
use uuid::Uuid;

/// `.../audit-log/exports/{id}`: one export of an audit log.
#[derive(Deserialize)]
pub(crate) struct AuditExportPath {
    id: Uuid,
}

impl AuditExportPath {
    /// The export named.
    #[must_use]
    pub(crate) fn export(&self) -> AuditExportId {
        AuditExportId::from_uuid(self.id)
    }
}
