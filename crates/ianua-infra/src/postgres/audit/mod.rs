//! The stores of the audit context: the trail every dispatched event is
//! kept in, each tenant's records chained and only ever added; the logs
//! read from it, a tenant's, an organization's and the platform's, and the
//! pages an export reads; an agent's evidence; the sweep's verdicts on
//! each chain; the retention purge; a deleted tenant's trail moved back
//! from its own schema; the exports of the logs; and the streams that copy
//! a tenant's records to a SIEM.

pub(crate) mod actors;
mod evidence;
mod exports;
pub(crate) mod logs;
mod moves;
pub(crate) mod payload;
mod retention;
mod streams;
pub(crate) mod through;
mod trail;
mod verdicts;

pub use evidence::PgEvidenceStore;
pub use exports::PgAuditExportStore;
pub use logs::{
    PgAuditExportSource, PgOrgAuditLogStore, PgPlatformAuditLogStore, PgTenantAuditLogStore,
};
pub use moves::PgAuditTrailMover;
pub use retention::PgAuditRetentionStore;
pub use streams::PgAuditStreamStore;
pub use trail::{PgAuditChainVerifier, PgEventDispatcher};
pub use verdicts::PgAuditChainVerdictStore;
