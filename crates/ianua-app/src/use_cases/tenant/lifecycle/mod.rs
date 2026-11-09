//! A tenant's life: provisioning, activating, suspending, archiving,
//! restoring, deleting and reading it, and the sweep that deletes archived
//! tenants once their grace has passed.

pub(crate) mod activate;
pub(crate) mod archive;
pub(crate) mod delete;
pub(crate) mod delete_archived;
pub(crate) mod delete_early;
pub(crate) mod provision;
pub(crate) mod reactivate;
/// Tenants as people read them.
pub(crate) mod reading;
pub(crate) mod restore;
pub mod steward;
pub(crate) mod suspend;

pub use activate::{ActivateTenantPorts, ActivateTenantUseCase};
pub use archive::{ArchiveTenantPorts, ArchiveTenantUseCase};
pub use delete::{DeleteTenantPorts, DeleteTenantUseCase};
pub use delete_archived::{DeleteArchivedPorts, DeleteArchivedUseCase};
pub use delete_early::{
    DeleteTenantEarlyPorts, DeleteTenantEarlyRequest, DeleteTenantEarlyUseCase,
};
pub use provision::{ProvisionTenantPorts, ProvisionTenantRequest, ProvisionTenantUseCase};
pub use reactivate::{ReactivateTenantPorts, ReactivateTenantUseCase};
pub use reading::{
    GetTenantLabelPorts, GetTenantLabelUseCase, GetTenantMetricsPorts, GetTenantMetricsUseCase,
    GetTenantPorts, GetTenantUseCase, ListTenantsPorts, ListTenantsRequest, ListTenantsUseCase,
    TenantLabel, TenantLister, TenantMetrics, TenantRead, TenantViewer,
};
pub use restore::{RestoreTenantPorts, RestoreTenantUseCase};
pub use suspend::{SuspendTenantPorts, SuspendTenantUseCase};
