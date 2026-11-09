//! Whose activity a calendar aggregates.

use crate::domains::audit::access::OrgLogView;
use crate::types::TenantId;

/// The organization or tenant an activity calendar is counted for.
///
/// An organization calendar counts the organization's own audit events and
/// those of the tenants its reader reaches. A tenant calendar counts only
/// the events of that tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivityScope {
    /// An organization's activity, as far into its tenants as its reader
    /// is shown.
    Organization(OrgLogView),
    /// Activity within a single tenant.
    Tenant(TenantId),
}
