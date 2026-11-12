//! Which rows a connection may see, set by row-level security.
//!
//! Every tenant table carries a policy that shows a row only when its
//! `tenant_id` is the one this connection was given, or when the connection
//! was opened for platform work that deliberately spans tenants. The scope is
//! set afresh at the start of every store call, inside its transaction, and
//! lapses with it, so a pooled connection never carries one tenant's scope
//! to the next borrower.

use ianua_app::tenancy::ScopedTenant;
use ianua_domain::types::TenantId;

/// Which rows a store call may see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RowScope {
    /// One tenant's rows.
    Tenant(TenantId),
    /// Every tenant's rows, for platform work that deliberately spans them.
    Platform,
    /// No tenant's rows, for the platform's own tables that row-level
    /// security does not cover.
    Unscoped,
}

impl From<&ScopedTenant> for RowScope {
    fn from(tenant: &ScopedTenant) -> Self {
        Self::Tenant(**tenant)
    }
}

/// The statement that gives the running transaction the rows of `scope`,
/// for this transaction only. It is sent in the same message as the
/// statements around it, so setting the scope costs no trip of its own;
/// its only values are a tenant id and fixed words, never caller text.
pub(crate) fn setting(scope: RowScope) -> String {
    let (tenant, platform) = match scope {
        RowScope::Tenant(tenant) => (tenant.as_uuid().to_string(), ""),
        RowScope::Platform => (String::new(), "on"),
        RowScope::Unscoped => (String::new(), ""),
    };
    format!(
        "SELECT set_config('app.current_tenant_id', '{tenant}', true), \
                set_config('app.platform_scope', '{platform}', true)"
    )
}
