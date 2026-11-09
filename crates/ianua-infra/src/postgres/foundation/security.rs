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
use sqlx::PgConnection;

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

/// Gives the running transaction on `connection` the rows of `scope`, for
/// this transaction only.
pub(crate) async fn apply(
    connection: &mut PgConnection,
    scope: RowScope,
) -> Result<(), sqlx::Error> {
    let (tenant, platform) = match scope {
        RowScope::Tenant(tenant) => (tenant.as_uuid().to_string(), ""),
        RowScope::Platform => (String::new(), "on"),
        RowScope::Unscoped => (String::new(), ""),
    };
    sqlx::query(
        "SELECT set_config('app.current_tenant_id', $1, true), \
                set_config('app.platform_scope', $2, true)",
    )
    .bind(tenant)
    .bind(platform)
    .execute(connection)
    .await?;
    Ok(())
}
