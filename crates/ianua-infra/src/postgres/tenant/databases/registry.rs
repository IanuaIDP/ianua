//! Which tenants live in a schema of their own, as the platform's database
//! records it, and this node's routes made to match.
//!
//! A node routes a tenant by its own map ([`Databases`]), which is filled
//! here at start and made to match again whenever the registry changes:
//! a route the registry no longer holds is dropped, one it holds is added.
//! A row whose schema name is not the one the platform makes for its
//! tenant is refused rather than skipped, since skipping it would route
//! that tenant's rows to the platform's tables, and following it could
//! route them into another tenant's schema.

use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::tenant_databases::schemas::{
    TenantSchema, TenantSchemaAccess, make,
};
use crate::postgres::foundation::unit::scoped;

/// The most tenants a node routes to schemas of their own. A registry
/// holding more stops the load, rather than leave some unrouted.
const MOST_APART: i64 = 100_000;

/// The schema `tenant` lives in, as the registry records it, or `None`
/// for a tenant on the platform's tables.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the registry cannot be read
/// or holds a name the platform does not make.
pub(crate) async fn schema_of(
    databases: &Databases,
    tenant: &TenantId,
) -> Result<Option<TenantSchema>, DomainError> {
    let name = scoped(databases, RowScope::Platform, async |connection| {
        sqlx::query_file_scalar!("queries/tenant_databases/by_tenant.sql", tenant.as_uuid())
            .fetch_optional(connection)
            .await
    })
    .await?;
    name.as_deref()
        .map(|name| TenantSchema::registered(tenant, name))
        .transpose()
}

/// Routes `tenant` on this node as the registry records it now. A route
/// already held is kept as it is, its pool with it.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the registry cannot be read
/// or holds a name the platform does not make.
pub(crate) async fn refresh(databases: &Databases, tenant: &TenantId) -> Result<(), DomainError> {
    let Some(schema) = schema_of(databases, tenant).await? else {
        databases.deregister(tenant);
        return Ok(());
    };
    if !databases.lives_apart(tenant) {
        databases.register(*tenant, databases.schema_of_platform(schema.name())?);
    }
    Ok(())
}

/// Brings every tenant schema the registry records up to date with the
/// tenant tables' migrations, and opens what they made to the app's role
/// and the audit purge's as a new schema is, for an upgrade: a schema is
/// migrated when it is made, and never again unless this runs. Answers how
/// many schemas it went through.
///
/// A schema being closed for its tenant's teardown is opened to the app's
/// writes again until the teardown's next try closes it; the teardown
/// closes it first on every try.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the registry cannot be read,
/// holds a name the platform does not make, or a schema's migration or
/// grants fail; the schemas before it stay migrated, and running this
/// again picks up where it stopped.
pub async fn migrate_tenant_schemas(
    databases: &Databases,
    access: &TenantSchemaAccess,
) -> Result<usize, DomainError> {
    let rows = scoped(databases, RowScope::Platform, async |connection| {
        sqlx::query_file!("queries/tenant_databases/every.sql", MOST_APART)
            .fetch_all(connection)
            .await
    })
    .await?;
    let mut schemas = Vec::with_capacity(rows.len());
    for row in rows {
        let tenant = TenantId::from_uuid(row.tenant_id);
        schemas.push(TenantSchema::registered(&tenant, &row.schema_name)?);
    }
    for schema in &schemas {
        make(access, schema).await?;
    }
    Ok(schemas.len())
}

/// Routes every tenant on this node as the registry records them: adds
/// each route it holds that the node has not, and drops each it no longer
/// holds.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the registry cannot be read,
/// holds a name the platform does not make, or holds more tenants than a
/// node routes.
pub async fn load_tenant_databases(databases: &Databases) -> Result<(), DomainError> {
    let rows = scoped(databases, RowScope::Platform, async |connection| {
        sqlx::query_file!("queries/tenant_databases/every.sql", MOST_APART)
            .fetch_all(connection)
            .await
    })
    .await?;
    if i64::try_from(rows.len()).unwrap_or(i64::MAX) >= MOST_APART {
        return Err(DomainError::infra_msg(
            "more tenants live apart than a node routes",
        ));
    }
    let mut held = Vec::with_capacity(rows.len());
    for row in rows {
        let tenant = TenantId::from_uuid(row.tenant_id);
        let schema = TenantSchema::registered(&tenant, &row.schema_name)?;
        held.push((tenant, databases.schema_of_platform(schema.name())?));
    }
    let kept: Vec<TenantId> = held.iter().map(|(tenant, _)| *tenant).collect();
    discard_unregistered(databases, &kept);
    for (tenant, database) in held {
        if !databases.lives_apart(&tenant) {
            databases.register(tenant, database);
        }
    }
    Ok(())
}

/// Removes local routes whose tenants no longer appear in the validated registry.
fn discard_unregistered(databases: &Databases, kept: &[TenantId]) {
    for gone in databases
        .with_own_database()
        .into_iter()
        .filter(|tenant| !kept.contains(tenant))
    {
        databases.deregister(&gone);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_app::ports::tenant::{ProvisionDatabaseRequest, TenantDatabaseProvisioner as _};
    use ianua_domain::domains::tenant::provisioning::infrastructure::{
        DeploymentRegion, IsolationLevel, Placement, TenantResidency,
    };
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::bus::MemoryBus;
    use crate::postgres::tenant::PgTenantDatabaseProvisioner;
    use crate::test_support::TestDb;
    use crate::test_support::rows::audit::{saved_organization, saved_tenant_of};

    /// Gives a new tenant a schema of its own, and answers the tenant.
    async fn moved_apart(db: &TestDb) -> TenantId {
        let organization = saved_organization(&db.databases).await;
        let tenant = *saved_tenant_of(&db.databases, organization).await;
        let residency = TenantResidency::new(
            Placement::Platform {
                region: DeploymentRegion::EuCentral1,
            },
            IsolationLevel::DedicatedSchema,
        )
        .unwrap();
        PgTenantDatabaseProvisioner::new(
            Arc::clone(&db.databases),
            Arc::clone(&db.audit_purge),
            db.schema_access(),
            Arc::new(MemoryBus::new(16)),
        )
        .provision(
            &tenant,
            &OrganizationId::new(),
            &ProvisionDatabaseRequest::for_residency(residency),
        )
        .await
        .unwrap();
        tenant
    }

    /// With no tenant living apart, an upgrade has no schema to migrate.
    #[tokio::test]
    async fn an_upgrade_with_no_tenant_schema_migrates_none() {
        let db = TestDb::fresh().await;

        let migrated = migrate_tenant_schemas(&db.databases, &db.schema_access()).await;

        assert_eq!(migrated.unwrap(), 0);
    }

    /// With one registered tenant schema, each of two migration runs reports
    /// one schema and the tenant's schema remains registered.
    #[tokio::test]
    async fn an_upgrade_migrates_every_tenant_schema_and_can_run_again() {
        let db = TestDb::fresh().await;
        let tenant = moved_apart(&db).await;

        let first = migrate_tenant_schemas(&db.databases, &db.schema_access()).await;
        let again = migrate_tenant_schemas(&db.databases, &db.schema_access()).await;

        assert_eq!(first.unwrap(), 1);
        assert_eq!(again.unwrap(), 1);
        assert!(schema_of(&db.databases, &tenant).await.unwrap().is_some());
    }
}
