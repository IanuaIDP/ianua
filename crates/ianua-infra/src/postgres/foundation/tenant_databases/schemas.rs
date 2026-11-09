//! A tenant's own schema of the platform's database: made, brought up to
//! date and opened to the app's role, the audit purge's and the gateway's,
//! or dropped.
//!
//! Making a schema and running the migrations in it is the owner's work;
//! the app's role only reads and writes its rows, and removes no audit
//! record, which only the audit purge's role may, and the gateway's role
//! holds what it holds in the platform's tables
//! (postgres/foundation/roles.rs). A schema's name cannot be
//! bound as a value, so it is made by the platform from the tenant's id,
//! checked to be the one made for its tenant when read back, and quoted,
//! never taken as given. Each step can run again: a schema made already is kept,
//! migrations applied already are skipped, and a schema dropped already is
//! gone.

use std::time::Duration;

use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::postgres::foundation::migrations::migrate_dedicated;
use crate::postgres::foundation::pool::DedicatedDatabase;
use crate::postgres::foundation::roles::{
    audit_kept_from, audit_purge_grants, checked_name, gateway_grants,
};

/// How long the owner's connection waits to be opened.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The start of every tenant schema's name.
const PREFIX: &str = "tenant_";

/// A tenant's schema, its name checked: `tenant_` and the tenant's id in
/// lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TenantSchema {
    name: String,
}

impl TenantSchema {
    /// The schema `tenant` gets.
    #[must_use]
    pub(crate) fn of(tenant: &TenantId) -> Self {
        Self {
            name: format!("{PREFIX}{}", tenant.as_uuid().simple()),
        }
    }

    /// The schema the registry names `name` for `tenant`, when it is the
    /// one [`of`](Self::of) makes for that tenant. A name of another
    /// tenant's schema would route this tenant's rows into it, so it is
    /// refused as surely as one carrying a statement of its own.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when `name` is not the schema
    /// the platform makes for `tenant`.
    pub(crate) fn registered(tenant: &TenantId, name: &str) -> Result<Self, DomainError> {
        let schema = Self::of(tenant);
        if schema.name != name {
            return Err(DomainError::corrupt_row(
                "tenant database",
                "a schema name the platform does not make for this tenant",
            ));
        }
        Ok(schema)
    }

    /// The schema's name.
    #[must_use]
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The schema's name, quoted as an identifier.
    #[must_use]
    pub(crate) fn quoted(&self) -> String {
        format!("\"{}\"", self.name)
    }
}

/// How tenant schemas are made and whom they are opened to: the database's
/// owner makes them, and the app's role, the audit purge's and the
/// gateway's are given what each may do there. The owner's options hold
/// its password, so this has no `Debug`.
#[derive(Clone)]
pub struct TenantSchemaAccess {
    /// How the database's owner connects.
    pub owner: PgConnectOptions,
    /// The role the app connects as.
    pub app_role: String,
    /// The role the audit retention purge connects as.
    pub audit_purge_role: String,
    /// The role the gateway connects as, or `None` where no gateway is
    /// deployed.
    pub gateway_role: Option<String>,
}

impl TenantSchemaAccess {
    /// The roles that write in a tenant's schema, checked and quoted: the
    /// app's, and the gateway's where there is one.
    fn writers(&self) -> Result<Vec<String>, DomainError> {
        std::iter::once(self.app_role.as_str())
            .chain(self.gateway_role.as_deref())
            .map(checked_name)
            .collect()
    }
}

/// Makes `schema` on the database `access.owner` reaches, brings it up to
/// date with the tenant tables' migrations, gives the app's role the rows
/// of every table in it but the audit records' removal, gives the audit
/// purge's role that removal and nothing more, and gives the gateway's
/// role, where there is one, what it holds in the platform's tables.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a role's name is not one the
/// platform makes, the owner cannot connect, or a statement or migration
/// fails.
pub(crate) async fn make(
    access: &TenantSchemaAccess,
    schema: &TenantSchema,
) -> Result<(), DomainError> {
    let app = checked_name(&access.app_role)?;
    let purge = checked_name(&access.audit_purge_role)?;
    let gateway = access
        .gateway_role
        .as_deref()
        .map(checked_name)
        .transpose()?;
    let quoted = schema.quoted();
    let platform = connect(access.owner.clone()).await?;
    run(&platform, &format!("CREATE SCHEMA IF NOT EXISTS {quoted}")).await?;
    migrate_schema(access, schema).await?;
    let grants = app_grants(&quoted, &app)
        .into_iter()
        .chain(audit_kept_from(&quoted, &app))
        .chain(audit_purge_grants(&quoted, &purge))
        .chain(
            gateway
                .iter()
                .flat_map(|gateway| gateway_grants(&quoted, gateway)),
        );
    for grant in grants {
        run(&platform, &grant).await?;
    }
    platform.close().await;
    Ok(())
}

/// Runs tenant migrations on a schema-pinned connection and closes it on either outcome.
async fn migrate_schema(
    access: &TenantSchemaAccess,
    schema: &TenantSchema,
) -> Result<(), DomainError> {
    let pinned = DedicatedDatabase::new(access.owner.clone(), Some(schema.name()))?;
    let in_schema = connect(pinned.options()).await?;
    let migrated = migrate_dedicated(&in_schema).await;
    in_schema.close().await;
    migrated
}

/// Takes every write in `schema` away from the app's role and the
/// gateway's, as the first step of the tenant leaving it, on the database
/// `access.owner` reaches. A node that has not heard of the move yet still
/// routes the tenant there; its writes now fail, and the request with
/// them, instead of landing in a schema about to be dropped. The app's
/// role keeps reading it, which the trail's copy back needs. A schema
/// already gone has nothing to close.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a role's name is not one the
/// platform makes, the owner cannot connect, or a revoke fails.
pub(crate) async fn close_to_writes(
    access: &TenantSchemaAccess,
    schema: &TenantSchema,
) -> Result<(), DomainError> {
    let writers = access.writers()?;
    let platform = connect(access.owner.clone()).await?;
    let closed = revoke_writes(&platform, schema, &writers).await;
    platform.close().await;
    closed
}

/// Revokes the writes of `roles` on every table of `schema`, when it is
/// there.
async fn revoke_writes(
    platform: &PgPool,
    schema: &TenantSchema,
    roles: &[String],
) -> Result<(), DomainError> {
    let there: bool = sqlx::query_scalar("SELECT to_regnamespace($1) IS NOT NULL")
        .bind(schema.name())
        .fetch_one(platform)
        .await
        .map_err(DomainError::infra)?;
    if !there {
        return Ok(());
    }
    let statement = format!(
        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA {} FROM {}",
        schema.quoted(),
        roles.join(", ")
    );
    run(platform, &statement).await
}

/// Drops `schema` and every table in it, from the database `owner` reaches.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the owner cannot connect or
/// the drop fails.
pub(crate) async fn remove(
    owner: &PgConnectOptions,
    schema: &TenantSchema,
) -> Result<(), DomainError> {
    let platform = connect(owner.clone()).await?;
    let statement = format!("DROP SCHEMA IF EXISTS {} CASCADE", schema.quoted());
    let dropped = run(&platform, &statement).await;
    platform.close().await;
    dropped
}

/// What the app's role may do in a tenant's schema: reach it, and read and
/// write the rows of its tables and sequences, before the audit trail is
/// kept from it.
fn app_grants(schema: &str, role: &str) -> [String; 3] {
    [
        format!("GRANT USAGE ON SCHEMA {schema} TO {role}"),
        format!("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} TO {role}"),
        format!("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {schema} TO {role}"),
    ]
}

/// A connection of the owner's, opened now.
async fn connect(options: PgConnectOptions) -> Result<PgPool, DomainError> {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(CONNECT_TIMEOUT)
        .connect_with(options)
        .await
        .map_err(DomainError::infra)
}

async fn run(pool: &PgPool, statement: &str) -> Result<(), DomainError> {
    sqlx::raw_sql(statement)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(DomainError::infra)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::pool::Databases;
    use crate::postgres::foundation::security::RowScope;
    use crate::postgres::foundation::unit::scoped;
    use crate::test_support::TestDb;
    use crate::test_support::rows::audit::{
        failed_sign_in, recorded, saved_organization, saved_tenant_of,
    };

    /// A tenant with two records kept in a schema of its own, routed there
    /// for the app's role, the audit purge's and the gateway's alike.
    async fn kept_apart() -> (TestDb, TenantId) {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = *saved_tenant_of(&db.databases, organization).await;
        let schema = TenantSchema::of(&tenant);
        make(&db.schema_access(), &schema).await.unwrap();
        for databases in [&db.databases, &db.audit_purge, &db.gateway] {
            let routed = databases.schema_of_platform(schema.name()).unwrap();
            databases.register(tenant, routed);
        }
        let events = vec![failed_sign_in(tenant, 1), failed_sign_in(tenant, 2)];
        recorded(&db.databases, events).await;
        (db, tenant)
    }

    /// Removes every audit record of `tenant` as the role of `databases`,
    /// and answers how many went.
    async fn removed(databases: &Databases, tenant: TenantId) -> Result<u64, DomainError> {
        ran(databases, tenant, "DELETE FROM audit_records").await
    }

    /// Runs `statement` as the role of `databases`, scoped to `tenant`, and
    /// answers the rows it touched.
    async fn ran(
        databases: &Databases,
        tenant: TenantId,
        statement: &str,
    ) -> Result<u64, DomainError> {
        scoped(databases, RowScope::Tenant(tenant), async |connection| {
            sqlx::query(statement)
                .execute(connection)
                .await
                .map(|done| done.rows_affected())
        })
        .await
    }

    /// The app role is refused deletion of audit records in a tenant's
    /// dedicated schema.
    #[tokio::test]
    async fn the_apps_role_never_removes_a_record_in_a_tenants_schema() {
        let (db, tenant) = kept_apart().await;

        let refused = removed(&db.databases, tenant).await;

        assert!(refused.is_err());
    }

    /// The audit purge's role removes a tenant's records in its schema,
    /// which is opened to it as the platform's tables are.
    #[tokio::test]
    async fn the_purge_role_removes_records_in_a_tenants_schema() {
        let (db, tenant) = kept_apart().await;

        let gone = removed(&db.audit_purge, tenant).await;

        assert_eq!(gone.unwrap(), 2);
    }

    /// In a tenant's dedicated schema, the gateway may read routes but
    /// cannot update them or delete audit records.
    #[tokio::test]
    async fn the_gateway_role_holds_no_more_in_a_tenants_schema() {
        let (db, tenant) = kept_apart().await;

        let records = removed(&db.gateway, tenant).await;
        let rerouted = ran(&db.gateway, tenant, "UPDATE routes SET name = 'mine'").await;
        let routes = ran(&db.gateway, tenant, "SELECT id FROM routes").await;

        assert!(records.is_err());
        assert!(rerouted.is_err());
        assert!(routes.is_ok());
    }

    /// A tenant's schema is named after it, and that name reads back.
    #[test]
    fn a_tenants_schema_is_named_after_it() {
        let tenant = TenantId::new();

        let schema = TenantSchema::of(&tenant);

        assert!(
            schema
                .name()
                .ends_with(&tenant.as_uuid().simple().to_string())
        );
        assert_eq!(
            TenantSchema::registered(&tenant, schema.name()).unwrap(),
            schema
        );
    }

    /// Registration rejects public, incomplete, uppercase and SQL-bearing
    /// schema names instead of accepting them as the tenant's schema.
    #[test]
    fn a_name_the_platform_does_not_make_is_refused() {
        let tenant = TenantId::new();
        let shouting = TenantSchema::of(&tenant).name().to_uppercase();
        for name in [
            "public",
            "tenant_1; DROP TABLE users",
            PREFIX,
            shouting.as_str(),
        ] {
            assert!(TenantSchema::registered(&tenant, name).is_err(), "{name}");
        }
    }

    /// Registering Globex's schema for Acme is refused as corrupt storage.
    #[test]
    fn another_tenants_schema_is_refused() {
        let (acme, globex) = (TenantId::new(), TenantId::new());
        let globex_schema = TenantSchema::of(&globex);

        let routed = TenantSchema::registered(&acme, globex_schema.name());

        assert!(matches!(routed, Err(DomainError::Infrastructure(_))));
    }
}
