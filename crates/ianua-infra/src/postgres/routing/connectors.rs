//! A tenant's private-network connectors, under row-level security.
//!
//! Every read goes through one checked query and one mapping into the
//! aggregate. A connector awaiting enrollment keeps the keyed hash of its
//! one-time code, never the code; once enrolled it keeps the key its link
//! is held with instead, and when its certificate ends, so a spent code
//! matches nothing. The gateway's reads and sightings are in [`tunnels`].

mod record;
mod tunnels;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::routing::ConnectorStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::routing::connector::PrivateConnector;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConnectorId, TokenHash};

use self::record::{ConnectorColumns, ConnectorRecord};
pub use self::tunnels::{PgConnectorSightings, PgConnectorTunnelStore};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a name to one connector of a tenant.
const NAME_KEY: &str = "connectors_name_key";

/// The Postgres connector store.
pub struct PgConnectorStore {
    databases: Arc<Databases>,
}

impl PgConnectorStore {
    /// A store keeping connectors in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgConnectorStore {}

/// The connector `record` holds, if any, rebuilt through the domain's
/// checks.
fn rebuilt(
    record: Option<ConnectorRecord>,
) -> Result<Option<PrivateConnector<ResolvedTenant>>, DomainError> {
    record.map(ConnectorRecord::into_connector).transpose()
}

/// Converts a conflicting connector name into the store's domain error.
fn ensure_name_available(written: Uniqueness) -> Result<(), DomainError> {
    match written {
        Uniqueness::Kept => Ok(()),
        Uniqueness::Taken => Err(DomainError::conflict(message!(
            "infra-another-connector-of-the-tenant-has",
            "another connector of the tenant has the name"
        ))),
    }
}

#[async_trait]
impl ConnectorStore for PgConnectorStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ConnectorId,
    ) -> Result<Option<PrivateConnector<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ConnectorRecord,
                    "queries/connectors/by_ids.sql",
                    tenant_id.as_uuid(),
                    &ids[..]
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        rebuilt(record)
    }

    async fn find_awaiting_by_code(
        &self,
        tenant_id: &ScopedTenant,
        code_hash: &TokenHash,
    ) -> Result<Option<PrivateConnector<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ConnectorRecord,
                    "queries/connectors/awaiting_by_code.sql",
                    tenant_id.as_uuid(),
                    code_hash.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        rebuilt(record)
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<PrivateConnector<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ConnectorRecord,
                    "queries/connectors/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(ConnectorRecord::into_connector)
            .collect()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        connector: &PrivateConnector<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = ConnectorColumns::of(connector)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/connectors/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.name,
                    columns.scope,
                    columns.code_hash,
                    columns.code_expires_at,
                    columns.public_key,
                    columns.certificate_expires_at,
                    columns.enrolled_at,
                    columns.status,
                    columns.created_at,
                    columns.updated_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, NAME_KEY)
            },
        )
        .await?;
        ensure_name_available(written)
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &ConnectorId) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/connectors/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::routing::connector::{
        ConnectorEnrollment, ConnectorStatus, LastSeen, PrivateConnectorRow,
    };
    use ianua_domain::types::{PublicKeyPin, TenantId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::routing::{connector_code_hash, connector_row};

    struct Fixture {
        database: TestDb,
        store: PgConnectorStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, one tenant, and the store on it.
    async fn fixture() -> Fixture {
        let database = TestDb::fresh().await;
        let store = PgConnectorStore::new(Arc::clone(&database.databases));
        Fixture {
            database,
            store,
            tenant: ScopedTenant::for_background(TenantId::new()),
        }
    }

    fn connector(row: PrivateConnectorRow) -> PrivateConnector<ResolvedTenant> {
        PrivateConnector::reconstitute(row).unwrap()
    }

    fn awaiting(name: &str, code: &str) -> PrivateConnector<ResolvedTenant> {
        connector(connector_row(name, code))
    }

    /// The connector `awaiting` became once enrolled with a key, its
    /// certificate good for a day.
    fn enrolled(awaiting: &PrivateConnector<ResolvedTenant>) -> PrivateConnector<ResolvedTenant> {
        connector(PrivateConnectorRow {
            id: *awaiting.id(),
            enrollment: ConnectorEnrollment::Enrolled {
                key: PublicKeyPin::from_digest([0xab; 32]),
                certificate_expires_at: at(60 + 86_400),
                enrolled_at: at(60),
            },
            updated_at: at(60),
            ..connector_row(awaiting.name().as_str(), "spent")
        })
    }

    /// A saved connector is found by its id, and by its code while it
    /// awaits enrollment.
    #[tokio::test]
    async fn an_awaiting_connector_is_found_by_its_id_and_its_code() {
        let db = fixture().await;
        let payroll = awaiting("payroll", "code-1");

        db.store.save(&db.tenant, &payroll).await.unwrap();

        let by_id = db
            .store
            .find_by_id(&db.tenant, payroll.id())
            .await
            .unwrap()
            .unwrap();
        let by_code = db
            .store
            .find_awaiting_by_code(&db.tenant, &connector_code_hash("code-1"))
            .await
            .unwrap()
            .unwrap();
        for found in [&by_id, &by_code] {
            assert_eq!(found.id(), payroll.id());
            assert_eq!(found.scope(), payroll.scope());
            assert_eq!(found.enrollment(), payroll.enrollment());
        }
    }

    /// After enrollment is saved, the spent code finds no awaiting connector;
    /// lookup by ID retains the enrollment and an unseen status.
    #[tokio::test]
    async fn a_spent_code_matches_nothing() {
        let db = fixture().await;
        let payroll = awaiting("payroll", "code-1");
        db.store.save(&db.tenant, &payroll).await.unwrap();
        let done = enrolled(&payroll);

        db.store.save(&db.tenant, &done).await.unwrap();

        let by_code = db
            .store
            .find_awaiting_by_code(&db.tenant, &connector_code_hash("code-1"))
            .await
            .unwrap();
        let found = db
            .store
            .find_by_id(&db.tenant, payroll.id())
            .await
            .unwrap()
            .unwrap();
        assert!(by_code.is_none());
        assert_eq!(found.enrollment(), done.enrollment());
        assert_eq!(found.last_seen(), LastSeen::Never);
    }

    /// Another tenant cannot find Acme's connector by ID or enrollment
    /// code, and its connector list is empty.
    #[tokio::test]
    async fn a_connector_is_invisible_to_another_tenant() {
        let db = fixture().await;
        let payroll = awaiting("payroll", "code-1");
        db.store.save(&db.tenant, &payroll).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let by_id = db.store.find_by_id(&other, payroll.id()).await.unwrap();
        let by_code = db
            .store
            .find_awaiting_by_code(&other, &connector_code_hash("code-1"))
            .await
            .unwrap();
        let listed = db.store.list(&other).await.unwrap();

        assert!(by_id.is_none());
        assert!(by_code.is_none());
        assert!(listed.is_empty());
    }

    /// The tenant's connectors list by name.
    #[tokio::test]
    async fn connectors_are_listed_by_name() {
        let db = fixture().await;
        for (name, code) in [("warehouse", "c-1"), ("payroll", "c-2"), ("office", "c-3")] {
            db.store
                .save(&db.tenant, &awaiting(name, code))
                .await
                .unwrap();
        }

        let listed = db.store.list(&db.tenant).await.unwrap();

        let names: Vec<&str> = listed.iter().map(|c| c.name().as_str()).collect();
        assert_eq!(names, ["office", "payroll", "warehouse"]);
    }

    /// Saving a second connector named `payroll` in the same tenant
    /// returns a conflict.
    #[tokio::test]
    async fn a_name_another_connector_has_is_refused() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &awaiting("payroll", "c-1"))
            .await
            .unwrap();

        let second = db.store.save(&db.tenant, &awaiting("payroll", "c-2")).await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// A revoked connector reads back revoked, and once deleted is gone.
    #[tokio::test]
    async fn a_revoked_connector_is_kept_and_then_deleted() {
        let db = fixture().await;
        let payroll = awaiting("payroll", "c-1");
        db.store.save(&db.tenant, &payroll).await.unwrap();
        let revoked = connector(PrivateConnectorRow {
            id: *payroll.id(),
            status: ConnectorStatus::Revoked,
            updated_at: at(5),
            ..connector_row("payroll", "c-1")
        });
        db.store.save(&db.tenant, &revoked).await.unwrap();

        let found = db
            .store
            .find_by_id(&db.tenant, payroll.id())
            .await
            .unwrap()
            .unwrap();
        db.store.delete(&db.tenant, payroll.id()).await.unwrap();
        let gone = db.store.find_by_id(&db.tenant, payroll.id()).await.unwrap();

        assert_eq!(found.status(), ConnectorStatus::Revoked);
        assert!(gone.is_none());
    }

    /// A connector whose stored enrollment code lasts a full day fails to
    /// load as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_connector_is_refused() {
        let db = fixture().await;
        let payroll = awaiting("payroll", "c-1");
        db.store.save(&db.tenant, &payroll).await.unwrap();
        db.database
            .tamper("UPDATE connectors SET code_expires_at = created_at + interval '1 day'")
            .await;

        let read = db.store.find_by_id(&db.tenant, payroll.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
