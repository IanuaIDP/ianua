//! What the gateway reads and notes of a tenant's connectors, under its own
//! database role: the parts a link is judged by, and when it last saw one.
//!
//! The role reads a connector's id, scope, pinned key and status, never its
//! enrollment code's digest, and writes its `last_seen_at` alone.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::routing::{ConnectorSightings, ConnectorTunnelStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::routing::connector::tunnel::ConnectorTunnel;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::ConnectorId;
use time::OffsetDateTime;

use self::record::TunnelRecord;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres read of the connectors a gateway lets links in for.
pub struct PgConnectorTunnelStore {
    databases: Arc<Databases>,
}

impl PgConnectorTunnelStore {
    /// A store reading `databases`, reached as the gateway's role.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgConnectorTunnelStore {}

#[async_trait]
impl ConnectorTunnelStore for PgConnectorTunnelStore {
    async fn enrolled(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<ConnectorTunnel>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    TunnelRecord,
                    "queries/connectors/enrolled_of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records.into_iter().map(TunnelRecord::into_tunnel).collect()
    }
}

/// The Postgres record of when the gateway last saw each connector's link.
pub struct PgConnectorSightings {
    databases: Arc<Databases>,
}

impl PgConnectorSightings {
    /// A record kept in `databases`, reached as the gateway's role.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgConnectorSightings {}

#[async_trait]
impl ConnectorSightings for PgConnectorSightings {
    async fn record(
        &self,
        tenant_id: &ScopedTenant,
        connector: &ConnectorId,
        at: OffsetDateTime,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/connectors/seen.sql",
                    tenant_id.as_uuid(),
                    connector.as_uuid(),
                    at
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
    use ianua_app::ports::routing::ConnectorStore;
    use ianua_domain::domains::routing::connector::{
        ConnectorEnrollment, ConnectorStatus, LastSeen, PrivateConnector, PrivateConnectorRow,
    };
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::{PublicKeyPin, TenantId};

    use super::*;
    use crate::postgres::routing::PgConnectorStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::routing::connector_row;

    /// A fresh database, one tenant, the app's store, and the gateway's
    /// read and record under the gateway's role.
    struct Fixture {
        connectors: PgConnectorStore,
        tunnels: PgConnectorTunnelStore,
        sightings: PgConnectorSightings,
        tenant: ScopedTenant,
        _database: TestDb,
    }

    async fn fixture() -> Fixture {
        let database = TestDb::fresh().await;
        Fixture {
            connectors: PgConnectorStore::new(Arc::clone(&database.databases)),
            tunnels: PgConnectorTunnelStore::new(Arc::clone(&database.gateway)),
            sightings: PgConnectorSightings::new(Arc::clone(&database.gateway)),
            tenant: ScopedTenant::for_background(TenantId::new()),
            _database: database,
        }
    }

    fn key() -> PublicKeyPin {
        PublicKeyPin::from_digest([3; 32])
    }

    /// The connector named `name`, enrolled with [`key`] a minute after it
    /// was made, its certificate good for a day from then.
    fn enrolled(name: &str, status: ConnectorStatus) -> PrivateConnector<ResolvedTenant> {
        PrivateConnector::reconstitute(PrivateConnectorRow {
            enrollment: ConnectorEnrollment::Enrolled {
                key: key(),
                certificate_expires_at: at(60 + 86_400),
                enrolled_at: at(60),
            },
            status,
            updated_at: at(60),
            ..connector_row(name, "spent")
        })
        .unwrap()
    }

    /// The gateway reads Acme's enrolled connectors, revoked ones too, with
    /// the key each enrolled with, and not the one still awaiting its
    /// agent.
    #[tokio::test]
    async fn the_gateway_reads_the_enrolled_connectors() {
        let db = fixture().await;
        let wiki = enrolled("wiki", ConnectorStatus::Active);
        let old = enrolled("old", ConnectorStatus::Revoked);
        let waiting = PrivateConnector::reconstitute(connector_row("waiting", "c-1")).unwrap();
        for connector in [&wiki, &old, &waiting] {
            db.connectors.save(&db.tenant, connector).await.unwrap();
        }

        let tunnels = db.tunnels.enrolled(&db.tenant).await.unwrap();

        assert_eq!(tunnels.len(), 2);
        let read = tunnels.iter().find(|t| t.id() == wiki.id()).unwrap();
        assert!(read.admits(&key()));
        let revoked = tunnels.iter().find(|t| t.id() == old.id()).unwrap();
        assert!(!revoked.admits(&key()));
    }

    /// Reading enrolled connectors from Bob's tenant returns none of Acme's.
    #[tokio::test]
    async fn another_tenants_connectors_are_not_read() {
        let db = fixture().await;
        let wiki = enrolled("wiki", ConnectorStatus::Active);
        db.connectors.save(&db.tenant, &wiki).await.unwrap();
        let bobs = ScopedTenant::for_background(TenantId::new());

        let tunnels = db.tunnels.enrolled(&bobs).await.unwrap();

        assert!(tunnels.is_empty());
    }

    /// The gateway notes it saw the wiki connector's link. The connector
    /// reads back seen then, and an earlier sighting arriving late does
    /// not move it back.
    #[tokio::test]
    async fn a_sighting_is_noted_and_never_moves_back() {
        let db = fixture().await;
        let wiki = enrolled("wiki", ConnectorStatus::Active);
        db.connectors.save(&db.tenant, &wiki).await.unwrap();

        db.sightings
            .record(&db.tenant, wiki.id(), at(600))
            .await
            .unwrap();
        db.sightings
            .record(&db.tenant, wiki.id(), at(300))
            .await
            .unwrap();

        let read = db
            .connectors
            .find_by_id(&db.tenant, wiki.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.last_seen(), LastSeen::At(at(600)));
    }

    /// A connector still awaiting its agent is never noted seen.
    #[tokio::test]
    async fn an_unenrolled_connector_is_never_seen() {
        let db = fixture().await;
        let waiting = PrivateConnector::reconstitute(connector_row("waiting", "c-1")).unwrap();
        db.connectors.save(&db.tenant, &waiting).await.unwrap();

        db.sightings
            .record(&db.tenant, waiting.id(), at(600))
            .await
            .unwrap();

        let read = db
            .connectors
            .find_by_id(&db.tenant, waiting.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.last_seen(), LastSeen::Never);
    }
}
