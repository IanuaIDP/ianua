//! The streams that copy a tenant's audit records to a SIEM, kept as
//! tenant rows under row-level security.
//!
//! Every credential of a destination is sealed by the platform's secret
//! sealer before the stream is made, and the store keeps it sealed: the
//! database never holds one in clear. A tenant keeps a handful of streams
//! at most, so they are read whole, oldest first.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::audit::AuditStreamStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::tenant::audit_streams::AuditStream;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::AuditStreamId;

use self::record::{StreamColumns, StreamRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of audit streams.
pub struct PgAuditStreamStore {
    databases: Arc<Databases>,
}

impl PgAuditStreamStore {
    /// A store keeping audit streams in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgAuditStreamStore {}

#[async_trait]
impl AuditStreamStore for PgAuditStreamStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        id: &AuditStreamId,
    ) -> Result<Option<AuditStream<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    StreamRecord,
                    "queries/audit_streams/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(StreamRecord::into_stream).transpose()
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<AuditStream<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    StreamRecord,
                    "queries/audit_streams/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records.into_iter().map(StreamRecord::into_stream).collect()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        stream: &AuditStream<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = StreamColumns::of(stream)?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/audit_streams/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.name,
                    columns.destination,
                    columns.events.as_deref(),
                    columns.state,
                    columns.state_since,
                    columns.failures,
                    columns.pause_reason,
                    columns.created_at,
                    columns.updated_at,
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &AuditStreamId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/audit_streams/delete.sql",
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
    use ianua_domain::domains::tenant::audit_streams::{AuditStreamRow, PauseReason, StreamState};
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::stream_row;

    struct Fixture {
        db: TestDb,
        tenant: ScopedTenant,
        store: PgAuditStreamStore,
    }

    /// A fresh database, a tenant, and the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let store = PgAuditStreamStore::new(Arc::clone(&db.databases));
        Fixture {
            db,
            tenant: ScopedTenant::for_background(TenantId::new()),
            store,
        }
    }

    fn stream(row: AuditStreamRow) -> AuditStream<ResolvedTenant> {
        AuditStream::reconstitute(row).unwrap()
    }

    fn names(streams: &[AuditStream<ResolvedTenant>]) -> Vec<&str> {
        streams
            .iter()
            .map(|stream| stream.name().as_str())
            .collect()
    }

    /// A saved stream is found by its id, its destination and its sealed
    /// token as they were saved.
    #[tokio::test]
    async fn a_saved_stream_is_found_by_its_id() {
        let db = fixture().await;
        let splunk = stream(stream_row("Splunk production", 0));

        db.store.save(&db.tenant, &splunk).await.unwrap();

        let found = db
            .store
            .find(&db.tenant, splunk.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.destination(), splunk.destination());
        assert_eq!(found.filter(), splunk.filter());
        assert_eq!(found.state(), StreamState::Active);
    }

    /// A stream that failed and was paused is saved again with how it
    /// stands, and found so.
    #[tokio::test]
    async fn saving_again_keeps_how_the_stream_stands() {
        let db = fixture().await;
        let splunk = stream(stream_row("Splunk production", 0));
        db.store.save(&db.tenant, &splunk).await.unwrap();
        let paused = stream(AuditStreamRow {
            id: *splunk.id(),
            state: StreamState::Paused {
                reason: PauseReason::AfterFailures,
                at: at(9),
            },
            updated_at: at(9),
            ..stream_row("Splunk production", 0)
        });

        db.store.save(&db.tenant, &paused).await.unwrap();

        let found = db.store.find(&db.tenant, splunk.id()).await.unwrap();
        assert_eq!(found.unwrap().state(), paused.state());
    }

    /// A tenant's streams are listed oldest first, and another tenant's are
    /// left out; a deleted stream is gone.
    #[tokio::test]
    async fn a_tenants_streams_are_listed_oldest_first() {
        let db = fixture().await;
        let other = ScopedTenant::for_background(TenantId::new());
        let newer = stream(stream_row("newer", 5));
        let older = stream(stream_row("older", 1));
        let gone = stream(stream_row("gone", 3));
        for saved in [&newer, &older, &gone] {
            db.store.save(&db.tenant, saved).await.unwrap();
        }
        db.store
            .save(&other, &stream(stream_row("theirs", 0)))
            .await
            .unwrap();

        db.store.delete(&db.tenant, gone.id()).await.unwrap();

        let listed = db.store.list(&db.tenant).await.unwrap();
        assert_eq!(names(&listed), ["older", "newer"]);
        assert!(db.store.find(&other, newer.id()).await.unwrap().is_none());
    }

    /// A tenant with a database of its own keeps its streams there.
    #[tokio::test]
    async fn a_tenant_apart_keeps_its_streams_in_its_own_database() {
        let db = fixture().await;
        let own = TestDb::fresh().await;
        db.db.databases.register(*db.tenant, own.as_dedicated());
        let splunk = stream(stream_row("Splunk", 0));

        db.store.save(&db.tenant, &splunk).await.unwrap();

        assert_eq!(names(&db.store.list(&db.tenant).await.unwrap()), ["Splunk"]);
        db.db.databases.deregister(&db.tenant);
        assert!(db.store.list(&db.tenant).await.unwrap().is_empty());
    }

    /// Reading a stream whose stored syslog destination was changed to
    /// localhost returns a corruption error.
    #[tokio::test]
    async fn a_destination_pointing_inside_is_refused() {
        let db = fixture().await;
        let splunk = stream(stream_row("Splunk", 0));
        db.store.save(&db.tenant, &splunk).await.unwrap();
        db.db
            .tamper(
                "UPDATE audit_streams SET destination = \
                 '{\"v\": 1, \"value\": {\"kind\": \"syslog\", \"host\": \"localhost\", \"port\": 6514}}'",
            )
            .await;

        let read = db.store.find(&db.tenant, splunk.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
