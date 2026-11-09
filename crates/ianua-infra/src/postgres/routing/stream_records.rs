//! The records of stream connections: written by the gateway, many in one
//! statement, each tenant's in the database the tenant lives in.
//!
//! A record is a tenant row under row-level security. The gateway's role
//! may insert them and read none back. Records past the tenant's retention
//! are removed by the platform, oldest first, a bounded number per
//! statement.

mod record;

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::routing::{StreamRecord, StreamRecordRetention, StreamRecordWriter};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::StreamBatch;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres writer of the gateway's stream records.
pub struct PgStreamRecordWriter {
    databases: Arc<Databases>,
}

impl PgStreamRecordWriter {
    /// A writer of stream records to `databases`, the gateway's.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Writes `batch`, one tenant's records, in one statement.
    async fn write_tenant(&self, tenant: TenantId, batch: StreamBatch) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::Tenant(tenant),
            async |connection| {
                sqlx::query_file!(
                    "queries/stream_records/write.sql",
                    tenant.as_uuid(),
                    &batch.ids,
                    &batch.stream_route_ids,
                    &batch.listen_ports,
                    &batch.client_addresses,
                    &batch.server_names as &[Option<String>],
                    &batch.callers as &[Option<String>],
                    &batch.caller_ids as &[Option<Uuid>],
                    &batch.decisions,
                    &batch.reasons,
                    &batch.backends as &[Option<String>],
                    &batch.bytes_to_backend,
                    &batch.bytes_to_client,
                    &batch.durations,
                    &batch.occurred_at as &[OffsetDateTime],
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }
}

#[async_trait]
impl StreamRecordWriter for PgStreamRecordWriter {
    async fn write(&self, records: &[StreamRecord]) -> Result<(), DomainError> {
        let mut by_tenant: HashMap<TenantId, Vec<&StreamRecord>> = HashMap::new();
        for record in records {
            by_tenant.entry(record.tenant_id).or_default().push(record);
        }
        try_join_all(
            by_tenant
                .into_iter()
                .map(|(tenant, records)| self.write_tenant(tenant, StreamBatch::of(records))),
        )
        .await?;
        Ok(())
    }
}

/// The Postgres removal of a tenant's stream records past its retention.
pub struct PgStreamRecordRetention {
    databases: Arc<Databases>,
}

impl PgStreamRecordRetention {
    /// A removal of the stream records in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgStreamRecordRetention {}

#[async_trait]
impl StreamRecordRetention for PgStreamRecordRetention {
    async fn forget_before(
        &self,
        tenant_id: &ScopedTenant,
        before: OffsetDateTime,
        most: NonZeroU32,
    ) -> Result<u64, DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/stream_records/forget_before.sql",
                    tenant_id.as_uuid(),
                    before,
                    i64::from(most.get()),
                )
                .execute(connection)
                .await
                .map(|done| done.rows_affected())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use ianua_app::ports::routing::{StreamConnectionCaller, StreamDecision};
    use ianua_domain::domains::routing::stream::ListenPort;
    use ianua_domain::types::{ConsumerId, DomainName, StreamRouteId};

    use super::*;
    use crate::test_support::TestDb;

    fn record(tenant_id: TenantId, decision: StreamDecision) -> StreamRecord {
        StreamRecord {
            tenant_id,
            stream_route_id: StreamRouteId::new(),
            listen_port: ListenPort::new(15432).unwrap(),
            client: IpAddr::from([198, 51, 100, 4]),
            server_name: Some(DomainName::new("db.acme.test").unwrap()),
            caller: Some(StreamConnectionCaller::Consumer(ConsumerId::new())),
            decision,
            reason: "spliced",
            backend: Some("10.0.0.5:5432".to_owned()),
            bytes_to_backend: 1_024,
            bytes_to_client: 4_096,
            duration_ms: 1_500,
            occurred_at: OffsetDateTime::now_utc(),
        }
    }

    fn refused(tenant_id: TenantId) -> StreamRecord {
        StreamRecord {
            caller: None,
            reason: "not_let_in",
            backend: None,
            bytes_to_backend: 0,
            bytes_to_client: 0,
            ..record(tenant_id, StreamDecision::Denied)
        }
    }

    /// The decisions kept for `tenant`. No store reads stream records back,
    /// so they are read past the stores.
    async fn kept(db: &TestDb, tenant: TenantId) -> Vec<(String, Option<String>, i64)> {
        db.read_back(&format!(
            "SELECT decision, caller, bytes_to_client FROM stream_records \
             WHERE tenant_id = '{}' ORDER BY decision",
            tenant.as_uuid()
        ))
        .await
    }

    /// The gateway role records Acme's allowed and denied connections with
    /// their caller and byte counts, and keeps Globex's connection separately.
    #[tokio::test]
    async fn the_gateway_writes_each_tenants_records() {
        let db = TestDb::fresh().await;
        let (acme, globex) = (TenantId::new(), TenantId::new());
        let writer = PgStreamRecordWriter::new(Arc::clone(&db.gateway));

        writer
            .write(&[
                record(acme, StreamDecision::Allowed),
                refused(acme),
                record(globex, StreamDecision::Allowed),
            ])
            .await
            .unwrap();

        assert_eq!(
            kept(&db, acme).await,
            [
                ("allowed".to_owned(), Some("consumer".to_owned()), 4_096),
                ("denied".to_owned(), None, 0),
            ]
        );
        assert_eq!(kept(&db, globex).await.len(), 1);
    }

    /// Acme's retention has passed its connection from two days ago but not
    /// today's. The old one goes, today's stays, and Globex's from two days
    /// ago is not Acme's to remove.
    #[tokio::test]
    async fn records_past_the_retention_go_and_only_the_tenants() {
        let db = TestDb::fresh().await;
        let (acme, globex) = (TenantId::new(), TenantId::new());
        let two_days_ago = OffsetDateTime::now_utc() - time::Duration::days(2);
        let old = |tenant| StreamRecord {
            occurred_at: two_days_ago,
            ..record(tenant, StreamDecision::Allowed)
        };
        PgStreamRecordWriter::new(Arc::clone(&db.gateway))
            .write(&[old(acme), refused(acme), old(globex)])
            .await
            .unwrap();
        let retention = PgStreamRecordRetention::new(Arc::clone(&db.databases));
        let yesterday = OffsetDateTime::now_utc() - time::Duration::days(1);

        let removed = retention
            .forget_before(
                &ScopedTenant::for_background(acme),
                yesterday,
                NonZeroU32::MIN,
            )
            .await
            .unwrap();

        assert_eq!(removed, 1);
        assert_eq!(kept(&db, acme).await, [("denied".to_owned(), None, 0)]);
        assert_eq!(kept(&db, globex).await.len(), 1);
    }
}
