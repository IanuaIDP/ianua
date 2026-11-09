//! The scheduled snapshots of every organization's and tenant's headline
//! counts, kept in the platform database so a trend can compare against a
//! past count no live table can give.
//!
//! A capture counts the tenants in the platform database in one
//! statement, each tenant with a database of its own in its own, keeps
//! those counts in one more, and then each organization's, added up from
//! its tenants' of the same moment.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::ports::metrics::MetricSnapshotWriter;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{CountsBatch, CountsRecord, into_captured};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres writer of the metrics snapshots.
pub struct PgMetricSnapshotWriter {
    databases: Arc<Databases>,
}

impl PgMetricSnapshotWriter {
    /// A writer keeping snapshots in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Keeps the counts of the tenants in the platform database, those in
    /// `apart` left out.
    async fn capture_shared(&self, now: OffsetDateTime, apart: &[Uuid]) -> Result<(), DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/tenant_metric_snapshots/capture_shared.sql",
                now,
                apart
            )
            .execute(connection)
            .await?;
            Ok(())
        })
        .await
    }

    /// The counts of `tenant`, read in its own database.
    async fn counted(
        &self,
        tenant: TenantId,
        now: OffsetDateTime,
    ) -> Result<(Uuid, CountsRecord), DomainError> {
        let counts = scoped(
            &self.databases,
            RowScope::Tenant(tenant),
            async |connection| {
                sqlx::query_file_as!(
                    CountsRecord,
                    "queries/users/snapshot_counts.sql",
                    tenant.as_uuid(),
                    now
                )
                .fetch_one(connection)
                .await
            },
        )
        .await?;
        Ok((*tenant.as_uuid(), counts))
    }

    /// Keeps the counts read from the tenants with a database of their own.
    async fn keep_apart(&self, now: OffsetDateTime, batch: CountsBatch) -> Result<(), DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/tenant_metric_snapshots/save_all.sql",
                now,
                &batch.tenant_ids,
                &batch.users,
                &batch.sessions
            )
            .execute(connection)
            .await?;
            Ok(())
        })
        .await
    }

    /// Keeps every organization's counts, and answers how many.
    async fn capture_organizations(&self, now: OffsetDateTime) -> Result<i64, DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_scalar!("queries/org_metric_snapshots/capture.sql", now)
                .fetch_one(connection)
                .await
        })
        .await
    }
}

#[async_trait]
impl MetricSnapshotWriter for PgMetricSnapshotWriter {
    async fn capture_all(&self) -> Result<u64, DomainError> {
        let now = clock::now();
        let apart = self.databases.with_own_database();
        let apart_ids: Vec<Uuid> = apart.iter().map(|tenant| *tenant.as_uuid()).collect();
        self.capture_shared(now, &apart_ids).await?;
        let counted =
            try_join_all(apart.into_iter().map(|tenant| self.counted(tenant, now))).await?;
        self.keep_apart(now, CountsBatch::into_batch(counted))
            .await?;
        let captured = self.capture_organizations(now).await?;
        Ok(into_captured(captured))
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_app::ports::metrics::{OrganizationMetricsReader, TenantMetricsReader};
    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::OrganizationId;
    use time::Duration;

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::postgres::metrics::{PgOrganizationMetricsReader, PgTenantMetricsReader};
    use crate::test_support::TestDb;
    use crate::test_support::rows::audit::{saved_organization, saved_tenant_of};
    use crate::test_support::rows::identity::user_row;

    /// Requires the historical tenant snapshot to retain its one original user.
    async fn assert_tenant_count(
        reader: &PgTenantMetricsReader,
        tenant: &ScopedTenant,
        back: OffsetDateTime,
    ) {
        assert_eq!(reader.count_users_as_of(tenant, back).await.unwrap(), 1);
    }

    /// Requires the historical organization snapshot to retain both tenants and users.
    async fn assert_organization_counts(
        reader: &PgOrganizationMetricsReader,
        organization: &OrganizationId,
        back: OffsetDateTime,
    ) {
        assert_eq!(
            reader.count_users_as_of(organization, back).await.unwrap(),
            2
        );
        assert_eq!(
            reader
                .count_tenants_as_of(organization, back)
                .await
                .unwrap(),
            2
        );
    }

    /// A capture keeps every organization's and tenant's counts, a tenant
    /// in a database of its own included; read for a moment three hours
    /// back, past what the live tables answer for, the counts are the
    /// snapshot's, though people joined since.
    #[tokio::test]
    async fn a_capture_keeps_the_counts_a_past_moment_reads() {
        let db = TestDb::fresh().await;
        let own = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let shared = saved_tenant_of(&db.databases, organization).await;
        let apart = saved_tenant_of(&db.databases, organization).await;
        db.databases.register(*apart, own.as_dedicated());
        saved_organization(&db.databases).await;
        let users = PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default());
        for (tenant, email) in [(&shared, "ann@acme.test"), (&apart, "bob@acme.test")] {
            let user = User::reconstitute(user_row(email)).unwrap();
            users.save(tenant, &user).await.unwrap();
        }
        let writer = PgMetricSnapshotWriter::new(Arc::clone(&db.databases));

        let captured = writer.capture_all().await.unwrap();
        db.tamper(
            "UPDATE tenant_metric_snapshots SET captured_at = captured_at - interval '4 hours'; \
             UPDATE org_metric_snapshots SET captured_at = captured_at - interval '4 hours';",
        )
        .await;
        let late = User::reconstitute(user_row("cy@acme.test")).unwrap();
        users.save(&shared, &late).await.unwrap();
        let back = clock::now().saturating_sub(Duration::hours(3));
        let tenant_reader = PgTenantMetricsReader::new(Arc::clone(&db.databases));
        let org_reader = PgOrganizationMetricsReader::new(Arc::clone(&db.databases));

        assert_eq!(captured, 2);
        assert_tenant_count(&tenant_reader, &shared, back).await;
        assert_tenant_count(&tenant_reader, &apart, back).await;
        assert_organization_counts(&org_reader, &organization, back).await;
    }
}
