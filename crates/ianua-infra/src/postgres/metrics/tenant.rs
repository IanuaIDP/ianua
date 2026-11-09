//! The figures of one tenant's metrics overview: its sign-ins, read from
//! its audit records; its traffic, from its request records; its people,
//! sessions and API keys, counted live; and for a past moment the counts
//! the scheduled snapshot kept.

pub(crate) mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::metrics::{RequestMetrics, TenantMetricsReader};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::metrics::{
    LatencyMs, LoginOutcomeCounts, MetricsWindow, TimeSeriesPoint,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{
    BucketRecord, DurationRecord, DurationsRecord, SnapshotRecord, TenantMetric, count,
};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;
use crate::postgres::metrics::figures::{
    durations, is_live, last_sign_in, outcomes, people_at, requests, series, sessions_at,
};

/// The Postgres reader of a tenant's metrics.
pub struct PgTenantMetricsReader {
    databases: Arc<Databases>,
}

impl PgTenantMetricsReader {
    /// A reader of the metrics in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The scope and the tenant list a figure of `tenant` is read with.
    fn of(tenant: &ScopedTenant) -> (RowScope, Vec<Uuid>) {
        (RowScope::from(tenant), vec![*tenant.as_uuid()])
    }

    /// The last snapshot at or before `at`, unless the live tables still
    /// answer for it; snapshots are kept in the platform database.
    async fn snapshot(
        &self,
        tenant: &ScopedTenant,
        at: OffsetDateTime,
    ) -> Result<Option<SnapshotRecord>, DomainError> {
        if is_live(at) {
            return Ok(None);
        }
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(
                SnapshotRecord,
                "queries/tenant_metric_snapshots/at_or_before.sql",
                tenant.as_uuid(),
                at
            )
            .fetch_optional(connection)
            .await
        })
        .await
    }

    /// The count of `metric` of `tenant` at `at`: live when the live tables still
    /// answer for it, else as the last snapshot kept it, else counted live
    /// as far as the tables can tell.
    async fn counted_at(
        &self,
        tenant: &ScopedTenant,
        at: OffsetDateTime,
        metric: TenantMetric,
    ) -> Result<u64, DomainError> {
        if let Some(kept) = self.snapshot(tenant, at).await? {
            return Ok(kept.into_count(metric));
        }
        let (scope, tenants) = Self::of(tenant);
        let live = match metric {
            TenantMetric::People => people_at(&self.databases, scope, tenants, at).await?,
            TenantMetric::Sessions => sessions_at(&self.databases, scope, tenants, at).await?,
        };
        Ok(count(live))
    }
}

impl TenantScoped for PgTenantMetricsReader {}

#[async_trait]
impl TenantMetricsReader for PgTenantMetricsReader {
    async fn login_outcomes(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<LoginOutcomeCounts, DomainError> {
        let (scope, tenants) = Self::of(tenant_id);
        let counted = outcomes(&self.databases, scope, tenants, window).await?;
        Ok(counted.into_counts())
    }

    async fn login_outcome_series(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<Vec<TimeSeriesPoint>, DomainError> {
        let (scope, tenants) = Self::of(tenant_id);
        let buckets = series(&self.databases, scope, tenants, window).await?;
        Ok(BucketRecord::into_series(buckets))
    }

    async fn average_auth_duration_ms(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<Option<LatencyMs>, DomainError> {
        let (scope, tenants) = Self::of(tenant_id);
        let measured = durations(&self.databases, scope, tenants, window).await?;
        Ok(DurationsRecord::into_average(&[measured]))
    }

    async fn count_users_as_of(
        &self,
        tenant_id: &ScopedTenant,
        at: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        self.counted_at(tenant_id, at, TenantMetric::People).await
    }

    async fn count_active_users(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<u64, DomainError> {
        let active = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/audit_records/people_signed_in.sql",
                    tenant_id.as_uuid(),
                    window.start(),
                    window.end()
                )
                .fetch_one(connection)
                .await
            },
        )
        .await?;
        Ok(count(active))
    }

    async fn count_active_sessions_as_of(
        &self,
        tenant_id: &ScopedTenant,
        at: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        self.counted_at(tenant_id, at, TenantMetric::Sessions).await
    }

    async fn request_metrics(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<RequestMetrics, DomainError> {
        let (scope, tenants) = Self::of(tenant_id);
        let read = requests(&self.databases, scope, tenants, window).await?;
        Ok(DurationRecord::into_metrics(read))
    }

    async fn last_login(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<OffsetDateTime>, DomainError> {
        let (scope, tenants) = Self::of(tenant_id);
        last_sign_in(&self.databases, scope, tenants).await
    }

    async fn count_active_api_keys(&self, tenant_id: &ScopedTenant) -> Result<u64, DomainError> {
        let now = clock::now();
        let active = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!("queries/api_keys/unexpired.sql", tenant_id.as_uuid(), now)
                    .fetch_one(connection)
                    .await
            },
        )
        .await?;
        Ok(count(active))
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::oauth::ApiKeyStore;
    use ianua_app::ports::proxy::ProxyAccessLogSink;
    use ianua_domain::domains::oauth::clients::api_key::ApiKey;
    use ianua_domain::domains::proxy::observation::RequestOutcome;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::test_support::events::sample_login_succeeded;
    use ianua_domain::types::{ActorRef, TenantId, UserId};

    use super::*;
    use crate::postgres::oauth::PgApiKeyStore;
    use crate::postgres::proxy::PgProxyAccessLogSink;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::{
        failed_sign_in, recorded, saved_organization, saved_tenant_of,
    };
    use crate::test_support::rows::authentication::signed_in_session;
    use crate::test_support::rows::oauth::api_key_row;
    use crate::test_support::rows::proxy::{allowed, request_record};

    struct Fixture {
        db: TestDb,
        tenant: ScopedTenant,
        reader: PgTenantMetricsReader,
    }

    /// A fresh database holding a tenant of Acme, and the reader on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        let reader = PgTenantMetricsReader::new(Arc::clone(&db.databases));
        Fixture { db, tenant, reader }
    }

    fn window(from: i64, until: i64) -> MetricsWindow {
        MetricsWindow::new(at(from), at(until)).unwrap()
    }

    /// Two sign-ins succeed, timed at 10 and 30 milliseconds, and one fails
    /// in the window; one more succeeds after it. The figures count the
    /// window's, Ann once as an active user, and the last sign-in is the
    /// latest of all.
    #[tokio::test]
    async fn sign_ins_in_the_window_are_counted() {
        let db = fixture().await;
        let ann = ActorRef::User(UserId::new());
        let tenant = *db.tenant;
        recorded(
            &db.db.databases,
            vec![
                sample_login_succeeded(tenant, 10, at(10)).with_actor(ann.clone()),
                sample_login_succeeded(tenant, 30, at(20)).with_actor(ann),
                failed_sign_in(tenant, 30),
                sample_login_succeeded(tenant, 99, at(5_000)),
            ],
        )
        .await;
        let hour = window(0, 3_600);

        let counted = db.reader.login_outcomes(&db.tenant, &hour).await.unwrap();
        let average = db
            .reader
            .average_auth_duration_ms(&db.tenant, &hour)
            .await
            .unwrap();
        let active = db
            .reader
            .count_active_users(&db.tenant, &hour)
            .await
            .unwrap();
        let last = db.reader.last_login(&db.tenant).await.unwrap();

        assert_eq!(counted, LoginOutcomeCounts::new(2, 1));
        assert_eq!(average, Some(LatencyMs::new(20)));
        assert_eq!(active, 1);
        assert_eq!(last, Some(at(5_000)));
    }

    /// Sign-ins are bucketed by the hour across a short window, in time
    /// order.
    #[tokio::test]
    async fn sign_ins_are_bucketed_by_the_hour() {
        let db = fixture().await;
        let tenant = *db.tenant;
        recorded(
            &db.db.databases,
            vec![
                sample_login_succeeded(tenant, 10, at(10)),
                failed_sign_in(tenant, 20),
                sample_login_succeeded(tenant, 10, at(3_700)),
            ],
        )
        .await;

        let points = db
            .reader
            .login_outcome_series(&db.tenant, &window(0, 7_200))
            .await
            .unwrap();

        let counts: Vec<LoginOutcomeCounts> =
            points.iter().map(TimeSeriesPoint::outcomes).collect();
        assert_eq!(
            counts,
            [LoginOutcomeCounts::new(1, 1), LoginOutcomeCounts::new(1, 0)]
        );
    }

    /// The window's requests are counted with their refusals and their
    /// 95th percentile; a request after it is left out.
    #[tokio::test]
    async fn the_windows_requests_are_measured() {
        let db = fixture().await;
        let tenant = *db.tenant;
        let refused = RequestOutcome::Undecided;
        PgProxyAccessLogSink::new(Arc::clone(&db.db.databases))
            .write_batch(&[
                request_record(tenant, allowed(200), 10, 1),
                request_record(tenant, refused, 20, 2),
                request_record(tenant, allowed(200), 500, 9_000),
            ])
            .await
            .unwrap();

        let metrics = db
            .reader
            .request_metrics(&db.tenant, &window(0, 3_600))
            .await
            .unwrap();

        assert_eq!(metrics.request_count, 2);
        assert_eq!(metrics.error_count, 1);
        assert_eq!(metrics.p95_latency_ms, Some(LatencyMs::new(20)));
    }

    /// The tenant's people, its active sessions and its working API keys
    /// are counted as they are now.
    #[tokio::test]
    async fn people_sessions_and_keys_are_counted_live() {
        let db = fixture().await;
        signed_in_session(&db.db.databases, &db.tenant).await;
        let key: ApiKey<ResolvedTenant> =
            ApiKey::reconstitute(api_key_row("ci", ActorRef::User(UserId::new()))).unwrap();
        PgApiKeyStore::new(Arc::clone(&db.db.databases))
            .insert(&db.tenant, &key)
            .await
            .unwrap();
        let now = clock::now().max(at(1));

        let people = db.reader.count_users_as_of(&db.tenant, now).await.unwrap();
        let sessions = db
            .reader
            .count_active_sessions_as_of(&db.tenant, clock::now())
            .await
            .unwrap();
        let keys = db.reader.count_active_api_keys(&db.tenant).await.unwrap();

        assert_eq!(people, 1);
        assert_eq!(sessions, 1);
        assert_eq!(keys, 1);
    }

    /// A tenant's sign-in totals stay zero when the only recorded failure
    /// belongs to another tenant.
    #[tokio::test]
    async fn another_tenants_sign_ins_are_not_counted() {
        let db = fixture().await;
        let other = ScopedTenant::for_background(TenantId::new());
        recorded(&db.db.databases, vec![failed_sign_in(*db.tenant, 10)]).await;

        let counted = db
            .reader
            .login_outcomes(&other, &window(0, 3_600))
            .await
            .unwrap();

        assert_eq!(counted, LoginOutcomeCounts::new(0, 0));
    }
}
