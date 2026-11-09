//! The figures of an organization's metrics overview: its tenants' figures
//! added up, read from the platform database for the tenants there and
//! from each tenant's own database for the others, all at once; and for a
//! past moment the counts the scheduled snapshot kept.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::metrics::{OrganizationMetricsReader, RequestMetrics};
use ianua_domain::domains::metrics::{
    LatencyMs, LoginOutcomeCounts, MetricsWindow, TimeSeriesPoint,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::OrganizationId;
use time::OffsetDateTime;

use self::record::{OrgMetric, OrgSnapshotRecord};
use crate::postgres::audit::logs::sources::organization_tenants;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;
use crate::postgres::metrics::figures::{
    Spread, durations, is_live, last_sign_in, outcomes, people_at, requests, series, sessions_at,
};
use crate::postgres::metrics::tenant::record::{
    BucketRecord, DurationRecord, DurationsRecord, OutcomesRecord, count,
};

/// The Postgres reader of an organization's metrics.
pub struct PgOrganizationMetricsReader {
    databases: Arc<Databases>,
}

impl PgOrganizationMetricsReader {
    /// A reader of the metrics in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Where the tenants of `organization` are read.
    async fn spread(&self, organization: &OrganizationId) -> Result<Spread, DomainError> {
        let tenants = organization_tenants(&self.databases, organization).await?;
        Ok(Spread::of(&self.databases, tenants))
    }

    /// The last snapshot of `organization` at or before `at`, unless the
    /// live tables still answer for it.
    async fn snapshot(
        &self,
        organization: &OrganizationId,
        at: OffsetDateTime,
    ) -> Result<Option<OrgSnapshotRecord>, DomainError> {
        if is_live(at) {
            return Ok(None);
        }
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                OrgSnapshotRecord,
                "queries/org_metric_snapshots/at_or_before.sql",
                organization.as_uuid(),
                at
            )
            .fetch_optional(connection)
            .await
        })
        .await
    }

    /// The live count of `metric` of `organization` at `at`.
    async fn live(
        &self,
        organization: &OrganizationId,
        at: OffsetDateTime,
        metric: OrgMetric,
    ) -> Result<u64, DomainError> {
        let databases = self.databases.as_ref();
        let spread = self.spread(organization).await?;
        let counts = match metric {
            OrgMetric::People => {
                spread
                    .gather(|scope, tenants| people_at(databases, scope, tenants, at))
                    .await?
            }
            OrgMetric::Sessions => {
                spread
                    .gather(|scope, tenants| sessions_at(databases, scope, tenants, at))
                    .await?
            }
            OrgMetric::Tenants => vec![self.tenants_at(organization, at).await?],
        };
        Ok(count(counts.into_iter().fold(0, i64::saturating_add)))
    }

    /// How many tenants `organization` held at `at`.
    async fn tenants_at(
        &self,
        organization: &OrganizationId,
        at: OffsetDateTime,
    ) -> Result<i64, DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_scalar!("queries/tenants/counted_at.sql", organization.as_uuid(), at)
                .fetch_one(connection)
                .await
        })
        .await
    }

    /// The count of `metric` at `at`: as the last snapshot kept it for a
    /// moment the live tables no longer answer for, else counted live.
    async fn counted_at(
        &self,
        organization: &OrganizationId,
        at: OffsetDateTime,
        metric: OrgMetric,
    ) -> Result<u64, DomainError> {
        if let Some(kept) = self.snapshot(organization, at).await? {
            return Ok(kept.into_count(metric));
        }
        self.live(organization, at, metric).await
    }
}

#[async_trait]
impl OrganizationMetricsReader for PgOrganizationMetricsReader {
    async fn login_outcomes(
        &self,
        organization_id: &OrganizationId,
        window: &MetricsWindow,
    ) -> Result<LoginOutcomeCounts, DomainError> {
        let databases = self.databases.as_ref();
        let counted = self
            .spread(organization_id)
            .await?
            .gather(|scope, tenants| outcomes(databases, scope, tenants, window))
            .await?;
        Ok(OutcomesRecord::summed(&counted).into_counts())
    }

    async fn login_outcome_series(
        &self,
        organization_id: &OrganizationId,
        window: &MetricsWindow,
    ) -> Result<Vec<TimeSeriesPoint>, DomainError> {
        let databases = self.databases.as_ref();
        let buckets = self
            .spread(organization_id)
            .await?
            .gather(|scope, tenants| series(databases, scope, tenants, window))
            .await?;
        Ok(BucketRecord::into_series(
            buckets.into_iter().flatten().collect(),
        ))
    }

    async fn average_auth_duration_ms(
        &self,
        organization_id: &OrganizationId,
        window: &MetricsWindow,
    ) -> Result<Option<LatencyMs>, DomainError> {
        let databases = self.databases.as_ref();
        let measured = self
            .spread(organization_id)
            .await?
            .gather(|scope, tenants| durations(databases, scope, tenants, window))
            .await?;
        Ok(DurationsRecord::into_average(&measured))
    }

    async fn count_users_as_of(
        &self,
        organization_id: &OrganizationId,
        at: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        self.counted_at(organization_id, at, OrgMetric::People)
            .await
    }

    async fn count_tenants_as_of(
        &self,
        organization_id: &OrganizationId,
        at: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        self.counted_at(organization_id, at, OrgMetric::Tenants)
            .await
    }

    async fn count_active_sessions_as_of(
        &self,
        organization_id: &OrganizationId,
        at: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        self.counted_at(organization_id, at, OrgMetric::Sessions)
            .await
    }

    async fn request_metrics(
        &self,
        organization_id: &OrganizationId,
        window: &MetricsWindow,
    ) -> Result<RequestMetrics, DomainError> {
        let databases = self.databases.as_ref();
        let read = self
            .spread(organization_id)
            .await?
            .gather(|scope, tenants| requests(databases, scope, tenants, window))
            .await?;
        Ok(DurationRecord::into_metrics(
            read.into_iter().flatten().collect(),
        ))
    }

    async fn last_login(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Option<OffsetDateTime>, DomainError> {
        let databases = self.databases.as_ref();
        let last = self
            .spread(organization_id)
            .await?
            .gather(|scope, tenants| last_sign_in(databases, scope, tenants))
            .await?;
        Ok(last.into_iter().flatten().max())
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_app::ports::proxy::ProxyAccessLogSink;
    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::test_support::events::sample_login_succeeded;

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::postgres::proxy::PgProxyAccessLogSink;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::{
        failed_sign_in, recorded, saved_organization, saved_tenant_of,
    };
    use crate::test_support::rows::identity::user_row;
    use crate::test_support::rows::proxy::{allowed, request_record};

    struct Fixture {
        db: TestDb,
        _own: TestDb,
        organization: OrganizationId,
        shared: ScopedTenant,
        apart: ScopedTenant,
        reader: PgOrganizationMetricsReader,
    }

    impl Fixture {
        /// Checks aggregate sign-in totals, hourly buckets, duration and latest success.
        async fn assert_sign_ins(&self) {
            let counted = self
                .reader
                .login_outcomes(&self.organization, &hour())
                .await
                .unwrap();
            let points = self
                .reader
                .login_outcome_series(&self.organization, &hour())
                .await
                .unwrap();
            let average = self
                .reader
                .average_auth_duration_ms(&self.organization, &hour())
                .await
                .unwrap();
            let last = self.reader.last_login(&self.organization).await.unwrap();
            assert_eq!(counted, LoginOutcomeCounts::new(2, 1));
            assert_eq!(points.len(), 1);
            assert_eq!(points[0].outcomes(), LoginOutcomeCounts::new(2, 1));
            assert_eq!(average, Some(LatencyMs::new(20)));
            assert_eq!(last, Some(at(20)));
        }
    }

    /// A fresh database holding Acme with two tenants, one of them in a
    /// database of its own, another organization with a tenant of its own,
    /// and the reader on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let own = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let shared = saved_tenant_of(&db.databases, organization).await;
        let apart = saved_tenant_of(&db.databases, organization).await;
        db.databases.register(*apart, own.as_dedicated());
        let reader = PgOrganizationMetricsReader::new(Arc::clone(&db.databases));
        Fixture {
            db,
            _own: own,
            organization,
            shared,
            apart,
            reader,
        }
    }

    fn hour() -> MetricsWindow {
        MetricsWindow::new(at(0), at(3_600)).unwrap()
    }

    /// The sign-ins of both of Acme's tenants are added up, wherever each
    /// lives, and another organization's are left out.
    #[tokio::test]
    async fn the_sign_ins_of_every_tenant_are_added_up() {
        let db = fixture().await;
        let globex = saved_organization(&db.db.databases).await;
        let theirs = saved_tenant_of(&db.db.databases, globex).await;
        recorded(
            &db.db.databases,
            vec![
                sample_login_succeeded(*db.shared, 10, at(10)),
                sample_login_succeeded(*db.apart, 30, at(20)),
                failed_sign_in(*db.apart, 30),
                sample_login_succeeded(*theirs, 99, at(40)),
            ],
        )
        .await;

        db.assert_sign_ins().await;
    }

    /// The requests of both tenants are counted together, with one 95th
    /// percentile over all of them.
    #[tokio::test]
    async fn the_requests_of_every_tenant_are_measured_together() {
        let db = fixture().await;
        PgProxyAccessLogSink::new(Arc::clone(&db.db.databases))
            .write_batch(&[
                request_record(*db.shared, allowed(200), 10, 1),
                request_record(*db.apart, allowed(200), 20, 2),
            ])
            .await
            .unwrap();

        let metrics = db
            .reader
            .request_metrics(&db.organization, &hour())
            .await
            .unwrap();

        assert_eq!(metrics.request_count, 2);
        assert_eq!(metrics.error_count, 0);
        assert_eq!(metrics.p95_latency_ms, Some(LatencyMs::new(20)));
    }

    /// Acme's people are counted across its tenants, and its tenants
    /// themselves, as they are now.
    #[tokio::test]
    async fn people_and_tenants_are_counted_live() {
        let db = fixture().await;
        let users = PgUserStore::new(Arc::clone(&db.db.databases), DomainLimits::default());
        for (tenant, email) in [(&db.shared, "ann@acme.test"), (&db.apart, "bob@acme.test")] {
            let user = User::reconstitute(user_row(email)).unwrap();
            users.save(tenant, &user).await.unwrap();
        }
        let moment = at(1);

        let people = db
            .reader
            .count_users_as_of(&db.organization, moment)
            .await
            .unwrap();
        let tenants = db
            .reader
            .count_tenants_as_of(&db.organization, moment)
            .await
            .unwrap();
        let sessions = db
            .reader
            .count_active_sessions_as_of(&db.organization, moment)
            .await
            .unwrap();

        assert_eq!(people, 2);
        assert_eq!(tenants, 2);
        assert_eq!(sessions, 0);
    }
}
