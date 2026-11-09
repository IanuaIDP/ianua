//! Assembles the tenant metrics overview from raw figures.
//!
//! Reads counts and aggregates through [`TenantMetricsReader`] and
//! turns them into rates, trends, and a composite health score using
//! the shared overview building blocks. The comparison baseline for
//! every trend is the equal-length window immediately preceding the
//! requested one.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{MetricsAction, SystemPermission};
use ianua_domain::domains::metrics::{
    HealthScore, LatencyMs, LoginOutcomeCounts, MetricsWindow, TimeSeriesPoint,
};
use time::OffsetDateTime;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::metrics::{RequestMetrics, TenantMetricsReader};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::metrics::overview::{
    ApiUsageMetrics, AuthenticationFigures, AuthenticationMetrics, Trended, count_trend,
};

/// The full tenant metrics overview.
pub struct TenantMetrics {
    /// The window these figures were computed over.
    pub window: MetricsWindow,
    /// Composite health score from 0 to 100 for the window.
    pub health: HealthScore,
    /// Authentication figures and charts.
    pub authentication: AuthenticationMetrics,
    /// Total users, trended against the window start.
    pub users: Trended<u64>,
    /// Distinct users that logged in within the window, trended
    /// against the preceding window.
    pub active_users: Trended<u64>,
    /// Active sessions, trended against the window start.
    pub active_sessions: Trended<u64>,
    /// Proxied API usage figures.
    pub api: ApiUsageMetrics,
    /// Unexpired API keys. Revoked keys are deleted, so a surviving,
    /// unexpired row is active.
    pub active_api_keys: u64,
}

/// The ports [`GetTenantMetricsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetTenantMetricsPorts {
    /// The tenant's figures.
    pub reader: Arc<dyn TenantMetricsReader>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Builds the tenant metrics overview.
pub struct GetTenantMetricsUseCase {
    ports: GetTenantMetricsPorts,
}

impl GetTenantMetricsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetTenantMetricsPorts) -> Self {
        Self { ports }
    }

    async fn authentication(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<AuthenticationMetrics, AppError> {
        let previous = window.previous();
        let (current, baseline, series, avg_current, avg_previous, last_login) = futures_util::try_join!(
            self.login_outcomes(tenant_id, window),
            self.login_outcomes(tenant_id, &previous),
            self.login_series(tenant_id, window),
            self.avg_auth(tenant_id, window),
            self.avg_auth(tenant_id, &previous),
            self.last_login(tenant_id),
        )?;

        Ok(AuthenticationMetrics::from(AuthenticationFigures {
            current,
            baseline,
            series,
            avg_auth_ms: avg_current,
            baseline_avg_auth_ms: avg_previous,
            last_login,
        }))
    }

    async fn user_trend(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<Trended<u64>, AppError> {
        let (current, previous) = futures_util::try_join!(
            self.count_users(tenant_id, window.end()),
            self.count_users(tenant_id, window.start()),
        )?;

        Ok(count_trend(current, previous))
    }

    async fn active_user_trend(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<Trended<u64>, AppError> {
        let previous = window.previous();
        let (current, baseline) = futures_util::try_join!(
            self.count_active_users(tenant_id, window),
            self.count_active_users(tenant_id, &previous),
        )?;

        Ok(count_trend(current, baseline))
    }

    async fn session_trend(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<Trended<u64>, AppError> {
        let (current, previous) = futures_util::try_join!(
            self.count_sessions(tenant_id, window.end()),
            self.count_sessions(tenant_id, window.start()),
        )?;

        Ok(count_trend(current, previous))
    }

    async fn api_usage(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<ApiUsageMetrics, AppError> {
        let previous = window.previous();
        let (current, baseline) = futures_util::try_join!(
            self.request_metrics(tenant_id, window),
            self.request_metrics(tenant_id, &previous),
        )?;

        Ok(ApiUsageMetrics::from_windows(current, baseline))
    }

    async fn login_outcomes(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<LoginOutcomeCounts, AppError> {
        self.ports
            .reader
            .login_outcomes(tenant_id, window)
            .await
            .or_internal()
    }

    async fn login_series(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<Vec<TimeSeriesPoint>, AppError> {
        self.ports
            .reader
            .login_outcome_series(tenant_id, window)
            .await
            .or_internal()
    }

    async fn avg_auth(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<Option<LatencyMs>, AppError> {
        self.ports
            .reader
            .average_auth_duration_ms(tenant_id, window)
            .await
            .or_internal()
    }

    async fn last_login(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<OffsetDateTime>, AppError> {
        self.ports.reader.last_login(tenant_id).await.or_internal()
    }

    async fn count_users(
        &self,
        tenant_id: &ScopedTenant,
        at: OffsetDateTime,
    ) -> Result<u64, AppError> {
        self.ports
            .reader
            .count_users_as_of(tenant_id, at)
            .await
            .or_internal()
    }

    async fn count_active_users(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<u64, AppError> {
        self.ports
            .reader
            .count_active_users(tenant_id, window)
            .await
            .or_internal()
    }

    async fn count_sessions(
        &self,
        tenant_id: &ScopedTenant,
        at: OffsetDateTime,
    ) -> Result<u64, AppError> {
        self.ports
            .reader
            .count_active_sessions_as_of(tenant_id, at)
            .await
            .or_internal()
    }

    async fn request_metrics(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<RequestMetrics, AppError> {
        self.ports
            .reader
            .request_metrics(tenant_id, window)
            .await
            .or_internal()
    }

    async fn active_api_keys(&self, tenant_id: &ScopedTenant) -> Result<u64, AppError> {
        self.ports
            .reader
            .count_active_api_keys(tenant_id)
            .await
            .or_internal()
    }
}

impl Query for GetTenantMetricsUseCase {
    type Caller = CallerContext;
    type Input = MetricsWindow;
    type Output = Result<TenantMetrics, AppError>;

    /// Builds the overview of the tenant `ctx` acts in, over `window`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view the tenant's
    ///   metrics.
    /// - `AppError::Internal` if the metrics reader fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        window: MetricsWindow,
    ) -> Result<TenantMetrics, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Metrics(MetricsAction::View))
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let (authentication, users, active_users, active_sessions, api, active_api_keys) = futures_util::try_join!(
            self.authentication(&tenant, &window),
            self.user_trend(&tenant, &window),
            self.active_user_trend(&tenant, &window),
            self.session_trend(&tenant, &window),
            self.api_usage(&tenant, &window),
            self.active_api_keys(&tenant),
        )?;

        Ok(TenantMetrics {
            window,
            health: health_score(&authentication, &api),
            authentication,
            users,
            active_users,
            active_sessions,
            api,
            active_api_keys,
        })
    }
}

fn health_score(authentication: &AuthenticationMetrics, api: &ApiUsageMetrics) -> HealthScore {
    HealthScore::from_rates([
        authentication
            .success_rate
            .current
            .map(|rate| rate.percent()),
        api.success_rate_percent(),
    ])
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::metrics::TrendDirection;
    use ianua_domain::shared::errors::DomainError;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::operator::operator_without_grant;
    use crate::test_support::{block_on, test_ctx};

    struct FakeReader {
        current: LoginOutcomeCounts,
        previous: LoginOutcomeCounts,
        users_now: u64,
        users_then: u64,
        active_now: u64,
        active_then: u64,
        requests_now: RequestMetrics,
        requests_then: RequestMetrics,
        api_keys: u64,
    }

    impl crate::ports::TenantScoped for FakeReader {}

    impl FakeReader {
        fn in_current_window(&self, window: &MetricsWindow) -> bool {
            window.start() == fixed_window().start()
        }
    }

    #[async_trait]
    impl TenantMetricsReader for FakeReader {
        async fn login_outcomes(
            &self,
            _: &crate::tenancy::ScopedTenant,
            window: &MetricsWindow,
        ) -> Result<LoginOutcomeCounts, DomainError> {
            Ok(match self.in_current_window(window) {
                true => self.current,
                false => self.previous,
            })
        }

        async fn login_outcome_series(
            &self,
            _: &crate::tenancy::ScopedTenant,
            _: &MetricsWindow,
        ) -> Result<Vec<TimeSeriesPoint>, DomainError> {
            Ok(vec![TimeSeriesPoint::new(
                fixed_window().start(),
                self.current,
            )])
        }

        async fn average_auth_duration_ms(
            &self,
            _: &crate::tenancy::ScopedTenant,
            window: &MetricsWindow,
        ) -> Result<Option<LatencyMs>, DomainError> {
            Ok(match self.in_current_window(window) {
                true => Some(LatencyMs::new(120)),
                false => Some(LatencyMs::new(150)),
            })
        }

        async fn count_users_as_of(
            &self,
            _: &crate::tenancy::ScopedTenant,
            at: OffsetDateTime,
        ) -> Result<u64, DomainError> {
            Ok(match at == fixed_window().end() {
                true => self.users_now,
                false => self.users_then,
            })
        }

        async fn count_active_users(
            &self,
            _: &crate::tenancy::ScopedTenant,
            window: &MetricsWindow,
        ) -> Result<u64, DomainError> {
            Ok(match self.in_current_window(window) {
                true => self.active_now,
                false => self.active_then,
            })
        }

        async fn count_active_sessions_as_of(
            &self,
            _: &crate::tenancy::ScopedTenant,
            _: OffsetDateTime,
        ) -> Result<u64, DomainError> {
            Ok(17)
        }

        async fn request_metrics(
            &self,
            _: &crate::tenancy::ScopedTenant,
            window: &MetricsWindow,
        ) -> Result<RequestMetrics, DomainError> {
            Ok(match self.in_current_window(window) {
                true => self.requests_now,
                false => self.requests_then,
            })
        }

        async fn last_login(
            &self,
            _: &crate::tenancy::ScopedTenant,
        ) -> Result<Option<OffsetDateTime>, DomainError> {
            Ok(Some(at(1_900)))
        }

        async fn count_active_api_keys(
            &self,
            _: &crate::tenancy::ScopedTenant,
        ) -> Result<u64, DomainError> {
            Ok(self.api_keys)
        }
    }

    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).unwrap()
    }

    fn fixed_window() -> MetricsWindow {
        MetricsWindow::new(at(1_000), at(2_000)).unwrap()
    }

    fn reader() -> Arc<FakeReader> {
        Arc::new(FakeReader {
            current: LoginOutcomeCounts::new(90, 10),
            previous: LoginOutcomeCounts::new(40, 10),
            users_now: 74,
            users_then: 64,
            active_now: 10,
            active_then: 8,
            requests_now: RequestMetrics {
                request_count: 1_000,
                error_count: 100,
                p95_latency_ms: Some(LatencyMs::new(90)),
            },
            requests_then: RequestMetrics {
                request_count: 800,
                error_count: 16,
                p95_latency_ms: Some(LatencyMs::new(110)),
            },
            api_keys: 2,
        })
    }

    fn overview_as(
        ctx: &CallerContext,
        authorities: FakeTenantAuthorities,
    ) -> Result<TenantMetrics, AppError> {
        let uc = GetTenantMetricsUseCase::new(GetTenantMetricsPorts {
            reader: reader(),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(uc.execute(ctx, fixed_window()))
    }

    fn metrics() -> TenantMetrics {
        overview_as(&test_ctx(), FakeTenantAuthorities::holding_everything()).unwrap()
    }

    /// 90 percent of sign-ins and 90 percent of requests went well. The
    /// health score is 90.
    #[test]
    fn health_averages_auth_and_api_success_rates() {
        assert_eq!(metrics().health.value(), 90);
    }

    /// Ten people signed in this week against eight the week before. The
    /// overview shows ten, up 25 percent.
    #[test]
    fn trends_active_users_against_the_previous_window() {
        let metrics = metrics();

        assert_eq!(metrics.active_users.current, 10);
        assert_eq!(metrics.active_users.trend.change_pct(), Some(25.0));
        assert_eq!(metrics.active_users.trend.direction(), TrendDirection::Up);
    }

    /// The overview carries the reader's user, session, sign-in, request
    /// and key figures as they are.
    #[test]
    fn assembles_counts_auth_figures_and_api_keys() {
        let metrics = metrics();

        assert_eq!(metrics.users.current, 74);
        assert_eq!(metrics.active_sessions.current, 17);
        assert_eq!(metrics.active_api_keys, 2);
        assert_eq!(
            metrics
                .authentication
                .success_rate
                .current
                .unwrap()
                .percent(),
            90.0
        );
        assert_eq!(metrics.authentication.failed_attempts.current.part(), 10);
        assert_eq!(
            metrics.authentication.failed_attempts.trend.direction(),
            TrendDirection::Flat
        );
        assert_eq!(metrics.authentication.last_login, Some(at(1_900)));
        assert_eq!(metrics.api.request_count.current, 1_000);
    }

    /// Signing in took 120 ms on average, down from 150, and the chart has
    /// the one bucket the reader holds.
    #[test]
    fn reports_the_average_auth_time_and_the_login_chart_the_reader_holds() {
        let metrics = metrics();

        assert_eq!(
            metrics
                .authentication
                .average_auth_time
                .current
                .map(|l| l.millis()),
            Some(120)
        );
        assert_eq!(
            metrics.authentication.average_auth_time.trend.direction(),
            TrendDirection::Down
        );
        assert_eq!(metrics.authentication.success_rate_series.len(), 1);
    }

    /// A caller without metrics-view rights cannot read the tenant's overview.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let result = overview_as(&test_ctx(), FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read the tenant's metrics.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = overview_as(
            &test_ctx(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator without an impersonation grant cannot read tenant metrics.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let result = overview_as(
            &operator_without_grant(),
            FakeTenantAuthorities::holding_everything(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
