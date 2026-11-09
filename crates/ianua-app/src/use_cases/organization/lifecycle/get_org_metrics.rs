//! Assembles the organization metrics overview from raw figures.
//!
//! Reads counts and aggregates through [`OrganizationMetricsReader`]
//! and turns them into rates, ratios, latencies, and period-over-period
//! trends using the shared overview building blocks. Sign-in and API usage
//! figures are compared with the equal-length window immediately preceding
//! the requested one; the user, tenant and session totals are compared with
//! their count at the start of the requested window.

use std::future::Future;
use std::sync::Arc;

use ianua_domain::domains::metrics::{
    LatencyMs, LoginOutcomeCounts, MetricsWindow, TimeSeriesPoint,
};
use ianua_domain::domains::organization::members::permission::{OrgMetricsAction, OrgPermission};
use ianua_domain::types::OrganizationId;
use time::OffsetDateTime;

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::metrics::{OrganizationMetricsReader, RequestMetrics};
use crate::use_case::Query;
use crate::use_cases::metrics::overview::{
    ApiUsageMetrics, AuthenticationFigures, AuthenticationMetrics, Trended, count_trend,
};

/// The full organization metrics overview.
pub struct OrganizationMetrics {
    /// The window these figures were computed over.
    pub window: MetricsWindow,
    /// Authentication figures and charts.
    pub authentication: AuthenticationMetrics,
    /// Total users, trended against the window start.
    pub users: Trended<u64>,
    /// Total tenants, trended against the window start.
    pub tenants: Trended<u64>,
    /// Active sessions, trended against the window start.
    pub active_sessions: Trended<u64>,
    /// Proxied API usage figures.
    pub api: ApiUsageMetrics,
}

/// The ports [`GetOrgMetricsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetOrgMetricsPorts {
    /// The organization's raw figures.
    pub reader: Arc<dyn OrganizationMetricsReader>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Builds the organization metrics overview.
pub struct GetOrgMetricsUseCase {
    ports: GetOrgMetricsPorts,
}

impl GetOrgMetricsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetOrgMetricsPorts) -> Self {
        Self { ports }
    }

    async fn authentication(
        &self,
        organization_id: &OrganizationId,
        window: &MetricsWindow,
    ) -> Result<AuthenticationMetrics, AppError> {
        let previous = window.previous();
        let (current, baseline, series, avg_current, avg_previous, last_login) = futures_util::try_join!(
            self.login_outcomes(organization_id, window),
            self.login_outcomes(organization_id, &previous),
            self.login_series(organization_id, window),
            self.avg_auth(organization_id, window),
            self.avg_auth(organization_id, &previous),
            self.last_login(organization_id),
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

    async fn last_login(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Option<OffsetDateTime>, AppError> {
        self.ports
            .reader
            .last_login(organization_id)
            .await
            .or_internal()
    }

    /// A count at the window's end, trended against the same count at its
    /// start.
    async fn trend_over<F, Fut>(
        window: &MetricsWindow,
        count_at: F,
    ) -> Result<Trended<u64>, AppError>
    where
        F: Fn(OffsetDateTime) -> Fut,
        Fut: Future<Output = Result<u64, AppError>>,
    {
        let (current, previous) =
            futures_util::try_join!(count_at(window.end()), count_at(window.start()))?;

        Ok(count_trend(current, previous))
    }

    async fn api_usage(
        &self,
        organization_id: &OrganizationId,
        window: &MetricsWindow,
    ) -> Result<ApiUsageMetrics, AppError> {
        let previous = window.previous();
        let (current, baseline) = futures_util::try_join!(
            self.request_metrics(organization_id, window),
            self.request_metrics(organization_id, &previous),
        )?;

        Ok(ApiUsageMetrics::from_windows(current, baseline))
    }

    async fn login_outcomes(
        &self,
        organization_id: &OrganizationId,
        window: &MetricsWindow,
    ) -> Result<LoginOutcomeCounts, AppError> {
        self.ports
            .reader
            .login_outcomes(organization_id, window)
            .await
            .or_internal()
    }

    async fn login_series(
        &self,
        organization_id: &OrganizationId,
        window: &MetricsWindow,
    ) -> Result<Vec<TimeSeriesPoint>, AppError> {
        self.ports
            .reader
            .login_outcome_series(organization_id, window)
            .await
            .or_internal()
    }

    async fn avg_auth(
        &self,
        organization_id: &OrganizationId,
        window: &MetricsWindow,
    ) -> Result<Option<LatencyMs>, AppError> {
        self.ports
            .reader
            .average_auth_duration_ms(organization_id, window)
            .await
            .or_internal()
    }

    async fn count_users(
        &self,
        organization_id: &OrganizationId,
        at: OffsetDateTime,
    ) -> Result<u64, AppError> {
        self.ports
            .reader
            .count_users_as_of(organization_id, at)
            .await
            .or_internal()
    }

    async fn count_tenants(
        &self,
        organization_id: &OrganizationId,
        at: OffsetDateTime,
    ) -> Result<u64, AppError> {
        self.ports
            .reader
            .count_tenants_as_of(organization_id, at)
            .await
            .or_internal()
    }

    async fn count_sessions(
        &self,
        organization_id: &OrganizationId,
        at: OffsetDateTime,
    ) -> Result<u64, AppError> {
        self.ports
            .reader
            .count_active_sessions_as_of(organization_id, at)
            .await
            .or_internal()
    }

    async fn request_metrics(
        &self,
        organization_id: &OrganizationId,
        window: &MetricsWindow,
    ) -> Result<RequestMetrics, AppError> {
        self.ports
            .reader
            .request_metrics(organization_id, window)
            .await
            .or_internal()
    }
}

impl Query for GetOrgMetricsUseCase {
    type Caller = OrgCaller;
    type Input = MetricsWindow;
    type Output = Result<OrganizationMetrics, AppError>;

    /// Builds the overview of `caller`'s organization over `window`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view the metrics.
    /// - `AppError::Internal` if the metrics reader fails.
    async fn execute(
        &self,
        caller: &OrgCaller,
        window: MetricsWindow,
    ) -> Result<OrganizationMetrics, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        actor
            .control()?
            .ensure_may(
                organization.id(),
                OrgPermission::Metrics(OrgMetricsAction::View),
            )
            .map_err(AppError::from_domain)?;
        self.overview(organization.id(), window).await
    }
}

impl GetOrgMetricsUseCase {
    /// The overview of `organization_id` over `window`.
    async fn overview(
        &self,
        organization_id: &OrganizationId,
        window: MetricsWindow,
    ) -> Result<OrganizationMetrics, AppError> {
        let (authentication, users, tenants, active_sessions, api) = futures_util::try_join!(
            self.authentication(organization_id, &window),
            Self::trend_over(&window, |at| self.count_users(organization_id, at)),
            Self::trend_over(&window, |at| self.count_tenants(organization_id, at)),
            Self::trend_over(&window, |at| self.count_sessions(organization_id, at)),
            self.api_usage(organization_id, &window),
        )?;

        Ok(OrganizationMetrics {
            window,
            authentication,
            users,
            tenants,
            active_sessions,
            api,
        })
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::metrics::TrendDirection;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::errors::DomainError;
    use time::OffsetDateTime;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::{block_on, test_org_caller};

    struct FakeReader {
        current: LoginOutcomeCounts,
        previous: LoginOutcomeCounts,
        users_now: u64,
        users_then: u64,
        requests_now: RequestMetrics,
        requests_then: RequestMetrics,
    }

    impl FakeReader {
        fn at_window(&self, window: &MetricsWindow, current: &MetricsWindow) -> bool {
            window.start() == current.start()
        }
    }

    #[async_trait]
    impl OrganizationMetricsReader for FakeReader {
        async fn login_outcomes(
            &self,
            _: &OrganizationId,
            window: &MetricsWindow,
        ) -> Result<LoginOutcomeCounts, DomainError> {
            Ok(match self.at_window(window, &fixed_window()) {
                true => self.current,
                false => self.previous,
            })
        }

        async fn login_outcome_series(
            &self,
            _: &OrganizationId,
            _: &MetricsWindow,
        ) -> Result<Vec<TimeSeriesPoint>, DomainError> {
            Ok(vec![TimeSeriesPoint::new(
                fixed_window().start(),
                self.current,
            )])
        }

        async fn average_auth_duration_ms(
            &self,
            _: &OrganizationId,
            window: &MetricsWindow,
        ) -> Result<Option<LatencyMs>, DomainError> {
            Ok(match self.at_window(window, &fixed_window()) {
                true => Some(LatencyMs::new(120)),
                false => Some(LatencyMs::new(150)),
            })
        }

        async fn count_users_as_of(
            &self,
            _: &OrganizationId,
            at: OffsetDateTime,
        ) -> Result<u64, DomainError> {
            Ok(match at == fixed_window().end() {
                true => self.users_now,
                false => self.users_then,
            })
        }

        async fn count_tenants_as_of(
            &self,
            _: &OrganizationId,
            _: OffsetDateTime,
        ) -> Result<u64, DomainError> {
            Ok(3)
        }

        async fn count_active_sessions_as_of(
            &self,
            _: &OrganizationId,
            _: OffsetDateTime,
        ) -> Result<u64, DomainError> {
            Ok(7)
        }

        async fn request_metrics(
            &self,
            _: &OrganizationId,
            window: &MetricsWindow,
        ) -> Result<RequestMetrics, DomainError> {
            Ok(match self.at_window(window, &fixed_window()) {
                true => self.requests_now,
                false => self.requests_then,
            })
        }

        async fn last_login(
            &self,
            _: &OrganizationId,
        ) -> Result<Option<OffsetDateTime>, DomainError> {
            Ok(Some(at(1_900)))
        }
    }

    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).unwrap()
    }

    fn fixed_window() -> MetricsWindow {
        MetricsWindow::new(at(1_000), at(2_000)).unwrap()
    }

    fn overview_of(use_case: &GetOrgMetricsUseCase) -> OrganizationMetrics {
        block_on(use_case.execute(&test_org_caller(), fixed_window())).unwrap()
    }

    fn refused_as(actors: FakeOrgActors) -> AppError {
        let use_case = GetOrgMetricsUseCase::new(GetOrgMetricsPorts {
            org_actors: Arc::new(actors),
            ..GetOrgMetricsPorts::fakes()
        });
        block_on(use_case.execute(&test_org_caller(), fixed_window()))
            .err()
            .expect("the caller is refused")
    }

    fn reader() -> FakeReader {
        FakeReader {
            current: LoginOutcomeCounts::new(288, 12),
            previous: LoginOutcomeCounts::new(180, 20),
            users_now: 120,
            users_then: 100,
            requests_now: RequestMetrics {
                request_count: 1_000,
                error_count: 10,
                p95_latency_ms: Some(LatencyMs::new(90)),
            },
            requests_then: RequestMetrics {
                request_count: 800,
                error_count: 16,
                p95_latency_ms: Some(LatencyMs::new(110)),
            },
        }
    }

    fn use_case() -> GetOrgMetricsUseCase {
        GetOrgMetricsUseCase::new(GetOrgMetricsPorts {
            reader: Arc::new(reader()),
            ..GetOrgMetricsPorts::fakes()
        })
    }

    /// Sam, a plain member, opens the metrics: 288 of 300 sign-ins went
    /// through, up on the window before. He sees the success rate rise and
    /// the failed attempts fall.
    #[test]
    fn assembles_success_rate_and_pie_breakdown() {
        let metrics = overview_of(&use_case());

        assert_eq!(
            metrics
                .authentication
                .success_rate
                .current
                .unwrap()
                .percent(),
            96.0
        );
        assert_eq!(
            metrics.authentication.success_rate.trend.direction(),
            TrendDirection::Up
        );
        assert_eq!(metrics.authentication.failed_attempts.current.part(), 12);
        assert_eq!(metrics.authentication.failed_attempts.current.whole(), 300);
        assert_eq!(
            metrics.authentication.failed_attempts.trend.direction(),
            TrendDirection::Down
        );
        assert_eq!(metrics.authentication.success_rate_series.len(), 1);
        assert_eq!(metrics.authentication.last_login, Some(at(1_900)));
    }

    /// Acme had 100 users when the window opened and 120 when it closed.
    /// The user count shows 120, up a fifth.
    #[test]
    fn trends_users_against_window_start() {
        let metrics = overview_of(&use_case());

        assert_eq!(metrics.users.current, 120);
        assert_eq!(metrics.users.trend.change_pct(), Some(20.0));
        assert_eq!(metrics.users.trend.direction(), TrendDirection::Up);
    }

    /// Sign-ins took 120 ms on average, down from 150 ms. The overview
    /// shows 120 ms, trending down.
    #[test]
    fn reports_the_average_auth_time_the_reader_measured() {
        let metrics = overview_of(&use_case());

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
    }

    /// Acme runs three tenants with seven sessions open. The overview shows
    /// both counts as the reader holds them.
    #[test]
    fn reports_the_tenant_and_session_counts_the_reader_holds() {
        let metrics = overview_of(&use_case());

        assert_eq!(metrics.tenants.current, 3);
        assert_eq!(metrics.active_sessions.current, 7);
    }

    /// An owner's key without the metrics right cannot obtain an overview.
    #[test]
    fn a_key_without_the_metrics_right_is_refused() {
        let error = refused_as(FakeOrgActors::through_key(OrgRole::Owner, Vec::new()));

        assert!(matches!(error, AppError::Forbidden(_)));
    }

    /// A signed-out caller must authenticate before obtaining metrics.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let error = refused_as(FakeOrgActors::refusing(Refusal::SignedOut));

        assert!(matches!(error, AppError::Unauthenticated));
    }

    /// Refused organization authority prevents obtaining the metrics overview.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let error = refused_as(FakeOrgActors::refusing(Refusal::Forbidden));

        assert!(matches!(error, AppError::Forbidden(_)));
    }

    /// Acme's API answered 1000 requests with 1% errors and a 90 ms p95,
    /// against 2% and 110 ms before. Both trend down.
    #[test]
    fn error_rate_falls_and_latency_improves() {
        let metrics = overview_of(&use_case());

        assert_eq!(metrics.api.request_count.current, 1_000);
        assert_eq!(metrics.api.error_rate.current, Some(1.0));
        assert_eq!(
            metrics.api.error_rate.trend.direction(),
            TrendDirection::Down
        );
        assert_eq!(metrics.api.p95_latency.current.unwrap().millis(), 90);
        assert_eq!(
            metrics.api.p95_latency.trend.direction(),
            TrendDirection::Down
        );
    }
}
