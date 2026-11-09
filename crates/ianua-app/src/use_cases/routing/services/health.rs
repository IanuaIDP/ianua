//! Service health: how a service's backends are probed, and what the
//! gateway's probes last saw of them.

use std::sync::Arc;

use ianua_domain::domains::routing::backend::health_check::HealthCheckPolicy;
use ianua_domain::types::ServiceId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::{BackendHealthReader, ServiceHealthReport, ServiceStore};
use crate::use_case::Query;
use crate::use_cases::routing::lookup::{ensure_may_view_routing, existing_service};

/// What is known of a service's backends right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveHealth {
    /// The service asks for no probing: every backend gets traffic, and
    /// nothing is checked to report.
    NotProbed,
    /// The service is probed and no gateway has reported lately: it may
    /// have stopped, or not reached the service yet. Never read as healthy.
    Unknown,
    /// What the gateway's probes last saw.
    Reported(ServiceHealthReport),
}

/// A service's probe settings, and what the probes last saw.
#[derive(Debug, Clone)]
pub struct ServiceHealth {
    /// How the service's backends are probed.
    pub check: HealthCheckPolicy,
    /// What is known of them now.
    pub live: LiveHealth,
}

/// The ports [`HealthUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct HealthPorts {
    /// Keeps the tenant's services.
    pub service_store: Arc<dyn ServiceStore>,
    /// What the gateway's health checks reported.
    pub health: Arc<dyn BackendHealthReader>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads a service's live backend health.
pub struct HealthUseCase {
    ports: HealthPorts,
}

impl HealthUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: HealthPorts) -> Self {
        Self { ports }
    }
}

impl Query for HealthUseCase {
    type Caller = CallerContext;
    type Input = ServiceId;
    type Output = Result<ServiceHealth, AppError>;

    /// The probe settings of the tenant's service `service_id`, and what
    /// the gateway's probes last saw of its backends.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view routing.
    /// - `AppError::NotFound` if the service doesn't exist.
    /// - `AppError::Internal` on storage failure, or when the reports
    ///   cannot be read.
    async fn execute(
        &self,
        caller: &CallerContext,
        service_id: ServiceId,
    ) -> Result<ServiceHealth, AppError> {
        ensure_may_view_routing(self.ports.tenant_authorities.as_ref(), caller).await?;
        let tenant = caller.tenant();
        let service =
            existing_service(self.ports.service_store.as_ref(), &tenant, &service_id).await?;
        let check = service.health_check().clone();
        let report = match check {
            HealthCheckPolicy::Disabled => None,
            HealthCheckPolicy::Active(_) => self
                .ports
                .health
                .latest(&tenant, &service_id)
                .await
                .or_internal()?,
        };
        Ok(ServiceHealth {
            live: live_health(&check, report),
            check,
        })
    }
}

/// What is known of a service probed under `check`, given the gateway's
/// latest valid `report`. A report on a service no longer probed is not
/// shown: it says what a check no longer running saw.
fn live_health(check: &HealthCheckPolicy, report: Option<ServiceHealthReport>) -> LiveHealth {
    match (check, report) {
        (HealthCheckPolicy::Disabled, _) => LiveHealth::NotProbed,
        (HealthCheckPolicy::Active(_), None) => LiveHealth::Unknown,
        (HealthCheckPolicy::Active(_), Some(report)) => LiveHealth::Reported(report),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::routing::service::Service;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::HttpUrl;

    use super::*;
    use crate::ports::routing::{BackendHealth, BackendVerdict};
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::routing::{
        FakeBackendHealth, FakeServiceStore, service_named, unpinned_upstream,
    };
    use crate::test_support::{block_on, test_ctx};

    fn stored(service: &Service<ResolvedTenant>) -> Arc<FakeServiceStore> {
        let services = Arc::new(FakeServiceStore::empty());
        block_on(services.save(&test_ctx().tenant(), service)).unwrap();
        services
    }

    fn one_down(service_id: ServiceId) -> ServiceHealthReport {
        ServiceHealthReport {
            service_id,
            backends: vec![BackendHealth {
                backend: HttpUrl::new("https://backend:8080").unwrap(),
                verdict: BackendVerdict::Down,
            }],
            observed_at: ianua_domain::shared::clock::now(),
        }
    }

    fn health_of(
        service: &Service<ResolvedTenant>,
        board: FakeBackendHealth,
        authorities: FakeTenantAuthorities,
    ) -> Result<ServiceHealth, AppError> {
        let use_case = HealthUseCase::new(HealthPorts {
            service_store: stored(service),
            health: Arc::new(board),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), *service.id()))
    }

    /// The gateway marked the API's only backend down. Ann sees it down.
    #[test]
    fn a_backend_the_gateway_marked_down_reads_down() {
        let service = service_named("api", unpinned_upstream("https://backend:8080"));
        let report = one_down(*service.id());
        let board = FakeBackendHealth::holding(*test_ctx().tenant(), report.clone());

        let health =
            health_of(&service, board, FakeTenantAuthorities::holding_everything()).unwrap();

        assert_eq!(health.live, LiveHealth::Reported(report));
    }

    /// A service configured for probing reports unknown health when no
    /// backend-health report is available.
    #[test]
    fn a_probed_service_nobody_reported_on_is_unknown() {
        let service = service_named("api", unpinned_upstream("https://backend:8080"));

        let health = health_of(
            &service,
            FakeBackendHealth::default(),
            FakeTenantAuthorities::holding_everything(),
        )
        .unwrap();

        assert_eq!(health.live, LiveHealth::Unknown);
    }

    /// A service that is not probed has nothing to report, whatever a
    /// check that ran before saw.
    #[test]
    fn a_service_not_probed_reports_nothing() {
        let service = service_named("api", unpinned_upstream("https://backend:8080"));

        let live = live_health(&HealthCheckPolicy::Disabled, Some(one_down(*service.id())));

        assert_eq!(live, LiveHealth::NotProbed);
    }

    /// Reading backend health requires the routing viewing right.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let service = service_named("api", unpinned_upstream("https://backend:8080"));

        let result = health_of(
            &service,
            FakeBackendHealth::default(),
            FakeTenantAuthorities::holding(&[]),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
