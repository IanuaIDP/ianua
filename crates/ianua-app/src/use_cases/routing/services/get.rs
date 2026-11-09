//! Get service: read one backend of the tenant.

use std::sync::Arc;

use ianua_domain::domains::routing::service::Service;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::ServiceId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::routing::ServiceStore;
use crate::use_case::Query;
use crate::use_cases::routing::lookup::{ensure_may_view_routing, existing_service};

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Keeps the tenant's services.
    pub service_store: Arc<dyn ServiceStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one backend.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = CallerContext;
    type Input = ServiceId;
    type Output = Result<Service<ResolvedTenant>, AppError>;

    /// The tenant's service `service_id`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view routing.
    /// - `AppError::NotFound` if the service doesn't exist.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        service_id: ServiceId,
    ) -> Result<Service<ResolvedTenant>, AppError> {
        ensure_may_view_routing(self.ports.tenant_authorities.as_ref(), caller).await?;
        existing_service(
            self.ports.service_store.as_ref(),
            &caller.tenant(),
            &service_id,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::routing::{FakeServiceStore, service_named, unpinned_upstream};
    use crate::test_support::{block_on, test_ctx};

    fn use_case_holding(authorities: FakeTenantAuthorities) -> (GetUseCase, ServiceId) {
        let service = service_named("api", unpinned_upstream("https://backend:8080"));
        let services = Arc::new(FakeServiceStore::empty());
        block_on(services.save(&test_ctx().tenant(), &service)).unwrap();
        let use_case = GetUseCase::new(GetPorts {
            service_store: services,
            tenant_authorities: Arc::new(authorities),
        });
        (use_case, *service.id())
    }

    /// Ann opens the API backend. She sees it.
    #[test]
    fn a_stored_service_is_returned() {
        let (use_case, id) = use_case_holding(FakeTenantAuthorities::holding_everything());

        let service = block_on(use_case.execute(&test_ctx(), id)).unwrap();

        assert_eq!(service.name().as_str(), "api");
    }

    /// Ann opens a service that does not exist. She is told it was not
    /// found.
    #[test]
    fn an_unknown_service_is_not_found() {
        let (use_case, _) = use_case_holding(FakeTenantAuthorities::holding_everything());

        let result = block_on(use_case.execute(&test_ctx(), ServiceId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading an existing backend requires the routing viewing right.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let (use_case, id) = use_case_holding(FakeTenantAuthorities::holding(&[]));

        let result = block_on(use_case.execute(&test_ctx(), id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read a backend service.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (use_case, id) = use_case_holding(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = block_on(use_case.execute(&test_ctx(), id));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
