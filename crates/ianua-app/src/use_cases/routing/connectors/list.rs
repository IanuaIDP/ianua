//! List connectors: every private-network connector of the tenant.

use std::sync::Arc;

use ianua_domain::domains::routing::connector::PrivateConnector;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::ConnectorStore;
use crate::use_case::Query;
use crate::use_cases::routing::lookup::ensure_may_view_routing;

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Keeps the tenant's connectors.
    pub connector_store: Arc<dyn ConnectorStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's connectors.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<PrivateConnector<ResolvedTenant>>, AppError>;

    /// Every connector in the tenant, by name.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view routing.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        (): (),
    ) -> Result<Vec<PrivateConnector<ResolvedTenant>>, AppError> {
        ensure_may_view_routing(self.ports.tenant_authorities.as_ref(), caller).await?;
        self.ports
            .connector_store
            .list(&caller.tenant())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::routing::{FakeConnectorStore, awaiting_connector};
    use crate::test_support::{block_on, test_ctx};

    /// A use case over `store`, the caller holding what `authorities` says.
    fn use_case(store: FakeConnectorStore, authorities: FakeTenantAuthorities) -> ListUseCase {
        ListUseCase::new(ListPorts {
            connector_store: Arc::new(store),
            tenant_authorities: Arc::new(authorities),
        })
    }

    /// A store holding the payroll connector in Ann's tenant.
    fn payroll_store() -> FakeConnectorStore {
        FakeConnectorStore::holding(
            test_ctx().tenant_id(),
            &awaiting_connector("payroll", "enroll-code-a", &["payroll.corp.internal"]),
        )
    }

    /// Ann lists her tenant's connectors. The payroll one is there.
    #[test]
    fn the_tenants_connectors_are_listed() {
        let use_case = use_case(payroll_store(), FakeTenantAuthorities::holding_everything());

        let listed = block_on(use_case.execute(&test_ctx(), ())).unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name().as_str(), "payroll");
    }

    /// A connector stored in another tenant is absent from the caller's list.
    #[test]
    fn another_tenants_connectors_are_not_listed() {
        let bobs = FakeConnectorStore::holding(
            TenantId::new(),
            &awaiting_connector("bobs", "enroll-code-b", &["bob.corp.internal"]),
        );
        let use_case = use_case(bobs, FakeTenantAuthorities::holding_everything());

        let listed = block_on(use_case.execute(&test_ctx(), ())).unwrap();

        assert!(listed.is_empty());
    }

    /// Listing connectors requires the routing viewing right.
    #[test]
    fn a_caller_who_may_not_view_routing_is_refused() {
        let use_case = use_case(payroll_store(), FakeTenantAuthorities::holding(&[]));

        let result = block_on(use_case.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list connectors.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = use_case(
            payroll_store(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = block_on(use_case.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
