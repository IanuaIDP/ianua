//! Get connector: read one private-network connector of the tenant.

use std::sync::Arc;

use ianua_domain::domains::routing::connector::PrivateConnector;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::ConnectorId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::routing::ConnectorStore;
use crate::use_case::Query;
use crate::use_cases::routing::connectors::lookup::existing_connector;
use crate::use_cases::routing::lookup::ensure_may_view_routing;

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Keeps the tenant's connectors.
    pub connector_store: Arc<dyn ConnectorStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one connector.
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
    type Input = ConnectorId;
    type Output = Result<PrivateConnector<ResolvedTenant>, AppError>;

    /// The tenant's connector `connector_id`. Its enrollment code was never
    /// kept, so none is in it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view routing.
    /// - `AppError::NotFound` if the connector doesn't exist.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        connector_id: ConnectorId,
    ) -> Result<PrivateConnector<ResolvedTenant>, AppError> {
        ensure_may_view_routing(self.ports.tenant_authorities.as_ref(), caller).await?;
        existing_connector(
            self.ports.connector_store.as_ref(),
            &caller.tenant(),
            &connector_id,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::routing::{FakeConnectorStore, awaiting_connector};
    use crate::test_support::{block_on, test_ctx};

    /// The payroll connector, awaiting its code.
    fn payroll() -> PrivateConnector<ResolvedTenant> {
        awaiting_connector("payroll", "enroll-code-a", &["payroll.corp.internal"])
    }

    /// A use case over a store holding `connector`, the caller holding what
    /// `authorities` says.
    fn use_case(
        connector: &PrivateConnector<ResolvedTenant>,
        authorities: FakeTenantAuthorities,
    ) -> GetUseCase {
        GetUseCase::new(GetPorts {
            connector_store: Arc::new(FakeConnectorStore::holding(
                test_ctx().tenant_id(),
                connector,
            )),
            tenant_authorities: Arc::new(authorities),
        })
    }

    /// Ann reads the payroll connector. She gets it, by its id.
    #[test]
    fn a_connector_is_read() {
        let connector = payroll();
        let use_case = use_case(&connector, FakeTenantAuthorities::holding_everything());

        let read = block_on(use_case.execute(&test_ctx(), *connector.id())).unwrap();

        assert_eq!(read.id(), connector.id());
    }

    /// Ann names a connector the tenant does not have. It is not found.
    #[test]
    fn an_unknown_connector_is_not_found() {
        let use_case = use_case(&payroll(), FakeTenantAuthorities::holding_everything());

        let result = block_on(use_case.execute(&test_ctx(), ConnectorId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading an existing connector requires the routing viewing right.
    #[test]
    fn a_caller_who_may_not_view_routing_is_refused() {
        let connector = payroll();
        let use_case = use_case(&connector, FakeTenantAuthorities::holding(&[]));

        let result = block_on(use_case.execute(&test_ctx(), *connector.id()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read a connector.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let connector = payroll();
        let use_case = use_case(
            &connector,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = block_on(use_case.execute(&test_ctx(), *connector.id()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
