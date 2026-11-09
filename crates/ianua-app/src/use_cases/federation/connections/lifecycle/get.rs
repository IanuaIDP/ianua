//! Get connection: one federation connection of the caller's tenant.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{FederationAction, SystemPermission};
use ianua_domain::domains::federation::connection::FederatedIdpConnection;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::ConnectionId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::federation::ConnectionStore;
use crate::use_case::Query;
use crate::use_cases::federation::lookup::existing_connection;

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Loads connections.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one federation connection.
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
    type Input = ConnectionId;
    type Output = Result<FederatedIdpConnection<ResolvedTenant>, AppError>;

    /// The connection with `id`, for a caller who may view federation.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not view federation.
    /// - `AppError::NotFound` if the connection doesn't exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        id: ConnectionId,
    ) -> Result<FederatedIdpConnection<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Federation(FederationAction::View))
            .map_err(AppError::from_domain)?;
        existing_connection(self.ports.connection_store.as_ref(), &ctx.tenant(), &id).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::federation::{FakeConnectionStore, test_connection};
    use crate::test_support::{block_on, test_ctx};

    fn use_case(authorities: FakeTenantAuthorities) -> (GetUseCase, ConnectionId) {
        let id = ConnectionId::new();
        let connection = test_connection(id, ConnectionStatus::Active);
        let store = FakeConnectionStore::holding(&test_ctx().tenant(), [connection]);
        let use_case = GetUseCase::new(GetPorts {
            connection_store: Arc::new(store),
            tenant_authorities: Arc::new(authorities),
        });
        (use_case, id)
    }

    /// Ann may view federation. She opens Acme's Okta connection and gets
    /// it.
    #[test]
    fn a_connection_of_the_tenant_is_returned() {
        let view = [SystemPermission::Federation(FederationAction::View)];
        let (use_case, id) = use_case(FakeTenantAuthorities::holding(&view));

        let connection = block_on(use_case.execute(&test_ctx(), id)).unwrap();

        assert_eq!(connection.id(), &id);
    }

    /// Ann names a connection her tenant does not have. It is not found.
    #[test]
    fn an_unknown_connection_is_not_found() {
        let (use_case, _) = use_case(FakeTenantAuthorities::holding_everything());

        let result = block_on(use_case.execute(&test_ctx(), ConnectionId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading an existing connection requires the federation viewing right.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let (use_case, id) = use_case(FakeTenantAuthorities::holding(&[]));

        let result = block_on(use_case.execute(&test_ctx(), id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read a federation connection.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (use_case, id) = use_case(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = block_on(use_case.execute(&test_ctx(), id));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
