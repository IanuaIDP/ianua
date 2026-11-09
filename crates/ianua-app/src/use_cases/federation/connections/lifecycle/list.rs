//! List connections: the tenant's federation connections, filtered, ordered
//! and paged.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{FederationAction, SystemPermission};
use ianua_domain::domains::federation::connection::FederatedIdpConnection;
use ianua_domain::domains::federation::connection_status::ConnectionStatus;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::federation::{ConnectionSortField, ConnectionStore};
use crate::use_case::Query;

/// Filter criteria for listing connections.
pub struct ConnectionFilter {
    /// Filter by status. `None` returns all statuses.
    pub status: Option<ConnectionStatus>,
}

impl ConnectionFilter {
    /// No filter: every connection.
    #[must_use]
    pub fn all() -> Self {
        Self { status: None }
    }
}

/// Which connections to list, in what order, and which page of them.
pub struct ListRequest {
    /// Which connections to include.
    pub filter: ConnectionFilter,
    /// The fields and directions to order by.
    pub sort: SortOrder<ConnectionSortField>,
    /// Which page of the ordered connections to return.
    pub page: PageRequest,
}

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Loads connections.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's federation connections.
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
    type Input = ListRequest;
    type Output = Result<Page<FederatedIdpConnection<ResolvedTenant>>, AppError>;

    /// The page of connections `request` asks for, for a caller who may view
    /// federation.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not view federation.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListRequest,
    ) -> Result<Page<FederatedIdpConnection<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Federation(FederationAction::View))
            .map_err(AppError::from_domain)?;
        let ListRequest { filter, sort, page } = request;
        self.ports
            .connection_store
            .list_all(&ctx.tenant(), filter.status, &sort, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::ConnectionId;

    use super::*;
    use crate::listing::Sort;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::federation::{FakeConnectionStore, test_connection_named};
    use crate::test_support::{block_on, test_ctx};

    fn store_holding(connections: &[(&str, ConnectionStatus)]) -> Arc<FakeConnectionStore> {
        let held = connections
            .iter()
            .map(|(name, status)| test_connection_named(ConnectionId::new(), name, *status));
        Arc::new(FakeConnectionStore::holding(&test_ctx().tenant(), held))
    }

    fn use_case(
        store: Arc<FakeConnectionStore>,
        authorities: FakeTenantAuthorities,
    ) -> ListUseCase {
        ListUseCase::new(ListPorts {
            connection_store: store,
            tenant_authorities: Arc::new(authorities),
        })
    }

    fn list(
        use_case: &ListUseCase,
        filter: ConnectionFilter,
        sort: SortOrder<ConnectionSortField>,
    ) -> Result<Page<FederatedIdpConnection<ResolvedTenant>>, AppError> {
        block_on(use_case.execute(
            &test_ctx(),
            ListRequest {
                filter,
                sort,
                page: PageRequest::default(),
            },
        ))
    }

    fn three_active() -> Arc<FakeConnectionStore> {
        store_holding(&[
            ("Charlie", ConnectionStatus::Active),
            ("Alice", ConnectionStatus::Active),
            ("Bravo", ConnectionStatus::Active),
        ])
    }

    /// Acme has three connections. Ann lists them all.
    #[test]
    fn every_connection_of_the_tenant_is_listed() {
        let use_case = use_case(three_active(), FakeTenantAuthorities::holding_everything());

        let page = list(&use_case, ConnectionFilter::all(), SortOrder::default()).unwrap();

        assert_eq!(page.items.len(), 3);
    }

    /// Ann orders the connections by provider name. They come back from A to
    /// C.
    #[test]
    fn connections_are_ordered_by_provider_name() {
        let use_case = use_case(three_active(), FakeTenantAuthorities::holding_everything());
        let sort = SortOrder::single(Sort::ascending(ConnectionSortField::ProviderName));

        let page = list(&use_case, ConnectionFilter::all(), sort).unwrap();

        let names: Vec<&str> = page
            .items
            .iter()
            .map(|c| c.provider_name().as_str())
            .collect();
        assert_eq!(names, ["Alice", "Bravo", "Charlie"]);
    }

    /// Acme has one active and one disabled connection. Ann asks for the
    /// active ones and gets the one.
    #[test]
    fn connections_are_filtered_by_status() {
        let store = store_holding(&[
            ("Active", ConnectionStatus::Active),
            ("Disabled", ConnectionStatus::Disabled),
        ]);
        let use_case = use_case(store, FakeTenantAuthorities::holding_everything());
        let active = ConnectionFilter {
            status: Some(ConnectionStatus::Active),
        };

        let page = list(&use_case, active, SortOrder::default()).unwrap();

        assert_eq!(page.items.len(), 1);
    }

    /// Acme has no connection yet. The list is empty.
    #[test]
    fn a_tenant_without_connections_lists_none() {
        let use_case = use_case(
            store_holding(&[]),
            FakeTenantAuthorities::holding_everything(),
        );

        let page = list(&use_case, ConnectionFilter::all(), SortOrder::default()).unwrap();

        assert!(page.is_empty());
    }

    /// Listing the tenant's connections requires the federation viewing right.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let use_case = use_case(three_active(), FakeTenantAuthorities::holding(&[]));

        let result = list(&use_case, ConnectionFilter::all(), SortOrder::default());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list federation connections.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = use_case(
            three_active(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = list(&use_case, ConnectionFilter::all(), SortOrder::default());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
