//! Listing the tenant's OAuth clients, filtered, ordered and paged.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{ApiKeyAction, SystemPermission};
use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::domains::oauth::clients::status::OAuthClientStatus;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::oauth::{OAuthClientSortField, OAuthClientStore};
use crate::use_case::Query;

/// Which clients a listing includes.
pub struct ClientFilter {
    /// Only clients in this status. `None` includes every status.
    pub status: Option<OAuthClientStatus>,
}

impl ClientFilter {
    /// Every client, whatever its status.
    #[must_use]
    pub fn all() -> Self {
        Self { status: None }
    }
}

/// Which page of the tenant's OAuth clients to return, filtered how and in
/// what order.
pub struct ListRequest {
    /// Which clients to include.
    pub filter: ClientFilter,
    /// The fields and directions to order by.
    pub sort: SortOrder<OAuthClientSortField>,
    /// Which page of the ordered clients to return.
    pub page: PageRequest,
}

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Where clients are kept.
    pub client_store: Arc<dyn OAuthClientStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's OAuth clients.
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
    type Output = Result<Page<OAuthClient<ResolvedTenant>>, AppError>;

    /// The page of `caller`'s tenant's clients that `request` asks for.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view API keys and
    ///   clients.
    /// - `AppError::Internal` when the clients cannot be read.
    async fn execute(
        &self,
        caller: &CallerContext,
        request: ListRequest,
    ) -> Result<Page<OAuthClient<ResolvedTenant>>, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::ApiKeys(ApiKeyAction::View))
            .map_err(AppError::from_domain)?;
        self.ports
            .client_store
            .list_all(
                &caller.tenant(),
                request.filter.status,
                &request.sort,
                &request.page,
            )
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::client::GrantType;

    use super::*;
    use crate::listing::{Limit, Sort};
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::oauth::{FakeOAuthClientStore, client_row, stored_client};
    use crate::test_support::{block_on, test_ctx};

    fn store_of(names: &[&str]) -> Arc<FakeOAuthClientStore> {
        let store = Arc::new(FakeOAuthClientStore::empty());
        for name in names {
            let client = stored_client(name, &[GrantType::ClientCredentials]);
            block_on(store.save(&test_ctx().tenant(), &client)).unwrap();
        }
        store
    }

    fn with_revoked(store: Arc<FakeOAuthClientStore>) -> Arc<FakeOAuthClientStore> {
        let mut row = client_row("Old", &[GrantType::ClientCredentials]);
        row.status = OAuthClientStatus::Revoked;
        block_on(store.save(
            &test_ctx().tenant(),
            &OAuthClient::reconstitute(row).unwrap(),
        ))
        .unwrap();
        store
    }

    fn request(filter: ClientFilter, page: PageRequest) -> ListRequest {
        ListRequest {
            filter,
            sort: SortOrder::default(),
            page,
        }
    }

    fn list(
        store: Arc<FakeOAuthClientStore>,
        request: ListRequest,
    ) -> Result<Page<OAuthClient<ResolvedTenant>>, AppError> {
        let use_case = ListUseCase::new(ListPorts {
            client_store: store,
            ..ListPorts::fakes()
        });
        block_on(use_case.execute(&test_ctx(), request))
    }

    fn list_as(
        authorities: FakeTenantAuthorities,
    ) -> Result<Page<OAuthClient<ResolvedTenant>>, AppError> {
        let use_case = ListUseCase::new(ListPorts {
            client_store: store_of(&["Portal"]),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(
            &test_ctx(),
            request(ClientFilter::all(), PageRequest::default()),
        ))
    }

    /// Acme has three clients. Ann lists them all on one page.
    #[test]
    fn every_client_is_listed() {
        let page = list(
            store_of(&["A", "B", "C"]),
            request(ClientFilter::all(), PageRequest::default()),
        )
        .unwrap();

        assert_eq!(page.items.len(), 3);
    }

    /// Acme has two active clients and a revoked one. Ann asks for the active
    /// ones and gets two.
    #[test]
    fn a_status_filter_keeps_only_that_status() {
        let filter = ClientFilter {
            status: Some(OAuthClientStatus::Active),
        };

        let page = list(
            with_revoked(store_of(&["A", "B"])),
            request(filter, PageRequest::default()),
        )
        .unwrap();

        assert_eq!(page.items.len(), 2);
    }

    /// Acme has five clients. Ann pages through them two at a time and gets
    /// three pages, the last with one client.
    #[test]
    fn clients_are_paged() {
        let store = store_of(&["A", "B", "C", "D", "E"]);
        let mut asked = Some(PageRequest::first(Limit::new(2).unwrap()));
        let mut sizes = Vec::new();

        while let Some(page) = asked.take() {
            let found = list(store.clone(), request(ClientFilter::all(), page.clone())).unwrap();
            asked = page.following(&found);
            sizes.push(found.items.len());
        }

        assert_eq!(sizes, [2, 2, 1]);
    }

    /// Acme has no clients. Ann's listing is empty.
    #[test]
    fn a_tenant_without_clients_lists_none() {
        let page = list(
            store_of(&[]),
            request(ClientFilter::all(), PageRequest::default()),
        )
        .unwrap();

        assert!(page.is_empty());
        assert_eq!(page.items.len(), 0);
    }

    /// Ann orders the clients by name and gets them alphabetically.
    #[test]
    fn clients_are_ordered_by_name() {
        let page = list(
            store_of(&["Charlie", "Alice", "Bob"]),
            ListRequest {
                sort: SortOrder::single(Sort::ascending(OAuthClientSortField::Name)),
                ..request(ClientFilter::all(), PageRequest::default())
            },
        )
        .unwrap();

        let names: Vec<_> = page.items.iter().map(|c| c.name().as_str()).collect();
        assert_eq!(names, ["Alice", "Bob", "Charlie"]);
    }

    /// A caller without view permission is forbidden from listing OAuth clients.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let result = list_as(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller receives unauthenticated when listing OAuth clients.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list_as(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
