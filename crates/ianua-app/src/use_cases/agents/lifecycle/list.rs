//! List agents: the tenant's agents, ordered and a page at a time.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::agents::{AgentSortField, AgentStore};
use crate::use_case::Query;

/// The order and page of agents to list.
pub struct ListAgentsRequest {
    /// The field and direction to order by.
    pub sort: SortOrder<AgentSortField>,
    /// Which page of the ordered agents to return.
    pub page: PageRequest,
}

/// The ports [`ListAgentsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListAgentsPorts {
    /// Loads agents.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the agents of the caller's tenant.
pub struct ListAgentsUseCase {
    ports: ListAgentsPorts,
}

impl ListAgentsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListAgentsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListAgentsUseCase {
    type Caller = CallerContext;
    type Input = ListAgentsRequest;
    type Output = Result<Page<AgentIdentity<ResolvedTenant>>, AppError>;

    /// The page of agents `request` asks for, once the caller may view
    /// agents.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view agents.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListAgentsRequest,
    ) -> Result<Page<AgentIdentity<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Agents(AgentAction::View))
            .map_err(AppError::from_domain)?;
        let ListAgentsRequest { sort, page } = request;
        self.ports
            .agent_store
            .list_all(&ctx.tenant(), &sort, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::model::aggregate::Aggregate;
    use ianua_domain::types::AgentId;

    use super::*;
    use crate::listing::Sort;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::FakeAgentStore;
    use crate::test_support::{block_on, test_ctx};

    fn three_agents() -> FakeAgentStore {
        let store = FakeAgentStore::empty();
        for _ in 0..3 {
            store.add_active(AgentId::new());
        }
        store
    }

    fn use_case(store: FakeAgentStore, authorities: FakeTenantAuthorities) -> ListAgentsUseCase {
        ListAgentsUseCase::new(ListAgentsPorts {
            agent_store: Arc::new(store),
            tenant_authorities: Arc::new(authorities),
        })
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)])
    }

    fn first_page(sort: SortOrder<AgentSortField>) -> ListAgentsRequest {
        ListAgentsRequest {
            sort,
            page: PageRequest::default(),
        }
    }

    /// Ann lists a tenant with three agents. All three come back.
    #[test]
    fn every_agent_is_listed() {
        let page = block_on(
            use_case(three_agents(), viewer())
                .execute(&test_ctx(), first_page(SortOrder::default())),
        )
        .unwrap();

        assert_eq!(page.items.len(), 3);
    }

    /// Ann orders the agents by when they changed, newest first. The page
    /// keeps that order.
    #[test]
    fn agents_follow_the_order_asked_for() {
        let sort = SortOrder::single(Sort::descending(AgentSortField::UpdatedAt));

        let page =
            block_on(use_case(three_agents(), viewer()).execute(&test_ctx(), first_page(sort)))
                .unwrap();

        let times: Vec<_> = page.items.iter().map(Aggregate::updated_at).collect();
        assert!(times.windows(2).all(|pair| pair[0] >= pair[1]));
    }

    /// Ann lists a tenant with no agents. The page is empty.
    #[test]
    fn a_tenant_without_agents_lists_none() {
        let page = block_on(
            use_case(FakeAgentStore::empty(), viewer())
                .execute(&test_ctx(), first_page(SortOrder::default())),
        )
        .unwrap();

        assert!(page.is_empty());
    }

    /// A caller without the view right cannot list the tenant's agents.
    #[test]
    fn a_caller_who_may_not_view_agents_is_refused() {
        let result = block_on(
            use_case(three_agents(), FakeTenantAuthorities::holding(&[]))
                .execute(&test_ctx(), first_page(SortOrder::default())),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller is refused the agent list.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = block_on(
            use_case(
                three_agents(),
                FakeTenantAuthorities::refusing(Refusal::SignedOut),
            )
            .execute(&test_ctx(), first_page(SortOrder::default())),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
