//! List channels: the channels people opened between the tenant's agents.

use std::sync::Arc;

use ianua_domain::domains::agents::channels::channel::AgentChannel;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest};
use crate::ports::messaging::AgentChannelStore;
use crate::use_case::Query;

/// Ports the list channels use case needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Where channels are kept.
    pub channel_store: Arc<dyn AgentChannelStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's channels, newest first.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// Creates the use case.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = PageRequest;
    type Output = Result<Page<AgentChannel<ResolvedTenant>>, AppError>;

    /// One page of the tenant's channels, open and closed.
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
        page: PageRequest,
    ) -> Result<Page<AgentChannel<ResolvedTenant>>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Agents(AgentAction::View))
            .map_err(AppError::from_domain)?;
        self.ports
            .channel_store
            .list(&ctx.tenant(), &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{AgentId, Human, HumanAccount, PersonKey, UserId};

    use super::*;
    use crate::listing::Limit;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::messaging::{FakeAgentChannelStore, open_channel};
    use crate::test_support::{block_on, test_ctx};

    fn three_channels() -> Arc<FakeAgentChannelStore> {
        let owner = Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("ann@example.test").unwrap(),
        );
        let store = Arc::new(FakeAgentChannelStore::default());
        for _ in 0..3 {
            let channel = open_channel(AgentId::new(), AgentId::new(), &owner);
            block_on(store.save(&test_ctx().tenant(), &channel)).unwrap();
        }
        store
    }

    fn with_authorities(people: FakeTenantAuthorities) -> ListUseCase {
        ListUseCase::new(ListPorts {
            channel_store: three_channels(),
            tenant_authorities: Arc::new(people),
        })
    }

    /// The tenant has three channels. Ann asks for a page of two and gets
    /// two, with the total of three.
    #[test]
    fn lists_the_tenants_channels_with_a_total() {
        let use_case =
            with_authorities(FakeTenantAuthorities::holding(&[SystemPermission::Agents(
                AgentAction::View,
            )]));

        let page =
            block_on(use_case.execute(&test_ctx(), PageRequest::first(Limit::new(2).unwrap())))
                .unwrap();

        assert_eq!(page.items.len(), 2);
        assert!(page.has_next());
    }

    /// Listing channels without agent view rights returns a forbidden error.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let use_case = with_authorities(FakeTenantAuthorities::holding(&[]));

        let result = block_on(use_case.execute(&test_ctx(), PageRequest::default()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller receives an unauthenticated error when listing channels.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = with_authorities(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = block_on(use_case.execute(&test_ctx(), PageRequest::default()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
