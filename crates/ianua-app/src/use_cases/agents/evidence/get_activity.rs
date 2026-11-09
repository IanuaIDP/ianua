//! Agent activity: the audit-log timeline of a single agent.
//!
//! Surfaces the individual audit records the agent produced: what it did,
//! for whom, allowed or denied. It is the read that makes teams comfortable
//! enabling agents. Reuses the audit-log query types; the store filters to
//! the agent actor within the tenant.

use std::sync::Arc;

use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Listing, PageRequest, SortOrder};
use crate::ports::agents::{AgentActivityStore, AgentStore};
use crate::ports::audit::{AuditLogFilter, AuditLogPage, AuditLogSortField};
use crate::use_case::Query;
use crate::use_cases::agents::evidence::watching::watched_agent;

/// The ports [`GetAgentActivityUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetAgentActivityPorts {
    /// The agents, to find whose timeline it is.
    pub agent_store: Arc<dyn AgentStore>,
    /// The agent's audit timeline.
    pub activity_store: Arc<dyn AgentActivityStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads an agent's activity timeline.
pub struct GetAgentActivityUseCase {
    ports: GetAgentActivityPorts,
}

/// Whose audit records to return, and which of them.
pub struct GetAgentActivityRequest {
    /// The agent whose timeline to read.
    pub agent_id: AgentId,
    /// Narrows the records returned.
    pub filter: AuditLogFilter,
    /// The order to return them in.
    pub sort: SortOrder<AuditLogSortField>,
    /// The rows to return.
    pub page: PageRequest,
}

impl GetAgentActivityUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetAgentActivityPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetAgentActivityUseCase {
    type Caller = CallerContext;
    type Input = GetAgentActivityRequest;
    type Output = Result<AuditLogPage, AppError>;

    /// The agent's audit records in the caller's tenant, filtered and paged.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such agent, or the
    ///   caller neither owns it nor may view agents, so that an agent of
    ///   someone else's answers as one that does not exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: GetAgentActivityRequest,
    ) -> Result<AuditLogPage, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        watched_agent(
            self.ports.agent_store.as_ref(),
            &authority,
            &tenant,
            &request.agent_id,
        )
        .await?;
        self.ports
            .activity_store
            .query(
                &tenant,
                &request.agent_id,
                Listing {
                    filter: &request.filter,
                    sort: &request.sort,
                    page: &request.page,
                },
            )
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listing::Limit;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeAgentActivityStore, FakeAgentStore, callers_agent};
    use crate::test_support::{block_on, test_ctx};

    fn read(ports: GetAgentActivityPorts, agent_id: AgentId) -> Result<AuditLogPage, AppError> {
        block_on(GetAgentActivityUseCase::new(ports).execute(
            &test_ctx(),
            GetAgentActivityRequest {
                agent_id,
                filter: AuditLogFilter::default(),
                sort: SortOrder::default(),
                page: PageRequest::first(Limit::new(50).unwrap()),
            },
        ))
    }

    fn ports_with(
        agents: FakeAgentStore,
        authorities: FakeTenantAuthorities,
    ) -> GetAgentActivityPorts {
        GetAgentActivityPorts {
            agent_store: Arc::new(agents),
            activity_store: Arc::new(FakeAgentActivityStore::empty()),
            tenant_authorities: Arc::new(authorities),
        }
    }

    /// Ann reads the timeline of her own agent and gets the store's page.
    #[test]
    fn an_owner_reads_their_agents_timeline() {
        let agent = AgentId::new();
        let ports = ports_with(callers_agent(agent), FakeTenantAuthorities::holding(&[]));

        let page = read(ports, agent);

        assert!(page.is_ok());
    }

    /// A caller without ownership or the view right receives a missing-agent
    /// response when requesting another person's timeline.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let agent = AgentId::new();
        let ports = ports_with(
            FakeAgentStore::with_active(agent),
            FakeTenantAuthorities::holding(&[]),
        );

        assert!(matches!(read(ports, agent), Err(AppError::NotFound(_))));
    }

    /// An unknown agent has no readable timeline, even for a caller with
    /// every permission.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let ports = ports_with(
            FakeAgentStore::empty(),
            FakeTenantAuthorities::holding_everything(),
        );

        assert!(matches!(
            read(ports, AgentId::new()),
            Err(AppError::NotFound(_))
        ));
    }

    /// A signed-out caller is refused access to their own agent's timeline.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let agent = AgentId::new();
        let ports = ports_with(
            callers_agent(agent),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(read(ports, agent), Err(AppError::Unauthenticated)));
    }
}
