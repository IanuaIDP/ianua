//! List reviews: who reviews an agent, and whom it reviews.

use std::sync::Arc;

use ianua_domain::domains::agents::oversight::review::ReviewAssignment;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, ReviewAssignmentStore};
use crate::use_case::Query;
use crate::use_cases::agents::evidence::watching::watched_agent;

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Keeps assignments.
    pub review_store: Arc<dyn ReviewAssignmentStore>,
    /// The agents, to find whose reviews they are.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists an agent's review assignments.
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
    type Input = AgentId;
    type Output = Result<Vec<ReviewAssignment<ResolvedTenant>>, AppError>;

    /// The assignments where `agent` reviews or is reviewed, newest first.
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
        agent: AgentId,
    ) -> Result<Vec<ReviewAssignment<ResolvedTenant>>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        watched_agent(self.ports.agent_store.as_ref(), &authority, &tenant, &agent).await?;
        self.ports
            .review_store
            .list_for_agent(&tenant, &agent)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::oversight::review::ReviewAssignmentRow;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{Ending, PrincipalRef, ReviewAssignmentId, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeAgentStore, FakeReviewStore, callers_agent};
    use crate::test_support::{block_on, test_ctx};

    /// A store with one review of `reviewed`.
    fn reviewed_once(reviewed: AgentId) -> FakeReviewStore {
        let store = FakeReviewStore::default();
        let assignment: ReviewAssignment<ResolvedTenant> =
            ReviewAssignment::reconstitute(ReviewAssignmentRow {
                id: ReviewAssignmentId::new(),
                reviewer: AgentId::new(),
                reviewed,
                assigned_by: PrincipalRef::User(UserId::new()),
                assigned_at: clock::now(),
                ending: Ending::Ongoing,
            })
            .unwrap();
        block_on(store.save(&test_ctx().tenant(), &assignment)).unwrap();
        store
    }

    fn list(
        agents: FakeAgentStore,
        agent: AgentId,
        authorities: FakeTenantAuthorities,
    ) -> Result<Vec<ReviewAssignment<ResolvedTenant>>, AppError> {
        let use_case = ListUseCase::new(ListPorts {
            review_store: Arc::new(reviewed_once(agent)),
            agent_store: Arc::new(agents),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), agent))
    }

    /// Ann lists the reviews of her own agent and sees the one standing.
    #[test]
    fn an_owner_lists_their_agents_reviews() {
        let agent = AgentId::new();

        let reviews = list(
            callers_agent(agent),
            agent,
            FakeTenantAuthorities::holding(&[]),
        )
        .unwrap();

        assert_eq!(reviews.len(), 1);
    }

    /// Without ownership or the view right, another agent's review list
    /// returns a missing-agent response.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let agent = AgentId::new();

        let result = list(
            FakeAgentStore::with_active(agent),
            agent,
            FakeTenantAuthorities::holding(&[]),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// An agent absent from the tenant's store has no readable review list.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let result = list(
            FakeAgentStore::empty(),
            AgentId::new(),
            FakeTenantAuthorities::holding_everything(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out owner cannot list their agent's reviews.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let agent = AgentId::new();

        let result = list(
            callers_agent(agent),
            agent,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
