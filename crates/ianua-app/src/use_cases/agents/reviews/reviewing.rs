//! A reviewer holds nothing but its review.
//!
//! An agent watching another reads evidence through its assignment and does
//! nothing else, so it cannot be steered into acting, or act to cover what it
//! saw. An agent holding a live delegation is never assigned to review, and
//! an agent that reviews is given no delegation. These helpers read the two
//! facts the domain decides on.

use ianua_domain::domains::agents::authority::capability::CapabilitySet;
use ianua_domain::domains::agents::authority::delegation::ReviewDuty;
use ianua_domain::domains::agents::oversight::review::ReviewerHolds;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::types::AgentId;

use crate::error::{AppError, OrInternal};
use crate::ports::agents::{DelegationStore, ReviewAssignmentStore};
use crate::tenancy::ScopedTenant;

/// Whether `agent` reviews another agent now, as a delegation to it must
/// say.
///
/// # Errors
///
/// Returns `AppError::Internal` when the assignments cannot be read.
pub(in crate::use_cases::agents) async fn review_duty(
    reviews: &dyn ReviewAssignmentStore,
    tenant_id: &ScopedTenant,
    agent: &AgentId,
) -> Result<ReviewDuty, AppError> {
    let reviewing = reviews
        .list_for_agent(tenant_id, agent)
        .await
        .or_internal()?
        .iter()
        .any(|assignment| assignment.is_active() && assignment.reviewer() == agent);
    if reviewing {
        return Ok(ReviewDuty::Reviewing);
    }
    Ok(ReviewDuty::NotReviewing)
}

/// Refuses `granted` to an agent that reviews another, unless it grants
/// nothing.
///
/// # Errors
///
/// - `AppError::Forbidden` when a reviewer would hold capabilities.
/// - `AppError::Internal` when the assignments cannot be read.
pub(in crate::use_cases::agents) async fn refuse_capabilities_for_reviewer(
    reviews: &dyn ReviewAssignmentStore,
    tenant_id: &ScopedTenant,
    agent: &AgentId,
    granted: &CapabilitySet,
) -> Result<(), AppError> {
    if granted.is_empty() {
        return Ok(());
    }
    match review_duty(reviews, tenant_id, agent).await? {
        ReviewDuty::NotReviewing => Ok(()),
        ReviewDuty::Reviewing => Err(AppError::Forbidden(message!(
            "agents-an-agent-that-reviews-another-holds",
            "an agent that reviews another holds no capabilities"
        ))),
    }
}

/// Whether `agent` holds any delegation live now, as assigning it to
/// review must say.
///
/// # Errors
///
/// Returns `AppError::Internal` when the delegations cannot be read.
pub(in crate::use_cases::agents) async fn reviewer_holds(
    delegations: &dyn DelegationStore,
    tenant_id: &ScopedTenant,
    agent: &AgentId,
) -> Result<ReviewerHolds, AppError> {
    let now = clock::now();
    let holds_any = delegations
        .list_for_agent(tenant_id, agent)
        .await
        .or_internal()?
        .iter()
        .any(|delegation| delegation.is_valid(now));
    if holds_any {
        return Ok(ReviewerHolds::Delegations);
    }
    Ok(ReviewerHolds::Nothing)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::{
        PubSub, TopicCapability, TopicPattern,
    };
    use ianua_domain::domains::agents::oversight::review::{ReviewAssignment, ReviewAssignmentRow};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::{Ending, PrincipalRef, ReviewAssignmentId, UserId};

    use super::*;
    use crate::test_support::agents::{FakeDelegationStore, FakeReviewStore, grant_from_user};
    use crate::test_support::{block_on, test_ctx};

    fn assignment(reviewer: AgentId, ending: Ending) -> ReviewAssignment<ResolvedTenant> {
        ReviewAssignment::reconstitute(ReviewAssignmentRow {
            id: ReviewAssignmentId::new(),
            reviewer,
            reviewed: AgentId::new(),
            assigned_by: PrincipalRef::User(UserId::new()),
            assigned_at: clock::now() - time::Duration::hours(1),
            ending,
        })
        .unwrap()
    }

    fn reviewing(agent: AgentId, ending: Ending) -> FakeReviewStore {
        let store = FakeReviewStore::default();
        block_on(store.save(&test_ctx().tenant(), &assignment(agent, ending))).unwrap();
        store
    }

    fn some_capability() -> CapabilitySet {
        CapabilitySet::new(
            Vec::new(),
            vec![TopicCapability::new(
                TopicPattern::new("agents.>").unwrap(),
                PubSub::Publish,
            )],
        )
    }

    /// An active reviewer cannot receive a topic-publishing capability.
    #[test]
    fn a_reviewer_is_granted_nothing() {
        let agent = AgentId::new();
        let store = reviewing(agent, Ending::Ongoing);

        let result = block_on(refuse_capabilities_for_reviewer(
            &store,
            &test_ctx().tenant(),
            &agent,
            &some_capability(),
        ));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Handing a reviewer an empty set of capabilities hands it nothing, so
    /// it is not refused.
    #[test]
    fn an_empty_grant_to_a_reviewer_is_not_refused() {
        let agent = AgentId::new();
        let store = reviewing(agent, Ending::Ongoing);

        let result = block_on(refuse_capabilities_for_reviewer(
            &store,
            &test_ctx().tenant(),
            &agent,
            &CapabilitySet::empty(),
        ));

        assert!(result.is_ok());
    }

    /// An agent that reviews nobody is unaffected by the reviewer rule.
    #[test]
    fn an_agent_that_reviews_nobody_is_unaffected() {
        let result = block_on(refuse_capabilities_for_reviewer(
            &FakeReviewStore::default(),
            &test_ctx().tenant(),
            &AgentId::new(),
            &some_capability(),
        ));

        assert!(result.is_ok());
    }

    /// An agent whose review a person ended no longer counts as reviewing.
    #[test]
    fn an_ended_review_leaves_the_agent_free() {
        let agent = AgentId::new();
        let store = reviewing(agent, Ending::Ended { at: clock::now() });

        let duty = block_on(review_duty(&store, &test_ctx().tenant(), &agent)).unwrap();

        assert_eq!(duty, ReviewDuty::NotReviewing);
    }

    /// An agent holding a live delegation holds something, whatever it
    /// grants.
    #[test]
    fn an_agent_with_a_live_delegation_holds_delegations() {
        let delegation = grant_from_user(UserId::new());
        let agent = *delegation.delegate();
        let store = FakeDelegationStore::empty();
        block_on(store.save(&test_ctx().tenant(), &delegation)).unwrap();

        let holds = block_on(reviewer_holds(&store, &test_ctx().tenant(), &agent)).unwrap();

        assert_eq!(holds, ReviewerHolds::Delegations);
    }

    /// An agent holding no delegation holds nothing and may review.
    #[test]
    fn an_agent_without_delegations_holds_nothing() {
        let holds = block_on(reviewer_holds(
            &FakeDelegationStore::empty(),
            &test_ctx().tenant(),
            &AgentId::new(),
        ))
        .unwrap();

        assert_eq!(holds, ReviewerHolds::Nothing);
    }
}
