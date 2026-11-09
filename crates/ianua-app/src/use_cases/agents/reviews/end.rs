//! End review: a person stops one agent watching another.
//!
//! The person who assigned the review may end it, and so may someone
//! allowed to update agents. The owner of the agent under review never may.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentId, ReviewAssignmentId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, ReviewAssignmentStore};
use crate::services::lookup::existing_agent;
use crate::use_case::Command;
use crate::use_cases::agents::lookup::owned_review_assignment;

/// The ports [`EndUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct EndPorts {
    /// Keeps assignments.
    pub review_store: Arc<dyn ReviewAssignmentStore>,
    /// The agents, for the reviewed agent's owner.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which assignment to end, addressed under the agent it reviews.
pub struct EndRequest {
    /// The agent under review.
    pub reviewed: AgentId,
    /// The assignment to end.
    pub assignment_id: ReviewAssignmentId,
}

/// Ends a review assignment.
pub struct EndUseCase {
    ports: EndPorts,
}

impl EndUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: EndPorts) -> Self {
        Self { ports }
    }
}

impl Command for EndUseCase {
    type Caller = CallerContext;
    type Input = EndRequest;
    type Output = Result<(), AppError>;

    /// Ends the assignment, addressed under the agent it reviews.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the assignment is not that agent's, the
    ///   agent is gone, or the caller neither assigned the review nor may
    ///   update agents, so that it answers as one that does not exist.
    /// - `AppError::Forbidden` when the caller owns the reviewed agent.
    /// - `AppError::Domain(InvalidTransition)` when it already ended.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: EndRequest,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let mut assignment = owned_review_assignment(
            self.ports.review_store.as_ref(),
            &tenant,
            &request.reviewed,
            &request.assignment_id,
            &control,
        )
        .await?;
        let reviewed =
            existing_agent(self.ports.agent_store.as_ref(), &tenant, &request.reviewed).await?;
        assignment
            .end(&control, reviewed.owner())
            .map_err(AppError::from_domain)?;

        self.ports
            .review_store
            .save(&tenant, &assignment)
            .await
            .or_internal()?;

        auditor
            .dispatch_by(&ctx.actor(), assignment.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::oversight::review::{ReviewAssignment, ReviewAssignmentRow};
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{Ending, PrincipalRef, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeReviewStore, caller_person, callers_agent,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        reviews: Arc<FakeReviewStore>,
        agents: Arc<FakeAgentStore>,
        reviewed: AgentId,
        assignment_id: ReviewAssignmentId,
    }

    /// A standing review of `reviewed`, kept in `agents`, assigned by
    /// `assigned_by`.
    fn reviewing(agents: FakeAgentStore, reviewed: AgentId, assigned_by: PrincipalRef) -> Fixture {
        let assignment: ReviewAssignment<ResolvedTenant> =
            ReviewAssignment::reconstitute(ReviewAssignmentRow {
                id: ReviewAssignmentId::new(),
                reviewer: AgentId::new(),
                reviewed,
                assigned_by,
                assigned_at: clock::now(),
                ending: Ending::Ongoing,
            })
            .unwrap();
        let reviews = Arc::new(FakeReviewStore::default());
        block_on(reviews.save(&test_ctx().tenant(), &assignment)).unwrap();
        Fixture {
            reviews,
            agents: Arc::new(agents),
            reviewed,
            assignment_id: *assignment.id(),
        }
    }

    /// The caller assigned a review of an agent someone else owns.
    fn assigned_by_caller() -> Fixture {
        let reviewed = AgentId::new();
        reviewing(
            FakeAgentStore::with_active(reviewed),
            reviewed,
            caller_person().principal(),
        )
    }

    impl Fixture {
        fn end_with(
            &self,
            authorities: FakeTenantAuthorities,
            sink: &Arc<FakeEventDispatcher>,
        ) -> Result<(), AppError> {
            block_on(
                EndUseCase::new(EndPorts {
                    review_store: self.reviews.clone(),
                    agent_store: self.agents.clone(),
                    tenant_authorities: Arc::new(authorities),
                })
                .execute(
                    &test_ctx(),
                    &test_auditor(sink.clone()),
                    EndRequest {
                        reviewed: self.reviewed,
                        assignment_id: self.assignment_id,
                    },
                ),
            )
        }

        fn end(&self) -> Result<(), AppError> {
            self.end_with(
                FakeTenantAuthorities::holding(&[]),
                &Arc::new(FakeEventDispatcher::new()),
            )
        }

        fn still_stands(&self) -> bool {
            block_on(
                self.reviews
                    .find_by_id(&test_ctx().tenant(), &self.assignment_id),
            )
            .unwrap()
            .unwrap()
            .is_active()
        }
    }

    /// Ann assigned a review and ends it. It no longer stands, and the end
    /// is recorded.
    #[test]
    fn the_person_who_assigned_a_review_ends_it() {
        let f = assigned_by_caller();
        let sink = Arc::new(FakeEventDispatcher::new());

        f.end_with(FakeTenantAuthorities::holding(&[]), &sink)
            .unwrap();

        assert!(!f.still_stands());
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.review_ended"]
        );
    }

    /// Bob may update agents. He ends a review someone else assigned.
    #[test]
    fn a_caller_who_may_update_agents_ends_a_review() {
        let reviewed = AgentId::new();
        let f = reviewing(
            FakeAgentStore::with_active(reviewed),
            reviewed,
            PrincipalRef::User(UserId::new()),
        );

        f.end_with(
            FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::Update)]),
            &Arc::new(FakeEventDispatcher::new()),
        )
        .unwrap();

        assert!(!f.still_stands());
    }

    /// An owner cannot end a review of their agent even with every agent
    /// permission; the review remains active.
    #[test]
    fn the_owner_of_the_reviewed_agent_cannot_end_it() {
        let reviewed = AgentId::new();
        let f = reviewing(
            callers_agent(reviewed),
            reviewed,
            PrincipalRef::User(UserId::new()),
        );

        let result = f.end_with(
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(f.still_stands());
    }

    /// A caller without authority to end the review receives the same missing
    /// result for real and unknown assignments, and the review remains active.
    #[test]
    fn a_stranger_cannot_end_a_review() {
        let reviewed = AgentId::new();
        let f = reviewing(
            FakeAgentStore::with_active(reviewed),
            reviewed,
            PrincipalRef::User(UserId::new()),
        );
        let unknown = Fixture {
            assignment_id: ReviewAssignmentId::new(),
            reviews: f.reviews.clone(),
            agents: f.agents.clone(),
            reviewed,
        };

        let real = f.end();

        assert!(matches!(real, Err(AppError::NotFound(_))));
        assert_eq!(
            real.err().map(|error| error.to_string()),
            unknown.end().err().map(|error| error.to_string())
        );
        assert!(f.still_stands());
    }

    /// Addressing a review under another agent reports it as missing.
    #[test]
    fn a_review_addressed_under_another_agent_is_not_found() {
        let f = assigned_by_caller();
        let f = Fixture {
            reviewed: AgentId::new(),
            ..f
        };

        assert!(matches!(f.end(), Err(AppError::NotFound(_))));
    }

    /// Ann ends a review she already ended. The second end is refused.
    #[test]
    fn an_ended_review_cannot_end_again() {
        let f = assigned_by_caller();
        f.end().unwrap();

        let result = f.end();

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::InvalidTransition(_)))
        ));
    }

    /// A signed-out caller cannot end the review, which remains active.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = assigned_by_caller();

        let result = f.end_with(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(f.still_stands());
    }
}
