//! Assign reviewer: a person sets one agent to watch another.
//!
//! The person must have a say over both agents: the one watched and the
//! reviewer, which may hold no live delegation while it reviews. The two
//! must answer to different people and share no delegation. The domain
//! decides each from what is loaded here.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::agents::oversight::review::{
    AssignReviewerParams, ReviewAssignment, ReviewOwners,
};
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::ReviewAssignmentStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::delegation::granting::lineage::{LineagePorts, agent_lineage};
use crate::use_cases::agents::lookup::{AgentReach, owned_agent};
use crate::use_cases::agents::reviews::reviewing::reviewer_holds;

/// Which agent watches which.
pub struct AssignReviewerRequest {
    /// The agent that reviews.
    pub reviewer: AgentId,
    /// The agent under review.
    pub reviewed: AgentId,
}

/// The ports [`AssignReviewerUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AssignReviewerPorts {
    /// Both agents, their delegations and the people behind them.
    pub lineage: LineagePorts,
    /// Keeps assignments.
    pub review_store: Arc<dyn ReviewAssignmentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Links an eligible reviewing agent to the agent it will oversee.
pub struct AssignReviewerUseCase {
    ports: AssignReviewerPorts,
}

impl AssignReviewerUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AssignReviewerPorts) -> Self {
        Self { ports }
    }
}

impl Command for AssignReviewerUseCase {
    type Caller = CallerContext;
    type Input = AssignReviewerRequest;
    type Output = Result<ReviewAssignment<ResolvedTenant>, AppError>;

    /// Assigns the reviewer to review the reviewed agent.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when either agent is not in the tenant, or the
    ///   caller neither owns it nor may update agents, so that an agent of
    ///   someone else's answers as one that does not exist.
    /// - `AppError::Forbidden` when the reviewer holds a live delegation.
    /// - `AppError::Domain(Validation)` when an agent would review itself or
    ///   the two are not independent.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: AssignReviewerRequest,
    ) -> Result<ReviewAssignment<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let agents = self.ports.lineage.agent_store.as_ref();
        let reach = AgentReach::Acting(AgentAction::Update);
        let reviewed = owned_agent(agents, &tenant, &request.reviewed, &control, reach).await?;
        let reviewer = owned_agent(agents, &tenant, &request.reviewer, &control, reach).await?;
        let params = assignment_params(&self.ports, &tenant, &request).await?;
        let owners = ReviewOwners {
            reviewer: reviewer.owner(),
            reviewed: reviewed.owner(),
        };
        let mut assignment =
            ReviewAssignment::assign(&control, owners, &params).map_err(AppError::from_domain)?;

        self.ports
            .review_store
            .save(&tenant, &assignment)
            .await
            .or_internal()?;

        auditor
            .dispatch_by(&ctx.actor(), assignment.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(assignment)
    }
}

/// What the domain needs to decide the assignment: both lineages and
/// whether the reviewer holds a live delegation.
async fn assignment_params(
    ports: &AssignReviewerPorts,
    tenant: &ScopedTenant,
    request: &AssignReviewerRequest,
) -> Result<AssignReviewerParams, AppError> {
    let lineage = &ports.lineage;
    Ok(AssignReviewerParams {
        reviewer: request.reviewer,
        reviewed: request.reviewed,
        reviewer_lineage: agent_lineage(lineage, tenant, &request.reviewer).await?,
        reviewed_lineage: agent_lineage(lineage, tenant, &request.reviewed).await?,
        reviewer_holds: reviewer_holds(
            lineage.delegation_store.as_ref(),
            tenant,
            &request.reviewer,
        )
        .await?,
    })
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::CapabilitySet;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{PrincipalRef, UserId};

    use super::*;
    use crate::ports::agents::DelegationStore;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeDelegationStore, FakeReviewStore, caller_person, root_delegation,
        someone,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        agents: Arc<FakeAgentStore>,
        delegations: Arc<FakeDelegationStore>,
        users: Arc<FakeUserStore>,
        reviews: Arc<FakeReviewStore>,
        reviewer: AgentId,
        reviewed: AgentId,
    }

    /// Two agents with different owners: the reviewer owned by a fresh
    /// person, the reviewed agent by the test caller.
    fn fixture() -> Fixture {
        let (reviewer, reviewed) = (AgentId::new(), AgentId::new());
        let agents = FakeAgentStore::with_active(reviewer);
        agents.add_owned_by(reviewed, caller_person());
        Fixture {
            agents: Arc::new(agents),
            delegations: Arc::new(FakeDelegationStore::empty()),
            users: Arc::new(FakeUserStore::empty()),
            reviews: Arc::new(FakeReviewStore::default()),
            reviewer,
            reviewed,
        }
    }

    impl Fixture {
        fn ports(&self, authorities: FakeTenantAuthorities) -> AssignReviewerPorts {
            AssignReviewerPorts {
                lineage: LineagePorts {
                    agent_store: self.agents.clone(),
                    delegation_store: self.delegations.clone(),
                    user_store: self.users.clone(),
                    ..LineagePorts::fakes()
                },
                review_store: self.reviews.clone(),
                tenant_authorities: Arc::new(authorities),
            }
        }

        fn hand_reviewer_a_delegation(&self) {
            let granter = UserId::new();
            self.users.add_active_user(granter, "gail@example.test");
            let held = root_delegation(
                PrincipalRef::User(granter),
                self.reviewer,
                CapabilitySet::empty(),
            );
            block_on(self.delegations.save(&test_ctx().tenant(), &held)).unwrap();
        }

        fn assign_with(
            &self,
            authorities: FakeTenantAuthorities,
            sink: &Arc<FakeEventDispatcher>,
        ) -> Result<ReviewAssignment<ResolvedTenant>, AppError> {
            block_on(AssignReviewerUseCase::new(self.ports(authorities)).execute(
                &test_ctx(),
                &test_auditor(sink.clone()),
                AssignReviewerRequest {
                    reviewer: self.reviewer,
                    reviewed: self.reviewed,
                },
            ))
        }

        fn assign(&self) -> Result<ReviewAssignment<ResolvedTenant>, AppError> {
            self.assign_with(updating_agents(), &Arc::new(FakeEventDispatcher::new()))
        }

        fn kept(&self) -> usize {
            block_on(
                self.reviews
                    .list_for_agent(&test_ctx().tenant(), &self.reviewer),
            )
            .unwrap()
            .len()
        }
    }

    /// What a caller who may update agents holds.
    fn updating_agents() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::Update)])
    }

    /// Ann may update agents. She sets another person's agent, which holds
    /// no delegation, to review hers. The assignment stands, is kept and is
    /// recorded.
    #[test]
    fn a_caller_who_may_update_agents_assigns_an_independent_reviewer() {
        let f = fixture();
        let sink = Arc::new(FakeEventDispatcher::new());

        let assignment = f.assign_with(updating_agents(), &sink).unwrap();

        assert!(assignment.is_active());
        assert_eq!(f.kept(), 1);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.reviewer_assigned"]
        );
    }

    /// Owning the reviewed agent does not authorize assigning someone
    /// else's reviewer; the request returns missing and stores no assignment.
    #[test]
    fn an_owner_without_a_say_over_the_reviewer_is_refused() {
        let f = fixture();

        let result = f.assign_with(
            FakeTenantAuthorities::holding(&[]),
            &Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(f.kept(), 0);
    }

    /// An agent holding a live delegation cannot become a reviewer,
    /// and no assignment is stored.
    #[test]
    fn a_reviewer_holding_a_delegation_is_refused() {
        let f = fixture();
        f.hand_reviewer_a_delegation();

        let result = f.assign();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.kept(), 0);
    }

    /// Agents owned by the same person cannot review one another.
    #[test]
    fn a_reviewer_answering_to_the_same_person_is_refused() {
        let f = fixture();
        let agents = FakeAgentStore::empty();
        agents.add_owned_by(f.reviewer, caller_person());
        agents.add_owned_by(f.reviewed, caller_person());
        let f = Fixture {
            agents: Arc::new(agents),
            ..f
        };

        let result = f.assign();

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
    }

    /// A caller without authority over the reviewed agent receives missing
    /// and creates no review assignment.
    #[test]
    fn a_caller_without_a_say_over_the_reviewed_agent_is_refused() {
        let f = fixture();
        let agents = FakeAgentStore::with_active(f.reviewer);
        agents.add_owned_by(f.reviewed, someone("bob@example.test"));
        let f = Fixture {
            agents: Arc::new(agents),
            ..f
        };

        let result = f.assign_with(
            FakeTenantAuthorities::holding(&[]),
            &Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(f.kept(), 0);
    }

    /// Bob may update agents. He assigns a reviewer to an agent someone else
    /// owns.
    #[test]
    fn a_caller_who_may_update_agents_assigns_a_reviewer() {
        let f = fixture();
        let agents = FakeAgentStore::with_active(f.reviewer);
        agents.add_owned_by(f.reviewed, someone("bob@example.test"));
        let f = Fixture {
            agents: Arc::new(agents),
            ..f
        };

        assert!(f.assign().is_ok());
    }

    /// A reviewer absent from the tenant is reported as missing.
    #[test]
    fn an_unknown_reviewer_is_not_found() {
        let f = fixture();
        let f = Fixture {
            reviewer: AgentId::new(),
            ..f
        };

        assert!(matches!(f.assign(), Err(AppError::NotFound(_))));
    }

    /// A signed-out caller cannot assign a reviewer, leaving no assignment stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture();

        let result = f.assign_with(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(f.kept(), 0);
    }
}
