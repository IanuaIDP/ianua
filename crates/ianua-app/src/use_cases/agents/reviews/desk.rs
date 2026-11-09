//! Review desk: where a reviewer agent reads evidence and gives verdicts.
//!
//! The reviewer signs in as itself with an assertion its own key signed. A
//! task token would not do: a reviewer holds no delegation, so it has none,
//! and a verdict is the reviewer's own act. Every request then re-checks
//! what made the assignment acceptable: a person's assignment from it to
//! the reviewed agent stands, it still holds no live delegation, and the
//! two lineages are still independent, since a delegation granted since
//! could have joined them.
//!
//! Reading evidence and giving a verdict are separate use cases
//! ([`read_review_evidence`](crate::use_cases::agents::reviews::read_evidence)
//! and
//! [`submit_review_verdict`](crate::use_cases::agents::reviews::submit_verdict));
//! this module holds the admission both run first.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::acting::ActingAgent;
use ianua_domain::domains::agents::oversight::review::{ReviewAssignment, ReviewerHolds};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{AgentId, Audience};

use crate::acting::AgentActors;
use crate::auditor::RequestAuditor;
use crate::context::AgentAssertion;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::ReviewAssignmentStore;
use crate::ports::audit::{AuditChainVerdictStore, EvidenceStore};
use crate::ports::notifications::AlertThrottle;
use crate::ports::shared::EventDispatcher;
use crate::services::agents::sign_in::{AgentDoor, signed_in_at};
use crate::tenancy::ScopedTenant;
use crate::use_cases::agents::delegation::granting::lineage::{LineagePorts, agent_lineage};
use crate::use_cases::agents::reviews::reviewing::reviewer_holds;

/// The ports the desk checks and reads through.
#[derive(Clone, ianua_macros::Fakes)]
pub struct DeskPorts {
    /// Signs the reviewer in as itself.
    pub agent_actors: Arc<dyn AgentActors>,
    /// Holds back records of a refused sign-in that looks like an attack
    /// to one a window per agent and kind of attack.
    pub alert_throttle: Arc<dyn AlertThrottle>,
    /// Records such an attack when reading evidence, which no command's
    /// auditor accompanies.
    pub event_dispatcher: Arc<dyn EventDispatcher>,
    /// The assignments.
    pub review_store: Arc<dyn ReviewAssignmentStore>,
    /// Both agents' lineages and what the reviewer holds.
    pub lineage: LineagePorts,
    /// Loads submitted material supporting a review decision.
    pub evidence_store: Arc<dyn EvidenceStore>,
    /// The sweep's kept verdicts on the chain the evidence hangs off.
    pub chain_verdicts: Arc<dyn AuditChainVerdictStore>,
}

/// One reviewer request: who asks, and about whom. The tenant it was
/// addressed to is the use case's caller.
pub struct ReviewRequest {
    /// The reviewer's signed assertion.
    pub reviewer: AgentAssertion,
    /// The agent under review.
    pub reviewed: AgentId,
}

/// A reviewer let in to the desk, with the assignment that lets it in.
pub(in crate::use_cases::agents) struct AdmittedReviewer {
    /// The reviewer, signed in as itself.
    pub(in crate::use_cases::agents) acting: ActingAgent,
    /// The standing assignment from it to the reviewed agent.
    pub(in crate::use_cases::agents) assignment: ReviewAssignment<ResolvedTenant>,
}

/// Where a reviewer's request comes in: the tenant it was addressed to,
/// the audience its assertion must name, and where a refused sign-in that
/// looks like an attack is recorded.
#[derive(Clone, Copy)]
pub(in crate::use_cases::agents) struct DeskVisit<'a> {
    /// The tenant the request was addressed to.
    pub(in crate::use_cases::agents) tenant: &'a ScopedTenant,
    /// The audience the reviewer's assertion must name.
    pub(in crate::use_cases::agents) audience: &'a Audience,
    /// Records an attack on the reviewer's sign-in.
    pub(in crate::use_cases::agents) auditor: &'a RequestAuditor,
}

/// The reviewer behind `req`, once it signed in as itself for the visit's
/// audience and every check that made its assignment acceptable still
/// holds in its tenant: a person's assignment to the reviewed agent
/// stands, it holds no live delegation, and the two lineages are still
/// independent. A sign-in refused as a replayed or forged assertion, or one
/// naming another agent, records `agents.token_attack_refused` once a
/// window per agent and kind of attack.
///
/// # Errors
///
/// - `AppError::Forbidden` when the assertion does not sign the reviewer in,
///   or the reviewer may not review that agent now.
/// - `AppError::Internal` when a check cannot be read, or an attack cannot
///   be recorded.
pub(in crate::use_cases::agents) async fn admitted_reviewer(
    ports: &DeskPorts,
    visit: DeskVisit<'_>,
    req: &ReviewRequest,
) -> Result<AdmittedReviewer, AppError> {
    let tenant = visit.tenant;
    let door = AgentDoor {
        actors: ports.agent_actors.as_ref(),
        attacks: ports.alert_throttle.as_ref(),
        tenant,
        audience: visit.audience,
    };
    let signed_in = signed_in_at(door, visit.auditor, &req.reviewer).await?;
    let reviewer = *signed_in.agent.id();
    let assignment = standing_assignment(ports, tenant, &reviewer, &req.reviewed).await?;
    ensure_empty_handed(ports, tenant, &reviewer).await?;
    ensure_still_independent(ports, tenant, &reviewer, &req.reviewed).await?;
    Ok(AdmittedReviewer {
        acting: signed_in.acting,
        assignment,
    })
}

/// Refuses a reviewer that holds a live delegation.
async fn ensure_empty_handed(
    ports: &DeskPorts,
    tenant: &ScopedTenant,
    reviewer: &AgentId,
) -> Result<(), AppError> {
    let delegations = ports.lineage.delegation_store.as_ref();
    match reviewer_holds(delegations, tenant, reviewer).await? {
        ReviewerHolds::Nothing => Ok(()),
        ReviewerHolds::Delegations => Err(AppError::Forbidden(message!(
            "agents-a-reviewer-holds-no-delegation",
            "a reviewer holds no delegation"
        ))),
    }
}

/// Refuses a reviewer that came to answer to the same people, or share a
/// delegation, with the agent it reviews.
async fn ensure_still_independent(
    ports: &DeskPorts,
    tenant: &ScopedTenant,
    reviewer: &AgentId,
    reviewed: &AgentId,
) -> Result<(), AppError> {
    let reviewer = agent_lineage(&ports.lineage, tenant, reviewer).await?;
    let reviewed = agent_lineage(&ports.lineage, tenant, reviewed).await?;
    if reviewer.independent_of(&reviewed) {
        return Ok(());
    }
    Err(AppError::Forbidden(message!(
        "agents-the-reviewer-no-longer-answers-to",
        "the reviewer no longer answers to different people than the agent it reviews"
    )))
}

/// The standing assignment from `reviewer` to `reviewed`.
async fn standing_assignment(
    ports: &DeskPorts,
    tenant: &ScopedTenant,
    reviewer: &AgentId,
    reviewed: &AgentId,
) -> Result<ReviewAssignment<ResolvedTenant>, AppError> {
    ports
        .review_store
        .list_for_agent(tenant, reviewer)
        .await
        .or_internal()?
        .into_iter()
        .find(|a| a.is_active() && a.reviewer() == reviewer && a.reviewed() == reviewed)
        .ok_or_else(|| {
            AppError::Forbidden(message!(
                "agents-no-person-assigned-this-agent-to",
                "no person assigned this agent to review that one"
            ))
        })
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::CapabilitySet;
    use ianua_domain::domains::agents::oversight::review::{
        CitedEvidence, ReviewAssignmentRow, VerdictKind, VerdictNote, VerdictParams,
    };
    use ianua_domain::domains::audit::walk::ChainStanding;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{
        Ending, Human, HumanAccount, PersonKey, PrincipalRef, ReviewAssignmentId, UserId,
    };

    use super::*;
    use crate::acting::agent::{AgentActing, AgentActingPorts};
    use crate::ports::agents::DelegationStore;
    use crate::test_support::acting::RefusingAgentActors;
    use crate::test_support::agents::{
        FakeAgentStore, FakeAssertionVerifier, FakeDelegationStore, FakeReviewStore,
        root_delegation, signing_in,
    };
    use crate::test_support::audit::{FakeChainVerdictStore, FakeEvidenceStore};
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::notification_delivery::FakeAlertThrottle;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_case::{Command, Query};
    use crate::use_cases::agents::evidence::EvidencePage;
    use crate::use_cases::agents::reviews::{
        ReadEvidenceRequest, ReadEvidenceUseCase, SubmitVerdictRequest, SubmitVerdictUseCase,
    };

    /// Two agents with different owners, the reviewer able to sign in, and
    /// the reviewed agent's evidence at records 1 to 3.
    struct Desk {
        ports: DeskPorts,
        delegations: Arc<FakeDelegationStore>,
        reviews: Arc<FakeReviewStore>,
        reviewer: AgentId,
        reviewer_owner: UserId,
        reviewed: AgentId,
        audit: Arc<FakeEventDispatcher>,
    }

    fn person(user: UserId, address: &str) -> Human {
        Human::new(HumanAccount::User(user), PersonKey::new(address).unwrap())
    }

    fn audience() -> Audience {
        Audience::new("https://acme.example.test/oauth/token").unwrap()
    }

    fn desk() -> Desk {
        let (reviewer, reviewed, reviewer_owner) = (AgentId::new(), AgentId::new(), UserId::new());
        let agents = Arc::new(FakeAgentStore::empty());
        agents.add_owned_by(reviewer, person(reviewer_owner, "rita@example.test"));
        agents.add_owned_by(reviewed, person(UserId::new(), "sam@example.test"));
        let (sign_in, _) = signing_in(agents.clone(), reviewer);
        let delegations = Arc::new(FakeDelegationStore::empty());
        let reviews = Arc::new(FakeReviewStore::default());
        let audit = Arc::new(FakeEventDispatcher::new());
        Desk {
            ports: DeskPorts {
                agent_actors: Arc::new(AgentActing::new(sign_in)),
                alert_throttle: Arc::new(FakeAlertThrottle::default()),
                event_dispatcher: audit.clone(),
                review_store: reviews.clone(),
                lineage: lineage(agents, &delegations, reviewer_owner),
                evidence_store: Arc::new(FakeEvidenceStore(reviewed)),
                chain_verdicts: Arc::new(FakeChainVerdictStore::holding(
                    test_ctx().tenant_id(),
                    ChainStanding::Intact,
                )),
            },
            delegations,
            reviews,
            reviewer,
            reviewer_owner,
            reviewed,
            audit,
        }
    }

    /// The reviewer traces authority through the stored agents, grants and owner.
    fn lineage(
        agents: Arc<FakeAgentStore>,
        delegations: &Arc<FakeDelegationStore>,
        owner: UserId,
    ) -> LineagePorts {
        LineagePorts {
            agent_store: agents,
            delegation_store: delegations.clone(),
            user_store: Arc::new(FakeUserStore::with_user(owner, "rita@example.test")),
            ..LineagePorts::fakes()
        }
    }

    impl Desk {
        fn assign(&self) {
            let assignment: ReviewAssignment<ResolvedTenant> =
                ReviewAssignment::reconstitute(ReviewAssignmentRow {
                    id: ReviewAssignmentId::new(),
                    reviewer: self.reviewer,
                    reviewed: self.reviewed,
                    assigned_by: PrincipalRef::User(UserId::new()),
                    assigned_at: clock::now(),
                    ending: Ending::Ongoing,
                })
                .unwrap();
            block_on(self.reviews.save(&test_ctx().tenant(), &assignment)).unwrap();
        }

        fn delegate(&self, from: UserId, to: AgentId) {
            let held = root_delegation(PrincipalRef::User(from), to, CapabilitySet::empty());
            block_on(self.delegations.save(&test_ctx().tenant(), &held)).unwrap();
        }

        fn request(&self) -> ReviewRequest {
            ReviewRequest {
                reviewer: AgentAssertion {
                    agent_id: self.reviewer,
                    assertion: "signed.assertion".to_owned(),
                },
                reviewed: self.reviewed,
            }
        }

        fn read(&self) -> Result<EvidencePage, AppError> {
            let use_case = ReadEvidenceUseCase::new(self.ports.clone(), audience());
            block_on(use_case.execute(
                &test_ctx().tenant(),
                ReadEvidenceRequest {
                    review: self.request(),
                    after_seq: 0,
                    limit: 10,
                },
            ))
        }

        fn verdict(&self, cited: Vec<i64>) -> Result<(), AppError> {
            let use_case = SubmitVerdictUseCase::new(self.ports.clone(), audience());
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.audit.clone()),
                SubmitVerdictRequest {
                    review: self.request(),
                    verdict: VerdictParams {
                        kind: VerdictKind::ContainmentRequested,
                        note: VerdictNote::new("it deleted what it was told to read").unwrap(),
                        cited: CitedEvidence::new(cited).unwrap(),
                    },
                },
            ))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Rita's agent is assigned to review Sam's. It signs in as itself and
    /// reads Sam's agent's evidence, with the chain's state beside it.
    #[test]
    fn an_assigned_reviewer_reads_evidence_with_the_chains_state() {
        let d = desk();
        d.assign();

        let page = d.read().unwrap();

        assert_eq!(page.records.len(), 3);
        let verdict = page.chain.unwrap();
        assert_eq!(verdict.standing(), ChainStanding::Intact);
    }

    /// An agent without a review assignment cannot read the evidence.
    #[test]
    fn without_an_assignment_nothing_is_read() {
        let d = desk();

        assert!(matches!(d.read(), Err(AppError::Forbidden(_))));
    }

    /// A reviewer refused at sign-in cannot read the evidence.
    #[test]
    fn a_reviewer_the_sign_in_refuses_reads_nothing() {
        let mut d = desk();
        d.assign();
        d.ports.agent_actors = Arc::new(RefusingAgentActors);

        assert!(matches!(d.read(), Err(AppError::Forbidden(_))));
    }

    /// An invalid assertion is rejected for both evidence reading and a
    /// verdict, recording one token attack for the two attempts.
    #[test]
    fn a_forged_assertion_at_the_desk_is_recorded_as_an_attack() {
        let mut d = desk();
        d.assign();
        let (sign_in, _) = signing_in(d.ports.lineage.agent_store.clone(), d.reviewer);
        d.ports.agent_actors = Arc::new(AgentActing::new(AgentActingPorts {
            verifier: Arc::new(FakeAssertionVerifier::rejecting("agent-key")),
            ..sign_in
        }));

        let read = d.read();
        let verdict = d.verdict(vec![1]);

        assert!(matches!(read, Err(AppError::Forbidden(_))));
        assert!(matches!(verdict, Err(AppError::Forbidden(_))));
        let attacks = d
            .recorded()
            .iter()
            .filter(|name| *name == "agents.token_attack_refused")
            .count();
        assert_eq!(attacks, 1);
    }

    /// An assigned reviewer loses evidence access when its owner grants
    /// authority to the reviewed agent.
    #[test]
    fn a_reviewer_that_came_to_share_a_person_is_shut_out() {
        let d = desk();
        d.assign();
        d.delegate(d.reviewer_owner, d.reviewed);

        assert!(matches!(d.read(), Err(AppError::Forbidden(_))));
    }

    /// An assigned reviewer with a live delegation cannot read the evidence.
    #[test]
    fn a_reviewer_holding_a_delegation_is_shut_out() {
        let d = desk();
        d.assign();
        d.delegate(d.reviewer_owner, d.reviewer);

        assert!(matches!(d.read(), Err(AppError::Forbidden(_))));
    }

    /// The reviewer gives a verdict citing records 1 and 3 of Sam's agent.
    /// It is recorded for a person to act on.
    #[test]
    fn a_verdict_citing_the_reviewed_agents_records_is_recorded() {
        let d = desk();
        d.assign();

        d.verdict(vec![1, 3]).unwrap();

        assert_eq!(d.recorded(), ["agents.review_verdict"]);
    }

    /// A verdict citing a record outside the reviewed agent's evidence is
    /// refused without recording an audit event.
    #[test]
    fn a_verdict_citing_records_that_are_not_the_agents_is_refused() {
        let d = desk();
        d.assign();

        let result = d.verdict(vec![1, 99]);

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
        assert!(d.recorded().is_empty());
    }

    /// Giving a verdict without an assignment is refused without recording
    /// an audit event.
    #[test]
    fn a_verdict_without_an_assignment_is_refused() {
        let d = desk();

        assert!(matches!(d.verdict(vec![1]), Err(AppError::Forbidden(_))));
        assert!(d.recorded().is_empty());
    }
}
