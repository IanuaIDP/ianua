//! One agent reviewing another, with no shared chain of authority.
//!
//! A reviewer is only useful if it does not answer to the same person, or
//! the same delegations, as the agent it watches. Ann could steer a reviewer
//! she controls to ignore what her own agent does. So a person may assign
//! agent R to review agent S only when their lineages are independent. The
//! parties at the roots of their authority must differ, and no delegation
//! may appear in both.
//!
//! The person assigning a reviewer must have a say over both agents: the
//! one reviewed, whose evidence the reviewer reads, and the reviewer, which
//! may act on nothing while it reviews. The reviewed agent's owner never
//! ends the review.
//!
//! A reviewer reads evidence and does nothing else. The app layer refuses it
//! any capabilities while it reviews. Its verdicts are advice and must cite
//! evidence ianua recorded. A verdict comes only from an assignment that
//! stands. Only a person acts on it.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::agents::events::oversight::{
    AgentReviewEnded, AgentReviewVerdict, AgentReviewerAssigned,
};
use crate::domains::agents::identity::acting::ActingAgent;
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::authorization::permission::AgentAction;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::invisible::strip_invisible;
use crate::shared::validation::numeric::validate_count;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{
    AgentId, DelegationId, Ending, Human, Initiator, PrincipalRef, ReviewAssignmentId,
};

/// Where an agent's authority comes from: the parties at the roots of its
/// delegations, its owner, and every delegation in its lineage.
///
/// Each root keeps the person behind the account. So one person with two
/// accounts counts as one root. There is always at least one root, because
/// an agent always has an owner. A lineage naming nobody would look
/// independent of every other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewLineage {
    roots: Vec<Initiator>,
    delegations: Vec<DelegationId>,
}

impl ReviewLineage {
    /// A lineage from its root parties and delegations.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `roots` is empty.
    pub fn new(roots: Vec<Initiator>, delegations: Vec<DelegationId>) -> Result<Self, DomainError> {
        validate_count("roots", roots.len(), 1..=usize::MAX)?;
        Ok(Self { roots, delegations })
    }

    /// The parties at the roots of the agent's authority.
    #[must_use]
    pub fn roots(&self) -> &[Initiator] {
        &self.roots
    }

    /// Every delegation in the agent's lineage.
    #[must_use]
    pub fn delegations(&self) -> &[DelegationId] {
        &self.delegations
    }

    /// Whether this lineage and `other` share no root party, through any of
    /// a person's accounts, and no delegation.
    #[must_use]
    pub fn independent_of(&self, other: &Self) -> bool {
        let shared_root = self.roots.iter().any(|root| {
            other
                .roots
                .iter()
                .any(|theirs| root.is_same_party_as(theirs))
        });
        let shared_delegation = self
            .delegations
            .iter()
            .any(|delegation| other.delegations.contains(delegation));
        !shared_root && !shared_delegation
    }
}

/// Whether the agent asked to review holds any live delegation.
///
/// A reviewer reads evidence and acts on nothing. Ann could give the reviewer
/// a delegation and let it act on what it watches. So an agent holding one is
/// never assigned to review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewerHolds {
    /// It holds no live delegation.
    Nothing,
    /// It holds at least one live delegation.
    Delegations,
}

/// What a person asks for when assigning a reviewer.
pub struct AssignReviewerParams {
    /// The agent that will review.
    pub reviewer: AgentId,
    /// The agent it will review.
    pub reviewed: AgentId,
    /// The reviewer's lineage.
    pub reviewer_lineage: ReviewLineage,
    /// The reviewed agent's lineage.
    pub reviewed_lineage: ReviewLineage,
    /// Whether the reviewer holds any live delegation.
    pub reviewer_holds: ReviewerHolds,
}

/// The people who own the two agents of a review.
#[derive(Debug, Clone, Copy)]
pub struct ReviewOwners<'a> {
    /// The owner of the agent that will review.
    pub reviewer: &'a Human,
    /// The owner of the agent it will review.
    pub reviewed: &'a Human,
}

/// Persisted identifiers, timestamps and ending state for reconstitution.
#[derive(Clone, Copy)]
pub struct ReviewAssignmentRow {
    /// Unique identifier.
    pub id: ReviewAssignmentId,
    /// The reviewing agent.
    pub reviewer: AgentId,
    /// The reviewed agent.
    pub reviewed: AgentId,
    /// The person who assigned it.
    pub assigned_by: PrincipalRef,
    /// When it was assigned.
    pub assigned_at: OffsetDateTime,
    /// Whether it has ended, and when.
    pub ending: Ending,
}

/// A person's assignment of one agent to review another.
#[derive(Debug)]
pub struct ReviewAssignment<T: TenantScope> {
    id: ReviewAssignmentId,
    reviewer: AgentId,
    reviewed: AgentId,
    assigned_by: PrincipalRef,
    assigned_at: OffsetDateTime,
    /// Whether it has ended, and when.
    ending: Ending,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> ReviewAssignment<T> {
    /// Assigns a reviewer, the two agents owned by `owners`.
    ///
    /// The person assigning it must own each agent, or hold the agent
    /// permission to change agents. A reviewer reads everything the agent
    /// it watches did. Sam may only view agents. Without the first check,
    /// Sam assigns his agent to review Ann's and reads all her agent's
    /// evidence. A reviewer may hold no delegation while it reviews.
    /// Without the second check, Sam sets Bob's agent to review his own,
    /// and Bob's agent can be given nothing to do until someone ends it.
    ///
    /// The reviewer's owner differs from the reviewed agent's, or the
    /// lineages below are not independent. So only someone who may change
    /// agents assigns a reviewer.
    ///
    /// Raises `agents.reviewer_assigned`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person assigning it neither owns
    ///   the reviewed agent nor may change agents.
    /// - [`DomainError::Forbidden`] when they neither own the reviewer nor
    ///   may change agents.
    /// - [`DomainError::Validation`] when an agent would review itself.
    /// - [`DomainError::Forbidden`] when the reviewer holds a live
    ///   delegation.
    /// - [`DomainError::Validation`] when the two lineages share a root party
    ///   or a delegation.
    pub fn assign(
        control: &AgentControl<'_>,
        owners: ReviewOwners<'_>,
        params: &AssignReviewerParams,
    ) -> Result<Self, DomainError> {
        control.ensure_may(owners.reviewed, AgentAction::Update)?;
        control.ensure_may(owners.reviewer, AgentAction::Update)?;
        Self::ensure_may_review(params)?;
        let mut assignment = Self {
            id: ReviewAssignmentId::new(),
            reviewer: params.reviewer,
            reviewed: params.reviewed,
            assigned_by: control.by().principal(),
            assigned_at: crate::shared::clock::now(),
            ending: Ending::Ongoing,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        assignment.raised.raise(AgentReviewerAssigned {
            assignment_id: assignment.id,
            reviewer: assignment.reviewer,
            reviewed: assignment.reviewed,
            occurred_at: assignment.assigned_at,
        });
        Ok(assignment)
    }

    /// Refuses a reviewer that is the agent it would review, holds a live
    /// delegation, or answers to the same people as the reviewed agent.
    fn ensure_may_review(params: &AssignReviewerParams) -> Result<(), DomainError> {
        if params.reviewer == params.reviewed {
            return Err(DomainError::invalid(message!(
                "agents-an-agent-cannot-review-itself",
                "an agent cannot review itself"
            )));
        }
        if params.reviewer_holds == ReviewerHolds::Delegations {
            return Err(DomainError::forbidden(message!(
                "agents-an-agent-holding-a-delegation-cannot",
                "an agent holding a delegation cannot review another agent"
            )));
        }
        if !params
            .reviewer_lineage
            .independent_of(&params.reviewed_lineage)
        {
            return Err(DomainError::invalid(message!(
                "agents-a-reviewer-must-answer-to-different",
                "a reviewer must answer to different people and share no delegation with the agent it reviews"
            )));
        }
        Ok(())
    }

    /// Rebuilds a review assignment from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row was assigned by anyone
    ///   but a person.
    /// - [`DomainError::Infrastructure`] when the row has an agent review
    ///   itself.
    /// - [`DomainError::Infrastructure`] when it ended before it was assigned.
    pub fn reconstitute(row: ReviewAssignmentRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            reviewer: row.reviewer,
            reviewed: row.reviewed,
            assigned_by: row.assigned_by,
            assigned_at: row.assigned_at,
            ending: row.ending,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &ReviewAssignmentRow) -> Result<(), DomainError> {
        RowCheck::of("review assignment")
            .holds(
                is_person(&row.assigned_by),
                "assigned by something other than a person",
            )
            .holds(row.reviewer != row.reviewed, "an agent reviewing itself")
            .in_order_if(
                row.assigned_at,
                row.ending.ended_at(),
                "ended before it was assigned",
            )
            .finish()
    }

    /// Unique identifier.
    #[must_use]
    pub fn id(&self) -> &ReviewAssignmentId {
        &self.id
    }

    /// The reviewing agent.
    #[must_use]
    pub fn reviewer(&self) -> &AgentId {
        &self.reviewer
    }

    /// The reviewed agent.
    #[must_use]
    pub fn reviewed(&self) -> &AgentId {
        &self.reviewed
    }

    /// The person who assigned it.
    #[must_use]
    pub fn assigned_by(&self) -> &PrincipalRef {
        &self.assigned_by
    }

    /// When it was assigned.
    #[must_use]
    pub fn assigned_at(&self) -> OffsetDateTime {
        self.assigned_at
    }

    /// When a person ended it, if they did.
    #[must_use]
    pub fn ended_at(&self) -> Option<OffsetDateTime> {
        self.ending.ended_at()
    }

    /// Whether the assignment still stands.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.ending.has_ended()
    }

    /// Ends the assignment watching the agent `reviewed_owner` owns.
    ///
    /// The person who assigned it may end it, and so may someone allowed to
    /// change agents. The reviewed agent's owner may not, through any of
    /// their accounts. Sam's agent is under review. Without this check, Sam
    /// ends the review and nobody watches what his agent does next.
    ///
    /// Raises `agents.review_ended`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person ending it owns the
    ///   reviewed agent.
    /// - [`DomainError::Forbidden`] when they neither assigned it nor may
    ///   change agents.
    /// - [`DomainError::InvalidTransition`] when it already ended.
    pub fn end(
        &mut self,
        control: &AgentControl<'_>,
        reviewed_owner: &Human,
    ) -> Result<(), DomainError> {
        self.ensure_may_end(control, reviewed_owner)?;
        if self.ending.has_ended() {
            return Err(DomainError::invalid_transition(message!(
                "agents-the-review-assignment-already-ended",
                "the review assignment already ended"
            )));
        }
        let at = crate::shared::clock::now();
        self.ending = Ending::Ended { at };
        self.raised.raise(AgentReviewEnded {
            assignment_id: self.id,
            occurred_at: at,
        });
        Ok(())
    }

    /// Refuses the reviewed agent's owner, and anyone who neither assigned
    /// the review nor may change agents.
    fn ensure_may_end(
        &self,
        control: &AgentControl<'_>,
        reviewed_owner: &Human,
    ) -> Result<(), DomainError> {
        if control.by().is_same_person_as(reviewed_owner) {
            return Err(DomainError::forbidden(message!(
                "agents-the-owner-of-an-agent-under",
                "the owner of an agent under review cannot end its review"
            )));
        }
        if control.by().principal() == self.assigned_by || control.holds_agent(AgentAction::Update)
        {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "agents-only-the-person-who-assigned-a",
            "only the person who assigned a review, or someone allowed to change agents, ends it"
        )))
    }

    /// The verdict `reviewer` gives under this assignment.
    ///
    /// The reviewed agent comes from the assignment, never from the reviewer.
    /// Mallory's agent reviews Bob's agent. Without this check, it files a
    /// verdict about Ann's agent asking for it to be contained. Whether the
    /// cited records belong to the reviewed agent is checked where they are
    /// read.
    ///
    /// Raises `agents.review_verdict`. The assignment itself does not change,
    /// so it is not saved: the verdict is taken from it once the cited
    /// records are found to be the reviewed agent's, and dropped with it
    /// otherwise.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the assignment has ended.
    /// - [`DomainError::Forbidden`] when `reviewer` signed in as an agent
    ///   other than the one this assignment names as reviewer.
    pub fn verdict(
        &mut self,
        reviewer: &ActingAgent,
        params: VerdictParams,
    ) -> Result<ReviewVerdict, DomainError> {
        if !self.is_active() {
            return Err(DomainError::forbidden(message!(
                "agents-a-verdict-comes-only-from-a",
                "a verdict comes only from a review that still stands"
            )));
        }
        if *reviewer.agent() != self.reviewer {
            return Err(DomainError::forbidden(message!(
                "agents-only-the-assigned-reviewer-gives-a",
                "only the assigned reviewer gives a verdict on this review"
            )));
        }
        let verdict = ReviewVerdict {
            assignment: self.id,
            reviewer: self.reviewer,
            reviewed: self.reviewed,
            kind: params.kind,
            cited: params.cited,
            note: params.note,
        };
        self.raised.raise(AgentReviewVerdict {
            reviewed: verdict.reviewed,
            kind: verdict.kind,
            cited: verdict.cited.clone(),
            note: verdict.note.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(verdict)
    }
}

impl<T: TenantScope> Raises for ReviewAssignment<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for ReviewAssignment<T> {
    type Id = ReviewAssignmentId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.assigned_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.ending.ended_at().unwrap_or(self.assigned_at)
    }
}

/// What a reviewer concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictKind {
    /// Something in the evidence deserves a person's attention.
    Concern,
    /// The reviewer believes the agent should be contained. A person decides.
    ContainmentRequested,
}

impl VerdictKind {
    /// The stored and wire form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Concern => "concern",
            Self::ContainmentRequested => "containment_requested",
        }
    }

    /// Parses the wire form.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the kind is unknown.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "concern" => Ok(Self::Concern),
            "containment_requested" => Ok(Self::ContainmentRequested),
            other => Err(DomainError::invalid(message!(
                "agents-unknown-verdict-kind",
                format!("unknown verdict kind: {other}")
            ))),
        }
    }
}

text_value! {
    /// A reviewer's note, with invisible characters removed. It holds 1 to
    /// 2000 characters.
    pub struct VerdictNote;
}

impl TextValue for VerdictNote {
    const FIELD: &'static str = "note";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.not_empty().char_length(1..=Self::MAX_LEN)
    }

    fn normalized(value: String) -> String {
        strip_invisible(&value)
    }
}

impl VerdictNote {
    /// Longest note accepted.
    const MAX_LEN: usize = 2000;
}

/// The evidence record numbers a verdict cites. A claim with no evidence is
/// not a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CitedEvidence(Vec<i64>);

impl CitedEvidence {
    /// The most records one verdict may cite.
    const MAX: usize = 100;

    /// Cites `seqs`, each once.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when none are cited.
    /// - [`DomainError::Validation`] when more than 100 distinct records are
    ///   cited.
    pub fn new(mut seqs: Vec<i64>) -> Result<Self, DomainError> {
        seqs.sort_unstable();
        seqs.dedup();
        validate_count("evidence", seqs.len(), 1..=Self::MAX)?;
        Ok(Self(seqs))
    }

    /// The cited record numbers, ascending.
    #[must_use]
    pub fn seqs(&self) -> &[i64] {
        &self.0
    }
}

/// What a reviewer writes in a verdict.
pub struct VerdictParams {
    /// What it concluded.
    pub kind: VerdictKind,
    /// The evidence records it cites.
    pub cited: CitedEvidence,
    /// The reviewer's explanation accompanying the cited evidence.
    pub note: VerdictNote,
}

/// A reviewer's verdict, made only by [`ReviewAssignment::verdict`].
///
/// It names the assignment it was given under. The reviewer and the
/// reviewed agent come from that assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewVerdict {
    assignment: ReviewAssignmentId,
    reviewer: AgentId,
    reviewed: AgentId,
    kind: VerdictKind,
    cited: CitedEvidence,
    note: VerdictNote,
}

impl ReviewVerdict {
    /// The assignment it was given under.
    #[must_use]
    pub fn assignment(&self) -> &ReviewAssignmentId {
        &self.assignment
    }

    /// The reviewing agent.
    #[must_use]
    pub fn reviewer(&self) -> &AgentId {
        &self.reviewer
    }

    /// The reviewed agent.
    #[must_use]
    pub fn reviewed(&self) -> &AgentId {
        &self.reviewed
    }

    /// What the reviewer concluded.
    #[must_use]
    pub fn kind(&self) -> VerdictKind {
        self.kind
    }

    /// The evidence records it cites.
    #[must_use]
    pub fn cited(&self) -> &CitedEvidence {
        &self.cited
    }

    /// The reviewer's note.
    #[must_use]
    pub fn note(&self) -> &VerdictNote {
        &self.note
    }
}

/// Whether `principal` is a person. Only people decide which agent watches
/// which, never an agent or a machine caller.
fn is_person(principal: &PrincipalRef) -> bool {
    matches!(principal, PrincipalRef::User(_) | PrincipalRef::OrgUser(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::SystemPermission;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::assumed_authority;
    use crate::test_support::events::raised_names;
    use crate::types::{HumanAccount, PersonKey, TenantId, UserId};

    fn person() -> PrincipalRef {
        PrincipalRef::User(UserId::new())
    }

    fn human(address: &str) -> Human {
        Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new(address).unwrap(),
        )
    }

    fn someone(address: &str) -> Initiator {
        Initiator::Human(human(address))
    }

    fn holding<'a>(by: &'a Human, system: &'a [SystemPermission]) -> AgentControl<'a> {
        AgentControl::new(assumed_authority(by, TenantId::new(), system, &[]))
    }

    const UPDATE: [SystemPermission; 1] = [SystemPermission::Agents(AgentAction::Update)];

    /// The reviewer owned by `reviewer`, the reviewed agent by `reviewed`.
    fn owned<'a>(reviewer: &'a Human, reviewed: &'a Human) -> ReviewOwners<'a> {
        ReviewOwners { reviewer, reviewed }
    }

    /// `params` assigned by Bob, who may change agents: Rita's agent to
    /// review Ann's.
    fn assigned(
        params: &AssignReviewerParams,
    ) -> Result<ReviewAssignment<ResolvedTenant>, DomainError> {
        let (ann, bob, rita) = (
            human("ann@corp.test"),
            human("bob@corp.test"),
            human("rita@corp.test"),
        );
        ReviewAssignment::assign(&holding(&bob, &UPDATE), owned(&rita, &ann), params)
    }

    fn verdict_params() -> VerdictParams {
        VerdictParams {
            kind: VerdictKind::ContainmentRequested,
            cited: CitedEvidence::new(vec![1]).unwrap(),
            note: VerdictNote::new("it read the payroll").unwrap(),
        }
    }

    fn lineage(root: Initiator, delegation: DelegationId) -> ReviewLineage {
        ReviewLineage::new(vec![root], vec![delegation]).unwrap()
    }

    fn any_lineage() -> ReviewLineage {
        lineage(Initiator::Agent(AgentId::new()), DelegationId::new())
    }

    fn params(reviewer: ReviewLineage, reviewed: ReviewLineage) -> AssignReviewerParams {
        AssignReviewerParams {
            reviewer: AgentId::new(),
            reviewed: AgentId::new(),
            reviewer_lineage: reviewer,
            reviewed_lineage: reviewed,
            reviewer_holds: ReviewerHolds::Nothing,
        }
    }

    /// An agent holding a live delegation cannot be assigned to review
    /// another agent, even with independent lineages.
    #[test]
    fn an_agent_holding_a_delegation_cannot_review() {
        let result = assigned(&AssignReviewerParams {
            reviewer_holds: ReviewerHolds::Delegations,
            ..params(
                lineage(someone("ann@corp.test"), DelegationId::new()),
                lineage(someone("bob@corp.test"), DelegationId::new()),
            )
        });

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Ann is behind the reviewer and Bob behind the reviewed agent, each
    /// through a delegation of their own. The assignment is accepted.
    #[test]
    fn independent_lineages_may_review() {
        let result = assigned(&params(
            lineage(someone("ann@corp.test"), DelegationId::new()),
            lineage(someone("bob@corp.test"), DelegationId::new()),
        ));

        assert!(result.is_ok());
    }

    /// A review assignment is refused when both lineages answer to the
    /// same person through different accounts.
    #[test]
    fn a_reviewer_answering_to_the_same_person_is_refused() {
        let result = assigned(&params(
            lineage(someone("boss@corp.test"), DelegationId::new()),
            lineage(someone("boss@corp.test"), DelegationId::new()),
        ));

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A shared delegation prevents a review assignment even when the
    /// reviewer and reviewed agent have different people at their roots.
    #[test]
    fn a_reviewer_sharing_a_delegation_is_refused() {
        let shared = DelegationId::new();

        let result = assigned(&params(
            lineage(someone("ann@corp.test"), shared),
            lineage(someone("bob@corp.test"), shared),
        ));

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// An agent assigned to review itself is refused, because it would
    /// report nothing against itself.
    #[test]
    fn an_agent_cannot_review_itself() {
        let agent = AgentId::new();

        let itself = assigned(&AssignReviewerParams {
            reviewer: agent,
            reviewed: agent,
            ..params(any_lineage(), any_lineage())
        });

        assert!(matches!(itself, Err(DomainError::Validation(_))));
    }

    /// Owning the reviewer and holding viewing rights does not authorize
    /// assigning it to another person's agent. A caller with update rights
    /// can assign it and is recorded as the assigner.
    #[test]
    fn only_the_owner_or_someone_changing_agents_assigns_a_reviewer() {
        let (ann, sam, bob) = (
            human("ann@corp.test"),
            human("sam@corp.test"),
            human("bob@corp.test"),
        );
        let view = [SystemPermission::Agents(AgentAction::View)];

        let by_sam = ReviewAssignment::<ResolvedTenant>::assign(
            &holding(&sam, &view),
            owned(&sam, &ann),
            &params(any_lineage(), any_lineage()),
        );
        let by_bob = ReviewAssignment::<ResolvedTenant>::assign(
            &holding(&bob, &UPDATE),
            owned(&sam, &ann),
            &params(any_lineage(), any_lineage()),
        )
        .unwrap();

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert_eq!(by_bob.assigned_by(), &bob.principal());
    }

    /// Owning the reviewed agent alone does not authorize assigning
    /// another person's agent as its reviewer; the assignment is forbidden.
    #[test]
    fn assigning_a_reviewer_takes_a_say_over_the_reviewer_too() {
        let (sam, bob) = (human("sam@corp.test"), human("bob@corp.test"));

        let result = ReviewAssignment::<ResolvedTenant>::assign(
            &holding(&sam, &[]),
            owned(&bob, &sam),
            &params(any_lineage(), any_lineage()),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Bob, who may change agents, ends an assignment and it is no longer
    /// active. Ending it again fails as an invalid transition, so the first
    /// end time stays.
    #[test]
    fn an_ended_assignment_cannot_end_again() {
        let (ann, bob) = (human("ann@corp.test"), human("bob@corp.test"));
        let update = [SystemPermission::Agents(AgentAction::Update)];
        let mut assignment = assigned(&params(any_lineage(), any_lineage())).unwrap();
        assignment.end(&holding(&bob, &update), &ann).unwrap();

        assert!(!assignment.is_active());
        assert!(matches!(
            assignment.end(&holding(&bob, &update), &ann),
            Err(DomainError::InvalidTransition(_))
        ));
    }

    /// The reviewed agent's owner cannot end its review through another
    /// account, even with update rights. A viewer who did not assign it is
    /// also refused, and the review remains active.
    #[test]
    fn the_reviewed_agents_owner_cannot_end_its_review() {
        let sam = human("sam@corp.test");
        let sam_through_org = Human::new(
            HumanAccount::OrgUser(crate::types::OrgUserId::new()),
            PersonKey::new("sam@corp.test").unwrap(),
        );
        let (bob, carol) = (human("bob@corp.test"), human("carol@corp.test"));
        let view = [SystemPermission::Agents(AgentAction::View)];
        let mut assignment = ReviewAssignment::<ResolvedTenant>::assign(
            &holding(&bob, &UPDATE),
            owned(&carol, &sam),
            &params(any_lineage(), any_lineage()),
        )
        .unwrap();

        let by_owner = assignment.end(&holding(&sam_through_org, &UPDATE), &sam);
        let by_carol = assignment.end(&holding(&carol, &view), &sam);

        assert!(matches!(by_owner, Err(DomainError::Forbidden(_))));
        assert!(matches!(by_carol, Err(DomainError::Forbidden(_))));
        assert!(assignment.is_active());
    }

    /// Ann assigns a reviewer to Bob's agent while holding the right to
    /// change agents, and later ends it herself with no permission left.
    /// The person who assigned a review may end it.
    #[test]
    fn the_person_who_assigned_a_review_may_end_it() {
        let (ann, bob, rita) = (
            human("ann@corp.test"),
            human("bob@corp.test"),
            human("rita@corp.test"),
        );
        let mut assignment = ReviewAssignment::<ResolvedTenant>::assign(
            &holding(&ann, &UPDATE),
            owned(&rita, &bob),
            &params(any_lineage(), any_lineage()),
        )
        .unwrap();

        assert!(assignment.end(&holding(&ann, &[]), &bob).is_ok());
    }

    /// Agent R reviews agent S. R's verdict names S and the assignment, as
    /// the assignment says, whatever R might claim.
    #[test]
    fn a_verdict_names_the_agent_its_assignment_reviews() {
        let mut assignment = assigned(&params(any_lineage(), any_lineage())).unwrap();

        let verdict = assignment
            .verdict(&signed_in_as(assignment.reviewer()), verdict_params())
            .unwrap();

        assert_eq!(verdict.reviewed(), assignment.reviewed());
        assert_eq!(verdict.assignment(), assignment.id());
    }

    /// `agent`, signed in as itself.
    fn signed_in_as(agent: &AgentId) -> ActingAgent {
        ActingAgent::assumed(*agent)
    }

    /// An unassigned agent cannot file a verdict through a review, and
    /// even its assigned reviewer is refused once the review has ended.
    #[test]
    fn a_verdict_needs_the_assigned_reviewer_and_a_standing_review() {
        let (ann, bob) = (human("ann@corp.test"), human("bob@corp.test"));
        let update = [SystemPermission::Agents(AgentAction::Update)];
        let mut assignment = assigned(&params(any_lineage(), any_lineage())).unwrap();
        let mallorys_agent = ActingAgent::assumed(AgentId::new());

        let by_another = assignment.verdict(&mallorys_agent, verdict_params());
        assignment.end(&holding(&bob, &update), &ann).unwrap();
        let after_the_end =
            assignment.verdict(&signed_in_as(assignment.reviewer()), verdict_params());

        assert!(matches!(by_another, Err(DomainError::Forbidden(_))));
        assert!(matches!(after_the_end, Err(DomainError::Forbidden(_))));
    }

    /// Citing no records is refused, and so is citing 101. Citing 3, 1 and 3
    /// keeps 1 and 3, in order.
    #[test]
    fn a_verdict_must_cite_evidence() {
        assert!(CitedEvidence::new(Vec::new()).is_err());
        assert!(CitedEvidence::new((0..101).collect()).is_err());
        assert_eq!(CitedEvidence::new(vec![3, 1, 3]).unwrap().seqs(), [1, 3]);
    }

    /// A verdict note loses its right-to-left override character. A note
    /// containing only a zero-width space becomes empty and is refused.
    #[test]
    fn a_note_is_cleaned_of_invisible_characters() {
        let note = VerdictNote::new("looks fine\u{202E}nruter").unwrap();

        assert_eq!(note.as_str(), "looks finenruter");
        assert!(VerdictNote::new("\u{200B}").is_err());
    }

    /// Both verdict kinds parse back from their wire form. `approve` is
    /// refused, since a reviewer only advises.
    #[test]
    fn verdict_kinds_round_trip() {
        for kind in [VerdictKind::Concern, VerdictKind::ContainmentRequested] {
            assert_eq!(VerdictKind::parse(kind.as_str()).unwrap(), kind);
        }
        assert!(VerdictKind::parse("approve").is_err());
    }

    /// A stored assignment names the same agent as reviewer and reviewed. The
    /// row is refused as corrupt.
    #[test]
    fn a_stored_review_of_an_agent_by_itself_is_refused() {
        let agent = AgentId::new();

        let review = ReviewAssignment::<ResolvedTenant>::reconstitute(ReviewAssignmentRow {
            id: ReviewAssignmentId::new(),
            reviewer: agent,
            reviewed: agent,
            assigned_by: person(),
            assigned_at: crate::shared::clock::now(),
            ending: Ending::Ongoing,
        });

        assert!(refused_as_corrupt(&review));
    }

    /// An assignment and what it raised since it was made, the assignment
    /// taken out first.
    fn fresh_assignment() -> ReviewAssignment<ResolvedTenant> {
        let mut assignment = assigned(&params(any_lineage(), any_lineage())).unwrap();
        raised_names(&mut assignment);
        assignment
    }

    /// Bob assigns Rita's agent to review Ann's. The assignment is raised.
    #[test]
    fn assigning_raises_agents_reviewer_assigned() {
        let mut assignment = assigned(&params(any_lineage(), any_lineage())).unwrap();

        assert_eq!(raised_names(&mut assignment), ["agents.reviewer_assigned"]);
    }

    /// Bob ends the review he assigned. The end is raised.
    #[test]
    fn ending_raises_agents_review_ended() {
        let (ann, bob) = (human("ann@corp.test"), human("bob@corp.test"));
        let mut assignment = fresh_assignment();

        assignment.end(&holding(&bob, &UPDATE), &ann).unwrap();

        assert_eq!(raised_names(&mut assignment), ["agents.review_ended"]);
    }

    /// The reviewer files a verdict. The verdict is raised on the
    /// assignment, which does not otherwise change.
    #[test]
    fn a_verdict_raises_agents_review_verdict() {
        let mut assignment = fresh_assignment();

        assignment
            .verdict(&signed_in_as(assignment.reviewer()), verdict_params())
            .unwrap();

        assert_eq!(raised_names(&mut assignment), ["agents.review_verdict"]);
        assert!(assignment.is_active());
    }

    /// A verdict from an agent other than the assigned reviewer is refused
    /// without raising any events.
    #[test]
    fn a_refused_verdict_raises_nothing() {
        let mut assignment = fresh_assignment();

        let refused = assignment.verdict(&ActingAgent::assumed(AgentId::new()), verdict_params());

        assert!(refused.is_err());
        assert!(raised_names(&mut assignment).is_empty());
    }

    /// A standing assignment is read back from storage. Loading it is no
    /// change, so it has raised nothing.
    #[test]
    fn an_assignment_read_back_from_storage_has_raised_nothing() {
        let mut review = ReviewAssignment::<ResolvedTenant>::reconstitute(ReviewAssignmentRow {
            id: ReviewAssignmentId::new(),
            reviewer: AgentId::new(),
            reviewed: AgentId::new(),
            assigned_by: person(),
            assigned_at: crate::shared::clock::now(),
            ending: Ending::Ongoing,
        })
        .unwrap();

        assert!(raised_names(&mut review).is_empty());
    }
}
