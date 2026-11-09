//! A workflow as its owner designs it: one version of a graph and the
//! trigger that starts it.
//!
//! A version is drafted, published, then archived. Only a draft is edited.
//! Executions run a published version, so it never changes under them. The
//! next version starts from a copy, made by
//! [`next_draft`](Workflow::next_draft). Every version shares one
//! [`WorkflowId`], and executions name the version they ran.
//!
//! Only a person designs, edits or publishes a version. Each of those takes
//! a [`Human`], so no agent can decide which steps run. The person who
//! published a version is kept, because whatever its trigger starts acts
//! for them.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::permission::WorkflowAction;
use crate::domains::workflows::control::WorkflowControl;
use crate::domains::workflows::design::authors::Authors;
use crate::domains::workflows::design::graph::WorkflowGraph;
use crate::domains::workflows::design::publish_rules::{
    ensure_before_decides, ensure_checks_are_of_other_agents, ensure_code_runnable,
    ensure_guardrails_read_text, ensure_high_risk_actions_approved, ensure_item_approvals_in_loops,
    ensure_networked_code_approved, ensure_paths_name_earlier_steps, ensure_trigger_event_offered,
};
use crate::domains::workflows::events::{
    VersionRef, WorkflowCreated, WorkflowVersionArchived, WorkflowVersionDrafted,
    WorkflowVersionPublished,
};
use crate::domains::workflows::integration::risk_override::TenantOperation;
use crate::domains::workflows::triggers::Trigger;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::types::{EventLabel, EventVisibility, Human, Label, Text, WorkflowId};

mod edits;
mod flow;
mod hold;
mod layout;
mod row;
mod version;

pub use flow::*;
pub use hold::*;
pub use layout::*;
pub use row::*;
pub use version::*;

/// One version of a workflow: a graph of steps and the trigger that starts
/// it.
///
/// People design it. An agent may run a workflow's steps but never write
/// one.
#[derive(Debug, Clone)]
pub struct Workflow<T: TenantScope> {
    id: WorkflowId,
    version: u32,
    name: Label,
    description: Option<Text>,
    graph: WorkflowGraph,
    layout: CanvasLayout,
    trigger: Trigger,
    run_limit: RunLimit,
    failure_alert: FailureAlert,
    status: WorkflowStatus,
    created_by: Human,
    edited_by: Human,
    authors: Authors,
    publication: Publication,
    origin: WorkflowOrigin,
    hold: Hold,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// What a fresh draft starts from: the first version's design, or the
/// version it follows.
struct DraftStart {
    id: WorkflowId,
    version: u32,
    name: Label,
    description: Option<Text>,
    graph: WorkflowGraph,
    layout: CanvasLayout,
    trigger: Trigger,
    run_limit: RunLimit,
    failure_alert: FailureAlert,
    by: Human,
    authors: Authors,
}

impl<T: TenantScope> Workflow<T> {
    /// Drafts the first version of a new workflow, designed by the person
    /// `by` names. Raises `workflows.workflow_created`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they may not create workflows.
    /// - [`DomainError::Validation`] when the layout places a step the
    ///   graph does not have.
    pub fn create(
        params: CreateWorkflowParams,
        by: &WorkflowControl<'_>,
    ) -> Result<Self, DomainError> {
        by.ensure_may(WorkflowAction::Create)?;
        params.layout.ensure_fits(&params.graph)?;
        let designer = by.by();
        let mut workflow = Self::fresh_draft(DraftStart {
            id: WorkflowId::new(),
            version: 1,
            name: params.name,
            description: params.description,
            graph: params.graph,
            layout: params.layout,
            trigger: params.trigger,
            run_limit: params.run_limit,
            failure_alert: params.failure_alert,
            by: designer.clone(),
            authors: Authors::first(designer),
        });
        workflow.raised.raise(WorkflowCreated {
            version: workflow.version_ref(),
            occurred_at: workflow.created_at,
        });
        Ok(workflow)
    }

    /// A draft started now as `start` says, designed by a person and held
    /// by nothing.
    fn fresh_draft(start: DraftStart) -> Self {
        let now = crate::shared::clock::now();
        Self {
            id: start.id,
            version: start.version,
            name: start.name,
            description: start.description,
            graph: start.graph,
            layout: start.layout,
            trigger: start.trigger,
            run_limit: start.run_limit,
            failure_alert: start.failure_alert,
            status: WorkflowStatus::Draft,
            created_by: start.by.clone(),
            edited_by: start.by,
            authors: start.authors,
            publication: Publication::Unpublished,
            origin: WorkflowOrigin::Designed,
            hold: Hold::Clear,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }

    /// Rebuilds a version from storage.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] for a version below one, changes before
    /// drafting, contradictory publication dates, or missing drafter/editor/publisher
    /// authorship. Published graphs require approvals and reachable reads; agent flows
    /// must be a single published manual version of agent runs and connecting steps.
    /// Layout entries must name graph steps.
    pub fn reconstitute(row: WorkflowRow) -> Result<Self, DomainError> {
        ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            version: row.version,
            name: row.name,
            description: row.description,
            graph: row.graph,
            layout: row.layout,
            trigger: row.trigger,
            run_limit: row.run_limit,
            failure_alert: row.failure_alert,
            status: row.status,
            created_by: row.created_by,
            edited_by: row.edited_by,
            authors: row.authors,
            publication: row.publication,
            origin: row.origin,
            hold: row.hold,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The next version: a draft with this one's name, description, graph,
    /// layout, trigger, run limit and failure alert, designed by `by`. This
    /// version is left exactly as it was.
    /// The new draft raises `workflows.version_drafted`.
    ///
    /// Its authors are this version's authors and `by`. The steps it copies
    /// are still the work of the people who wrote them.
    ///
    /// Version numbers stay unique only when every draft follows the latest
    /// version. Storage keeps each workflow and version pair unique, so a
    /// second draft from the same version is refused there.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not draft workflows.
    /// - [`DomainError::Conflict`] when this is a flow, which has one
    ///   version only.
    /// - [`DomainError::Conflict`] when this version is still a draft. A
    ///   draft is edited, not followed.
    /// - [`DomainError::Conflict`] when no version number is left.
    pub fn next_draft(&self, control: &WorkflowControl<'_>) -> Result<Self, DomainError> {
        control.ensure_may(WorkflowAction::Create)?;
        let version = self.next_version()?;
        let mut authors = self.authors.clone();
        authors.add(control.by());
        let mut draft = Self::fresh_draft(DraftStart {
            id: self.id,
            version,
            name: self.name.clone(),
            description: self.description.clone(),
            graph: self.graph.clone(),
            layout: self.layout.clone(),
            trigger: self.trigger.clone(),
            run_limit: self.run_limit,
            failure_alert: self.failure_alert,
            by: control.by().clone(),
            authors,
        });
        draft.raised.raise(WorkflowVersionDrafted {
            version: draft.version_ref(),
            occurred_at: draft.created_at,
        });
        Ok(draft)
    }

    /// The number the version after this one takes.
    fn next_version(&self) -> Result<u32, DomainError> {
        if let WorkflowOrigin::Flow(_) = self.origin {
            return Err(DomainError::conflict(message!(
                "workflows-a-flow-has-one-version-and",
                "a flow has one version and is never redrafted"
            )));
        }
        if self.status == WorkflowStatus::Draft {
            return Err(DomainError::conflict(message!(
                "workflows-a-draft-is-edited-not-followed",
                "a draft is edited, not followed by another draft"
            )));
        }
        self.version.checked_add(1).ok_or_else(|| {
            DomainError::conflict(message!(
                "workflows-this-workflow-has-no-version-number",
                "this workflow has no version number left"
            ))
        })
    }

    /// `by` publishes a draft.
    ///
    /// Every action step must fit the operation its integration offers now.
    /// Every high-risk action must have an approval right before it.
    /// `offered` holds the operations the graph uses as the tenant treats
    /// them: the catalog's specs raised by the tenant's overrides. An
    /// operation missing from it is no longer offered, and the draft is not
    /// published. Whatever the trigger starts from now on acts for `by`.
    ///
    /// `facts.sees` is what `by` may see now. A workflow on an event they
    /// may not see is refused. Sam may not read signing key events. Without
    /// this, he publishes a workflow on a key event that posts the event's
    /// data to his server.
    ///
    /// `reviewed` is the revision `by` looked at. Sam edits Ann's draft so a
    /// step pays him through her account, just before she publishes. Every
    /// run the trigger starts would then pay Sam with Ann's authority. So a
    /// draft that changed since `by` reviewed it is refused, and they look
    /// again.
    ///
    /// `replaces` is the version published now, which this one takes over
    /// from. It is archived in the same step, so only one version of a
    /// workflow is ever in service. With two, a schedule would fire both and
    /// the invoices would be paid twice.
    ///
    /// Raises `workflows.version_published`. The version it replaces raises
    /// `workflows.version_archived`, so its events are taken first.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Forbidden`] without publish rights or event visibility;
    /// [`DomainError::Conflict`] for a stale review or replacement other than an earlier
    /// published version of this workflow; or [`DomainError::InvalidTransition`] unless draft.
    /// Returns [`DomainError::Validation`] for unavailable or mismatched operations,
    /// unrunnable sandboxes, unreachable reads, guardrails pointing at no text, or missing
    /// high-risk/network approvals.
    pub fn publish(
        &mut self,
        by: &WorkflowControl<'_>,
        reviewed: Revision,
        replaces: Replaces<'_, T>,
        facts: PublishFacts<'_, impl EventVisibility>,
    ) -> Result<(), DomainError> {
        by.ensure_may(WorkflowAction::Update)?;
        if reviewed != self.revision() {
            return Err(DomainError::conflict(message!(
                "workflows-the-draft-changed-since-it-was",
                "the draft changed since it was reviewed; look at it again before publishing"
            )));
        }
        let published = self.status.try_transition(WorkflowStatus::Published)?;
        replaces.ensure_earlier_than(self.id, self.version)?;
        self.ensure_trigger_visible(facts.sees)?;
        ensure_trigger_event_offered(&self.trigger, facts.events)?;
        self.ensure_actions_offered(facts.offered)?;
        ensure_code_runnable(&self.graph, facts.runnable)?;
        ensure_paths_name_earlier_steps(&self.graph)?;
        ensure_checks_are_of_other_agents(&self.graph)?;
        ensure_guardrails_read_text(&self.graph)?;
        ensure_high_risk_actions_approved(&self.graph)?;
        ensure_item_approvals_in_loops(&self.graph)?;
        ensure_networked_code_approved(&self.graph, facts.runnable)?;
        ensure_before_decides(&self.trigger, &self.graph)?;
        replaces.retire()?;
        self.status = published;
        self.publication = Publication::PublishedBy(by.by().clone());
        self.record_edit(by.by());
        self.raised.raise(WorkflowVersionPublished {
            version: self.version_ref(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    fn ensure_trigger_visible(&self, sees: &impl EventVisibility) -> Result<(), DomainError> {
        let Trigger::Event(on) = &self.trigger else {
            return Ok(());
        };
        if !sees.may_see(&on.event()) {
            return Err(DomainError::forbidden(message!(
                "workflows-a-workflow-starts-only-on-events",
                "a workflow starts only on events its publisher may see"
            )));
        }
        Ok(())
    }

    fn ensure_actions_offered(&self, offered: &[TenantOperation]) -> Result<(), DomainError> {
        self.graph.action_steps().try_for_each(|(_, step)| {
            let spec = offered.iter().map(TenantOperation::spec).find(|spec| {
                spec.integration() == step.integration() && spec.operation() == step.operation()
            });
            let Some(spec) = spec else {
                return Err(DomainError::invalid(message!(
                    "workflows-the-operation-is-not-offered-any-more",
                    format!(
                        "the operation {}.{} is not offered any more",
                        step.integration(),
                        step.operation()
                    )
                )));
            };
            step.ensure_fits(spec)
        })
    }

    /// Takes a version out of service for good, for someone who may delete
    /// workflows.
    ///
    /// Archiving is how a workflow is removed: it never runs again and its
    /// schedules stop. Sam may edit workflows. Without this, he archives the
    /// nightly offboarding run, and leavers keep their access. Raises
    /// `workflows.version_archived`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not delete workflows.
    /// - [`DomainError::InvalidTransition`] when it is already archived.
    pub fn archive(&mut self, by: &WorkflowControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(WorkflowAction::Delete)?;
        self.move_to_archived()
    }

    /// Archives this version because a newer one took over. The person
    /// publishing the newer one was already checked.
    pub(super) fn retire_for_successor(&mut self) -> Result<(), DomainError> {
        self.move_to_archived()
    }

    /// Takes this version out of service and raises
    /// `workflows.version_archived`.
    fn move_to_archived(&mut self) -> Result<(), DomainError> {
        self.status = self.status.try_transition(WorkflowStatus::Archived)?;
        self.touch();
        self.raised.raise(WorkflowVersionArchived {
            version: self.version_ref(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// This version as the audit trail names it, with its name as it is now.
    pub(crate) fn version_ref(&self) -> VersionRef {
        VersionRef {
            workflow_id: self.id,
            version: self.version,
            label: EventLabel::of(self.name.as_str()),
        }
    }

    fn ensure_draft(&self) -> Result<(), DomainError> {
        if self.status != WorkflowStatus::Draft {
            return Err(DomainError::conflict(message!(
                "workflows-this-version-is-and-cannot-be",
                format!(
                    "this version is {} and cannot be edited; draft the next one",
                    self.status.as_str()
                )
            )));
        }
        Ok(())
    }

    /// Adds the editor to the authors and advances the revision used by publication checks.
    fn record_edit(&mut self, by: &Human) {
        self.edited_by = by.clone();
        self.authors.add(by);
        self.touch();
    }

    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }

    /// The revision of this version as it stands now. A publisher hands it
    /// back to say which revision they reviewed.
    #[must_use]
    pub fn revision(&self) -> Revision {
        Revision::reviewed(self.updated_at)
    }

    /// The workflow every version belongs to.
    #[must_use]
    pub fn id(&self) -> &WorkflowId {
        &self.id
    }

    /// The positive sequence ordering this workflow's revisions.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The display label used to identify this revision in lists and records.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// What it does, as its authors describe it.
    #[must_use]
    pub fn description(&self) -> Option<&Text> {
        self.description.as_ref()
    }

    /// Its steps and edges.
    #[must_use]
    pub fn graph(&self) -> &WorkflowGraph {
        &self.graph
    }

    /// Where its steps sit on the canvas.
    #[must_use]
    pub fn layout(&self) -> &CanvasLayout {
        &self.layout
    }

    /// Who is told when one of its runs fails.
    #[must_use]
    pub fn failure_alert(&self) -> FailureAlert {
        self.failure_alert
    }

    /// What starts it.
    #[must_use]
    pub fn trigger(&self) -> &Trigger {
        &self.trigger
    }

    /// How long one execution may run.
    #[must_use]
    pub fn run_limit(&self) -> RunLimit {
        self.run_limit
    }

    /// Where it stands.
    #[must_use]
    pub fn status(&self) -> WorkflowStatus {
        self.status
    }

    /// The person who drafted this version.
    #[must_use]
    pub fn created_by(&self) -> &Human {
        &self.created_by
    }

    /// The person who last edited it.
    #[must_use]
    pub fn edited_by(&self) -> &Human {
        &self.edited_by
    }

    /// Whether it was published, and by whom.
    #[must_use]
    pub fn publication(&self) -> &Publication {
        &self.publication
    }

    /// Everyone who drafted, edited or published it, or a version it was
    /// copied from.
    #[must_use]
    pub fn authors(&self) -> &Authors {
        &self.authors
    }
}

impl<T: TenantScope> Raises for Workflow<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for Workflow<T> {
    type Id = WorkflowId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::domains::workflows::design::graph::Edge;
    use crate::domains::workflows::design::node::{
        Join, Mapping, Node, NodeKey, NodeKind, Port, Source,
    };
    use crate::domains::workflows::execution::tests::fixtures::{
        SeesAll, agent_step, ann, append_row, approval_of, bob, cid, code, condition, draft,
        draft_with, each_running, edge, field, holding_only, managing, node, offered, path,
        publish_as, spec_of, transform, viewing, wait,
    };
    use crate::domains::workflows::integration::{ActionAccount, ActionStep, OperationSpec};
    use crate::domains::workflows::triggers::EventTrigger;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::event_type::{CryptoEvent, IdentityEvent};
    use crate::types::{ActionClass, AgentId, DeclaredAction, EventType, IntegrationAccountId};

    fn payment() -> OperationSpec {
        spec_of(ActionClass::Financial, DataClassLevel::Internal)
    }

    fn pay(join: Join) -> Node {
        let step = ActionStep::new(
            &payment(),
            ActionAccount::Account(IntegrationAccountId::new()),
            Mapping::new(vec![(field("values"), Source::Input(path("trigger")))]).unwrap(),
        )
        .unwrap();
        node("pay", NodeKind::Action(step), join)
    }

    fn approval_for(class: DeclaredAction) -> Node {
        approval_of("ok", class)
    }

    fn financial_approval() -> Node {
        approval_for(DeclaredAction::Declared(ActionClass::Financial))
    }

    fn publishing(nodes: Vec<Node>, edges: Vec<Edge>) -> Result<(), DomainError> {
        publish_as(
            &mut draft(nodes, edges),
            &ann(),
            &[offered(payment())],
            &SeesAll,
        )
    }

    fn stored(workflow: &Workflow<ResolvedTenant>) -> WorkflowRow {
        WorkflowRow {
            id: workflow.id,
            version: workflow.version,
            name: workflow.name.clone(),
            description: workflow.description.clone(),
            graph: workflow.graph.clone(),
            layout: workflow.layout.clone(),
            trigger: workflow.trigger.clone(),
            run_limit: workflow.run_limit,
            failure_alert: workflow.failure_alert,
            status: workflow.status,
            created_by: workflow.created_by.clone(),
            edited_by: workflow.edited_by.clone(),
            authors: workflow.authors.clone(),
            publication: workflow.publication.clone(),
            origin: workflow.origin.clone(),
            hold: workflow.hold.clone(),
            created_at: workflow.created_at,
            updated_at: workflow.updated_at,
        }
    }

    /// Workflow viewing rights cannot authorize renaming or replacing a
    /// draft's graph, archiving a published version or drafting its successor.
    #[test]
    fn changing_a_workflow_needs_the_right_for_it() {
        let mut draft_version = digest();
        let mut published = digest();
        publish_as(&mut published, &ann(), &[], &SeesAll).unwrap();
        let sam = bob();

        let renamed = draft_version.rename(&viewing(&sam), Label::new("name", "Mine").unwrap());
        let replaced = draft_version.replace_graph(&viewing(&sam), draft_version.graph().clone());
        let archived = published.archive(&viewing(&sam));
        let next = published.next_draft(&viewing(&sam));

        for result in [renamed, replaced, archived] {
            assert!(matches!(result, Err(DomainError::Forbidden(_))));
        }
        assert!(matches!(next, Err(DomainError::Forbidden(_))));
    }

    /// Replacing a graph advances the draft's revision. Publication using the
    /// earlier reviewed revision fails, and the workflow remains a draft.
    #[test]
    fn a_draft_changed_since_it_was_reviewed_is_not_published() {
        let mut workflow = digest();
        let reviewed = workflow.revision();
        let _later = crate::shared::clock::freeze(workflow.updated_at + time::Duration::SECOND);
        workflow
            .replace_graph(&managing(&bob()), workflow.graph().clone())
            .unwrap();

        let published = workflow.publish(
            &managing(&ann()),
            reviewed,
            Replaces::Nothing,
            PublishFacts {
                offered: &[],
                events: &[],
                sees: &SeesAll,
                runnable: &[],
            },
        );

        assert!(matches!(published, Err(DomainError::Conflict(_))));
        assert_eq!(workflow.status(), WorkflowStatus::Draft);
    }

    /// The store keeps times to the microsecond. Ann's save is answered with
    /// the revision the store will give back, so her screen does not take
    /// her own save for someone else's.
    #[test]
    fn a_revision_is_told_to_the_microsecond_the_store_keeps() {
        let stored =
            OffsetDateTime::UNIX_EPOCH + time::Duration::microseconds(1_794_263_355_372_087);
        let saved = stored + time::Duration::nanoseconds(290);

        assert_eq!(Revision::reviewed(saved), Revision::reviewed(stored));
        assert_eq!(Revision::reviewed(saved).changed_at(), stored);
    }

    /// Ann's screen shows the time her draft last changed, and her request to
    /// publish hands it back. That is the revision she reviewed, so the
    /// draft is published.
    #[test]
    fn a_revision_handed_back_by_its_time_is_the_one_reviewed() {
        let mut workflow = digest();
        let shown = workflow.revision().changed_at();

        let published = workflow.publish(
            &managing(&ann()),
            Revision::reviewed(shown),
            Replaces::Nothing,
            PublishFacts {
                offered: &[],
                events: &[],
                sees: &SeesAll,
                runnable: &[],
            },
        );

        assert!(published.is_ok());
        assert_eq!(workflow.status(), WorkflowStatus::Published);
    }

    /// Version 1 of Ann's workflow is in service. She publishes version 2
    /// in its place. Version 1 is archived in the same step, so a schedule
    /// never fires both and nothing is paid twice.
    #[test]
    fn publishing_a_version_retires_the_one_it_replaces() {
        let mut first = digest();
        publish_as(&mut first, &ann(), &[], &SeesAll).unwrap();
        let mut second = first.next_draft(&managing(&ann())).unwrap();
        let reviewed = second.revision();

        second
            .publish(
                &managing(&ann()),
                reviewed,
                Replaces::Version(&mut first),
                PublishFacts {
                    offered: &[],
                    events: &[],
                    sees: &SeesAll,
                    runnable: &[],
                },
            )
            .unwrap();

        assert_eq!(first.status(), WorkflowStatus::Archived);
        assert_eq!(second.status(), WorkflowStatus::Published);
    }

    /// A draft names as its predecessor a version of another workflow, one
    /// still a draft, or a later one. Each is refused, and nothing is
    /// archived.
    #[test]
    fn a_version_replaces_only_an_earlier_published_one_of_its_workflow() {
        let mut other = digest();
        publish_as(&mut other, &ann(), &[], &SeesAll).unwrap();
        let mut still_draft = digest();
        let mut candidate = digest();
        let reviewed = candidate.revision();
        let facts = PublishFacts {
            offered: &[],
            events: &[],
            sees: &SeesAll,
            runnable: &[],
        };

        let over_other = candidate.publish(
            &managing(&ann()),
            reviewed,
            Replaces::Version(&mut other),
            facts,
        );
        let over_draft = candidate.publish(
            &managing(&ann()),
            reviewed,
            Replaces::Version(&mut still_draft),
            facts,
        );

        assert!(matches!(over_other, Err(DomainError::Conflict(_))));
        assert!(matches!(over_draft, Err(DomainError::Conflict(_))));
        assert_eq!(other.status(), WorkflowStatus::Published);
    }

    fn digest() -> Workflow<ResolvedTenant> {
        draft(vec![transform("tidy", Join::All)], Vec::new())
    }

    /// Sees everything but signing key events.
    struct NoCrypto;

    impl EventVisibility for NoCrypto {
        fn may_see(&self, event_type: &EventType) -> bool {
            !matches!(event_type, EventType::Crypto(_))
        }
    }

    fn on_event(event: EventType) -> Workflow<ResolvedTenant> {
        let trigger = Trigger::Event(EventTrigger::new(event).unwrap());
        draft_with(vec![transform("tidy", Join::All)], Vec::new(), trigger)
    }

    /// A publisher unable to see signing key events cannot publish a workflow
    /// triggered by one, which stays a draft. A visible user event is accepted.
    #[test]
    fn a_workflow_on_an_event_its_publisher_may_not_see_is_refused() {
        let mut on_keys = on_event(CryptoEvent::ALL[0].0.into());
        let mut on_users = on_event(IdentityEvent::UserRegistered.into());

        let refused = publish_as(&mut on_keys, &bob(), &[], &NoCrypto);
        let allowed = publish_as(&mut on_users, &bob(), &[], &NoCrypto);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(on_keys.status(), WorkflowStatus::Draft);
        assert!(allowed.is_ok());
    }

    /// Ann drafts a workflow, Bob changes its steps, Ann renames it and Cid
    /// publishes it. All three are its authors. The next version Ann drafts
    /// keeps them, since it copies Bob's steps.
    #[test]
    fn everyone_who_shaped_a_version_is_an_author() {
        let mut workflow = digest();
        workflow
            .replace_graph(&managing(&bob()), workflow.graph().clone())
            .unwrap();
        workflow
            .rename(&managing(&ann()), Label::new("name", "Payouts").unwrap())
            .unwrap();
        publish_as(&mut workflow, &cid(), &[], &SeesAll).unwrap();

        let next = workflow.next_draft(&managing(&ann())).unwrap();

        for person in [ann(), bob(), cid()] {
            assert!(workflow.authors().includes(&person));
            assert!(next.authors().includes(&person));
        }
        assert_eq!(next.authors().as_slice().len(), 3);
    }

    /// A stored version whose last editor or publisher is not among its
    /// authors is refused as corrupt. Else that person could approve the
    /// steps they wrote.
    #[test]
    fn a_stored_version_missing_an_author_is_refused() {
        let mut published = digest();
        publish_as(&mut published, &bob(), &[], &SeesAll).unwrap();

        let without_bob = WorkflowRow {
            authors: Authors::first(&ann()),
            ..stored(&published)
        };

        assert!(refused_as_corrupt(
            &Workflow::<ResolvedTenant>::reconstitute(without_bob)
        ));
    }

    /// Ann drafts a workflow and Bob publishes it. It is published by Bob,
    /// last edited by Bob, and still drafted by Ann.
    #[test]
    fn publishing_a_draft_records_who_published_it() {
        let mut workflow = digest();

        publish_as(&mut workflow, &bob(), &[], &SeesAll).unwrap();

        assert_eq!(workflow.status(), WorkflowStatus::Published);
        assert_eq!(workflow.publication(), &Publication::PublishedBy(bob()));
        assert_eq!(workflow.edited_by(), &bob());
        assert_eq!(workflow.created_by(), &ann());
    }

    /// Bob sets a draft's trigger to a webhook and its run limit to two
    /// hours, and Ann publishes it. Bob's later changes to either are
    /// refused, and the published values stay.
    #[test]
    fn the_trigger_and_run_limit_change_only_on_a_draft() {
        let longer = RunLimit::new(crate::types::Lifetime::seconds(7_200).unwrap()).unwrap();
        let mut workflow = digest();
        workflow
            .change_trigger(&managing(&bob()), Trigger::Webhook)
            .unwrap();
        workflow
            .change_run_limit(&managing(&bob()), longer)
            .unwrap();
        publish_as(&mut workflow, &ann(), &[], &SeesAll).unwrap();

        let trigger = workflow.change_trigger(&managing(&bob()), Trigger::Manual);
        let shorter = RunLimit::new(crate::types::Lifetime::seconds(60).unwrap()).unwrap();
        let limit = workflow.change_run_limit(&managing(&bob()), shorter);

        assert!(matches!(trigger, Err(DomainError::Conflict(_))));
        assert!(matches!(limit, Err(DomainError::Conflict(_))));
        assert_eq!(workflow.trigger(), &Trigger::Webhook);
        assert_eq!(workflow.run_limit(), longer);
    }

    /// Publication rejects a code step absent from the runnable versions and
    /// leaves the workflow a draft. Supplying the runnable version allows it.
    #[test]
    fn a_draft_whose_code_may_not_run_is_not_published() {
        let mut workflow = draft(vec![code("clean")], Vec::new());
        let reviewed = workflow.revision();

        let refused = workflow.publish(
            &managing(&ann()),
            reviewed,
            Replaces::Nothing,
            PublishFacts {
                offered: &[],
                events: &[],
                sees: &SeesAll,
                runnable: &[],
            },
        );

        assert!(matches!(refused, Err(DomainError::Validation(_))));
        assert_eq!(workflow.status(), WorkflowStatus::Draft);
        assert!(publish_as(&mut workflow, &ann(), &[], &SeesAll).is_ok());
    }

    /// A draft pays through an operation the catalog does not offer. It
    /// is not published, whether the catalog offers another operation or
    /// none, and stays an unpublished draft.
    #[test]
    fn a_draft_using_an_operation_no_longer_offered_is_not_published() {
        let mut workflow = draft(
            vec![financial_approval(), pay(Join::All)],
            vec![edge("ok", Port::Next, "pay")],
        );

        assert!(publish_as(&mut workflow, &ann(), &[offered(append_row())], &SeesAll).is_err());
        assert!(publish_as(&mut workflow, &ann(), &[], &SeesAll).is_err());
        assert_eq!(workflow.status(), WorkflowStatus::Draft);
        assert_eq!(workflow.publication(), &Publication::Unpublished);
    }

    /// Ann publishes "Weekly report" and then tries to rename it, which is
    /// refused. Bob drafts version 2 of the same workflow and renames that
    /// instead, and version 1 keeps its name.
    #[test]
    fn a_published_version_is_kept_and_the_next_draft_starts_from_it() {
        let mut workflow = digest();
        publish_as(&mut workflow, &ann(), &[], &SeesAll).unwrap();

        let renamed = workflow.rename(&managing(&ann()), Label::new("name", "Other").unwrap());
        let mut next = workflow.next_draft(&managing(&bob())).unwrap();
        next.rename(
            &managing(&bob()),
            Label::new("name", "Weekly digest").unwrap(),
        )
        .unwrap();

        assert!(matches!(renamed, Err(DomainError::Conflict(_))));
        assert_eq!(next.version(), 2);
        assert_eq!(next.id(), workflow.id());
        assert_eq!(next.status(), WorkflowStatus::Draft);
        assert_eq!(next.publication(), &Publication::Unpublished);
        assert_eq!(next.created_by(), &bob());
        assert_eq!(workflow.name().as_str(), "Weekly report");
    }

    /// An archived version cannot be archived again or published.
    #[test]
    fn an_archived_version_stays_archived() {
        let mut workflow = digest();
        workflow.archive(&managing(&ann())).unwrap();

        assert!(workflow.archive(&managing(&ann())).is_err());
        assert!(publish_as(&mut workflow, &ann(), &[], &SeesAll).is_err());
    }

    /// Update rights do not authorize archiving a workflow, and the version
    /// remains published after the refusal.
    #[test]
    fn archiving_a_workflow_needs_the_right_to_delete_it() {
        let mut published = digest();
        publish_as(&mut published, &ann(), &[], &SeesAll).unwrap();
        let sam = bob();

        let result = published.archive(&holding_only(&sam, WorkflowAction::Update));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(published.status(), WorkflowStatus::Published);
    }

    /// Someone who may delete workflows archives one version, and someone
    /// who manages workflows archives another. Both are archived.
    #[test]
    fn the_delete_or_manage_right_archives_a_workflow() {
        let mut first = digest();
        let mut second = digest();

        first
            .archive(&holding_only(&bob(), WorkflowAction::Delete))
            .unwrap();
        second
            .archive(&holding_only(&ann(), WorkflowAction::Manage))
            .unwrap();

        assert_eq!(first.status(), WorkflowStatus::Archived);
        assert_eq!(second.status(), WorkflowStatus::Archived);
    }

    /// A published version numbered `u32::MAX` has no number left after
    /// it. Drafting the next one is refused instead of wrapping to zero.
    #[test]
    fn no_version_follows_the_last_number() {
        let mut published = digest();
        publish_as(&mut published, &ann(), &[], &SeesAll).unwrap();
        let last = Workflow::<ResolvedTenant>::reconstitute(WorkflowRow {
            version: u32::MAX,
            ..stored(&published)
        })
        .unwrap();

        assert!(matches!(
            last.next_draft(&managing(&ann())),
            Err(DomainError::Conflict(_))
        ));
    }

    /// Drafting a next version from a draft is refused, since the draft is
    /// edited in place. From an archived version it gives version 2.
    #[test]
    fn a_draft_is_edited_not_followed_by_another_draft() {
        let draft = digest();
        let mut archived = digest();
        archived.archive(&managing(&ann())).unwrap();

        assert!(matches!(
            draft.next_draft(&managing(&ann())),
            Err(DomainError::Conflict(_))
        ));
        assert_eq!(archived.next_draft(&managing(&ann())).unwrap().version(), 2);
    }

    /// A payment step whose only edge in comes from a payment approval is
    /// published.
    #[test]
    fn an_approval_right_before_a_high_risk_action_lets_it_publish() {
        let published = publishing(
            vec![financial_approval(), pay(Join::All)],
            vec![edge("ok", Port::Next, "pay")],
        );

        assert!(published.is_ok());
    }

    /// A transform sits between the payment approval and the payment. It
    /// only reshapes what was approved, so the workflow is published.
    #[test]
    fn a_transform_between_the_approval_and_the_action_is_allowed() {
        let published = publishing(
            vec![
                financial_approval(),
                transform("shape", Join::All),
                pay(Join::All),
            ],
            vec![
                edge("ok", Port::Next, "shape"),
                edge("shape", Port::Next, "pay"),
            ],
        );

        assert!(published.is_ok());
    }

    /// Publication rejects a payment graph with a wait or agent run between
    /// the financial approval and payment step.
    #[test]
    fn a_wait_or_an_agent_run_between_the_approval_and_the_action_is_refused() {
        let through_a_wait = publishing(
            vec![financial_approval(), wait("later"), pay(Join::All)],
            vec![
                edge("ok", Port::Next, "later"),
                edge("later", Port::Next, "pay"),
            ],
        );
        let through_an_agent = publishing(
            vec![
                financial_approval(),
                agent_step(AgentId::new(), &[]),
                pay(Join::All),
            ],
            vec![
                edge("ok", Port::Next, "summarise"),
                edge("summarise", Port::Next, "pay"),
            ],
        );

        assert!(matches!(through_a_wait, Err(DomainError::Validation(_))));
        assert!(matches!(through_an_agent, Err(DomainError::Validation(_))));
    }

    /// A read-class approval does not satisfy publication checks for a payment
    /// step, while an approval with no declared class does.
    #[test]
    fn an_approval_declared_for_another_class_does_not_cover_the_action() {
        let mislabelled = publishing(
            vec![
                approval_for(DeclaredAction::Declared(ActionClass::Read)),
                pay(Join::All),
            ],
            vec![edge("ok", Port::Next, "pay")],
        );
        let undeclared = publishing(
            vec![approval_for(DeclaredAction::Undeclared), pay(Join::All)],
            vec![edge("ok", Port::Next, "pay")],
        );

        assert!(matches!(mislabelled, Err(DomainError::Validation(_))));
        assert!(undeclared.is_ok());
    }

    /// A step after "first" may read `first.seen` or `trigger.ok`. Reading
    /// `aside.seen` from an unconnected step, the typo `frist.seen`, or a
    /// path starting at a list position is refused at publish.
    #[test]
    fn a_step_reading_a_step_that_cannot_come_before_it_is_not_published() {
        assert!(publish_reading("first.seen").is_ok());
        assert!(publish_reading("trigger.ok").is_ok());
        assert!(matches!(
            publish_reading("aside.seen"),
            Err(DomainError::Validation(_))
        ));
        assert!(matches!(
            publish_reading("frist.seen"),
            Err(DomainError::Validation(_))
        ));
        assert!(matches!(
            publish_reading("0"),
            Err(DomainError::Validation(_))
        ));
    }

    /// Tries publishing a reader reached from `first`, with `aside` on an unrelated branch.
    fn publish_reading(path_text: &str) -> Result<(), DomainError> {
        let reader = node(
            "reader",
            NodeKind::Transform(
                Mapping::new(vec![(field("value"), Source::Input(path(path_text)))]).unwrap(),
            ),
            Join::All,
        );
        publish_as(
            &mut draft(
                vec![
                    transform("first", Join::All),
                    transform("aside", Join::All),
                    reader,
                ],
                vec![edge("first", Port::Next, "reader")],
            ),
            &ann(),
            &[],
            &SeesAll,
        )
    }

    /// A payment loop cannot publish with approval only outside the loop.
    /// Placing the approval before the payment inside each pass is accepted.
    #[test]
    fn a_high_risk_action_in_a_loop_needs_its_approval_inside_the_loop() {
        let inside = WorkflowGraph::new(
            vec![financial_approval(), pay(Join::All)],
            vec![edge("ok", Port::Next, "pay")],
        )
        .unwrap();
        let unguarded = WorkflowGraph::new(vec![pay(Join::All)], Vec::new()).unwrap();
        let approved_outside = publishing(
            vec![
                approval_of("before", DeclaredAction::Declared(ActionClass::Financial)),
                each_running("each", "trigger.invoices", unguarded, 1),
            ],
            vec![edge("before", Port::Next, "each")],
        );

        let approved_inside = publishing(
            vec![each_running("each", "trigger.invoices", inside, 1)],
            Vec::new(),
        );

        assert!(matches!(approved_outside, Err(DomainError::Validation(_))));
        assert!(approved_inside.is_ok());
    }

    /// A step inside a loop reads `trigger.item`, what its pass starts with.
    /// One reading a step outside the loop is refused, since a pass is
    /// handed only its item and what the loop maps.
    #[test]
    fn a_step_in_a_loop_reads_only_what_its_pass_starts_with() {
        let reads = |path_text: &str| {
            let reader = node(
                "reader",
                NodeKind::Transform(
                    Mapping::new(vec![(field("value"), Source::Input(path(path_text)))]).unwrap(),
                ),
                Join::All,
            );
            let body = WorkflowGraph::new(vec![reader], Vec::new()).unwrap();
            publishing(
                vec![
                    transform("first", Join::All),
                    each_running("each", "first.seen", body, 1),
                ],
                vec![edge("first", Port::Next, "each")],
            )
        };

        assert!(reads("trigger.item").is_ok());
        assert!(matches!(
            reads("first.seen"),
            Err(DomainError::Validation(_))
        ));
    }

    /// A script step does not say what it does. With no approval before
    /// it, or a payment approval, it is refused. With an approval that
    /// declares no class either, it is published.
    #[test]
    fn an_undeclared_operation_needs_an_undeclared_approval_before_it() {
        let script = spec_with(DeclaredAction::Undeclared);
        let run_script = |before: Vec<Node>| {
            let mut nodes = before;
            let edges = if nodes.is_empty() {
                Vec::new()
            } else {
                vec![edge("ok", Port::Next, "run")]
            };
            nodes.push(acting_on(&script, "run"));
            publish_as(
                &mut draft(nodes, edges),
                &ann(),
                &[offered(script.clone())],
                &SeesAll,
            )
        };

        let unguarded = run_script(Vec::new());
        let labelled_financial = run_script(vec![financial_approval()]);
        let undeclared = run_script(vec![approval_for(DeclaredAction::Undeclared)]);

        assert!(matches!(unguarded, Err(DomainError::Validation(_))));
        assert!(matches!(
            labelled_financial,
            Err(DomainError::Validation(_))
        ));
        assert!(undeclared.is_ok());
    }

    /// Ann's code step runs a version that reaches the network. With no
    /// approval before it, or a payment approval, publishing is refused;
    /// with an approval that declares no class, as for an action that does
    /// not say what it does, it is published. The same step running code
    /// that reaches no network needs no approval.
    #[test]
    fn code_that_reaches_the_network_needs_an_approval_before_it() {
        let unguarded = publish_code(Vec::new(), CodeReach::Networked);
        let labelled_financial = publish_code(vec![financial_approval()], CodeReach::Networked);
        let approved = publish_code(
            vec![approval_for(DeclaredAction::Undeclared)],
            CodeReach::Networked,
        );
        let closed = publish_code(Vec::new(), CodeReach::Closed);

        assert!(matches!(unguarded, Err(DomainError::Validation(_))));
        assert!(matches!(
            labelled_financial,
            Err(DomainError::Validation(_))
        ));
        assert!(approved.is_ok());
        assert!(closed.is_ok());
    }

    /// Publishes a code step after the supplied approval nodes, with its actual network reach.
    fn publish_code(mut nodes: Vec<Node>, reach: CodeReach) -> Result<(), DomainError> {
        let edges = if nodes.is_empty() {
            Vec::new()
        } else {
            vec![edge("ok", Port::Next, "run")]
        };
        nodes.push(code("run"));
        let mut workflow = draft(nodes, edges);
        let runnable = runnable_as(&workflow, reach);
        let reviewed = workflow.revision();
        workflow.publish(
            &managing(&ann()),
            reviewed,
            Replaces::Nothing,
            PublishFacts {
                offered: &[],
                events: &[],
                sees: &SeesAll,
                runnable: &runnable,
            },
        )
    }

    /// Supplies the reach of each exact sandbox version referenced by this draft.
    fn runnable_as(workflow: &Workflow<ResolvedTenant>, reach: CodeReach) -> Vec<RunnableCode> {
        workflow
            .graph()
            .code_steps()
            .map(|(_, step)| RunnableCode {
                version: step.version(),
                reach,
            })
            .collect()
    }

    /// "Update row" is declared a write, so a workflow calls it with no
    /// approval and is published. Once Ann raises it to financial, the same
    /// workflow is refused for lacking a payment approval.
    #[test]
    fn an_operation_a_tenant_raised_needs_the_approval_its_new_class_does() {
        let update_row = spec_with(DeclaredAction::Declared(ActionClass::Write));
        let raised =
            crate::domains::workflows::integration::risk_override::OperationRiskOverride::<
                ResolvedTenant,
            >::raise(
                crate::domains::workflows::integration::risk_override::RaiseRiskParams {
                    integration: update_row.integration().clone(),
                    operation: update_row.operation().clone(),
                    effect: DeclaredAction::Declared(ActionClass::Financial),
                },
                &managing(&ann()),
            )
            .unwrap();
        let as_raised = TenantOperation::of(update_row.clone(), &[raised]);
        let without_approval = || draft(vec![acting_on(&update_row, "run")], Vec::new());

        let as_declared = publish_as(
            &mut without_approval(),
            &ann(),
            &[offered(update_row.clone())],
            &SeesAll,
        );
        let after_the_raise = publish_as(&mut without_approval(), &ann(), &[as_raised], &SeesAll);

        assert!(as_declared.is_ok());
        assert!(matches!(after_the_raise, Err(DomainError::Validation(_))));
    }

    fn spec_with(effect: DeclaredAction) -> OperationSpec {
        OperationSpec::new(
            crate::domains::workflows::integration::OperationSpecParams {
                integration: crate::domains::workflows::integration::IntegrationKey::new("scripts")
                    .unwrap(),
                operation: crate::domains::workflows::integration::OperationKey::new("run")
                    .unwrap(),
                inputs: Vec::new(),
                effect,
                account: crate::domains::workflows::integration::AccountNeed::NoAccount,
                ceiling: DataClassLevel::Internal,
            },
        )
        .unwrap()
    }

    fn acting_on(spec: &OperationSpec, name: &str) -> Node {
        let step = ActionStep::new(
            spec,
            ActionAccount::NoAccount,
            Mapping::new(Vec::new()).unwrap(),
        )
        .unwrap();
        node(name, NodeKind::Action(step), Join::All)
    }

    /// A workflow that is a payment step alone, with nothing before it, is
    /// refused.
    #[test]
    fn a_high_risk_action_with_nothing_before_it_is_refused() {
        assert!(matches!(
            publishing(vec![pay(Join::All)], Vec::new()),
            Err(DomainError::Validation(_))
        ));
    }

    /// Publication rejects a conditional path that reaches a payment without
    /// passing through the approval step.
    #[test]
    fn a_branch_around_the_approval_is_refused() {
        let around = publishing(
            vec![condition("check"), financial_approval(), pay(Join::Any)],
            vec![
                edge("check", Port::WhenTrue, "ok"),
                edge("ok", Port::Next, "pay"),
                edge("check", Port::WhenFalse, "pay"),
            ],
        );

        assert!(matches!(around, Err(DomainError::Validation(_))));
    }

    /// A stored published version reads back. Rows numbered 0, a draft
    /// marked published, a published version marked unpublished, and a
    /// published unguarded payment are each refused as corrupt.
    #[test]
    fn a_stored_version_that_breaks_a_rule_is_refused() {
        let mut published = digest();
        publish_as(&mut published, &ann(), &[], &SeesAll).unwrap();
        let unapproved = draft(vec![pay(Join::All)], Vec::new());
        let corrupt = [
            WorkflowRow {
                version: 0,
                ..stored(&digest())
            },
            WorkflowRow {
                publication: Publication::PublishedBy(ann()),
                ..stored(&digest())
            },
            WorkflowRow {
                publication: Publication::Unpublished,
                ..stored(&published)
            },
            WorkflowRow {
                graph: unapproved.graph().clone(),
                ..stored(&published)
            },
        ];

        assert!(Workflow::<ResolvedTenant>::reconstitute(stored(&published)).is_ok());
        for row in corrupt {
            assert!(refused_as_corrupt(
                &Workflow::<ResolvedTenant>::reconstitute(row)
            ));
        }
    }

    /// Ann's digest draft, with its creation already taken out.
    fn fresh_digest() -> Workflow<ResolvedTenant> {
        let mut workflow = digest();
        raised_names(&mut workflow);
        workflow
    }

    /// Ann's digest, published, with what that raised taken out.
    fn published_digest() -> Workflow<ResolvedTenant> {
        let mut workflow = fresh_digest();
        publish_as(&mut workflow, &ann(), &[], &SeesAll).unwrap();
        raised_names(&mut workflow);
        workflow
    }

    /// Ann drafts a new workflow. Its creation is raised, naming the
    /// workflow, its version and its name.
    #[test]
    fn creating_raises_workflows_workflow_created() {
        let mut workflow = digest();

        let events = raised(&mut workflow);

        assert_eq!(
            events[0].event_type().to_string(),
            "workflows.workflow_created"
        );
        assert_eq!(events[0].payload().get("version"), Some("1"));
    }

    /// Ann renames her draft, replaces its steps, changes its trigger and
    /// its run limit. Each edit is raised, in order.
    #[test]
    fn each_draft_edit_raises_its_own_event() {
        let mut workflow = fresh_digest();
        let ann = ann();
        let by = managing(&ann);
        let graph = workflow.graph().clone();
        let run_limit = workflow.run_limit();

        workflow
            .rename(&by, Label::new("name", "Weekly digest").unwrap())
            .unwrap();
        workflow.replace_graph(&by, graph).unwrap();
        workflow.change_trigger(&by, Trigger::Manual).unwrap();
        workflow.change_run_limit(&by, run_limit).unwrap();

        assert_eq!(
            raised_names(&mut workflow),
            [
                "workflows.draft_renamed",
                "workflows.draft_steps_replaced",
                "workflows.draft_trigger_changed",
                "workflows.draft_run_limit_changed",
            ]
        );
    }

    /// Ann publishes her draft. The publication is raised.
    #[test]
    fn publishing_raises_workflows_version_published() {
        let mut workflow = fresh_digest();

        publish_as(&mut workflow, &ann(), &[], &SeesAll).unwrap();

        assert_eq!(raised_names(&mut workflow), ["workflows.version_published"]);
    }

    /// Ann publishes version 2 over version 1. Version 1 raises its archive
    /// and version 2 its publication, each on the version it is about.
    #[test]
    fn publishing_over_a_version_raises_its_archive_on_the_old_one() {
        let mut first = published_digest();
        let mut second = first.next_draft(&managing(&ann())).unwrap();
        raised_names(&mut second);
        let reviewed = second.revision();

        second
            .publish(
                &managing(&ann()),
                reviewed,
                Replaces::Version(&mut first),
                PublishFacts {
                    offered: &[],
                    events: &[],
                    sees: &SeesAll,
                    runnable: &[],
                },
            )
            .unwrap();

        let archived = raised(&mut first);
        assert_eq!(
            archived[0].event_type().to_string(),
            "workflows.version_archived"
        );
        assert_eq!(archived[0].payload().get("version"), Some("1"));
        assert_eq!(raised_names(&mut second), ["workflows.version_published"]);
    }

    /// Ann drafts version 2 of her published digest. The new draft raises
    /// that it was drafted, and version 1 raises nothing.
    #[test]
    fn the_next_draft_raises_workflows_version_drafted() {
        let mut first = published_digest();

        let mut second = first.next_draft(&managing(&ann())).unwrap();

        let events = raised(&mut second);
        assert_eq!(
            events[0].event_type().to_string(),
            "workflows.version_drafted"
        );
        assert_eq!(events[0].payload().get("version"), Some("2"));
        assert!(raised_names(&mut first).is_empty());
    }

    /// Ann archives her published digest. The archive is raised.
    #[test]
    fn archiving_raises_workflows_version_archived() {
        let mut workflow = published_digest();

        workflow.archive(&managing(&ann())).unwrap();

        assert_eq!(raised_names(&mut workflow), ["workflows.version_archived"]);
    }

    /// A viewer's rename and archive attempts and an edit to a published
    /// version all fail without raising events on either version.
    #[test]
    fn a_refused_change_raises_nothing() {
        let mut draft_version = fresh_digest();
        let mut published = published_digest();
        let sam = bob();

        let renamed = draft_version.rename(&viewing(&sam), Label::new("name", "Mine").unwrap());
        let archived = published.archive(&viewing(&sam));
        let edited = published.change_trigger(&managing(&ann()), Trigger::Manual);

        assert!(renamed.is_err());
        assert!(archived.is_err());
        assert!(edited.is_err());
        assert!(raised_names(&mut draft_version).is_empty());
        assert!(raised_names(&mut published).is_empty());
    }

    /// Ann's published digest is read back from storage. Loading it is no
    /// change, so it has raised nothing.
    #[test]
    fn a_version_read_back_from_storage_has_raised_nothing() {
        let published = published_digest();

        let mut read = Workflow::<ResolvedTenant>::reconstitute(stored(&published)).unwrap();

        assert!(raised_names(&mut read).is_empty());
    }

    /// The account the "tidy" step needs, switched off.
    fn switched_off() -> MissingAccount {
        MissingAccount {
            account: IntegrationAccountId::new(),
            at: AccountUse::Step(NodeKey::new("tidy").unwrap()),
            why: AccountUnusable::Disabled,
        }
    }

    /// Pat's calendar is switched off, so Ann's digest is held: it says
    /// which step needs an account, refuses to start, and the hold is
    /// raised once however often it is found again.
    #[test]
    fn a_held_version_refuses_to_start_and_is_raised_once() {
        let mut published = published_digest();

        published.hold_for(switched_off()).unwrap();
        published.hold_for(switched_off()).unwrap();

        let refused = published.ensure_startable();
        assert!(matches!(refused, Err(DomainError::Conflict(_))));
        assert_eq!(raised_names(&mut published), ["workflows.version_held"]);
    }

    /// Bob picks another account and drafts the next version: the draft,
    /// and the version he publishes from it, start again.
    #[test]
    fn the_next_version_of_a_held_one_is_not_held() {
        let mut published = published_digest();
        published.hold_for(switched_off()).unwrap();

        let mut next = published.next_draft(&managing(&bob())).unwrap();
        publish_as(&mut next, &bob(), &[], &SeesAll).unwrap();

        assert_eq!(next.hold(), &Hold::Clear);
        assert!(next.ensure_startable().is_ok());
    }

    /// A draft cannot be placed on hold, and a stored draft carrying a hold is
    /// rejected as corrupt.
    #[test]
    fn only_a_version_in_service_is_held() {
        let mut draft_version = fresh_digest();

        let held = draft_version.hold_for(switched_off());
        let read = Workflow::<ResolvedTenant>::reconstitute(WorkflowRow {
            hold: Hold::NeedsAccount(switched_off()),
            ..stored(&draft_version)
        });

        assert!(matches!(held, Err(DomainError::Conflict(_))));
        assert!(refused_as_corrupt(&read));
    }

    /// A version whose trigger and one step act through accounts lists
    /// both, the trigger first.
    #[test]
    fn every_account_a_version_acts_through_is_listed() {
        let account = IntegrationAccountId::new();
        let mut workflow = draft(
            vec![node(
                "pay",
                NodeKind::Action(
                    ActionStep::new(
                        &payment(),
                        ActionAccount::Account(account),
                        Mapping::new(vec![(field("values"), Source::Input(path("trigger")))])
                            .unwrap(),
                    )
                    .unwrap(),
                ),
                Join::All,
            )],
            Vec::new(),
        );
        raised_names(&mut workflow);

        let used = workflow.accounts_used();

        assert_eq!(used.len(), 1);
        assert_eq!(used[0].account, account);
        assert_eq!(used[0].at, AccountUse::Step(NodeKey::new("pay").unwrap()));
    }

    fn tidy_at(x: u32, y: u32) -> CanvasLayout {
        CanvasLayout::new(vec![(
            NodeKey::new("tidy").unwrap(),
            StepPosition::new(x, y).unwrap(),
        )])
        .unwrap()
    }

    /// Ann reviews her draft, then Bob moves its step on the canvas. Moving
    /// changes nothing a run does, so it raises nothing, the revision Ann
    /// reviewed still stands, and she publishes it.
    #[test]
    fn moving_steps_keeps_the_reviewed_revision() {
        let mut workflow = digest();
        raised_names(&mut workflow);
        let reviewed = workflow.revision();
        let _later = crate::shared::clock::freeze(workflow.updated_at + time::Duration::SECOND);

        workflow
            .arrange(&managing(&bob()), tidy_at(40, 300))
            .unwrap();

        assert!(raised_names(&mut workflow).is_empty());
        assert_eq!(workflow.revision(), reviewed);
        assert_eq!(
            workflow
                .layout()
                .position_of(&NodeKey::new("tidy").unwrap()),
            Some(StepPosition::new(40, 300).unwrap())
        );
    }

    /// Rearranging steps rejects a viewer, a layout with a missing graph step
    /// and an already published version.
    #[test]
    fn arranging_refuses_viewers_strays_and_published_versions() {
        let mut draft_version = digest();
        let mut published = digest();
        publish_as(&mut published, &ann(), &[], &SeesAll).unwrap();
        let stray = CanvasLayout::new(vec![(
            NodeKey::new("gone").unwrap(),
            StepPosition::new(0, 0).unwrap(),
        )])
        .unwrap();

        let by_viewer = draft_version.arrange(&viewing(&bob()), tidy_at(1, 1));
        let with_stray = draft_version.arrange(&managing(&ann()), stray);
        let on_published = published.arrange(&managing(&ann()), tidy_at(1, 1));

        assert!(matches!(by_viewer, Err(DomainError::Forbidden(_))));
        assert!(matches!(with_stray, Err(DomainError::Validation(_))));
        assert!(matches!(on_published, Err(DomainError::Conflict(_))));
    }

    /// Ann describes her draft and asks to hear of its failures herself.
    /// Each is an edit: it raises its event and makes a new revision.
    #[test]
    fn describing_and_choosing_the_failure_alert_are_edits() {
        let mut workflow = digest();
        raised_names(&mut workflow);
        let before = workflow.revision();
        let _later = crate::shared::clock::freeze(workflow.updated_at + time::Duration::SECOND);
        let description = Text::new("description", "Tidies the weekly report").unwrap();

        workflow
            .describe(&managing(&ann()), Some(description.clone()))
            .unwrap();
        workflow
            .change_failure_alert(&managing(&ann()), FailureAlert::AlsoAuthors)
            .unwrap();

        assert_eq!(
            raised_names(&mut workflow),
            [
                "workflows.draft_described",
                "workflows.draft_failure_alert_changed"
            ]
        );
        assert_ne!(workflow.revision(), before);
        assert_eq!(workflow.description(), Some(&description));
        assert!(workflow.failure_alert().tells_authors());
    }

    /// Ann replaces her draft's steps with a set that drops one. The layout
    /// forgets the dropped step and keeps the rest.
    #[test]
    fn replacing_steps_keeps_where_the_remaining_ones_sit() {
        let mut workflow = draft(
            vec![transform("tidy", Join::All), transform("extra", Join::All)],
            Vec::new(),
        );
        let both = CanvasLayout::new(vec![
            (
                NodeKey::new("tidy").unwrap(),
                StepPosition::new(40, 300).unwrap(),
            ),
            (
                NodeKey::new("extra").unwrap(),
                StepPosition::new(340, 300).unwrap(),
            ),
        ])
        .unwrap();
        workflow.arrange(&managing(&ann()), both).unwrap();

        workflow
            .replace_graph(&managing(&ann()), digest().graph().clone())
            .unwrap();

        assert_eq!(workflow.layout(), &tidy_at(40, 300));
    }

    /// The next draft starts with this version's description, layout and
    /// failure alert, so Ann's picture and settings carry over.
    #[test]
    fn the_next_draft_keeps_the_picture_and_settings() {
        let mut workflow = digest();
        workflow
            .arrange(&managing(&ann()), tidy_at(40, 300))
            .unwrap();
        workflow
            .change_failure_alert(&managing(&ann()), FailureAlert::AlsoAuthors)
            .unwrap();
        publish_as(&mut workflow, &ann(), &[], &SeesAll).unwrap();

        let next = workflow.next_draft(&managing(&ann())).unwrap();

        assert_eq!(next.layout(), &tidy_at(40, 300));
        assert_eq!(next.failure_alert(), FailureAlert::AlsoAuthors);
    }

    /// Reconstitution rejects a layout referring to a missing graph step as
    /// corrupt storage.
    #[test]
    fn a_stored_layout_placing_a_missing_step_is_corrupt() {
        let stray = CanvasLayout::new(vec![(
            NodeKey::new("gone").unwrap(),
            StepPosition::new(0, 0).unwrap(),
        )])
        .unwrap();

        let read = Workflow::<ResolvedTenant>::reconstitute(WorkflowRow {
            layout: stray,
            ..stored(&digest())
        });

        assert!(refused_as_corrupt(&read));
    }
}
