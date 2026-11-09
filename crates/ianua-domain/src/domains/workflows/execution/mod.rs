//! One run of a published workflow version: which steps have run, which are
//! under way, and what each produced.
//!
//! An execution carries the graph of the version it runs, so a later
//! version never changes one already started. It acts for one person
//! throughout:
//! - every agent run it starts acts for them and may not exceed their
//!   authority,
//! - every integration account it uses must be one they may use,
//! - they may not approve their own execution's approval steps.
//!
//! Every step's input carries the most sensitive data that reached it. No
//! integration is handed data above its ceiling.
//!
//! Condition and transform steps finish the moment they are ready. Every
//! other step's work happens outside the domain and is reported back here.
//! Each change hands back what it did as [`ExecutionRecord`]s, for the audit
//! trail. Nothing changes once the execution has ended or passed its
//! workflow's run limit. The one exception is work still under way at the
//! end, which is recorded when it reports back.

mod acting;
mod progress;
pub mod record;
mod restart;
pub mod retention;
mod retry;
mod rules;
mod starts;
pub mod step;
mod steps;
mod view;

use std::marker::PhantomData;

use time::OffsetDateTime;

pub use self::acting::ActingAuthority;
use self::record::ExecutionRecord;
pub use self::restart::{RestartFrom, RestartParams};
pub use self::starts::mode::{ExecutionMode, StoredMode, TestPlan};
pub use self::starts::refusal::StartRefusal;
pub use self::starts::service::ServiceStartParams;
pub use self::starts::webhook::WebhookStartParams;
use self::step::StepState;
pub use self::steps::action::{ActionCall, ActionClearance, ActionStart, Offer};
pub use self::steps::agent::{ANSWER_FIELD, AgentRunStart, RunAuthority, RunBacking};
pub use self::steps::code::{CodeRun, CodeStart};
pub use self::steps::deferral::RUN_LIMIT_PAUSE;
pub use self::steps::guardrail::GuardrailRules;
pub use self::steps::items::{ItemsAsked, ItemsSeen, SeenPage};
pub use self::steps::loops::{LoopMoves, PassStart};
pub use self::steps::wait::HoursBegin;
pub use self::view::{ExecutionView, StepView};
use crate::domains::agents::authority::delegation::HeldResources;
use crate::domains::authorization::permission::WorkflowAction;
use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::control::WorkflowControl;
use crate::domains::workflows::data::FlowData;
use crate::domains::workflows::design::authors::Authors;
use crate::domains::workflows::design::graph::WorkflowGraph;
use crate::domains::workflows::design::node::{Node, NodeKey, NodeKind};
use crate::domains::workflows::design::workflow::{FailureAlert, Workflow, WorkflowStatus};
use crate::domains::workflows::integration::company::{COMPANY_INTEGRATION, CompanyOperation};
use crate::domains::workflows::triggers::Trigger;
use crate::domains::workflows::triggers::before::{GuardedChange, Verdict};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::chain::{ChainDepth, EventOrigin};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::transition::{InvalidTransition, checked};
use crate::types::{EventType, Human, WorkflowExecutionId, WorkflowId};

/// Where an execution stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// Steps are still to run.
    Running,
    /// It ended, this way.
    Ended(record::ExecutionEnd),
}

impl ExecutionStatus {
    /// Moves to `to` if an execution in this status may. Only a running one
    /// ends, and it ends once.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] for any other move.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| {
            matches!((from, to), (Self::Running, Self::Ended(_)))
        })
    }
}

/// What started an execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    /// A person started it by hand.
    Manual,
    /// Its schedule came round.
    Schedule,
    /// Its webhook was called.
    Webhook,
    /// An integration's service sent the event it starts on.
    Service,
    /// This event happened.
    Event {
        /// The typed domain occurrence matched by the workflow's trigger.
        event: EventType,
        /// Where it came from.
        origin: EventOrigin,
    },
    /// A change is about to happen, and the run decides it.
    Before {
        /// The change it decides.
        change: GuardedChange,
    },
    /// The person an earlier run acted for started it again after that run
    /// failed or ran out of time.
    Restart {
        /// The run it starts again.
        of: WorkflowExecutionId,
        /// Where it picks up.
        from: RestartFrom,
    },
}

impl Cause {
    /// A stable name for what started it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Schedule => "schedule",
            Self::Webhook => "webhook",
            Self::Service => "service",
            Self::Event { .. } => "event",
            Self::Before { .. } => "before",
            Self::Restart { from, .. } => from.as_str(),
        }
    }

    /// Whether a signed-in person started it, acting for themselves.
    #[must_use]
    pub fn is_by_a_person(self) -> bool {
        match self {
            Self::Manual | Self::Restart { .. } => true,
            Self::Schedule
            | Self::Webhook
            | Self::Service
            | Self::Event { .. }
            | Self::Before { .. } => false,
        }
    }

    /// Whether this is something `trigger` starts on.
    fn fits(self, trigger: &Trigger) -> bool {
        match (self, trigger) {
            (Self::Manual, Trigger::Manual)
            | (Self::Schedule, Trigger::Schedule(_))
            | (Self::Webhook, Trigger::Webhook)
            | (Self::Service, Trigger::Service(_)) => true,
            (Self::Event { event, .. }, Trigger::Event(on)) => event == on.event(),
            (Self::Before { change }, Trigger::Before(on)) => change == *on,
            (
                Self::Manual
                | Self::Schedule
                | Self::Webhook
                | Self::Service
                | Self::Event { .. }
                | Self::Before { .. }
                | Self::Restart { .. },
                _,
            ) => false,
        }
    }

    /// How deep in its chain the execution this starts is.
    ///
    /// A start that is refused is recorded at this depth too. Sam publishes
    /// a workflow on refused starts and then leaves. Each refusal it records
    /// would start it again, and be refused again, without end. Marked at
    /// this depth, the chain stops at
    /// [`MAX_CHAIN_DEPTH`](crate::shared::events::chain::MAX_CHAIN_DEPTH).
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the event came from a chain of
    ///   executions already that long.
    pub fn chain_depth(self) -> Result<ChainDepth, DomainError> {
        match self {
            Self::Event {
                origin: EventOrigin::Execution(depth),
                ..
            } => depth.next(),
            Self::Manual
            | Self::Schedule
            | Self::Webhook
            | Self::Service
            | Self::Restart { .. }
            | Self::Before { .. }
            | Self::Event {
                origin: EventOrigin::Outside,
                ..
            } => Ok(ChainDepth::FIRST),
        }
    }
}

/// The values a schedule, webhook or event starts an execution with.
pub struct StartExecutionParams {
    /// The person it acts for, with what they hold right now: whoever
    /// published the version its trigger started. Anyone else is refused.
    pub acting_for: ActingAuthority,
    /// What started it: a schedule or an event, for
    /// [`WorkflowExecution::start_on_trigger`]. A person starting it by hand
    /// uses [`WorkflowExecution::start_by_hand`], and a webhook call goes
    /// through [`WorkflowExecution::start_on_webhook`].
    pub cause: Cause,
    /// The trigger's data.
    pub input: FlowData,
    /// The most sensitive data in it.
    ///
    /// The domain cannot read the trigger's data and tell how sensitive it
    /// is, so this comes from the caller: the adapter that received a
    /// webhook, the event's own class, or what a person declared when they
    /// started it. Every step then holds the execution to it, and it only
    /// rises.
    pub exposure: DataClassLevel,
}

/// The values a person starts an execution with by hand.
///
/// The person is not among them. The execution acts for whoever the
/// [`WorkflowControl`] it is started with names.
pub struct ManualStartParams {
    /// The relationship graph's answer for the person starting it: the
    /// resources they were given use of. Their permissions come from their
    /// control.
    pub resources: HeldResources,
    /// The data they start it with.
    pub input: FlowData,
    /// The most sensitive data in it, as they declared it. Every step then
    /// holds the execution to it, and it only rises.
    pub exposure: DataClassLevel,
}

/// The loop an execution runs one pass of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassOf {
    /// The execution whose loop step started it.
    pub execution: WorkflowExecutionId,
    /// That loop step.
    pub step: NodeKey,
    /// The item it is the pass for, counted from zero.
    pub index: u32,
}

/// An execution as stored.
pub struct WorkflowExecutionRow {
    /// The persisted identity correlating this run's steps and external work.
    pub id: WorkflowExecutionId,
    /// The workflow it runs.
    pub workflow_id: WorkflowId,
    /// The version it runs.
    pub version: u32,
    /// That version's steps and edges.
    pub graph: WorkflowGraph,
    /// The person it acts for.
    pub acting_for: Human,
    /// The authors of the version it runs.
    pub authors: Authors,
    /// Who that version tells when a run fails.
    pub failure_alert: FailureAlert,
    /// Whether it is a real run or a test of a draft.
    pub mode: StoredMode,
    /// What started it.
    pub cause: Cause,
    /// The loop it runs one pass of, if it is a pass.
    pub pass: Option<PassOf>,
    /// How many executions led to it.
    pub chain_depth: ChainDepth,
    /// The trigger's data.
    pub input: FlowData,
    /// The most sensitive data in it.
    pub exposure: DataClassLevel,
    /// Each step's state, in the graph's order.
    pub steps: Vec<StepState>,
    /// Where it stands.
    pub status: ExecutionStatus,
    /// When it is stopped if it has not ended.
    pub deadline: OffsetDateTime,
    /// When it started.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// One run of a published workflow version.
#[derive(Debug, Clone)]
pub struct WorkflowExecution<T: TenantScope> {
    id: WorkflowExecutionId,
    workflow_id: WorkflowId,
    version: u32,
    graph: WorkflowGraph,
    acting_for: Human,
    authors: Authors,
    failure_alert: FailureAlert,
    mode: ExecutionMode,
    cause: Cause,
    pass: Option<PassOf>,
    chain_depth: ChainDepth,
    input: FlowData,
    exposure: DataClassLevel,
    steps: Vec<StepState>,
    status: ExecutionStatus,
    deadline: OffsetDateTime,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> WorkflowExecution<T> {
    /// `starter` starts an execution of `workflow` by hand, acting for
    /// themselves, and every step the domain finishes itself runs as far as
    /// it goes.
    ///
    /// Who it acts for comes from `starter`, never from the request. Sam
    /// starts Ann's published payroll workflow. If the request named the
    /// person, he would name Bob, and every step would act with Bob's
    /// rights and accounts.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `starter` does not hold the right
    ///   to run workflows.
    /// - [`DomainError::Forbidden`] when `params.resources` was answered
    ///   for someone else.
    /// - [`DomainError::Conflict`] when `workflow` is not published.
    /// - [`DomainError::Validation`] when `workflow` does not start by hand.
    pub fn start_by_hand(
        workflow: &Workflow<T>,
        starter: WorkflowControl<'_>,
        params: ManualStartParams,
    ) -> Result<(Self, Vec<ExecutionRecord>), DomainError> {
        starter.ensure_may(WorkflowAction::Run)?;
        let acting_for = ActingAuthority::of_signed_in(starter.authority(), &params.resources)?;
        Self::start_checked(
            workflow,
            StartExecutionParams {
                acting_for,
                cause: Cause::Manual,
                input: params.input,
                exposure: params.exposure,
            },
        )
    }

    /// Starts an execution of `workflow` because its schedule came round or
    /// its event happened, and runs every step the domain finishes itself,
    /// as far as they go.
    ///
    /// It acts for the person who published the version, as the version
    /// records it. Nobody else chose to have it act for them.
    ///
    /// A webhook call starts one only through
    /// [`start_on_webhook`](Self::start_on_webhook), with the call its
    /// secret admitted. Without that, anyone who learnt the webhook's
    /// address would start runs acting for the publisher. A service's event
    /// likewise starts one only through
    /// [`start_on_service_event`](Self::start_on_service_event), with the
    /// delivery its subscription admitted.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Forbidden`] for manual, restart, webhook or service-event
    /// causes; an actor who cannot run workflows, is not the publisher, or cannot see
    /// the event; or a chain already [`MAX_CHAIN_DEPTH`](crate::shared::events::chain::MAX_CHAIN_DEPTH) long.
    /// Returns [`DomainError::Conflict`] unless published, or
    /// [`DomainError::Validation`] when the cause does not match the trigger.
    pub fn start_on_trigger(
        workflow: &Workflow<T>,
        params: StartExecutionParams,
    ) -> Result<(Self, Vec<ExecutionRecord>), DomainError> {
        match params.cause {
            Cause::Schedule | Cause::Event { .. } | Cause::Before { .. } => {
                Self::start_checked(workflow, params)
            }
            Cause::Webhook => Err(DomainError::forbidden(message!(
                "workflows-a-webhook-starts-a-workflow-only",
                "a webhook starts a workflow only once its secret is checked"
            ))),
            Cause::Service => Err(DomainError::forbidden(message!(
                "workflows-a-service-event-starts-a-workflow-only",
                "a service's event starts a workflow only once its subscription admits it"
            ))),
            Cause::Manual | Cause::Restart { .. } => Err(DomainError::forbidden(message!(
                "workflows-a-start-by-hand-acts-for",
                "a start by hand acts for the person who proves who they are"
            ))),
        }
    }

    /// Starts an execution of `workflow` as `params` says, once it is
    /// published, `params` fits its trigger and the person may have it run.
    fn start_checked(
        workflow: &Workflow<T>,
        params: StartExecutionParams,
    ) -> Result<(Self, Vec<ExecutionRecord>), DomainError> {
        if workflow.status() != WorkflowStatus::Published {
            return Err(DomainError::conflict(message!(
                "workflows-only-a-published-workflow-runs",
                "only a published workflow runs"
            )));
        }
        if !params.cause.fits(workflow.trigger()) {
            return Err(DomainError::invalid(message!(
                "workflows-this-is-not-what-the-workflow",
                "this is not what the workflow starts on"
            )));
        }
        if let Some(refusal) = StartRefusal::of(workflow, &params) {
            return Err(refusal.into());
        }
        let chain_depth = params.cause.chain_depth()?;
        let mut execution = Self::fresh(workflow, params, chain_depth);
        let mut records = vec![ExecutionRecord::Started];
        execution.advance(&mut records);
        Ok((execution, records))
    }

    /// A running execution of `workflow` whose steps all wait.
    fn fresh(
        workflow: &Workflow<T>,
        params: StartExecutionParams,
        chain_depth: ChainDepth,
    ) -> Self {
        let now = crate::shared::clock::now();
        Self {
            id: WorkflowExecutionId::new(),
            workflow_id: *workflow.id(),
            version: workflow.version(),
            graph: workflow.graph().clone(),
            acting_for: params.acting_for.person().clone(),
            authors: workflow.authors().clone(),
            failure_alert: workflow.failure_alert(),
            mode: ExecutionMode::Live,
            cause: params.cause,
            pass: None,
            chain_depth,
            input: params.input,
            exposure: params.exposure,
            steps: vec![StepState::Waiting; workflow.graph().nodes().len()],
            status: ExecutionStatus::Running,
            deadline: now.saturating_add(workflow.run_limit().lifetime().duration()),
            created_at: now,
            updated_at: now,
            _scope: PhantomData,
        }
    }

    /// Rebuilds an execution from storage.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] for graph/state mismatch, unreachable
    /// states, waiting on work of the wrong kind, exposure below the trigger, or steps
    /// contradicting execution status. Times must be ordered and within their limits,
    /// and the graph must be publishable. Loop passes cannot contain loops or exceed
    /// the item limit; an execution that is not a pass cannot end as one.
    pub fn reconstitute(row: WorkflowExecutionRow) -> Result<Self, DomainError> {
        rules::consistency::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            workflow_id: row.workflow_id,
            version: row.version,
            graph: row.graph,
            acting_for: row.acting_for,
            authors: row.authors,
            failure_alert: row.failure_alert,
            mode: row.mode.mode(),
            cause: row.cause,
            pass: row.pass,
            chain_depth: row.chain_depth,
            input: row.input,
            exposure: row.exposure,
            steps: row.steps,
            status: row.status,
            deadline: row.deadline,
            created_at: row.created_at,
            updated_at: row.updated_at,
            _scope: PhantomData,
        })
    }

    /// The stable identity correlating this run's steps and external work.
    #[must_use]
    pub fn id(&self) -> &WorkflowExecutionId {
        &self.id
    }

    /// The workflow it runs.
    #[must_use]
    pub fn workflow_id(&self) -> &WorkflowId {
        &self.workflow_id
    }

    /// The version it runs.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The steps and edges it runs.
    #[must_use]
    pub fn graph(&self) -> &WorkflowGraph {
        &self.graph
    }

    /// The person it acts for.
    #[must_use]
    pub fn acting_for(&self) -> &Human {
        &self.acting_for
    }

    /// The authors of the version it runs. None of them may give an
    /// approval its high-risk steps need.
    #[must_use]
    pub fn authors(&self) -> &Authors {
        &self.authors
    }

    /// Who is told when it fails or runs out of time, as the version it
    /// runs chose.
    #[must_use]
    pub fn failure_alert(&self) -> FailureAlert {
        self.failure_alert
    }

    /// Whether it is a real run or a test of a draft.
    #[must_use]
    pub fn mode(&self) -> &ExecutionMode {
        &self.mode
    }

    /// What started it.
    #[must_use]
    pub fn cause(&self) -> Cause {
        self.cause
    }

    /// The loop it runs one pass of. `None` for an execution its trigger,
    /// a person or a restart started.
    #[must_use]
    pub fn pass(&self) -> Option<&PassOf> {
        self.pass.as_ref()
    }

    /// How many executions, this one included, led to it.
    ///
    /// An event its work raises starts others with
    /// [`EventOrigin::Execution`] of this depth.
    #[must_use]
    pub fn chain_depth(&self) -> ChainDepth {
        self.chain_depth
    }

    /// The trigger's data.
    #[must_use]
    pub fn input(&self) -> &FlowData {
        &self.input
    }

    /// The most sensitive data in the trigger's data.
    #[must_use]
    pub fn exposure(&self) -> DataClassLevel {
        self.exposure
    }

    /// Where it stands.
    #[must_use]
    pub fn status(&self) -> ExecutionStatus {
        self.status
    }

    /// When it is stopped if it has not ended.
    #[must_use]
    pub fn deadline(&self) -> OffsetDateTime {
        self.deadline
    }

    /// Each step, with where it stands.
    pub fn steps(&self) -> impl Iterator<Item = (&Node, &StepState)> {
        self.graph.nodes().iter().zip(&self.steps)
    }

    /// What a "before" run decided: the verdict of the Allow or Refuse step
    /// it finished, or `None` while none has. A run that ends without one
    /// decided nothing, which its guard counts as Refuse.
    #[must_use]
    pub fn verdict(&self) -> Option<Verdict> {
        self.steps().find_map(|(node, state)| {
            let NodeKind::Action(step) = node.kind() else {
                return None;
            };
            let StepState::Succeeded { .. } = state else {
                return None;
            };
            if step.integration().as_str() != COMPANY_INTEGRATION {
                return None;
            }
            let operation = CompanyOperation::named(step.operation())?;
            let allows = (operation == CompanyOperation::Allow).then_some(Verdict::Allow);
            allows.or((operation == CompanyOperation::Refuse).then_some(Verdict::Refuse))
        })
    }

    /// The trigger's data and every finished step's output, as one map a
    /// step after all of them would read: `trigger`, then each step's key.
    /// An evaluation checks a case's results here once its test ended.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when together they exceed what one
    ///   value may hold.
    pub fn results(&self) -> Result<FlowData, DomainError> {
        let every: Vec<NodeKey> = self
            .graph
            .nodes()
            .iter()
            .map(|node| node.key().clone())
            .collect();
        self.input_seen_by(&every)
    }

    /// Where the step called `key` stands, if the workflow has one.
    #[must_use]
    pub fn step(&self, key: &NodeKey) -> Option<&StepState> {
        self.steps()
            .find(|(node, _)| node.key() == key)
            .map(|(_, state)| state)
    }

    /// The steps ready to start, whose work is done outside the domain.
    pub fn ready(&self) -> impl Iterator<Item = &Node> {
        self.steps()
            .filter(|(_, state)| matches!(state, StepState::Ready { .. }))
            .map(|(node, _)| node)
    }
}

impl<T: TenantScope> Aggregate for WorkflowExecution<T> {
    type Id = WorkflowExecutionId;

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
pub(crate) mod tests {
    pub(crate) mod fixtures;

    use self::fixtures::{
        Execution, SeesAll, ann, approval, bob, by_hand, draft, draft_with, frozen_at, instant,
        managing, on_trigger, publish_as, published, runs_workflows, start, start_as, viewing,
    };
    use super::*;
    use crate::domains::agents::authority::capability::CapabilitySet;
    use crate::domains::authorization::permission::{SystemPermission, UserAction};
    use crate::domains::workflows::triggers::{CronSchedule, EventTrigger};
    use crate::shared::events::chain::MAX_CHAIN_DEPTH;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::types::event_type::IdentityEvent;

    const REGISTERED: EventType = EventType::Identity(IdentityEvent::UserRegistered);

    fn triggered_by(trigger: Trigger) -> Workflow<crate::isolation::scope::ResolvedTenant> {
        let mut workflow = draft_with(vec![approval("check")], Vec::new(), trigger);
        publish_as(&mut workflow, &ann(), &[], &SeesAll).unwrap();
        workflow
    }

    fn on_registration() -> Workflow<crate::isolation::scope::ResolvedTenant> {
        triggered_by(Trigger::Event(EventTrigger::new(REGISTERED).unwrap()))
    }

    /// What `person` holds when they may run workflows and see user events.
    fn sees_users(person: &Human) -> ActingAuthority {
        let users = CapabilitySet::new(vec![SystemPermission::Users(UserAction::View)], Vec::new());
        ActingAuthority::assumed(person.clone(), runs_workflows().union(&users))
    }

    fn from_event(origin: EventOrigin, acting_for: &Human) -> StartExecutionParams {
        StartExecutionParams {
            acting_for: sees_users(acting_for),
            ..on_trigger(
                acting_for,
                Cause::Event {
                    event: REGISTERED,
                    origin,
                },
            )
        }
    }

    /// Ann's registration-triggered workflow starts while she can view
    /// users. Losing that right makes the same event start forbidden.
    #[test]
    fn an_event_the_publisher_may_no_longer_see_does_not_start_it() {
        let workflow = on_registration();
        let lost_the_right = StartExecutionParams {
            acting_for: ActingAuthority::assumed(ann(), runs_workflows()),
            ..from_event(EventOrigin::Outside, &ann())
        };

        let still_sees =
            Execution::start_on_trigger(&workflow, from_event(EventOrigin::Outside, &ann()));
        let refused = Execution::start_on_trigger(&workflow, lost_the_right);

        assert!(still_sees.is_ok());
        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Ann starts a workflow that is still a draft, and one that was
    /// archived. Both are refused as conflicts, since only a published
    /// version runs.
    #[test]
    fn a_draft_or_archived_workflow_does_not_start() {
        let unpublished = draft(vec![approval("check")], Vec::new());
        let mut archived = published(vec![approval("check")], Vec::new());
        archived.archive(&managing(&ann())).unwrap();

        let from_draft = start_as(&unpublished, &ann(), by_hand(DataClassLevel::Public));
        let from_archive = start_as(&archived, &ann(), by_hand(DataClassLevel::Public));

        assert!(matches!(from_draft, Err(DomainError::Conflict(_))));
        assert!(matches!(from_archive, Err(DomainError::Conflict(_))));
    }

    /// A workflow that starts only by hand is started as if a schedule came
    /// round. That is refused, since it has no schedule. A scheduled one
    /// started by hand is refused too.
    #[test]
    fn a_cause_its_trigger_does_not_start_on_is_refused() {
        let by_hand_only = published(vec![approval("check")], Vec::new());
        let scheduled = triggered_by(Trigger::Schedule(CronSchedule::parse("0 9 * * 1").unwrap()));

        assert!(matches!(
            Execution::start_on_trigger(&by_hand_only, on_trigger(&ann(), Cause::Schedule)),
            Err(DomainError::Validation(_))
        ));
        assert!(matches!(
            start_as(&scheduled, &ann(), by_hand(DataClassLevel::Public)),
            Err(DomainError::Validation(_))
        ));
    }

    /// Bob's workflow view right cannot start Ann's published workflow by
    /// hand; the start is forbidden.
    #[test]
    fn a_start_by_hand_needs_the_right_to_run_workflows() {
        let workflow = published(vec![approval("check")], Vec::new());
        let bob = bob();

        let started =
            Execution::start_by_hand(&workflow, viewing(&bob), by_hand(DataClassLevel::Public));

        assert!(matches!(started, Err(DomainError::Forbidden(_))));
    }

    /// Bob cannot start a workflow using resources resolved for Ann.
    /// The mismatched authority makes the manual start forbidden.
    #[test]
    fn a_start_by_hand_holds_only_what_the_starter_holds() {
        let workflow = published(vec![approval("check")], Vec::new());
        let anns = by_hand(DataClassLevel::Public);

        let started = Execution::start_by_hand(&workflow, managing(&bob()), anns);

        assert!(matches!(started, Err(DomainError::Forbidden(_))));
    }

    /// A manual cause naming Bob cannot bypass the signed-in control by
    /// using the trigger entry point; the start is forbidden.
    #[test]
    fn a_start_by_hand_does_not_go_through_the_trigger_path() {
        let workflow = published(vec![approval("check")], Vec::new());

        let started = Execution::start_on_trigger(&workflow, on_trigger(&bob(), Cause::Manual));

        assert!(matches!(started, Err(DomainError::Forbidden(_))));
    }

    /// A workflow with a one-day run limit starts at time 0. Its execution
    /// must end by 86,400 seconds later.
    #[test]
    fn an_execution_must_end_within_its_workflows_run_limit() {
        let _clock = frozen_at(0);
        let workflow = published(vec![approval("check")], Vec::new());

        let (execution, _) = start(&workflow);

        assert_eq!(execution.deadline(), instant(86_400));
    }

    /// A new execution's first record says it started, before any step's
    /// record.
    #[test]
    fn the_first_record_of_an_execution_is_that_it_started() {
        let workflow = published(vec![approval("check")], Vec::new());

        let (_, records) = start(&workflow);

        assert_eq!(records.first(), Some(&ExecutionRecord::Started));
    }

    /// Ann published a scheduled workflow and then lost the right to run
    /// workflows. Its schedule is refused, and the refusal names why, so the
    /// app can tell her team the workflow stopped. A run for Bob names that
    /// it is not the publisher's.
    #[test]
    fn a_refused_start_names_its_reason() {
        let scheduled = triggered_by(Trigger::Schedule(CronSchedule::parse("0 9 * * 1").unwrap()));
        let ann_gone = StartExecutionParams {
            acting_for: ActingAuthority::assumed(ann(), CapabilitySet::empty()),
            ..on_trigger(&ann(), Cause::Schedule)
        };
        let for_bob = on_trigger(&bob(), Cause::Schedule);

        assert_eq!(
            StartRefusal::of(&scheduled, &ann_gone),
            Some(StartRefusal::PersonMayNotRun)
        );
        assert_eq!(
            StartRefusal::of(&scheduled, &for_bob),
            Some(StartRefusal::NotThePublisher)
        );
        assert!(matches!(
            Execution::start_on_trigger(&scheduled, ann_gone),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Ann's scheduled and event workflows cannot start acting for Bob.
    /// Both starts are forbidden; a scheduled run acting for Ann starts.
    #[test]
    fn a_triggered_execution_acting_for_anyone_but_the_publisher_is_refused() {
        let scheduled = triggered_by(Trigger::Schedule(CronSchedule::parse("0 9 * * 1").unwrap()));
        let by_schedule =
            Execution::start_on_trigger(&scheduled, on_trigger(&bob(), Cause::Schedule));
        let by_event = Execution::start_on_trigger(
            &on_registration(),
            from_event(EventOrigin::Outside, &bob()),
        );

        assert!(matches!(by_schedule, Err(DomainError::Forbidden(_))));
        assert!(matches!(by_event, Err(DomainError::Forbidden(_))));
        assert!(
            Execution::start_on_trigger(&scheduled, on_trigger(&ann(), Cause::Schedule)).is_ok()
        );
    }

    /// A webhook cause cannot bypass its secret check through the trigger
    /// entry point, even when it names publisher Ann; the start is forbidden.
    #[test]
    fn a_webhook_start_does_not_go_through_the_trigger_path() {
        let hooked = triggered_by(Trigger::Webhook);

        let started = Execution::start_on_trigger(&hooked, on_trigger(&ann(), Cause::Webhook));

        assert!(matches!(started, Err(DomainError::Forbidden(_))));
    }

    /// Ann's weekly schedule cannot start a run after she loses all
    /// authority; the start returns a forbidden error.
    #[test]
    fn nothing_starts_for_someone_who_may_no_longer_run_workflows() {
        let scheduled = triggered_by(Trigger::Schedule(CronSchedule::parse("0 9 * * 1").unwrap()));
        let left = StartExecutionParams {
            acting_for: ActingAuthority::assumed(ann(), CapabilitySet::empty()),
            ..on_trigger(&ann(), Cause::Schedule)
        };

        let started = Execution::start_on_trigger(&scheduled, left);

        assert!(matches!(started, Err(DomainError::Forbidden(_))));
    }

    /// Bob starts Ann's published workflow by hand. The run acts for Bob,
    /// not Ann, and starts a new chain.
    #[test]
    fn a_person_starting_a_workflow_by_hand_acts_for_themselves() {
        let workflow = published(vec![approval("check")], Vec::new());

        let (execution, _) = start_as(&workflow, &bob(), by_hand(DataClassLevel::Public)).unwrap();

        assert_eq!(execution.acting_for(), &bob());
        assert_eq!(execution.chain_depth(), ChainDepth::FIRST);
    }

    /// An event from an execution one below the chain limit starts a run at
    /// the limit. An event from a run already at the limit starts nothing,
    /// so two workflows cannot start each other without end.
    #[test]
    fn an_event_from_an_execution_starts_one_level_deeper_up_to_the_limit() {
        let workflow = on_registration();
        let second = ChainDepth::from_stored(MAX_CHAIN_DEPTH - 1).unwrap();
        let last = ChainDepth::from_stored(MAX_CHAIN_DEPTH).unwrap();

        let (deeper, _) = Execution::start_on_trigger(
            &workflow,
            from_event(EventOrigin::Execution(second), &ann()),
        )
        .unwrap();
        let too_deep = Execution::start_on_trigger(
            &workflow,
            from_event(EventOrigin::Execution(last), &ann()),
        );

        assert_eq!(deeper.chain_depth(), last);
        assert!(matches!(too_deep, Err(DomainError::Forbidden(_))));
    }

    /// A user registers outside any workflow. The run that event starts is
    /// the first of a new chain.
    #[test]
    fn an_event_from_outside_any_workflow_starts_a_chain() {
        let (execution, _) = Execution::start_on_trigger(
            &on_registration(),
            from_event(EventOrigin::Outside, &ann()),
        )
        .unwrap();

        assert_eq!(execution.chain_depth(), ChainDepth::FIRST);
    }

    /// A schedule's cause sits first in a chain, and an event from a run at
    /// the limit has no depth left. So a start refused on that event is not
    /// recorded at a depth that sets off another.
    #[test]
    fn a_cause_says_how_deep_its_start_would_be() {
        let last = ChainDepth::from_stored(MAX_CHAIN_DEPTH).unwrap();
        let from_the_last = Cause::Event {
            event: REGISTERED,
            origin: EventOrigin::Execution(last),
        };

        assert_eq!(Cause::Schedule.chain_depth().unwrap(), ChainDepth::FIRST);
        assert!(matches!(
            from_the_last.chain_depth(),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A stored chain depth of 0, or one past the limit, is refused as
    /// corrupt. A stored depth of 1 reads as the first.
    #[test]
    fn a_stored_chain_depth_outside_its_range_is_corrupt() {
        assert!(refused_as_corrupt(&ChainDepth::from_stored(0)));
        assert!(refused_as_corrupt(&ChainDepth::from_stored(
            MAX_CHAIN_DEPTH + 1
        )));
        assert_eq!(ChainDepth::from_stored(1).unwrap(), ChainDepth::FIRST);
    }
}
