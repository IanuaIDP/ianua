//! The steps a workflow is made of: what each does, the ways out of it, and
//! how it waits for the steps before it.

pub mod checking;
pub mod code;
pub mod guardrail;
mod hands_on;
mod key;
pub mod looping;
mod port;

use time::Duration;

use crate::domains::agents::authority::intent::IntentEnvelope;
use crate::domains::agents::execution::run::GoalTemplate;
use crate::domains::agents::execution::tool::ToolName;
use crate::domains::agents::execution::usage::Spend;
use crate::domains::agents::oversight::approval::ApprovalAction;
use crate::domains::workflows::data::{DataPath, FieldName, FlowData};
use crate::domains::workflows::design::also_ask::AlsoAsk;
use crate::domains::workflows::design::condition::{Clause, ConditionRule};
use crate::domains::workflows::design::graph::WorkflowGraph;
pub use crate::domains::workflows::design::node::checking::Checks;
pub use crate::domains::workflows::design::node::code::CodeStep;
pub use crate::domains::workflows::design::node::guardrail::{
    GuardrailParams, GuardrailStep, OnFinding,
};
pub use crate::domains::workflows::design::node::hands_on::HandsOn;
pub use crate::domains::workflows::design::node::key::NodeKey;
pub use crate::domains::workflows::design::node::looping::{LoopParams, LoopStep};
pub use crate::domains::workflows::design::node::port::Port;
use crate::domains::workflows::design::working_hours::WorkingHours;
use crate::domains::workflows::integration::ActionStep;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::restriction::Restriction;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::{validate_count, validate_range};
use crate::types::{ActionClass, AgentId, DeclaredAction, Label, Lifetime, ModelProviderId};

/// The largest step budget one agent run in a workflow may have.
pub(crate) const MAX_AGENT_STEPS: u32 = 50;

/// The most fields one mapping may set.
pub(crate) const MAX_MAPPED_FIELDS: usize = 64;

/// The longest a workflow may wait in one step.
pub(crate) const MAX_WAIT: Duration = Duration::days(30);

/// The longest an approval step stays open for its decision.
pub(crate) const MAX_DECISION_WINDOW: Duration = Duration::days(7);

/// The field the trigger's data is found under by the steps it starts.
pub const TRIGGER_FIELD: &str = "trigger";

/// The values to hand an agent run, before they are checked.
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
pub struct AgentRunParams {
    /// The acting agent.
    pub agent_id: AgentId,
    /// The model provider it reasons with.
    pub provider_id: ModelProviderId,
    /// The instruction, before the inputs are composed into it.
    pub goal: GoalTemplate,
    /// What of the step's input the run is given, composed into its goal.
    /// Nothing else that came before reaches the model.
    pub inputs: Mapping,
    /// The purpose envelope bounding its tool actions.
    pub purpose: IntentEnvelope,
    /// Tools granted to the run. An empty list means no tool at all.
    pub tools: Vec<ToolName>,
    /// Action classes whose tool calls wait for a person's approval.
    pub approval_classes: Vec<ActionClass>,
    /// The run's step cap.
    pub max_steps: u32,
    /// The most the run may spend on its model; it stops, over budget, once
    /// it would spend more. Unrestricted when the author sets no cap.
    pub spend_cap: Restriction<Spend>,
    /// What the run may spend before it pauses for a person to let it go
    /// on. Unrestricted when it never pauses over spend.
    pub ask_past: Restriction<Spend>,
    /// Whether it checks an earlier agent step's work.
    #[cfg_attr(feature = "serde", serde(default))]
    pub checks: Checks,
}

/// A governed agent run. Its goal is composed with the fields it maps from
/// the step's input.
///
/// It runs as an [`AgentRun`] of its own, acting for whoever started the
/// execution. So every rule an agent run keeps also holds inside a
/// workflow.
///
/// [`AgentRun`]: crate::domains::agents::execution::run::AgentRun
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "AgentRunParams"))]
pub struct AgentRunStep {
    agent_id: AgentId,
    provider_id: ModelProviderId,
    goal: GoalTemplate,
    inputs: Mapping,
    purpose: IntentEnvelope,
    tools: Vec<ToolName>,
    approval_classes: Vec<ActionClass>,
    max_steps: u32,
    spend_cap: Restriction<Spend>,
    ask_past: Restriction<Spend>,
    checks: Checks,
}

impl AgentRunStep {
    /// An agent run step.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] for a step cap outside `1..=MAX_AGENT_STEPS`,
    /// duplicate tools or approval classes, a zero spend cap or approval threshold,
    /// a threshold at or above the cap, or a reviewer given tools.
    pub fn new(params: AgentRunParams) -> Result<Self, DomainError> {
        validate_range("max_steps", params.max_steps, 1..=MAX_AGENT_STEPS)?;
        ensure_spend_bounds(&params)?;
        ensure_tools(&params)?;
        if first_repeat(&params.approval_classes).is_some() {
            return Err(DomainError::invalid(message!(
                "workflows-an-approval-class-is-named-twice",
                "an approval class is named twice"
            )));
        }
        Ok(Self {
            agent_id: params.agent_id,
            provider_id: params.provider_id,
            goal: params.goal,
            inputs: params.inputs,
            purpose: params.purpose,
            tools: params.tools,
            approval_classes: params.approval_classes,
            max_steps: params.max_steps,
            spend_cap: params.spend_cap,
            ask_past: params.ask_past,
            checks: params.checks,
        })
    }

    /// Whether it checks an earlier agent step's work.
    #[must_use]
    pub fn checks(&self) -> &Checks {
        &self.checks
    }

    /// The same run, given the fields `inputs` maps from a step's input, as
    /// a code step naming a version that holds an agent gives it.
    #[must_use]
    pub(crate) fn given(self, inputs: Mapping) -> Self {
        Self { inputs, ..self }
    }

    /// The acting agent.
    #[must_use]
    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    /// The model provider.
    #[must_use]
    pub fn provider_id(&self) -> &ModelProviderId {
        &self.provider_id
    }

    /// The instruction, as written.
    #[must_use]
    pub fn goal(&self) -> &GoalTemplate {
        &self.goal
    }

    /// What of the step's input the run is given.
    #[must_use]
    pub fn inputs(&self) -> &Mapping {
        &self.inputs
    }

    /// The purpose envelope.
    #[must_use]
    pub fn purpose(&self) -> &IntentEnvelope {
        &self.purpose
    }

    /// The tools granted to the run.
    #[must_use]
    pub fn tools(&self) -> &[ToolName] {
        &self.tools
    }

    /// The action classes that wait for approval.
    #[must_use]
    pub fn approval_classes(&self) -> &[ActionClass] {
        &self.approval_classes
    }

    /// The run's step cap.
    #[must_use]
    pub fn max_steps(&self) -> u32 {
        self.max_steps
    }

    /// The most the run may spend on its model.
    #[must_use]
    pub fn spend_cap(&self) -> Restriction<Spend> {
        self.spend_cap
    }

    /// What the run may spend before it pauses for a person.
    #[must_use]
    pub fn ask_past(&self) -> Restriction<Spend> {
        self.ask_past
    }
}

/// Refuses a tool named twice, and any tool for a step checking another's
/// work, which reads and judges and does nothing else.
fn ensure_tools(params: &AgentRunParams) -> Result<(), DomainError> {
    if params.checks != Checks::Nothing && !params.tools.is_empty() {
        return Err(DomainError::invalid(message!(
            "workflows-a-step-checking-another-s-work-is",
            "a step checking another's work is given no tool"
        )));
    }
    if first_repeat(&params.tools).is_some() {
        return Err(DomainError::invalid(message!(
            "workflows-a-tool-is-granted-twice",
            "a tool is granted twice"
        )));
    }
    Ok(())
}

/// Refuses a spending cap of nothing, and an amount to ask a person at
/// that is nothing or not below the cap.
fn ensure_spend_bounds(params: &AgentRunParams) -> Result<(), DomainError> {
    if let Restriction::To(cap) = params.spend_cap {
        validate_range("spend_cap", cap.micros(), 1..=u64::MAX)?;
    }
    if let Restriction::To(mark) = params.ask_past {
        validate_range("ask_past", mark.micros(), 1..=below(params.spend_cap))?;
    }
    Ok(())
}

/// The most that is still below `cap`, in millionths.
fn below(cap: Restriction<Spend>) -> u64 {
    cap.limit()
        .map_or(u64::MAX, |cap| cap.micros().saturating_sub(1))
}

/// Where a mapped field's value comes from.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Source {
    /// The value at this path in the step's input. Null when there is none.
    Input(DataPath),
    /// This value, as written.
    Literal(FlowData),
}

/// Fields to build from a step's input.
///
/// Each field is named once. Each comes from a path in the input or from a
/// value written out.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "crate::domains::workflows::stored::MappingWire")
)]
pub struct Mapping {
    fields: Vec<(FieldName, Source)>,
}

impl Mapping {
    /// A mapping of `fields`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it sets more than
    ///   `MAX_MAPPED_FIELDS` fields.
    /// - [`DomainError::Validation`] when it sets one field twice.
    pub fn new(fields: Vec<(FieldName, Source)>) -> Result<Self, DomainError> {
        validate_count("mapped_fields", fields.len(), 0..=MAX_MAPPED_FIELDS)?;
        if let Some(twice) = first_repeat(fields.iter().map(|(name, _)| name)) {
            return Err(DomainError::invalid(message!(
                "workflows-the-field-is-mapped-twice",
                format!("the field {twice} is mapped twice")
            )));
        }
        Ok(Self { fields })
    }

    /// The fields it sets.
    #[must_use]
    pub fn fields(&self) -> &[(FieldName, Source)] {
        &self.fields
    }

    /// The paths in the input it reads.
    #[must_use]
    pub fn paths(&self) -> Vec<&DataPath> {
        self.fields
            .iter()
            .filter_map(|(_, source)| match source {
                Source::Input(path) => Some(path),
                Source::Literal(_) => None,
            })
            .collect()
    }

    /// The map these fields make from `input`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the result is larger or deeper
    ///   than workflow data may be.
    pub fn apply(&self, input: &FlowData) -> Result<FlowData, DomainError> {
        let entries = self
            .fields
            .iter()
            .map(|(name, source)| (name.clone(), Self::resolve(source, input)))
            .collect();
        FlowData::map(entries)
    }

    fn resolve(source: &Source, input: &FlowData) -> FlowData {
        match source {
            Source::Input(path) => input.at(path).cloned().unwrap_or_else(FlowData::null),
            Source::Literal(value) => value.clone(),
        }
    }
}

/// What an approval step among a loop's own steps is asked about.
///
/// Outside a loop an approval is asked once per run whatever it says, and
/// publishing refuses [`WholeLoop`](Self::WholeLoop) there.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Covering {
    /// Each pass asks about its own item. Steps stored before the choice
    /// existed asked this way, so it is what a step names by default.
    #[default]
    EachPass,
    /// One approval, asked before any pass starts, lists every item the
    /// loop will act on. A yes counts once the approver was shown every
    /// item, and then lets every pass through this step.
    WholeLoop,
}

impl Covering {
    /// Whether each pass asks about its own item, which a stored step
    /// leaves unsaid.
    #[must_use]
    pub fn is_each_pass(&self) -> bool {
        *self == Self::EachPass
    }
}

/// A pause until people approve going on.
///
/// It keeps the same rules as an agent's approval:
/// - whoever the execution acts for may not approve it,
/// - an action that may be high-risk needs two different people, each
///   present with a fresh second factor, and neither an author of the
///   workflow,
/// - each approval is for the exact data the approver was shown, not only
///   the summary,
/// - nobody may approve once the decision window has closed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "crate::domains::workflows::stored::ApprovalStepWire")
)]
pub struct WorkflowApprovalStep {
    summary: ApprovalAction,
    action_class: DeclaredAction,
    window: Lifetime,
    also_ask: AlsoAsk,
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Covering::is_each_pass")
    )]
    covers: Covering,
}

impl WorkflowApprovalStep {
    /// Asks people to approve `summary`, an action of `action_class`,
    /// within `window` of the step starting.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the window is longer than
    ///   `MAX_DECISION_WINDOW`.
    pub fn new(
        summary: ApprovalAction,
        action_class: DeclaredAction,
        window: Lifetime,
    ) -> Result<Self, DomainError> {
        if window.duration() > MAX_DECISION_WINDOW {
            return Err(DomainError::invalid(message!(
                "workflows-an-approval-may-stay-open-at",
                format!(
                    "an approval may stay open at most {} days",
                    MAX_DECISION_WINDOW.whole_days()
                )
            )));
        }
        Ok(Self {
            summary,
            action_class,
            window,
            also_ask: AlsoAsk::Nowhere,
            covers: Covering::EachPass,
        })
    }

    /// The step asking in `also_ask` too, beside the platform's inbox.
    #[must_use]
    pub fn also_asking(self, also_ask: AlsoAsk) -> Self {
        Self { also_ask, ..self }
    }

    /// The step asking about what `covers` names, when it sits among a
    /// loop's own steps.
    #[must_use]
    pub fn covering(self, covers: Covering) -> Self {
        Self { covers, ..self }
    }

    /// Whether, inside a loop, it is asked once per pass or once for every
    /// item.
    #[must_use]
    pub fn covers_items(&self) -> Covering {
        self.covers
    }

    /// Where else it asks, beside the platform's inbox.
    #[must_use]
    pub fn also_ask(&self) -> &AlsoAsk {
        &self.also_ask
    }

    /// What the people are asked to approve.
    #[must_use]
    pub fn summary(&self) -> &ApprovalAction {
        &self.summary
    }

    /// The class of what follows.
    #[must_use]
    pub fn action_class(&self) -> DeclaredAction {
        self.action_class
    }

    /// How long after the step starts it may be approved.
    #[must_use]
    pub fn window(&self) -> Lifetime {
        self.window
    }

    /// Whether this approval covers an action of `effect`.
    ///
    /// It does when it declares that class, or declares none, which counts
    /// as the riskiest. An undeclared action is covered only by an approval
    /// that declares nothing either. So people are never shown a label that
    /// could mislead them.
    #[must_use]
    pub fn covers(&self, effect: DeclaredAction) -> bool {
        match (self.action_class, effect) {
            (DeclaredAction::Undeclared, _) => true,
            (DeclaredAction::Declared(class), DeclaredAction::Declared(guarded)) => {
                class == guarded
            }
            (DeclaredAction::Declared(_), DeclaredAction::Undeclared) => false,
        }
    }

    /// How many different people must approve. Two when what follows may
    /// be high-risk, one otherwise.
    #[must_use]
    pub fn approvers_needed(&self) -> u8 {
        if self.action_class.may_be_high_risk() {
            return 2;
        }
        1
    }

    /// Whether each approver must prove they are present with a fresh
    /// second factor. It applies exactly when two approvers are needed.
    #[must_use]
    pub fn needs_presence(&self) -> bool {
        self.action_class.may_be_high_risk()
    }
}

/// When a wait ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaitUntil {
    /// Once this long has passed.
    Elapsed(Lifetime),
    /// Once these working hours have begun: at once when they are on.
    WorkingHours(WorkingHours),
}

/// A pause for a set time, or until working hours.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(
        into = "crate::domains::workflows::stored::WaitStepWire",
        try_from = "crate::domains::workflows::stored::WaitStepWire"
    )
)]
pub struct WaitStep {
    until: WaitUntil,
}

impl WaitStep {
    /// Waits for `duration`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it is longer than `MAX_WAIT`.
    pub fn new(duration: Lifetime) -> Result<Self, DomainError> {
        if duration.duration() > MAX_WAIT {
            return Err(DomainError::invalid(message!(
                "workflows-a-workflow-may-wait-at-most",
                format!(
                    "a workflow may wait at most {} days in one step",
                    MAX_WAIT.whole_days()
                )
            )));
        }
        Ok(Self {
            until: WaitUntil::Elapsed(duration),
        })
    }

    /// Waits until `hours` are on.
    #[must_use]
    pub fn for_working_hours(hours: WorkingHours) -> Self {
        Self {
            until: WaitUntil::WorkingHours(hours),
        }
    }

    /// When it ends.
    #[must_use]
    pub fn until(&self) -> &WaitUntil {
        &self.until
    }
}

/// What a step does.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum NodeKind {
    /// Starts a governed agent run.
    AgentRun(AgentRunStep),
    /// Calls one operation of an integration.
    Action(ActionStep),
    /// Decides which way to go on.
    Condition(ConditionRule),
    /// Builds new data from its input.
    Transform(Mapping),
    /// Waits for a person's approval.
    Approval(WorkflowApprovalStep),
    /// Waits for a set time.
    Wait(WaitStep),
    /// Runs a group of steps once for each item of a list.
    Loop(LoopStep),
    /// Runs a sandbox version's code.
    Code(CodeStep),
    /// Checks a text from an earlier step before the workflow goes on.
    Guardrail(GuardrailStep),
}

impl NodeKind {
    /// A stable name for the kind of step.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AgentRun(_) => "agent_run",
            Self::Action(_) => "action",
            Self::Condition(_) => "condition",
            Self::Transform(_) => "transform",
            Self::Approval(_) => "approval",
            Self::Wait(_) => "wait",
            Self::Loop(_) => "loop",
            Self::Code(_) => "code",
            Self::Guardrail(_) => "guardrail",
        }
    }

    /// Every path a step of this kind reads its input at.
    ///
    /// A loop's own steps read the data each pass starts with, not this
    /// step's input, so only the paths the loop itself reads are here.
    #[must_use]
    pub fn input_paths(&self) -> Vec<&DataPath> {
        match self {
            Self::AgentRun(step) => step.inputs().paths(),
            Self::Action(step) => step.inputs().paths(),
            Self::Transform(mapping) => mapping.paths(),
            Self::Condition(rule) => rule.clauses().iter().map(Clause::path).collect(),
            Self::Loop(step) => step.paths(),
            Self::Code(step) => step.inputs().paths(),
            Self::Guardrail(step) => vec![step.text()],
            Self::Approval(_) | Self::Wait(_) => Vec::new(),
        }
    }

    /// The ways out of a step of this kind.
    #[must_use]
    pub fn ports(&self) -> &'static [Port] {
        match self {
            Self::Condition(_) => &[Port::WhenTrue, Port::WhenFalse],
            Self::AgentRun(_)
            | Self::Action(_)
            | Self::Transform(_)
            | Self::Approval(_)
            | Self::Wait(_)
            | Self::Loop(_)
            | Self::Code(_)
            | Self::Guardrail(_) => &[Port::Next],
        }
    }

    /// Who does a step of this kind's work.
    #[must_use]
    pub fn work(&self) -> Work {
        match self {
            Self::Condition(_) | Self::Transform(_) => Work::InTheDomain,
            Self::AgentRun(_)
            | Self::Action(_)
            | Self::Approval(_)
            | Self::Wait(_)
            | Self::Loop(_)
            | Self::Code(_)
            | Self::Guardrail(_) => Work::Outside,
        }
    }

    /// The steps a loop runs for each item. `None` for every other kind.
    #[must_use]
    pub fn body(&self) -> Option<&WorkflowGraph> {
        match self {
            Self::Loop(step) => Some(step.body()),
            Self::AgentRun(_)
            | Self::Action(_)
            | Self::Condition(_)
            | Self::Transform(_)
            | Self::Approval(_)
            | Self::Wait(_)
            | Self::Code(_)
            | Self::Guardrail(_) => None,
        }
    }
}

/// Who does a step's work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    /// The domain, from the step's input alone, the moment it is ready.
    InTheDomain,
    /// Something outside the domain, which reports back how it went. That
    /// is an agent run, an integration, a person, a timer, the passes of a
    /// loop, a sandbox running code, or a guardrail reading the tenant's
    /// classification rules.
    Outside,
}

/// How a step with several steps before it waits for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Join {
    /// It starts once every step before it has finished, and runs if at
    /// least one of them led to it.
    All,
    /// It starts as soon as one step before it leads to it.
    Any,
}

/// One step of a workflow.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Node {
    key: NodeKey,
    name: Label,
    kind: NodeKind,
    join: Join,
}

impl Node {
    /// A step named `key` in its workflow and `name` for people.
    #[must_use]
    pub fn new(key: NodeKey, name: Label, kind: NodeKind, join: Join) -> Self {
        Self {
            key,
            name,
            kind,
            join,
        }
    }

    /// Its key in the workflow.
    #[must_use]
    pub fn key(&self) -> &NodeKey {
        &self.key
    }

    /// Its name for people.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// What it does.
    #[must_use]
    pub fn kind(&self) -> &NodeKind {
        &self.kind
    }

    /// How it waits for the steps before it.
    #[must_use]
    pub fn join(&self) -> Join {
        self.join
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::design::condition::{Clause, Matching, Test};

    fn field(name: &str) -> FieldName {
        FieldName::new(name).unwrap()
    }

    fn approval_of(class: DeclaredAction) -> WorkflowApprovalStep {
        WorkflowApprovalStep::new(
            ApprovalAction::new("pay the invoice").unwrap(),
            class,
            Lifetime::seconds(3600).unwrap(),
        )
        .unwrap()
    }

    /// Approving a payment, or an action that does not say what it is,
    /// needs two people, each present with a fresh second factor. Approving
    /// a message needs one person and no presence check.
    #[test]
    fn an_approval_that_may_be_high_risk_needs_two_present_people() {
        let risky = [
            DeclaredAction::Declared(ActionClass::Financial),
            DeclaredAction::Undeclared,
        ];
        let message = approval_of(DeclaredAction::Declared(ActionClass::Communicate));

        for class in risky {
            let approval = approval_of(class);
            assert_eq!(approval.approvers_needed(), 2);
            assert!(approval.needs_presence());
        }
        assert_eq!(message.approvers_needed(), 1);
        assert!(!message.needs_presence());
    }

    /// An approval step that stays open one second past
    /// [`MAX_DECISION_WINDOW`] is refused. What made an action safe to
    /// approve may be gone a week later.
    #[test]
    fn an_approval_may_stay_open_at_most_its_longest_window() {
        let too_long = WorkflowApprovalStep::new(
            ApprovalAction::new("pay the invoice").unwrap(),
            DeclaredAction::Undeclared,
            Lifetime::new(MAX_DECISION_WINDOW + Duration::SECOND).unwrap(),
        );

        assert!(matches!(too_long, Err(DomainError::Validation(_))));
    }

    /// The key `fetch-orders` is also the field its output is found under.
    /// The key `trigger` is refused, since it names the trigger's data, and
    /// so are `Fetch` and an empty key.
    #[test]
    fn a_node_key_is_its_field_and_trigger_is_kept_for_the_trigger() {
        let key = NodeKey::new("fetch-orders").unwrap();

        assert_eq!(key.as_field().as_str(), "fetch-orders");
        assert!(NodeKey::new(TRIGGER_FIELD).is_err());
        assert!(NodeKey::new("Fetch").is_err());
        assert!(NodeKey::new("").is_err());
    }

    /// A mapping takes `id` from `order.id`, `missing` from `order.note`
    /// and sets `channel` to "email". The order has no note, so `missing`
    /// comes out null.
    #[test]
    fn a_mapping_builds_fields_from_paths_and_values() {
        let mapping = order_mapping();
        let input = FlowData::map(vec![(
            field("order"),
            FlowData::map(vec![(field("id"), FlowData::text("o-1").unwrap())]).unwrap(),
        )])
        .unwrap();

        let out = mapping.apply(&input).unwrap();

        assert_eq!(
            out.at(&DataPath::parse("id").unwrap()),
            Some(&FlowData::text("o-1").unwrap())
        );
        assert_eq!(
            out.at(&DataPath::parse("missing").unwrap()),
            Some(&FlowData::null())
        );
        assert_eq!(
            out.at(&DataPath::parse("channel").unwrap()),
            Some(&FlowData::text("email").unwrap())
        );
    }

    /// Maps two order paths and a literal delivery channel without filling absent input.
    fn order_mapping() -> Mapping {
        Mapping::new(vec![
            (
                field("id"),
                Source::Input(DataPath::parse("order.id").unwrap()),
            ),
            (
                field("missing"),
                Source::Input(DataPath::parse("order.note").unwrap()),
            ),
            (
                field("channel"),
                Source::Literal(FlowData::text("email").unwrap()),
            ),
        ])
        .unwrap()
    }

    /// A mapping that sets `id` twice is refused, since the second would
    /// silently win.
    #[test]
    fn a_mapping_setting_a_field_twice_is_refused() {
        let twice = Mapping::new(vec![
            (field("id"), Source::Literal(FlowData::null())),
            (field("id"), Source::Literal(FlowData::null())),
        ]);

        assert!(twice.is_err());
    }

    /// A wait of one minute is allowed. A wait one second past
    /// [`MAX_WAIT`] is refused.
    #[test]
    fn a_wait_longer_than_any_may_be_is_refused() {
        assert!(WaitStep::new(Lifetime::seconds(60).unwrap()).is_ok());
        assert!(WaitStep::new(Lifetime::new(MAX_WAIT + Duration::SECOND).unwrap()).is_err());
    }

    /// A condition has the ways out "when true" and "when false", and its
    /// work is done in the domain. A transform has only `Next`.
    #[test]
    fn only_a_condition_has_two_ways_out() {
        let rule = ConditionRule::new(
            Matching::All,
            vec![Clause::new(DataPath::parse("ok").unwrap(), Test::Exists).unwrap()],
        )
        .unwrap();
        let transform =
            Mapping::new(vec![(field("a"), Source::Literal(FlowData::null()))]).unwrap();

        assert_eq!(
            NodeKind::Condition(rule.clone()).ports(),
            [Port::WhenTrue, Port::WhenFalse]
        );
        assert_eq!(NodeKind::Transform(transform).ports(), [Port::Next]);
        assert_eq!(NodeKind::Condition(rule).work(), Work::InTheDomain);
    }
}
