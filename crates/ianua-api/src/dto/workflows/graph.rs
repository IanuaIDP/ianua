//! A workflow's steps, edges and trigger on the wire.
//!
//! A workflow read from the API can be sent back as it came: every body
//! here is both what a client writes and what it reads.

use std::collections::BTreeMap;

use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
use ianua_domain::domains::agents::execution::run::GoalTemplate;
use ianua_domain::domains::agents::execution::tool::ToolName;
use ianua_domain::domains::agents::oversight::approval::ApprovalAction;
use ianua_domain::domains::workflows::data::{DataPath, FieldName};
use ianua_domain::domains::workflows::design::also_ask::{AlsoAsk, SlackAsk, SlackChannel};
use ianua_domain::domains::workflows::design::condition::{Clause, ConditionRule, Matching, Test};
use ianua_domain::domains::workflows::design::graph::{Edge, WorkflowGraph};
use ianua_domain::domains::workflows::design::node::{
    AgentRunParams, AgentRunStep, Checks, CodeStep, Covering, Join, LoopParams, LoopStep, Mapping,
    Node, NodeKey, NodeKind, Port, Source, WaitStep, WaitUntil, WorkflowApprovalStep,
};
use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
use ianua_domain::domains::workflows::integration::{
    AccountNeed, ActionAccount, ActionStep, InputNeed, InputSpec, IntegrationKey, OperationKey,
    OperationSpec, OperationSpecParams,
};
use ianua_domain::domains::workflows::triggers::before::GuardedChange;
use ianua_domain::domains::workflows::triggers::{
    CronSchedule, EventFilter, EventTrigger, FilterValue, ServiceTrigger, Trigger,
};
use ianua_domain::message;
use ianua_domain::types::{
    ActionClass, AgentId, EventType, IntegrationAccountId, Label, Lifetime, ModelProviderId,
    SandboxVersionId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::dto::agents::runs::{amount, micros_of};
use crate::dto::workflows::data::{action_class, data_class, declared_action, flow_data, json_of};
use crate::dto::workflows::guardrail::{
    GuardrailCheckBody, GuardrailClaim, OnFindingBody, confidential,
};
use crate::dto::workflows::hours::WorkingHoursBody;
use crate::error::ApiError;

/// A workflow's steps and the edges between them.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct GraphBody {
    /// The steps, each with a key unique in the workflow.
    pub nodes: Vec<NodeBody>,
    /// The ways from one step to the next.
    #[serde(default)]
    pub edges: Vec<EdgeBody>,
}

/// One step.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct NodeBody {
    /// Its key: lowercase letters, digits, `-` and `_`, never `trigger`.
    /// Later steps find its output under it.
    pub key: String,
    /// Its name for people.
    pub name: String,
    /// How it waits for several steps before it: `all` (the default) or
    /// `any`.
    #[serde(default)]
    pub join: JoinBody,
    /// What it does, named by `kind`.
    #[serde(flatten)]
    pub step: StepBody,
}

/// How a step waits for the steps before it.
#[derive(Serialize, Deserialize, utoipa::ToSchema, Default, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub(crate) enum JoinBody {
    /// Once every step before it finished.
    #[default]
    All,
    /// As soon as one step before it leads to it.
    Any,
}

/// What a step does.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum StepBody {
    /// A governed agent run.
    AgentRun {
        /// The acting agent.
        agent_id: Uuid,
        /// The model provider it reasons with.
        provider_id: Uuid,
        /// The instruction, before the mapped inputs are added to it.
        goal: String,
        /// What of the step's input the run is given.
        #[serde(default)]
        inputs: Vec<MappedFieldBody>,
        /// The action classes its tool calls may take, such as `read`.
        #[serde(default)]
        purpose: Vec<String>,
        /// The tools it may call. None when empty.
        #[serde(default)]
        tools: Vec<String>,
        /// Action classes whose tool calls wait for a person's approval.
        #[serde(default)]
        approval_classes: Vec<String>,
        /// The most steps the run may take.
        max_steps: u32,
        /// The most the run may spend on its model, in millionths of the
        /// tenant's billing currency. Once spent, the run stops and the
        /// step fails as over budget. Left out for no limit.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        spend_cap_micros: Option<u64>,
        /// What the run may spend before it pauses for a person to let it
        /// go on, in the same millionths; below the cap when both are set.
        /// Left out for no pause.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ask_past_micros: Option<u64>,
        /// The key of an earlier agent step, run by another agent, whose
        /// work this run checks. Its answer then starts with `OK` or
        /// `NOT OK`, and the step hands on `verdict` (`ok`, `not_ok` or
        /// `unclear`) and `notes`. A checking step is given no tool. Left
        /// out for a run doing its own work.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        checks: Option<String>,
    },
    /// One call of an integration's operation.
    Action {
        /// The integration, such as `google-sheets`.
        integration: String,
        /// The operation, such as `append-row`.
        operation: String,
        /// The tenant's account it acts through, or `null` for none.
        account_id: Option<Uuid>,
        /// How the operation's inputs are built from the step's input.
        #[serde(default)]
        inputs: Vec<MappedFieldBody>,
        /// The kind of action the operation takes: `undeclared` or an
        /// action class. Checked against the catalog at publish.
        effect: String,
        /// The most sensitive data the operation may be handed, such as
        /// `internal`. Checked against the catalog at publish.
        ceiling: String,
    },
    /// Decides which way to go on: `when_true` or `when_false`.
    Condition {
        /// Whether `all` clauses must hold, or `any` one.
        matching: MatchingBody,
        /// What is asked of the step's input.
        clauses: Vec<ClauseBody>,
    },
    /// Builds new data from the step's input.
    Transform {
        /// The fields it sets.
        fields: Vec<MappedFieldBody>,
    },
    /// Waits for people's approval.
    Approval {
        /// What they are asked to approve.
        summary: String,
        /// The class of what follows: `undeclared` or an action class.
        action_class: String,
        /// How long after the step starts it may be decided, in seconds.
        window_seconds: i64,
        /// A Slack channel it also asks in, through a connected Slack
        /// account. The message's buttons only open the approval in ianua.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        slack: Option<SlackAskBody>,
        /// Among a loop's steps, `each_pass` (the default) asks once per
        /// item; `whole_loop`, only as the loop's first step, asks once,
        /// listing every item, before any pass starts.
        #[serde(default, skip_serializing_if = "CoveringBody::is_each_pass")]
        covers: CoveringBody,
    },
    /// Waits for a set time, or until working hours begin: exactly one of
    /// the two is given.
    Wait {
        /// How long, in seconds; left out when it waits for working hours.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_seconds: Option<i64>,
        /// The working hours it waits for, going on at once while they are
        /// on; left out when it waits a set time.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        working_hours: Option<WorkingHoursBody>,
    },
    /// Runs its own steps once for each item of a list, each pass a run of
    /// its own. A step inside finds its item at `trigger.item`, its
    /// position from zero at `trigger.index`, and the mapped `inputs` at
    /// `trigger.<field>`. It gives back the list of what each pass gave
    /// back: the output of each of its last steps, under their keys.
    Loop {
        /// Where the list is in the step's input, such as `search.issues`.
        over: String,
        /// What else of the step's input each pass is given.
        #[serde(default)]
        inputs: Vec<MappedFieldBody>,
        /// The steps each pass runs, with keys unique in the workflow. They
        /// hold no loop of their own.
        #[schema(no_recursion)]
        steps: GraphBody,
        /// The most items the list may hold, at most 1000. A longer list
        /// fails the step without running any pass.
        most_items: u32,
        /// How many passes run at the same time, from 1 to 10.
        #[serde(default = "StepBody::one_at_a_time")]
        at_once: u32,
    },
    /// Runs one sandbox version's code in a sandbox with no network,
    /// handing it the mapped `inputs` as one JSON object. What the code
    /// gives back is the step's output. The version must be built, and its
    /// sandbox not archived, when the workflow is published.
    Code {
        /// The sandbox version whose code runs.
        sandbox_version_id: Uuid,
        /// What of the step's input the code is given.
        #[serde(default)]
        inputs: Vec<MappedFieldBody>,
    },
    /// Checks a text from an earlier step before the run goes on. It hands
    /// on `checked` (the value it checked, with its findings taken out when
    /// it removes them), `findings` (each one's `kind`, `check`, `field`,
    /// `start` and `length`, never the text it matched) and `found` (how
    /// many in all). Rules that cannot be read, or nothing where `text`
    /// points, stop the run whatever `on_finding` says. Publishing refuses
    /// a `text` that starts at a condition, approval or wait, which hand
    /// nothing on.
    Guardrail {
        /// Where the text is in the step's input, such as `draft.answer`.
        text: String,
        /// The checks it runs, each once, at least one.
        checks: Vec<GuardrailCheckBody>,
        /// The least sensitive classification level a field counts as
        /// personal data at: `internal`, `confidential` (the default) or
        /// `restricted`.
        #[serde(default = "confidential")]
        personal_from: String,
        /// The words and phrases it bans, matched as whole words in any
        /// case; given exactly when it checks `banned_words`, at most 200.
        #[serde(default)]
        banned_words: Vec<String>,
        /// What a finding does: `stop` (the default), `remove` or `record`.
        #[serde(default)]
        on_finding: OnFindingBody,
    },
}

/// What an approval among a loop's steps asks about.
#[derive(Serialize, Deserialize, utoipa::ToSchema, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoveringBody {
    /// Each pass asks about its own item; a step written without saying
    /// asks this way.
    #[default]
    EachPass,
    /// One approval listing every item, before any pass starts.
    WholeLoop,
}

impl CoveringBody {
    /// Whether it asks once per pass, which the wire leaves unsaid.
    fn is_each_pass(&self) -> bool {
        *self == Self::EachPass
    }
}

impl From<CoveringBody> for Covering {
    fn from(body: CoveringBody) -> Self {
        match body {
            CoveringBody::EachPass => Self::EachPass,
            CoveringBody::WholeLoop => Self::WholeLoop,
        }
    }
}

impl From<Covering> for CoveringBody {
    fn from(covering: Covering) -> Self {
        match covering {
            Covering::EachPass => Self::EachPass,
            Covering::WholeLoop => Self::WholeLoop,
        }
    }
}

/// Whether every clause must hold, or any one.
#[derive(Serialize, Deserialize, utoipa::ToSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MatchingBody {
    /// Every clause.
    All,
    /// Any one clause.
    Any,
}

/// One field a mapping sets.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct MappedFieldBody {
    /// The field it sets.
    pub field: String,
    /// Where its value comes from, named by `from`.
    #[serde(flatten)]
    pub source: SourceBody,
}

/// Where a mapped field's value comes from.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "from", rename_all = "snake_case")]
pub(crate) enum SourceBody {
    /// The value at a path in the step's input, such as `trigger.order.id`.
    Input {
        /// The path, as steps between dots.
        path: String,
    },
    /// A value written out.
    Literal {
        /// The JSON constant copied into the mapped field.
        #[schema(value_type = Object)]
        value: Value,
    },
}

/// One thing a condition asks of the step's input.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct ClauseBody {
    /// Where the value is, as steps between dots.
    pub path: String,
    /// What is asked of it, named by `test`.
    #[serde(flatten)]
    pub test: TestBody,
}

/// What a clause asks of the value at its path.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "test", rename_all = "snake_case")]
pub(crate) enum TestBody {
    /// There is a value, even null.
    Exists,
    /// There is no value, or it is empty.
    IsEmpty,
    /// The value is this one.
    Equals {
        /// The JSON constant the input must equal.
        #[schema(value_type = Object)]
        value: Value,
    },
    /// The value is not this one.
    NotEquals {
        /// The JSON constant the input must differ from.
        #[schema(value_type = Object)]
        value: Value,
    },
    /// The value is text containing this, or a list holding it.
    Contains {
        /// The text.
        value: String,
    },
    /// The value is a number greater than this.
    GreaterThan {
        /// The bound.
        value: f64,
    },
    /// The value is a number less than this.
    LessThan {
        /// The bound.
        value: f64,
    },
}

/// A way from one step to the next.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct EdgeBody {
    /// The step it leaves.
    pub from: String,
    /// The way out it leaves by: `next`, `when_true` or `when_false`.
    #[serde(default = "EdgeBody::next")]
    pub port: String,
    /// The step it leads to.
    pub to: String,
}

/// What starts a workflow, named by `type`.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum TriggerBody {
    /// A person starts it.
    Manual,
    /// A schedule starts it.
    Schedule {
        /// The cron expression.
        cron: String,
    },
    /// A call to its webhook starts it.
    Webhook,
    /// An event in the tenant starts it.
    Event {
        /// The event, as it is published, such as `identity.user_registered`.
        event: String,
    },
    /// An event an integration's service sends starts it, such as an issue
    /// opened at GitHub, registered at the service through one of the
    /// tenant's accounts when the version is published.
    Service {
        /// The integration whose service sends it, such as `github`.
        integration: String,
        /// The event, such as `issue-opened`.
        event: String,
        /// The account the registration is made through.
        account_id: Uuid,
        /// The event's filters by name, such as `{"repository": "acme/web"}`.
        #[serde(default)]
        filters: BTreeMap<String, String>,
    },
    /// A change about to happen starts it, and every way through it ends
    /// in the company step `allow` or `refuse`, which the change waits for.
    Before {
        /// `access_given`, `admin_given`, `app_opened_to_workflows` or
        /// `audit_exported`.
        change: String,
    },
}

impl EdgeBody {
    /// The port an edge leaves from when the body names none.
    fn next() -> String {
        Port::Next.as_str().to_owned()
    }
}

impl TryFrom<GraphBody> for WorkflowGraph {
    type Error = ApiError;

    fn try_from(body: GraphBody) -> Result<Self, ApiError> {
        let nodes = body
            .nodes
            .into_iter()
            .map(Node::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let edges = body
            .edges
            .iter()
            .map(EdgeBody::edge)
            .collect::<Result<Vec<_>, _>>()?;
        WorkflowGraph::new(nodes, edges).map_err(ApiError::validation)
    }
}

impl From<&WorkflowGraph> for GraphBody {
    fn from(graph: &WorkflowGraph) -> Self {
        Self {
            nodes: graph.nodes().iter().map(NodeBody::from).collect(),
            edges: graph.edges().iter().map(EdgeBody::from).collect(),
        }
    }
}

impl TryFrom<NodeBody> for Node {
    type Error = ApiError;

    fn try_from(body: NodeBody) -> Result<Self, ApiError> {
        let key = node_key(&body.key)?;
        let name = Label::new("name", body.name).map_err(ApiError::validation)?;
        Ok(Node::new(key, name, body.step.kind()?, body.join.into()))
    }
}

impl From<&Node> for NodeBody {
    fn from(node: &Node) -> Self {
        Self {
            key: node.key().as_str().to_owned(),
            name: node.name().as_str().to_owned(),
            join: node.join().into(),
            step: StepBody::from(node.kind()),
        }
    }
}

impl From<JoinBody> for Join {
    fn from(body: JoinBody) -> Self {
        match body {
            JoinBody::All => Self::All,
            JoinBody::Any => Self::Any,
        }
    }
}

impl From<Join> for JoinBody {
    fn from(join: Join) -> Self {
        match join {
            Join::All => Self::All,
            Join::Any => Self::Any,
        }
    }
}

impl From<MatchingBody> for Matching {
    fn from(body: MatchingBody) -> Self {
        match body {
            MatchingBody::All => Self::All,
            MatchingBody::Any => Self::Any,
        }
    }
}

impl From<Matching> for MatchingBody {
    fn from(matching: Matching) -> Self {
        match matching {
            Matching::All => Self::All,
            Matching::Any => Self::Any,
        }
    }
}

impl StepBody {
    /// The step this body describes.
    /// Keeps the exhaustive wire variants and their ordered field validation together.
    #[allow(clippy::too_many_lines)]
    fn kind(self) -> Result<NodeKind, ApiError> {
        match self {
            Self::AgentRun {
                agent_id,
                provider_id,
                goal,
                inputs,
                purpose,
                tools,
                approval_classes,
                max_steps,
                spend_cap_micros,
                ask_past_micros,
                checks,
            } => agent_run(AgentRunParams {
                agent_id: AgentId::from_uuid(agent_id),
                provider_id: ModelProviderId::from_uuid(provider_id),
                goal: GoalTemplate::new(goal).map_err(ApiError::validation)?,
                inputs: mapping(inputs)?,
                purpose: IntentEnvelope::new(classes(&purpose)?),
                tools: tool_names(tools)?,
                approval_classes: classes(&approval_classes)?,
                max_steps,
                spend_cap: amount(spend_cap_micros),
                ask_past: amount(ask_past_micros),
                checks: checked(checks)?,
            }),
            Self::Action {
                integration,
                operation,
                account_id,
                inputs,
                effect,
                ceiling,
            } => action(
                OperationClaim {
                    integration,
                    operation,
                    effect,
                    ceiling,
                },
                account_id,
                inputs,
            ),
            Self::Condition { matching, clauses } => condition(matching, clauses),
            Self::Transform { fields } => Ok(NodeKind::Transform(mapping(fields)?)),
            Self::Approval {
                summary,
                action_class,
                window_seconds,
                slack,
                covers,
            } => approval(&summary, &action_class, window_seconds, slack)
                .map(|step| NodeKind::Approval(step.covering(covers.into()))),
            Self::Wait {
                duration_seconds,
                working_hours,
            } => Ok(NodeKind::Wait(wait(duration_seconds, working_hours)?)),
            Self::Loop {
                over,
                inputs,
                steps,
                most_items,
                at_once,
            } => looping(LoopParams {
                over: DataPath::parse(&over).map_err(ApiError::validation)?,
                inputs: mapping(inputs)?,
                body: WorkflowGraph::try_from(steps)?,
                most: most_items,
                at_once,
            }),
            Self::Code {
                sandbox_version_id,
                inputs,
            } => Ok(NodeKind::Code(CodeStep::new(
                SandboxVersionId::from_uuid(sandbox_version_id),
                mapping(inputs)?,
            ))),
            Self::Guardrail {
                text,
                checks,
                personal_from,
                banned_words,
                on_finding,
            } => GuardrailClaim {
                text,
                checks,
                personal_from,
                banned_words,
                on_finding,
            }
            .kind(),
        }
    }

    /// The passes a loop runs at once when the body names no number.
    fn one_at_a_time() -> u32 {
        1
    }
}

impl From<&NodeKind> for StepBody {
    fn from(kind: &NodeKind) -> Self {
        match kind {
            NodeKind::AgentRun(step) => Self::from(step),
            NodeKind::Action(step) => Self::from(step),
            NodeKind::Condition(rule) => Self::Condition {
                matching: rule.matching().into(),
                clauses: rule.clauses().iter().map(ClauseBody::from).collect(),
            },
            NodeKind::Transform(fields) => Self::Transform {
                fields: mapped_fields(fields),
            },
            NodeKind::Approval(step) => Self::from(step),
            NodeKind::Wait(step) => Self::from(step),
            NodeKind::Loop(step) => Self::Loop {
                over: step.over().to_string(),
                inputs: mapped_fields(step.inputs()),
                steps: GraphBody::from(step.body()),
                most_items: step.most(),
                at_once: step.at_once(),
            },
            NodeKind::Code(step) => Self::Code {
                sandbox_version_id: *step.version().as_uuid(),
                inputs: mapped_fields(step.inputs()),
            },
            NodeKind::Guardrail(step) => Self::from(step),
        }
    }
}

impl From<&WorkflowApprovalStep> for StepBody {
    fn from(step: &WorkflowApprovalStep) -> Self {
        Self::Approval {
            summary: step.summary().as_str().to_owned(),
            action_class: step.action_class().as_str().to_owned(),
            window_seconds: step.window().whole_seconds(),
            slack: SlackAskBody::of(step.also_ask()),
            covers: step.covers_items().into(),
        }
    }
}

impl From<&AgentRunStep> for StepBody {
    fn from(step: &AgentRunStep) -> Self {
        Self::AgentRun {
            agent_id: *step.agent_id().as_uuid(),
            provider_id: *step.provider_id().as_uuid(),
            goal: step.goal().as_str().to_owned(),
            inputs: mapped_fields(step.inputs()),
            purpose: class_names(step.purpose().allowed()),
            tools: step
                .tools()
                .iter()
                .map(|tool| tool.as_str().to_owned())
                .collect(),
            approval_classes: class_names(step.approval_classes()),
            max_steps: step.max_steps(),
            spend_cap_micros: micros_of(step.spend_cap()),
            ask_past_micros: micros_of(step.ask_past()),
            checks: match step.checks() {
                Checks::Nothing => None,
                Checks::Step(key) => Some(key.as_str().to_owned()),
            },
        }
    }
}

impl From<&ActionStep> for StepBody {
    fn from(step: &ActionStep) -> Self {
        Self::Action {
            integration: step.integration().as_str().to_owned(),
            operation: step.operation().as_str().to_owned(),
            account_id: match step.account() {
                ActionAccount::Account(id) => Some(*id.as_uuid()),
                ActionAccount::NoAccount => None,
            },
            inputs: mapped_fields(step.inputs()),
            effect: step.effect().as_str().to_owned(),
            ceiling: step.ceiling().as_str().to_owned(),
        }
    }
}

impl From<&WaitStep> for StepBody {
    fn from(step: &WaitStep) -> Self {
        match step.until() {
            WaitUntil::Elapsed(duration) => Self::Wait {
                duration_seconds: Some(duration.duration().whole_seconds()),
                working_hours: None,
            },
            WaitUntil::WorkingHours(hours) => Self::Wait {
                duration_seconds: None,
                working_hours: Some(WorkingHoursBody::from(hours)),
            },
        }
    }
}

/// What an action step's body says of the operation it calls.
struct OperationClaim {
    integration: String,
    operation: String,
    effect: String,
    ceiling: String,
}

impl OperationClaim {
    /// The operation as claimed, taking every field `inputs` maps.
    ///
    /// Publishing checks the step against the catalog as it stands then, so
    /// a draft whose claim the catalog does not bear out is never
    /// published.
    fn spec(self, inputs: &Mapping, account: ActionAccount) -> Result<OperationSpec, ApiError> {
        OperationSpec::new(OperationSpecParams {
            integration: IntegrationKey::new(self.integration).map_err(ApiError::validation)?,
            operation: OperationKey::new(self.operation).map_err(ApiError::validation)?,
            inputs: inputs
                .fields()
                .iter()
                .map(|(name, _)| InputSpec::new(name.clone(), InputNeed::Optional))
                .collect(),
            effect: declared_action(&self.effect)?,
            account: match account {
                ActionAccount::Account(_) => AccountNeed::Account,
                ActionAccount::NoAccount => AccountNeed::NoAccount,
            },
            ceiling: data_class(&self.ceiling)?,
        })
        .map_err(ApiError::validation)
    }
}

/// An agent run step, refused when its settings are not valid.
fn agent_run(params: AgentRunParams) -> Result<NodeKind, ApiError> {
    AgentRunStep::new(params)
        .map(NodeKind::AgentRun)
        .map_err(ApiError::validation)
}

/// An action step for the claimed operation, run with the account named
/// or none, fed from the mapped inputs.
fn action(
    claim: OperationClaim,
    account_id: Option<Uuid>,
    inputs: Vec<MappedFieldBody>,
) -> Result<NodeKind, ApiError> {
    let account = account_id.map_or(ActionAccount::NoAccount, |id| {
        ActionAccount::Account(IntegrationAccountId::from_uuid(id))
    });
    let inputs = mapping(inputs)?;
    let spec = claim.spec(&inputs, account)?;
    ActionStep::new(&spec, account, inputs)
        .map(NodeKind::Action)
        .map_err(ApiError::validation)
}

/// A condition step that matches its clauses all or any, refused when a
/// clause is not valid.
fn condition(matching: MatchingBody, clauses: Vec<ClauseBody>) -> Result<NodeKind, ApiError> {
    let clauses = clauses
        .into_iter()
        .map(ClauseBody::clause)
        .collect::<Result<Vec<_>, _>>()?;
    ConditionRule::new(matching.into(), clauses)
        .map(NodeKind::Condition)
        .map_err(ApiError::validation)
}

/// An approval step: what is asked, the class of action it covers and how
/// long the approver has to answer.
fn approval(
    summary: &str,
    class: &str,
    window_seconds: i64,
    slack: Option<SlackAskBody>,
) -> Result<WorkflowApprovalStep, ApiError> {
    let summary = ApprovalAction::new(summary).map_err(ApiError::validation)?;
    let also_ask = slack.map_or(Ok(AlsoAsk::Nowhere), SlackAskBody::into_also_ask)?;
    WorkflowApprovalStep::new(summary, declared_action(class)?, lifetime(window_seconds)?)
        .map(|step| step.also_asking(also_ask))
        .map_err(ApiError::validation)
}

/// A Slack channel an approval also asks in.
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SlackAskBody {
    /// The connected Slack account the message is posted through.
    pub account_id: Uuid,
    /// The channel, by its id or its name with `#`.
    pub channel: String,
}

impl SlackAskBody {
    /// The body `also_ask` is written as; none when it asks nowhere else.
    fn of(also_ask: &AlsoAsk) -> Option<Self> {
        let AlsoAsk::Slack(ask) = also_ask else {
            return None;
        };
        Some(Self {
            account_id: *ask.account().as_uuid(),
            channel: ask.channel().as_str().to_owned(),
        })
    }

    /// Where the body says the approval also asks.
    fn into_also_ask(self) -> Result<AlsoAsk, ApiError> {
        let channel = SlackChannel::new(self.channel).map_err(ApiError::validation)?;
        let account = IntegrationAccountId::from_uuid(self.account_id);
        Ok(AlsoAsk::Slack(SlackAsk::new(account, channel)))
    }
}

/// A loop step, refused when its limits or its steps are not valid.
fn looping(params: LoopParams) -> Result<NodeKind, ApiError> {
    LoopStep::new(params)
        .map(NodeKind::Loop)
        .map_err(ApiError::validation)
}

/// The wait the body describes: a set time, or working hours, exactly one.
fn wait(
    duration_seconds: Option<i64>,
    working_hours: Option<WorkingHoursBody>,
) -> Result<WaitStep, ApiError> {
    match (duration_seconds, working_hours) {
        (Some(seconds), None) => WaitStep::new(lifetime(seconds)?).map_err(ApiError::validation),
        (None, Some(hours)) => Ok(WaitStep::for_working_hours(hours.try_into()?)),
        (Some(_), Some(_)) | (None, None) => Err(ApiError::validation(message!(
            "api-a-wait-takes-a-time-or-working-hours",
            "a wait takes either duration_seconds or working_hours"
        ))),
    }
}

/// A lifetime of so many seconds, refused when it is out of range.
fn lifetime(seconds: i64) -> Result<Lifetime, ApiError> {
    Lifetime::seconds(seconds).map_err(ApiError::validation)
}

/// The node key sent, refused when it is not a valid key.
fn node_key(value: &str) -> Result<NodeKey, ApiError> {
    NodeKey::new(value).map_err(ApiError::validation)
}

/// The step whose work an agent run checks, when it names one.
fn checked(key: Option<String>) -> Result<Checks, ApiError> {
    key.map_or(Ok(Checks::Nothing), |key| Ok(Checks::Step(node_key(&key)?)))
}

/// The action classes the names pick, refused when one is unknown.
pub(crate) fn classes(names: &[String]) -> Result<Vec<ActionClass>, ApiError> {
    names.iter().map(|name| action_class(name)).collect()
}

/// The names of the action classes, as the API sends them.
pub(crate) fn class_names(classes: &[ActionClass]) -> Vec<String> {
    classes
        .iter()
        .map(|class| class.as_str().to_owned())
        .collect()
}

/// The tool names sent, refused when one is not a valid name.
pub(crate) fn tool_names(names: Vec<String>) -> Result<Vec<ToolName>, ApiError> {
    names
        .into_iter()
        .map(|name| ToolName::new(name).map_err(ApiError::validation))
        .collect()
}

/// The mapping the sent fields describe, refused when a field is not valid.
fn mapping(fields: Vec<MappedFieldBody>) -> Result<Mapping, ApiError> {
    let fields = fields
        .into_iter()
        .map(MappedFieldBody::field)
        .collect::<Result<Vec<_>, _>>()?;
    Mapping::new(fields).map_err(ApiError::validation)
}

/// The fields of a mapping, in the shape the API sends.
fn mapped_fields(mapping: &Mapping) -> Vec<MappedFieldBody> {
    mapping
        .fields()
        .iter()
        .map(|(name, source)| MappedFieldBody {
            field: name.as_str().to_owned(),
            source: match source {
                Source::Input(path) => SourceBody::Input {
                    path: path.to_string(),
                },
                Source::Literal(value) => SourceBody::Literal {
                    value: json_of(value),
                },
            },
        })
        .collect()
}

impl MappedFieldBody {
    /// The field name and where its value comes from, refused when either
    /// is not valid.
    fn field(self) -> Result<(FieldName, Source), ApiError> {
        let name = FieldName::new(self.field).map_err(ApiError::validation)?;
        let source = match self.source {
            SourceBody::Input { path } => {
                Source::Input(DataPath::parse(&path).map_err(ApiError::validation)?)
            }
            SourceBody::Literal { value } => Source::Literal(flow_data(&value)?),
        };
        Ok((name, source))
    }
}

impl ClauseBody {
    /// The condition clause this body describes, refused when the path or
    /// the test is not valid.
    fn clause(self) -> Result<Clause, ApiError> {
        let path = DataPath::parse(&self.path).map_err(ApiError::validation)?;
        let test = match self.test {
            TestBody::Exists => Test::Exists,
            TestBody::IsEmpty => Test::IsEmpty,
            TestBody::Equals { value } => Test::Equals(flow_data(&value)?),
            TestBody::NotEquals { value } => Test::NotEquals(flow_data(&value)?),
            TestBody::Contains { value } => Test::Contains(value),
            TestBody::GreaterThan { value } => Test::GreaterThan(value),
            TestBody::LessThan { value } => Test::LessThan(value),
        };
        Clause::new(path, test).map_err(ApiError::validation)
    }
}

impl From<&Clause> for ClauseBody {
    fn from(clause: &Clause) -> Self {
        Self {
            path: clause.path().to_string(),
            test: match clause.test() {
                Test::Exists => TestBody::Exists,
                Test::IsEmpty => TestBody::IsEmpty,
                Test::Equals(value) => TestBody::Equals {
                    value: json_of(value),
                },
                Test::NotEquals(value) => TestBody::NotEquals {
                    value: json_of(value),
                },
                Test::Contains(value) => TestBody::Contains {
                    value: value.clone(),
                },
                Test::GreaterThan(value) => TestBody::GreaterThan { value: *value },
                Test::LessThan(value) => TestBody::LessThan { value: *value },
            },
        }
    }
}

impl EdgeBody {
    /// The edge this body describes, refused when a key or the port is not valid.
    fn edge(&self) -> Result<Edge, ApiError> {
        Ok(Edge::new(
            node_key(&self.from)?,
            port(&self.port)?,
            node_key(&self.to)?,
        ))
    }
}

/// The port a name picks, or a validation error for a name no port has.
fn port(value: &str) -> Result<Port, ApiError> {
    [Port::Next, Port::WhenTrue, Port::WhenFalse]
        .into_iter()
        .find(|port| port.as_str() == value)
        .ok_or_else(|| {
            ApiError::validation(message!(
                "api-unknown-port",
                format!("unknown port: {value}")
            ))
        })
}

impl From<&Edge> for EdgeBody {
    fn from(edge: &Edge) -> Self {
        Self {
            from: edge.from().as_str().to_owned(),
            port: edge.port().as_str().to_owned(),
            to: edge.to().as_str().to_owned(),
        }
    }
}

impl TryFrom<TriggerBody> for Trigger {
    type Error = ApiError;

    fn try_from(body: TriggerBody) -> Result<Self, ApiError> {
        match body {
            TriggerBody::Manual => Ok(Self::Manual),
            TriggerBody::Webhook => Ok(Self::Webhook),
            TriggerBody::Schedule { cron } => CronSchedule::parse(&cron)
                .map(Self::Schedule)
                .map_err(ApiError::validation),
            TriggerBody::Event { event } => {
                let Some(event) = EventType::parse(&event) else {
                    return Err(ApiError::validation(message!(
                        "api-unknown-event",
                        format!("unknown event: {event}")
                    )));
                };
                EventTrigger::new(event)
                    .map(Self::Event)
                    .map_err(ApiError::validation)
            }
            TriggerBody::Service {
                integration,
                event,
                account_id,
                filters,
            } => service_trigger(&integration, &event, account_id, filters).map(Self::Service),
            TriggerBody::Before { change } => GuardedChange::named(&change)
                .map(Self::Before)
                .map_err(ApiError::validation),
        }
    }
}

/// The service trigger a draft's body names.
fn service_trigger(
    integration: &str,
    event: &str,
    account_id: Uuid,
    filters: BTreeMap<String, String>,
) -> Result<ServiceTrigger, ApiError> {
    let filters = filters
        .into_iter()
        .map(|(name, value)| {
            Ok(EventFilter::new(
                FieldName::new(&name).map_err(ApiError::validation)?,
                FilterValue::new(value).map_err(ApiError::validation)?,
            ))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    ServiceTrigger::drafted(
        IntegrationKey::new(integration).map_err(ApiError::validation)?,
        ServiceEventKey::new(event).map_err(ApiError::validation)?,
        IntegrationAccountId::from_uuid(account_id),
        filters,
    )
    .map_err(ApiError::validation)
}

impl From<&Trigger> for TriggerBody {
    fn from(trigger: &Trigger) -> Self {
        match trigger {
            Trigger::Manual => Self::Manual,
            Trigger::Webhook => Self::Webhook,
            Trigger::Schedule(cron) => Self::Schedule {
                cron: cron.as_str().to_owned(),
            },
            Trigger::Event(event) => Self::Event {
                event: event.event().as_str().to_owned(),
            },
            Trigger::Service(on) => Self::Service {
                integration: on.integration().as_str().to_owned(),
                event: on.event().as_str().to_owned(),
                account_id: *on.account().as_uuid(),
                filters: on
                    .filters()
                    .iter()
                    .map(|filter| {
                        (
                            filter.name().as_str().to_owned(),
                            filter.value().as_str().to_owned(),
                        )
                    })
                    .collect(),
            },
            Trigger::Before(change) => Self::Before {
                change: change.as_str().to_owned(),
            },
        }
    }
}
