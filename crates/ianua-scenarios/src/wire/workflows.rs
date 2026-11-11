//! The automation product a tenant builds workflows in: the accounts a
//! workflow acts through, a workflow's trigger and graph, its versions,
//! the secret its webhook is called with, its executions, and the
//! approvals a step waits for.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `POST …/workflows/accounts`: an integration's account connected to the
/// tenant. Holds the credential, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct NewAccount {
    /// The integration, such as `http`.
    pub integration: String,
    /// The name people see.
    pub name: String,
    /// The credential, as the integration takes it.
    pub credential: String,
    /// Who may act through it: `tenant` for everyone in the tenant.
    pub sharing: String,
}

/// The account connected.
#[derive(Debug, Clone, Deserialize)]
pub struct Account {
    /// Handle referenced by steps that act through the connected account.
    pub id: String,
}

/// `POST …/workflows/accounts/connections`: an account to connect by
/// signing in at its service.
#[derive(Debug, Clone, Serialize)]
pub struct NewConnection {
    /// The integration, such as `github`.
    pub integration: String,
    /// The name people see.
    pub name: String,
    /// Who may act through it: `tenant` for everyone in the tenant.
    pub sharing: String,
    /// The space at the service it works in, for an integration whose
    /// sign-in asks for one, such as the Jira site.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub place: Option<String>,
}

/// Browser sign-in destination and correlation handle for linking an account.
#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionBegun {
    /// The connection, which finishing it names.
    pub connection_id: String,
    /// Where the browser is sent to sign in at the service.
    pub address: String,
}

/// `POST …/accounts/connections/{id}/finish`: the one-time code the
/// browser brought back. Holds the code, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct FinishConnection {
    /// Single-use authorization returned by the external service.
    pub code: String,
}

/// One route open to workflows, from `GET …/workflows/apps`.
#[derive(Debug, Clone, Deserialize)]
pub struct App {
    /// The route, which a Protected apps step names.
    pub id: String,
    /// Route label shown when selecting a protected application step.
    pub name: String,
    /// The paths it claims.
    pub path_pattern: String,
}

/// `GET …/workflows/data`: one stream route a Protected data step may
/// reach.
#[derive(Debug, Clone, Deserialize)]
pub struct DataRoute {
    /// The stream route, which a Protected data step names.
    pub id: String,
    /// Stream-route label shown when selecting a protected data step.
    pub name: String,
}

/// One integration installed, from `GET …/workflows/integrations`.
#[derive(Debug, Clone, Deserialize)]
pub struct Integration {
    /// The key its operations and accounts name, such as `github`.
    pub key: String,
    /// Its name for people.
    pub title: String,
    /// What it lets a workflow do.
    pub description: String,
    /// The name of its icon.
    pub icon: String,
    /// Where its own picture is served, or `None` for a step the platform
    /// itself offers.
    pub picture: Option<String>,
    /// Its brand colour, such as `#24292f`.
    pub brand: String,
}

/// One operation offered, from `GET …/workflows/operations`.
#[derive(Debug, Clone, Deserialize)]
pub struct Operation {
    /// Installed provider key used with the operation in step definitions.
    pub integration: String,
    /// Its key, such as `create-issue`.
    pub operation: String,
    /// Its name for people.
    pub title: String,
    /// What it does.
    pub description: String,
    /// The inputs it takes, each with what it means.
    pub inputs: Vec<OperationInput>,
    /// The values it gives back.
    pub outputs: Vec<OperationOutput>,
    /// The kind of action, such as `write`.
    pub effect: String,
    /// The most sensitive data its step may take, such as `internal`.
    pub ceiling: String,
    /// How its step is previewed, when it is.
    #[serde(default)]
    pub preview: Option<Preview>,
}

/// One input an operation takes.
#[derive(Debug, Clone, Deserialize)]
pub struct OperationInput {
    /// Its field name.
    pub name: String,
    /// Whether the operation runs without it.
    pub required: bool,
    /// What it means.
    pub description: String,
    /// How the builder asks for it.
    #[serde(default)]
    pub form: Option<InputForm>,
}

/// How the builder asks for one input.
#[derive(Debug, Clone, Deserialize)]
pub struct InputForm {
    /// Human-readable prompt shown beside the input control.
    pub label: String,
    /// The block, such as `multi_picker`.
    pub block: String,
    /// The options of a choice.
    #[serde(default)]
    pub choices: Vec<FormChoice>,
    /// What fills a picker.
    #[serde(default)]
    pub picker: Option<Picker>,
    /// `main` or `more_options`.
    pub group: String,
}

/// One option of a choice in a form.
#[derive(Debug, Clone, Deserialize)]
pub struct FormChoice {
    /// What the input is set to.
    pub value: String,
    /// Its tone, such as `success`.
    pub tone: String,
}

/// What fills a picker.
#[derive(Debug, Clone, Deserialize)]
pub struct Picker {
    /// The read that lists its options.
    pub filled_by: String,
    /// The input chosen first, when there is one.
    #[serde(default)]
    pub depends_on: Option<String>,
}

/// How a step is previewed.
#[derive(Debug, Clone, Deserialize)]
pub struct Preview {
    /// Such as `issue`.
    pub kind: String,
    /// Which input fills each part.
    pub parts: Vec<PreviewPart>,
}

/// Binding from an operation input to a visible portion of its preview.
#[derive(Debug, Clone, Deserialize)]
pub struct PreviewPart {
    /// Such as `title`.
    pub part: String,
    /// The input filling it.
    pub input: String,
}

/// `POST …/operations/{integration}/{operation}/inputs/{input}/choices`:
/// fill a picker through an account.
#[derive(Debug, Clone, Serialize)]
pub struct ListChoices {
    /// The account the read goes through.
    pub account_id: String,
    /// The value of the input the picker depends on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<Value>,
}

/// The options a picker offers now.
#[derive(Debug, Clone, Deserialize)]
pub struct Choices {
    /// The options.
    pub choices: Vec<Choice>,
    /// What the service said instead of a list.
    #[serde(default)]
    pub unavailable: Option<String>,
}

/// One option a picker offers.
#[derive(Debug, Clone, Deserialize)]
pub struct Choice {
    /// What the input is set to.
    pub value: String,
    /// How it is shown.
    pub label: String,
}

/// What one step may read, from `GET …/workflows/{id}/step-data`.
#[derive(Debug, Clone, Deserialize)]
pub struct StepData {
    /// The step.
    pub key: String,
    /// The trigger first, then each step that can come before it.
    pub earlier: Vec<EarlierData>,
}

/// The values one source hands on.
#[derive(Debug, Clone, Deserialize)]
pub struct EarlierData {
    /// `trigger`, or a step's key.
    pub source: String,
    /// Each value.
    pub values: Vec<ReadableValue>,
}

/// One value a step may read.
#[derive(Debug, Clone, Deserialize)]
pub struct ReadableValue {
    /// Its full path, such as `create.json.number`.
    pub path: String,
    /// Whether only a run shows its shape.
    pub whole: bool,
}

/// One value an operation gives back.
#[derive(Debug, Clone, Deserialize)]
pub struct OperationOutput {
    /// Its path in the step's output, such as `json.number`.
    pub path: String,
    /// What it is.
    pub description: String,
}

/// What starts a workflow.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Trigger {
    /// A person starts it.
    Manual,
    /// A call to its webhook starts it.
    Webhook,
    /// A schedule starts it.
    Schedule {
        /// The cron expression.
        cron: String,
    },
    /// An event an integration's service sends starts it, registered at
    /// the service through an account when the version is published.
    Service {
        /// The integration, such as `github`.
        integration: String,
        /// The event, such as `issue-opened`.
        event: String,
        /// The account the registration is made through.
        account_id: String,
        /// The event's filters by name, such as the repository.
        filters: BTreeMap<String, String>,
    },
    /// A change about to happen in the tenant starts it, and its Allow or
    /// Refuse step decides whether the change goes ahead.
    Before {
        /// The change, such as `admin_given`.
        change: String,
    },
    /// An event in the tenant starts it, such as an agent's run stopping
    /// over budget; the event's details are the run's input.
    Event {
        /// The event, as it is published, such as
        /// `agents.run_stopped_over_budget`.
        event: String,
    },
}

/// A workflow's steps and the edges between them.
#[derive(Debug, Clone, Serialize)]
pub struct Graph {
    /// The steps.
    pub nodes: Vec<Node>,
    /// The ways from one step to the next.
    pub edges: Vec<Edge>,
}

/// One step of a workflow.
#[derive(Debug, Clone, Serialize)]
pub struct Node {
    /// Its key, unique in the workflow.
    pub key: String,
    /// Its name for people.
    pub name: String,
    /// What it does.
    #[serde(flatten)]
    pub step: Step,
}

/// What a step does, named by `kind`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Step {
    /// A governed run of one of the tenant's agents.
    AgentRun {
        /// The acting agent.
        agent_id: String,
        /// The model provider it reasons with.
        provider_id: String,
        /// The instruction.
        goal: String,
        /// What of the step's input the run is given.
        inputs: Vec<MappedField>,
        /// The action classes its tool calls may take, such as `read`.
        purpose: Vec<String>,
        /// The tools it may call.
        tools: Vec<String>,
        /// The action classes whose calls wait for a person's approval.
        approval_classes: Vec<String>,
        /// The most steps the run may take.
        max_steps: u32,
        /// The most it may spend on its model, in millionths of the
        /// tenant's billing currency, or none for no cap.
        #[serde(skip_serializing_if = "Option::is_none")]
        spend_cap_micros: Option<u64>,
        /// The key of an earlier agent step, another agent's, whose work
        /// this run checks, or none for a run doing its own work.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        checks: Option<String>,
    },
    /// One call of an integration's operation.
    Action {
        /// The integration, such as `http`.
        integration: String,
        /// The operation, such as `get-with-account`.
        operation: String,
        /// The account it acts through, or none for an operation acting as
        /// the run's person or needing no account.
        #[serde(skip_serializing_if = "Option::is_none")]
        account_id: Option<String>,
        /// The kind of action the operation takes, such as `read`.
        effect: String,
        /// The most sensitive data it may be handed, such as `internal`.
        ceiling: String,
        /// How the operation's inputs are built.
        inputs: Vec<MappedField>,
    },
    /// Waits for a person's approval.
    Approval {
        /// What they are asked to approve.
        summary: String,
        /// The class of what follows, such as `read`.
        action_class: String,
        /// How long after the step starts it may be decided, in seconds.
        window_seconds: u32,
    },
    /// Runs its own steps once for each item of a list, each pass a run of
    /// its own that finds its item at `trigger.item`.
    Loop {
        /// Where the list is in the step's input, such as
        /// `trigger.issues`.
        over: String,
        /// The steps each pass runs.
        steps: Graph,
        /// The most items the list may hold.
        most_items: u32,
        /// How many passes run at the same time.
        at_once: u32,
    },
    /// Waits a set time, or until working hours begin.
    Wait {
        /// How long, in seconds, or none when it waits for working hours.
        #[serde(skip_serializing_if = "Option::is_none")]
        duration_seconds: Option<i64>,
        /// The working hours it waits for, or none.
        #[serde(skip_serializing_if = "Option::is_none")]
        working_hours: Option<WorkingHours>,
    },
    /// Runs one sandbox version's code on the mapped inputs.
    Code {
        /// The version whose code runs.
        sandbox_version_id: String,
        /// What of the step's input the code is given.
        inputs: Vec<MappedField>,
    },
    /// Checks a text from an earlier step before the run goes on with it.
    Guardrail {
        /// Where the text is in the step's input, such as `draft.answer`.
        text: String,
        /// The checks it runs: `personal_data`, `model_tricks`,
        /// `banned_words`.
        checks: Vec<String>,
        /// The words and phrases it bans, for `banned_words`.
        banned_words: Vec<String>,
        /// What a finding does: `stop`, `remove` or `record`.
        on_finding: String,
    },
    /// The loop's first step asking one approval for every item before any
    /// pass starts, written as an approval step that `covers` the whole
    /// loop.
    #[serde(rename = "approval")]
    WholeLoopApproval {
        /// What they are asked to approve.
        summary: String,
        /// The class of what each pass does, such as `read`.
        action_class: String,
        /// How long after it opens it may be decided, in seconds.
        window_seconds: u32,
        /// Always `whole_loop`.
        covers: String,
    },
    /// An approval step that also asks its question in a Slack channel,
    /// written as an approval step with `slack`; it is still decided in
    /// the platform.
    #[serde(rename = "approval")]
    SlackApproval {
        /// What they are asked to approve.
        summary: String,
        /// The class of what follows, such as `read`.
        action_class: String,
        /// How long after the step starts it may be decided, in seconds.
        window_seconds: u32,
        /// The Slack channel it also asks in.
        slack: SlackAsk,
        /// `whole_loop` for a loop's first step asking once for every
        /// item, or none for an approval asked where it stands.
        #[serde(skip_serializing_if = "Option::is_none")]
        covers: Option<String>,
    },
}

/// The Slack channel an approval also asks in, through a connected Slack
/// account.
#[derive(Debug, Clone, Serialize)]
pub struct SlackAsk {
    /// The connected Slack account the question is posted through.
    pub account_id: String,
    /// The channel, by its id or its name with `#`.
    pub channel: String,
}

/// The hours a team works.
#[derive(Debug, Clone, Serialize)]
pub struct WorkingHours {
    /// The days worked, such as `monday`.
    pub days: Vec<String>,
    /// When work begins, as `HH:MM`.
    pub opens: String,
    /// When work ends, as `HH:MM`.
    pub closes: String,
    /// The time zone, such as `Europe/Berlin`.
    pub timezone: String,
}

/// One input of an operation and where its value comes from.
#[derive(Debug, Clone, Serialize)]
pub struct MappedField {
    /// The input.
    pub field: String,
    /// Where its value comes from.
    #[serde(flatten)]
    pub source: Source,
}

/// Where a mapped input's value comes from, named by `from`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "from", rename_all = "snake_case")]
pub enum Source {
    /// A value written out, such as text or a list of labels.
    Literal {
        /// Constant JSON supplied to every execution of the mapped step.
        value: Value,
    },
    /// The value at a path in the step's input, such as an earlier step's
    /// `open-issue.json.number`.
    Input {
        /// The path, as steps between dots.
        path: String,
    },
}

/// A way from one step to the next.
#[derive(Debug, Clone, Serialize)]
pub struct Edge {
    /// The step it leaves.
    pub from: String,
    /// The step it leads to.
    pub to: String,
}

/// `POST …/workflows`: a new workflow, as a draft.
#[derive(Debug, Clone, Serialize)]
pub struct NewWorkflow {
    /// Label shown in the tenant's automation catalogue.
    pub name: String,
    /// What starts it.
    pub trigger: Trigger,
    /// Its steps.
    pub graph: Graph,
    /// The longest one execution may run, in seconds.
    pub run_limit_seconds: u32,
}

/// A version of a workflow.
#[derive(Debug, Clone, Deserialize)]
pub struct Workflow {
    /// The workflow's id, the same across its versions.
    pub id: String,
    /// This version's number.
    pub version: u32,
    /// `draft`, `published` or `archived`.
    pub status: String,
    /// When the draft was last edited: what a publisher says they
    /// reviewed.
    pub revision: String,
}

/// `PATCH …/workflows/{id}/draft`: one change to the draft, named by
/// `edit`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "edit", rename_all = "snake_case")]
pub enum DraftEdit {
    /// Its steps and edges replaced.
    ReplaceSteps {
        /// The steps and edges.
        graph: Graph,
    },
}

/// `POST …/workflows/{id}/publish`: the draft revision the publisher
/// reviewed, and no other.
#[derive(Debug, Clone, Serialize)]
pub struct Publication {
    /// Exact draft version reviewed by the publisher, preventing stale approval.
    pub revision: String,
}

/// `POST …/workflows/risks`: an integration's operation counted as riskier
/// by the tenant than the integration declares it.
#[derive(Debug, Clone, Serialize)]
pub struct NewRisk {
    /// The integration offering it, such as `http`.
    pub integration: String,
    /// The operation, such as `get-with-account`.
    pub operation: String,
    /// What it counts as from now on, such as `financial`.
    pub effect: String,
}

/// An operation the tenant raised, from `POST …/workflows/risks`.
#[derive(Debug, Clone, Deserialize)]
pub struct Risk {
    /// Handle to change or remove it with.
    pub id: String,
    /// What it counts as, such as `financial`.
    pub effect: String,
}

/// `POST …/workflows/suggestions`: a person's words for the tenant's
/// model to turn into steps.
#[derive(Debug, Clone, Serialize)]
pub struct SuggestSteps {
    /// The model provider asked.
    pub provider_id: String,
    /// What the person wants the workflow to do.
    pub words: String,
}

/// The steps a model proposed, checked against the catalog.
#[derive(Debug, Clone, Deserialize)]
pub struct Proposal {
    /// The steps kept.
    pub steps: Vec<ProposedStep>,
    /// The arrows between kept steps.
    pub edges: Vec<Value>,
    /// What was left out, and why.
    pub notes: Vec<String>,
}

/// A step the model proposed that the catalog offers, for the builder to
/// place on the canvas.
#[derive(Debug, Clone, Deserialize)]
pub struct ProposedStep {
    /// What the model called it, which the proposal's arrows name.
    pub key: String,
    /// What it does, such as `action`.
    pub kind: String,
}

/// `POST …/flows`: an agent flow, made and started at once.
#[derive(Debug, Clone, Serialize)]
pub struct NewFlow {
    /// Label shown in the tenant's list of flows.
    pub name: String,
    /// Its stages, each a list of agent runs started together once every
    /// run of the stage before has answered.
    pub stages: Vec<Vec<FlowRun>>,
}

/// One agent run of a flow, as its maker lays it out.
#[derive(Debug, Clone, Serialize)]
pub struct FlowRun {
    /// The acting agent.
    pub agent_id: String,
    /// The model provider it reasons with.
    pub provider_id: String,
    /// The instruction.
    pub goal: String,
    /// The action classes its tool calls may take, such as `read`.
    pub purpose: Vec<String>,
}

/// An agent flow and where it stands, from `GET …/flows/{id}`.
#[derive(Debug, Clone, Deserialize)]
pub struct Flow {
    /// Handle to read, cancel or delete it with.
    pub id: String,
    /// `Running`, `Completed`, `Failed` or `Canceled`.
    #[serde(default)]
    pub status: Option<String>,
    /// Its stages, each run with where it stands.
    pub stages: Vec<Vec<FlowRunState>>,
}

/// Where one agent run of a flow stands.
#[derive(Debug, Clone, Deserialize)]
pub struct FlowRunState {
    /// The instruction it was given.
    pub goal: String,
    /// `Pending`, `Dispatched`, `Completed` or `Failed`.
    #[serde(default)]
    pub status: Option<String>,
    /// What it answered, once it completed.
    #[serde(default)]
    pub output: Option<String>,
    /// Why it failed, when it did.
    #[serde(default)]
    pub error_message: Option<String>,
}

/// The secret a workflow's webhook is called with, from
/// `POST …/workflows/{id}/trigger-secret` and its `/rotate`. Holds the
/// secret, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct TriggerSecret {
    /// The trigger the webhook calls.
    pub trigger_id: String,
    /// The secret, shown this once.
    pub secret: String,
}

/// What a webhook call answered.
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookStarted {
    /// `started` when an execution was.
    pub status: String,
    /// The execution, when one started.
    #[serde(default)]
    pub execution_id: Option<String>,
}

/// `POST …/workflows/{id}/executions`: a workflow started by hand.
#[derive(Debug, Clone, Serialize)]
pub struct StartExecution {
    /// The data it starts with.
    pub input: Value,
    /// The most sensitive data in it, such as `internal`.
    pub exposure: String,
}

/// Where an execution stands after a command on it.
#[derive(Debug, Clone, Deserialize)]
pub struct ExecutionDecided {
    /// The execution; a retry gets one of its own.
    pub execution_id: String,
    /// `running`, or how it ended.
    pub status: String,
}

/// One execution, from `GET …/workflows/executions/{id}`.
#[derive(Debug, Clone, Deserialize)]
pub struct Execution {
    /// Handle used to inspect, retry or cancel this workflow execution.
    pub id: String,
    /// `running`, or how it ended: `succeeded`, `failed`, `denied`.
    pub status: String,
    /// What started it, such as `manual` or `before`.
    pub cause: String,
    /// The data it started with, null when the reader is not cleared for
    /// it.
    #[serde(default)]
    pub input: Value,
    /// Its steps, with what each produced.
    pub steps: Vec<ExecutionStep>,
}

/// One execution in a workflow's list, from
/// `GET …/workflows/{id}/executions`.
#[derive(Debug, Clone, Deserialize)]
pub struct ExecutionSummary {
    /// Handle used to open the full execution detail from the list.
    pub id: String,
    /// What started it, such as `service`.
    pub cause: String,
    /// `live`, or `test` for a test of a draft.
    pub mode: String,
    /// `running`, or how it ended.
    pub status: String,
}

/// One pass of a loop, from `GET …/workflows/executions/{id}/passes`.
#[derive(Debug, Clone, Deserialize)]
pub struct PassRun {
    /// The pass's own id, read like any execution.
    pub id: String,
    /// `running`, or how it ended, such as `loop_ended` when its loop
    /// failed first.
    pub status: String,
    /// The loop it is a pass of.
    pub pass: PassOf,
}

/// The loop a pass belongs to.
#[derive(Debug, Clone, Deserialize)]
pub struct PassOf {
    /// The execution whose loop step started it.
    pub execution_id: String,
    /// That loop step's key.
    pub step: String,
    /// The item it is the pass for, counted from zero.
    pub index: u32,
}

/// Recorded phase, output and failure for a node during a workflow execution.
#[derive(Debug, Clone, Deserialize)]
pub struct ExecutionStep {
    /// The step's key in the graph.
    pub key: String,
    /// `waiting`, `running`, `succeeded`, `failed` and so on.
    pub phase: String,
    /// What it produced, when the reader is cleared for it.
    #[serde(default)]
    pub output: Option<Value>,
    /// Why it failed, once it failed.
    #[serde(default)]
    pub failure: Option<StepFailed>,
}

/// Why a step failed.
#[derive(Debug, Clone, Deserialize)]
pub struct StepFailed {
    /// The kind of failure, such as `code_timed_out`.
    pub code: String,
    /// What else is known, such as the end of the error the code raised.
    pub detail: String,
}

/// What an approval step lets through, from
/// `GET …/executions/{id}/approvals/{step}`.
#[derive(Debug, Clone, Deserialize)]
pub struct Approval {
    /// The data an approver is shown and approves exactly.
    pub shown: Value,
}

/// `POST …/executions/{id}/approvals/{step}/approve`: the data the
/// approver was shown, as it came, and for a high-risk step a fresh code
/// from their second factor.
#[derive(Debug, Clone, Serialize)]
pub struct Approve {
    /// The data.
    pub shown: Value,
    /// The approver's fresh second-factor code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_code: Option<String>,
}

/// One page of the items a loop asks one approval for, from
/// `GET …/executions/{id}/approvals/{step}/items`.
#[derive(Debug, Clone, Deserialize)]
pub struct ItemsPage {
    /// What people are asked to approve.
    pub summary: String,
    /// How many different people must approve.
    pub approvers_needed: u8,
    /// How many items the loop will act on.
    pub total: u32,
    /// How many of them the reader was shown so far, this page included.
    pub shown: u32,
    /// The items on this page, in the order the passes take them.
    pub items: Vec<ApprovalItem>,
    /// The cursor of the next page, or none on the last one.
    pub next_cursor: Option<String>,
}

/// One item a loop will act on, at its place in the list.
#[derive(Debug, Clone, Deserialize)]
pub struct ApprovalItem {
    /// Its position, counted from zero.
    pub position: u32,
    /// The item, as its pass starts with it at `trigger.item`.
    pub item: Value,
}

/// `POST …/approvals/{step}/items/approve`: a yes to every item, with a
/// fresh second-factor code before a high-risk action.
#[derive(Debug, Clone, Serialize)]
pub struct ApproveItems {
    /// The approver's fresh second-factor code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_code: Option<String>,
}

/// `PUT …/workflows/{id}/evaluation-set`: the sample cases a workflow's
/// versions are evaluated against.
#[derive(Debug, Clone, Serialize)]
pub struct NewEvaluationSet {
    /// The cases, each named once.
    pub cases: Vec<EvaluationCase>,
    /// `must_pass` holds publishing back until the draft's last evaluation
    /// passed; none leaves the gate off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publish_gate: Option<String>,
}

/// One sample case: the trigger data its test starts with and the checks
/// its results must pass.
#[derive(Debug, Clone, Serialize)]
pub struct EvaluationCase {
    /// What the author calls it.
    pub name: String,
    /// The trigger data its test starts with.
    pub input: Value,
    /// The most sensitive data in the input, such as `internal`.
    pub exposure: String,
    /// The checks its results must pass.
    pub checks: Vec<CaseCheck>,
}

/// One check of a case's results, named by `kind`: `equals` a value,
/// `contains` a text, or `matches` a pattern.
#[derive(Debug, Clone, Serialize)]
pub struct CaseCheck {
    /// `equals`, `contains` or `matches`.
    pub kind: String,
    /// Where in the results the value is read, such as `deliver.json`.
    pub at: String,
    /// The value expected, for `equals`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    /// The text expected within, for `contains`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The pattern expected, for `matches`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

/// A workflow's saved sample cases and its publishing gate.
#[derive(Debug, Clone, Deserialize)]
pub struct EvaluationSet {
    /// `off` or `must_pass`.
    pub publish_gate: String,
    /// The cases, in the order saved.
    pub cases: Vec<ShownCase>,
}

/// One sample case as its reader may see it.
#[derive(Debug, Clone, Deserialize)]
pub struct ShownCase {
    /// What the author calls it.
    pub name: String,
    /// Whether its input is above the reader's clearance.
    pub withheld: bool,
}

/// One evaluation of a workflow version, from starting it or
/// `GET …/workflows/{id}/evaluations/{evaluation_id}`.
#[derive(Debug, Clone, Deserialize)]
pub struct Evaluation {
    /// Handle used to read it back.
    pub id: String,
    /// The version it tries.
    pub version: u32,
    /// `running`, then `passed` or `failed`.
    pub status: String,
    /// What each case came to, in the set's order.
    pub cases: Vec<CaseResult>,
}

/// What one case of an evaluation came to.
#[derive(Debug, Clone, Deserialize)]
pub struct CaseResult {
    /// Which case it was, by name, and whether its input is withheld from
    /// the reader.
    pub case: ShownCase,
    /// `waiting`, `running`, `passed`, `failed` or `not_run`.
    pub outcome: String,
    /// The case's test run, once it started.
    #[serde(default)]
    pub execution_id: Option<String>,
    /// Why it could not run, for `not_run`.
    #[serde(default)]
    pub reason: Option<String>,
    /// What differed, for `failed`.
    #[serde(default)]
    pub differences: Option<Vec<Difference>>,
}

/// One thing that differed in a failed case.
#[derive(Debug, Clone, Deserialize)]
pub struct Difference {
    /// `run_ended` or `check`.
    pub kind: String,
    /// How the run ended, for `run_ended`.
    #[serde(default)]
    pub run_end: Option<String>,
    /// Which check, counted from zero, for `check`.
    #[serde(default)]
    pub check: Option<usize>,
    /// What was found at the check's path.
    #[serde(default)]
    pub found: Option<String>,
}
