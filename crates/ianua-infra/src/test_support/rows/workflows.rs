//! Rows the workflows store tests build from: versions of designed
//! workflows and agent flows, runs of them, the person who writes and runs
//! them, and the accounts, connections, registrations, overrides and
//! webhook secrets around them, all dated from the fixed moment.

use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
use ianua_domain::domains::agents::execution::model_provider::ModelName;
use ianua_domain::domains::agents::execution::run::GoalTemplate;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::account::connection::{
    ConnectionStage, PendingConnectionRow,
};
use ianua_domain::domains::workflows::account::{
    AccountSharing, AccountStatus, IntegrationAccountRow, OperationScope,
};
use ianua_domain::domains::workflows::data::{FieldName, FlowData};
use ianua_domain::domains::workflows::design::authors::Authors;
use ianua_domain::domains::workflows::design::graph::WorkflowGraph;
use ianua_domain::domains::workflows::design::node::{
    AgentRunParams, AgentRunStep, Checks, Join, Mapping, Node, NodeKey, NodeKind, WaitStep,
};
use ianua_domain::domains::workflows::design::workflow::{
    CanvasLayout, FailureAlert, FlowDescription, Hold, Publication, RunLimit, Workflow,
    WorkflowOrigin, WorkflowRow, WorkflowStatus,
};
use ianua_domain::domains::workflows::execution::step::{StepState, Underway};
use ianua_domain::domains::workflows::execution::{
    Cause, ExecutionStatus, StoredMode, WorkflowExecutionRow,
};
use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
use ianua_domain::domains::workflows::integration::risk_override::OperationRiskOverrideRow;
use ianua_domain::domains::workflows::integration::{IntegrationKey, OperationKey};
use ianua_domain::domains::workflows::memory::source::{EmbeddingSource, VectorSize};
use ianua_domain::domains::workflows::memory::{MemoryRow, MemoryStatus};
use ianua_domain::domains::workflows::triggers::secret::WorkflowTriggerSecretRow;
use ianua_domain::domains::workflows::triggers::subscription::{
    Registration, ServiceSubscriptionRow, SubscriptionStatus,
};
use ianua_domain::domains::workflows::triggers::{
    EventFilter, FilterValue, ServiceTrigger, Trigger,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::chain::ChainDepth;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{
    ActionClass, AgentId, AgentRunId, DeclaredAction, EventLabel, Human, HumanAccount,
    IntegrationAccountId, Label, Lifetime, MemoryId, ModelProviderId, OperationRiskOverrideId,
    PendingConnectionId, PersonKey, SealedSecret, ServiceSubscriptionId, TokenHash, UserId,
    WorkflowExecutionId, WorkflowId, WorkflowTriggerId,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::test_support::rows::at;

/// Ann, who writes, publishes and runs every test workflow.
///
/// # Panics
///
/// Never: her address is fixed and valid.
#[must_use]
pub fn ann() -> Human {
    Human::new(
        HumanAccount::User(UserId::from_uuid(Uuid::from_u128(0xa11))),
        PersonKey::new("ann@acme.example").expect("a valid address"),
    )
}

/// Ann's support tickets memory on the platform's embedding server, its
/// vectors three numbers long, made and last changed at `made`, in
/// `status`.
///
/// # Panics
///
/// Never: its name, model and size are fixed and valid.
#[must_use]
pub fn memory_row(status: MemoryStatus, made: OffsetDateTime) -> MemoryRow {
    MemoryRow {
        id: MemoryId::new(),
        name: Label::new("name", "Support tickets").expect("a valid name"),
        source: EmbeddingSource::Platform(ModelName::new("bge-small").expect("a valid model")),
        vector_size: VectorSize::new(3).expect("a valid size"),
        clearance: DataClassLevel::Internal,
        status,
        created_by: ann(),
        created_at: made,
        updated_at: made,
    }
}

/// A step `key` of `kind`.
///
/// # Panics
///
/// When `key` is not a step key, which is a mistake in the test.
#[must_use]
pub fn step(key: &str, kind: NodeKind) -> Node {
    Node::new(
        NodeKey::new(key).expect("a valid step key"),
        Label::new("name", key).expect("a valid name"),
        kind,
        Join::All,
    )
}

/// A graph of one step that waits an hour.
///
/// # Panics
///
/// Never: one wait forms a graph.
#[must_use]
pub fn wait_graph() -> WorkflowGraph {
    let wait = WaitStep::new(Lifetime::seconds(3600).expect("an hour")).expect("an hour wait");
    WorkflowGraph::new(vec![step("pause", NodeKind::Wait(wait))], Vec::new())
        .expect("one step is a graph")
}

/// A graph of one agent run that summarises, calling no tool.
///
/// # Panics
///
/// Never: the run is a bounded one.
#[must_use]
pub fn agent_graph() -> WorkflowGraph {
    let run = AgentRunStep::new(AgentRunParams {
        agent_id: AgentId::from_uuid(Uuid::from_u128(0xa6e)),
        provider_id: ModelProviderId::from_uuid(Uuid::from_u128(0x9e0)),
        goal: GoalTemplate::new("summarise the week").expect("a goal"),
        inputs: Mapping::new(Vec::new()).expect("no field is a mapping"),
        purpose: IntentEnvelope::new([ActionClass::Read]),
        tools: Vec::new(),
        approval_classes: Vec::new(),
        max_steps: 5,
        spend_cap: Restriction::Unrestricted,
        ask_past: Restriction::Unrestricted,
        checks: Checks::Nothing,
    })
    .expect("a bounded run");
    WorkflowGraph::new(vec![step("summarise", NodeKind::AgentRun(run))], Vec::new())
        .expect("one step is a graph")
}

/// Version 1 of a workflow Ann designed, called `name`, a draft that waits
/// an hour, started by hand, drafted and last changed `created` seconds
/// from the fixed moment.
///
/// # Panics
///
/// When `name` is not a name, which is a mistake in the test.
#[must_use]
pub fn draft_row(name: &str, created: i64) -> WorkflowRow {
    WorkflowRow {
        id: WorkflowId::new(),
        version: 1,
        name: Label::new("name", name).expect("a valid name"),
        description: None,
        graph: wait_graph(),
        layout: CanvasLayout::default(),
        trigger: Trigger::Manual,
        run_limit: RunLimit::new(Lifetime::seconds(86_400).expect("a day")).expect("a day"),
        failure_alert: FailureAlert::default(),
        status: WorkflowStatus::Draft,
        created_by: ann(),
        edited_by: ann(),
        authors: Authors::from_stored(vec![ann()]).expect("one author"),
        publication: Publication::Unpublished,
        origin: WorkflowOrigin::Designed,
        hold: Hold::Clear,
        created_at: at(created),
        updated_at: at(created),
    }
}

/// [`draft_row`], published by Ann, running one agent summary.
#[must_use]
pub fn published_row(name: &str, created: i64) -> WorkflowRow {
    WorkflowRow {
        graph: agent_graph(),
        status: WorkflowStatus::Published,
        publication: Publication::PublishedBy(ann()),
        ..draft_row(name, created)
    }
}

/// An agent flow Ann made, called `name`, with what she wrote about it:
/// one published version of one agent summary, started by hand.
///
/// # Panics
///
/// Never: the description is fixed and valid.
#[must_use]
pub fn flow_row(name: &str, created: i64) -> WorkflowRow {
    WorkflowRow {
        origin: WorkflowOrigin::Flow(FlowDescription::Written(
            Label::new("description", "the weekly digest").expect("a valid description"),
        )),
        ..published_row(name, created)
    }
}

/// The data every test run starts with: `{"ok": true}`.
///
/// # Panics
///
/// Never: the data is fixed and small.
#[must_use]
pub fn trigger_data() -> FlowData {
    FlowData::map(vec![(
        FieldName::new("ok").expect("a field name"),
        FlowData::bool(true),
    )])
    .expect("one field is data")
}

/// A run of `workflow`, which runs one agent summary, that Ann started by
/// hand `created` seconds from the fixed moment, waiting on the agent run
/// `run`.
#[must_use]
pub fn running_row(
    workflow: &Workflow<ResolvedTenant>,
    run: AgentRunId,
    created: i64,
) -> WorkflowExecutionRow {
    WorkflowExecutionRow {
        id: WorkflowExecutionId::new(),
        workflow_id: *workflow.id(),
        version: workflow.version(),
        graph: workflow.graph().clone(),
        acting_for: ann(),
        authors: workflow.authors().clone(),
        failure_alert: workflow.failure_alert(),
        mode: StoredMode::Live,
        cause: Cause::Manual,
        pass: None,
        chain_depth: ChainDepth::FIRST,
        input: trigger_data(),
        exposure: DataClassLevel::Internal,
        steps: vec![StepState::Running {
            exposure: DataClassLevel::Internal,
            seen: Vec::new(),
            underway: Underway::AgentRun(run),
            started_at: at(created),
        }],
        status: ExecutionStatus::Running,
        deadline: at(created.saturating_add(86_400)),
        created_at: at(created),
        updated_at: at(created),
    }
}

/// An account Ann connected to the spreadsheet integration, called
/// `name`, kept to her, for every operation, connected `created` seconds
/// from the fixed moment.
///
/// # Panics
///
/// When `name` is not a name, which is a mistake in the test.
#[must_use]
pub fn account_row(name: &str, created: i64) -> IntegrationAccountRow {
    IntegrationAccountRow {
        id: IntegrationAccountId::new(),
        integration: IntegrationKey::new("google-sheets").expect("an integration key"),
        name: Label::new("name", name).expect("a valid name"),
        credential: SealedSecret::new("v1.c2hlZXRzLXRva2Vu").expect("a sealed form"),
        owner: ann(),
        sharing: AccountSharing::OwnerOnly,
        scope: OperationScope::All,
        status: AccountStatus::Active,
        created_at: at(created),
        updated_at: at(created),
    }
}

/// Ann's override counting `operation` of the spreadsheet integration as a
/// payment, set `created` seconds from the fixed moment.
///
/// # Panics
///
/// When `operation` is not an operation key, which is a mistake in the
/// test.
#[must_use]
pub fn risk_row(operation: &str, created: i64) -> OperationRiskOverrideRow {
    OperationRiskOverrideRow {
        id: OperationRiskOverrideId::new(),
        integration: IntegrationKey::new("google-sheets").expect("an integration key"),
        operation: OperationKey::new(operation).expect("an operation key"),
        effect: DeclaredAction::Declared(ActionClass::Financial),
        raised_by: ann(),
        created_at: at(created),
        updated_at: at(created),
    }
}

/// A connection Ann began to the spreadsheet integration, waiting for the
/// service, its state kept by the digest named after `state`, begun
/// `created` seconds from the fixed moment and running out ten minutes
/// later.
///
/// # Panics
///
/// Never: every value is fixed and valid.
#[must_use]
pub fn pending_connection_row(state: &str, created: i64) -> PendingConnectionRow {
    PendingConnectionRow {
        id: PendingConnectionId::new(),
        integration: IntegrationKey::new("google-sheets").expect("an integration key"),
        name: Label::new("name", "Finance sheets").expect("a valid name"),
        sharing: AccountSharing::OwnerOnly,
        scope: OperationScope::All,
        place: None,
        started_by: ann(),
        state: TokenHash::from_stored(format!("hash of {state}")),
        verifier: SealedSecret::new("v1.dmVyaWZpZXI").expect("a sealed form"),
        stage: ConnectionStage::AwaitingService,
        expires_at: at(created.saturating_add(600)),
        created_at: at(created),
        updated_at: at(created),
    }
}

/// The registration of version `version` of `workflow` on new rows in the
/// finance sheet, through `account`, being made at the service, opened at
/// the fixed moment.
///
/// # Panics
///
/// Never: every value is fixed and valid.
#[must_use]
pub fn subscription_row(
    workflow: WorkflowId,
    version: u32,
    account: IntegrationAccountId,
) -> ServiceSubscriptionRow {
    ServiceSubscriptionRow {
        id: ServiceSubscriptionId::new(),
        workflow_id: workflow,
        version,
        trigger: ServiceTrigger::from_stored(
            IntegrationKey::new("google-sheets").expect("an integration key"),
            ServiceEventKey::new("row-added").expect("an event key"),
            account,
            vec![EventFilter::new(
                FieldName::new("sheet").expect("a field name"),
                FilterValue::new("finance").expect("a filter value"),
            )],
        )
        .expect("one filter, once"),
        secret: SealedSecret::new("v1.c2lnbmluZw").expect("a sealed form"),
        status: SubscriptionStatus::Registering,
        registration: Registration::NotTaken,
        label: EventLabel::of("Watch finance"),
        created_at: at(0),
        updated_at: at(0),
    }
}

/// The webhook secret Ann issued for `workflow` at the fixed moment, kept
/// by the digest named after `secret`.
#[must_use]
pub fn trigger_secret_row(workflow: WorkflowId, secret: &str) -> WorkflowTriggerSecretRow {
    WorkflowTriggerSecretRow {
        id: WorkflowTriggerId::new(),
        workflow_id: workflow,
        secret_hash: TokenHash::from_stored(format!("hash of {secret}")),
        issued_by: ann(),
        created_at: at(0),
        secret_changed_at: at(0),
    }
}
