//! A workflow version as its row holds it, with the origin its workflow's
//! row keeps: read back into the aggregate, and written out from it.

use ianua_domain::domains::workflows::design::authors::Authors;
use ianua_domain::domains::workflows::design::node::NodeKey;
use ianua_domain::domains::workflows::design::workflow::{
    AccountUnusable, AccountUse, CanvasLayout, FailureAlert, FlowDescription, Hold, MissingAccount,
    Publication, RunLimit, StepPosition, Workflow, WorkflowOrigin, WorkflowRow, WorkflowStatus,
};
use ianua_domain::domains::workflows::triggers::before::GuardedChange;
use ianua_domain::domains::workflows::triggers::{CronSchedule, EventTrigger, Trigger};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{
    EventType, Human, IntegrationAccountId, Label, Lifetime, Text, WorkflowId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};
use crate::postgres::workflows::triggers::service::StoredTrigger;
use crate::postgres::workflows::versions::words::{OriginKind, TriggerKind};

const WORKFLOW: Stored = Stored("workflow");

const GRAPH: Kept = Kept {
    entity: WORKFLOW.0,
    column: "graph",
    shape: 1,
};

const CREATED_BY: Kept = Kept {
    entity: WORKFLOW.0,
    column: "created_by",
    shape: 1,
};

const EDITED_BY: Kept = Kept {
    entity: WORKFLOW.0,
    column: "edited_by",
    shape: 1,
};

const AUTHORS: Kept = Kept {
    entity: WORKFLOW.0,
    column: "authors",
    shape: 1,
};

const PUBLISHED_BY: Kept = Kept {
    entity: WORKFLOW.0,
    column: "published_by",
    shape: 1,
};

const TRIGGER_SERVICE: Kept = Kept {
    entity: WORKFLOW.0,
    column: "trigger_service",
    shape: 1,
};

const HOLD: Kept = Kept {
    entity: WORKFLOW.0,
    column: "hold",
    shape: 1,
};

const LAYOUT: Kept = Kept {
    entity: WORKFLOW.0,
    column: "layout",
    shape: 1,
};

/// Where one step sits on the canvas, as the layout column holds it.
#[derive(Serialize, Deserialize)]
struct StoredPosition {
    key: String,
    x: u32,
    y: u32,
}

/// Copies canvas coordinates into the JSON shape kept in a version's layout column.
fn stored_layout(layout: &CanvasLayout) -> Vec<StoredPosition> {
    layout
        .iter()
        .map(|(key, at)| StoredPosition {
            key: key.as_str().to_owned(),
            x: at.x(),
            y: at.y(),
        })
        .collect()
}

/// The layout the stored positions hold, read back.
fn layout_from(stored: Vec<StoredPosition>) -> Result<CanvasLayout, DomainError> {
    let positions = stored
        .into_iter()
        .map(|position| {
            let key = WORKFLOW.value("placed step", NodeKey::new(position.key))?;
            let at = StepPosition::new(position.x, position.y).map_err(|_| {
                DomainError::corrupt_row(WORKFLOW.0, "a step placed off the canvas")
            })?;
            Ok((key, at))
        })
        .collect::<Result<Vec<_>, DomainError>>()?;
    CanvasLayout::new(positions)
        .map_err(|_| DomainError::corrupt_row(WORKFLOW.0, "a step placed twice"))
}

/// The account a held version needs, as its column holds it.
#[derive(Serialize, Deserialize)]
struct StoredHold {
    account: Uuid,
    /// `None` for the trigger, otherwise the step's key.
    step: Option<String>,
    why: String,
}

impl StoredHold {
    /// `missing` as it is stored.
    fn of(missing: &MissingAccount) -> Self {
        Self {
            account: *missing.account.as_uuid(),
            step: match &missing.at {
                AccountUse::Trigger => None,
                AccountUse::Step(key) => Some(key.as_str().to_owned()),
            },
            why: missing.why.as_str().to_owned(),
        }
    }

    /// The account the stored hold names, read back.
    fn into_missing(self) -> Result<MissingAccount, DomainError> {
        let at = match self.step {
            None => AccountUse::Trigger,
            Some(key) => AccountUse::Step(WORKFLOW.value("held step", NodeKey::new(key))?),
        };
        Ok(MissingAccount {
            account: IntegrationAccountId::from_uuid(self.account),
            at,
            why: why_from(&self.why)?,
        })
    }
}

/// Why an account was unusable, from the word it is stored as.
fn why_from(word: &str) -> Result<AccountUnusable, DomainError> {
    [
        AccountUnusable::Gone,
        AccountUnusable::Disabled,
        AccountUnusable::OwnerCannotLend,
        AccountUnusable::NotLent,
        AccountUnusable::NotForThisUse,
    ]
    .into_iter()
    .find(|why| why.as_str() == word)
    .ok_or_else(|| DomainError::corrupt_row(WORKFLOW.0, "an unknown reason for a hold"))
}

/// A version as it is read, with its workflow's origin. The store's
/// checked queries fill it.
pub(super) struct WorkflowRecord {
    pub(super) workflow_id: Uuid,
    pub(super) version: i32,
    pub(super) name: String,
    pub(super) graph: Value,
    pub(super) trigger_kind: String,
    pub(super) trigger_schedule: Option<String>,
    pub(super) trigger_event: Option<String>,
    pub(super) trigger_service: Option<Value>,
    pub(super) trigger_change: Option<String>,
    pub(super) run_limit_secs: i32,
    pub(super) status: String,
    pub(super) created_by: Value,
    pub(super) edited_by: Value,
    pub(super) authors: Value,
    pub(super) published_by: Option<Value>,
    pub(super) hold: Option<Value>,
    pub(super) description: Option<String>,
    pub(super) layout: Value,
    pub(super) failure_alert: String,
    pub(super) origin: String,
    pub(super) flow_description: Option<String>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl WorkflowRecord {
    /// The version the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule a version
    /// keeps.
    pub(super) fn into_workflow(self) -> Result<Workflow<ResolvedTenant>, DomainError> {
        let trigger = trigger_from(
            WORKFLOW.choice(&self.trigger_kind)?,
            TriggerColumns {
                schedule: self.trigger_schedule,
                event: self.trigger_event,
                service: self.trigger_service,
                change: self.trigger_change,
            },
        )?;
        Workflow::reconstitute(WorkflowRow {
            id: WorkflowId::from_uuid(self.workflow_id),
            version: u32::try_from(self.version)
                .map_err(|_| DomainError::corrupt_row(WORKFLOW.0, "a negative version"))?,
            name: WORKFLOW.value("name", Label::new("name", self.name))?,
            description: description_from(self.description)?,
            graph: GRAPH.open(self.graph)?,
            layout: layout_from(LAYOUT.open(self.layout)?)?,
            trigger,
            run_limit: run_limit_from(self.run_limit_secs)?,
            failure_alert: FailureAlert::from_stored(&self.failure_alert)?,
            status: WorkflowStatus::from_stored(&self.status)?,
            created_by: CREATED_BY.open(self.created_by)?,
            edited_by: EDITED_BY.open(self.edited_by)?,
            authors: Authors::from_stored(AUTHORS.open(self.authors)?)?,
            publication: publication_from(self.published_by)?,
            origin: origin_from(WORKFLOW.choice(&self.origin)?, self.flow_description)?,
            hold: hold_from(self.hold)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Restores the publisher when the version's publication column is populated.
fn publication_from(stored: Option<Value>) -> Result<Publication, DomainError> {
    let publisher = stored
        .map(|value| PUBLISHED_BY.open::<Human>(value))
        .transpose()?;
    Ok(publisher.map_or(Publication::Unpublished, Publication::PublishedBy))
}

/// Validates a stored description without turning corrupt text into caller input errors.
fn description_from(stored: Option<String>) -> Result<Option<Text>, DomainError> {
    stored
        .map(|written| WORKFLOW.value("description", Text::new("description", written)))
        .transpose()
}

/// Restores a held account and its reason, or the absence of a hold.
fn hold_from(stored: Option<Value>) -> Result<Hold, DomainError> {
    match stored {
        None => Ok(Hold::Clear),
        Some(stored) => Ok(Hold::NeedsAccount(
            HOLD.open::<StoredHold>(stored)?.into_missing()?,
        )),
    }
}

/// The columns a trigger's own values are kept in, each set only for its
/// case.
struct TriggerColumns {
    schedule: Option<String>,
    event: Option<String>,
    service: Option<Value>,
    change: Option<String>,
}

/// What starts a version of `kind`, from the schedule, event, service
/// trigger or guarded change its columns hold.
fn trigger_from(kind: TriggerKind, columns: TriggerColumns) -> Result<Trigger, DomainError> {
    if (kind == TriggerKind::Before) != columns.change.is_some() {
        return Err(contradicted());
    }
    match (kind, columns.schedule, columns.event, columns.service) {
        (TriggerKind::Manual, None, None, None) => Ok(Trigger::Manual),
        (TriggerKind::Webhook, None, None, None) => Ok(Trigger::Webhook),
        (TriggerKind::Schedule, Some(schedule), None, None) => CronSchedule::parse(&schedule)
            .map(Trigger::Schedule)
            .map_err(DomainError::infra),
        (TriggerKind::Event, None, Some(event), None) => {
            event_trigger_from(&event).map(Trigger::Event)
        }
        (TriggerKind::Service, None, None, Some(service)) => TRIGGER_SERVICE
            .open::<StoredTrigger>(service)?
            .into_trigger(WORKFLOW)
            .map(Trigger::Service),
        (TriggerKind::Before, None, None, None) => before_trigger(columns.change),
        (
            TriggerKind::Manual
            | TriggerKind::Webhook
            | TriggerKind::Schedule
            | TriggerKind::Event
            | TriggerKind::Service
            | TriggerKind::Before,
            _,
            _,
            _,
        ) => Err(contradicted()),
    }
}

/// The refusal of a row whose trigger columns contradict its kind.
fn contradicted() -> DomainError {
    DomainError::corrupt_row(WORKFLOW.0, "a trigger its columns contradict")
}

/// The trigger before the change stored as `change`.
fn before_trigger(change: Option<String>) -> Result<Trigger, DomainError> {
    let change = change.and_then(|name| GuardedChange::named(&name).ok());
    let Some(change) = change else {
        return Err(DomainError::corrupt_row(
            WORKFLOW.0,
            "an unknown guarded change",
        ));
    };
    Ok(Trigger::Before(change))
}

/// The trigger on the event stored as `event`.
fn event_trigger_from(event: &str) -> Result<EventTrigger, DomainError> {
    let event = EventType::parse(event)
        .ok_or_else(|| DomainError::corrupt_row(WORKFLOW.0, "an unknown trigger event"))?;
    EventTrigger::new(event).map_err(DomainError::infra)
}

/// The run limit of `seconds`.
fn run_limit_from(seconds: i32) -> Result<RunLimit, DomainError> {
    let lifetime = WORKFLOW.value("run limit", Lifetime::seconds(i64::from(seconds)))?;
    RunLimit::new(lifetime).map_err(DomainError::infra)
}

/// Where a workflow of `kind` came from, with what its flow's maker wrote.
fn origin_from(
    kind: OriginKind,
    description: Option<String>,
) -> Result<WorkflowOrigin, DomainError> {
    match (kind, description) {
        (OriginKind::Designed, None) => Ok(WorkflowOrigin::Designed),
        (OriginKind::Flow, None) => Ok(WorkflowOrigin::Flow(FlowDescription::Blank)),
        (OriginKind::Flow, Some(written)) => {
            let written = WORKFLOW.value("flow description", Label::new("description", written))?;
            Ok(WorkflowOrigin::Flow(FlowDescription::Written(written)))
        }
        (OriginKind::Designed, Some(_)) => Err(DomainError::corrupt_row(
            WORKFLOW.0,
            "a description of a designed workflow",
        )),
    }
}

/// A version's columns, and its workflow's, as they are written.
pub(super) struct WorkflowColumns<'a> {
    pub(super) workflow_id: &'a Uuid,
    pub(super) version: i32,
    pub(super) name: &'a str,
    pub(super) graph: Value,
    pub(super) trigger_kind: &'static str,
    pub(super) trigger_schedule: Option<&'a str>,
    pub(super) trigger_event: Option<&'static str>,
    pub(super) trigger_service: Option<Value>,
    pub(super) trigger_change: Option<&'static str>,
    pub(super) run_limit_secs: i32,
    pub(super) status: &'static str,
    pub(super) created_by: Value,
    pub(super) edited_by: Value,
    pub(super) authors: Value,
    pub(super) published_by: Option<Value>,
    pub(super) hold: Option<Value>,
    pub(super) description: Option<&'a str>,
    pub(super) layout: Value,
    pub(super) failure_alert: &'static str,
    pub(super) origin: &'static str,
    pub(super) flow_description: Option<&'a str>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> WorkflowColumns<'a> {
    /// The columns `workflow` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value cannot be written
    /// out as JSON, or a number does not fit its column.
    pub(super) fn of(workflow: &'a Workflow<ResolvedTenant>) -> Result<Self, DomainError> {
        let trigger = trigger_columns(workflow.trigger())?;
        let published_by = publication_column(workflow.publication())?;
        let flow_description = flow_description(workflow.origin());
        Ok(Self {
            workflow_id: workflow.id().as_uuid(),
            version: i32::try_from(workflow.version()).map_err(DomainError::infra)?,
            name: workflow.name().as_str(),
            graph: GRAPH.seal(workflow.graph())?,
            trigger_kind: TriggerKind::of(workflow.trigger()).word(),
            trigger_schedule: trigger.schedule,
            trigger_event: trigger.event,
            trigger_service: trigger.service,
            trigger_change: trigger.change,
            run_limit_secs: i32::try_from(workflow.run_limit().lifetime().whole_seconds())
                .map_err(DomainError::infra)?,
            status: workflow.status().as_str(),
            created_by: CREATED_BY.seal(workflow.created_by())?,
            edited_by: EDITED_BY.seal(workflow.edited_by())?,
            authors: AUTHORS.seal(workflow.authors().as_slice())?,
            published_by,
            hold: hold_column(workflow.hold())?,
            description: workflow.description().map(Text::as_str),
            layout: LAYOUT.seal(&stored_layout(workflow.layout()))?,
            failure_alert: workflow.failure_alert().as_str(),
            origin: OriginKind::of(workflow.origin()).word(),
            flow_description,
            created_at: workflow.created_at(),
            updated_at: workflow.updated_at(),
        })
    }
}

/// Trigger-specific columns, with only the selected trigger's payload populated.
#[derive(Default)]
struct WrittenTrigger<'a> {
    schedule: Option<&'a str>,
    event: Option<&'static str>,
    service: Option<Value>,
    change: Option<&'static str>,
}

/// Serializes the trigger payload independently of the column naming its variant.
fn trigger_columns(trigger: &Trigger) -> Result<WrittenTrigger<'_>, DomainError> {
    Ok(match trigger {
        Trigger::Manual | Trigger::Webhook => WrittenTrigger::default(),
        Trigger::Schedule(schedule) => WrittenTrigger {
            schedule: Some(schedule.as_str()),
            ..WrittenTrigger::default()
        },
        Trigger::Event(on) => WrittenTrigger {
            event: Some(on.event().as_str()),
            ..WrittenTrigger::default()
        },
        Trigger::Service(on) => WrittenTrigger {
            service: Some(TRIGGER_SERVICE.seal(&StoredTrigger::of(on))?),
            ..WrittenTrigger::default()
        },
        Trigger::Before(change) => WrittenTrigger {
            change: Some(change.as_str()),
            ..WrittenTrigger::default()
        },
    })
}

/// Seals the publisher in the stored envelope only for a published version.
fn publication_column(publication: &Publication) -> Result<Option<Value>, DomainError> {
    match publication {
        Publication::Unpublished => Ok(None),
        Publication::PublishedBy(publisher) => PUBLISHED_BY.seal(publisher).map(Some),
    }
}

/// A flow's written description, leaving designed workflows and blank flows unset.
fn flow_description(origin: &WorkflowOrigin) -> Option<&str> {
    match origin {
        WorkflowOrigin::Designed | WorkflowOrigin::Flow(FlowDescription::Blank) => None,
        WorkflowOrigin::Flow(FlowDescription::Written(written)) => Some(written.as_str()),
    }
}

/// Seals the missing-account details only while the version is held.
fn hold_column(hold: &Hold) -> Result<Option<Value>, DomainError> {
    match hold {
        Hold::Clear => Ok(None),
        Hold::NeedsAccount(missing) => HOLD.seal(&StoredHold::of(missing)).map(Some),
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::domains::agents::oversight::approval::ApprovalAction;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::workflows::data::DataPath;
    use ianua_domain::domains::workflows::design::graph::WorkflowGraph;
    use ianua_domain::domains::workflows::design::node::{
        CodeStep, Covering, GuardrailParams, GuardrailStep, Join, LoopParams, LoopStep, Mapping,
        Node, NodeKey, NodeKind, OnFinding, WaitStep, WorkflowApprovalStep,
    };
    use ianua_domain::domains::workflows::guardrail::banned::{BannedWord, BannedWords};
    use ianua_domain::domains::workflows::guardrail::finding::GuardrailCheck;
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
    use ianua_domain::domains::workflows::triggers::ServiceTrigger;
    use ianua_domain::types::{
        DeclaredAction, HumanAccount, Lifetime, PersonKey, SandboxVersionId, UserId,
    };
    use serde_json::json;

    use super::*;

    fn ann() -> Human {
        Human::new(
            HumanAccount::User(UserId::from_uuid(Uuid::nil())),
            PersonKey::new("ann@acme.example").unwrap(),
        )
    }

    /// Where the steps sit on the canvas is written in the shape pinned
    /// here, one position per step, and reads back.
    #[test]
    fn the_layout_is_stored_in_its_pinned_shape() {
        let layout = CanvasLayout::new(vec![(
            NodeKey::new("pause").unwrap(),
            StepPosition::new(40, 300).unwrap(),
        )])
        .unwrap();
        let stored = json!({"v": 1, "value": [{"key": "pause", "x": 40, "y": 300}]});

        assert_eq!(LAYOUT.seal(&stored_layout(&layout)).unwrap(), stored);
        assert_eq!(layout_from(LAYOUT.open(stored).unwrap()).unwrap(), layout);
    }

    /// A graph of one wait is written in the shape pinned here, and a graph
    /// in that shape reads back.
    #[test]
    fn the_graph_is_stored_in_its_pinned_shape() {
        let wait = WaitStep::new(Lifetime::seconds(3600).unwrap()).unwrap();
        let graph = WorkflowGraph::new(
            vec![Node::new(
                NodeKey::new("pause").unwrap(),
                Label::new("name", "Pause").unwrap(),
                NodeKind::Wait(wait),
                Join::All,
            )],
            Vec::new(),
        )
        .unwrap();
        let stored = json!({"v": 1, "value": {
            "nodes": [{
                "key": "pause",
                "name": "Pause",
                "kind": {"wait": {"duration": 3600}},
                "join": "all"
            }],
            "edges": []
        }});

        assert_eq!(GRAPH.seal(&graph).unwrap(), stored);
        assert_eq!(GRAPH.open::<WorkflowGraph>(stored).unwrap(), graph);
    }

    /// A loop running one wait for each issue, two at a time, is written
    /// in the shape pinned here, its own steps inside it, and reads back.
    #[test]
    fn a_loop_is_stored_in_its_pinned_shape() {
        let graph = issue_loop();
        let stored = json!({"v": 1, "value": {
            "nodes": [{
                "key": "each",
                "name": "Each issue",
                "kind": {"loop": {
                    "over": "trigger.issues",
                    "inputs": {"fields": []},
                    "body": {
                        "nodes": [{
                            "key": "pause",
                            "name": "Pause",
                            "kind": {"wait": {"duration": 60}},
                            "join": "all"
                        }],
                        "edges": []
                    },
                    "most": 50,
                    "at_once": 2
                }},
                "join": "all"
            }],
            "edges": []
        }});

        assert_eq!(GRAPH.seal(&graph).unwrap(), stored);
        assert_eq!(GRAPH.open::<WorkflowGraph>(stored).unwrap(), graph);
    }

    /// The loop body waits one minute for each supplied issue.
    fn issue_wait() -> WorkflowGraph {
        let wait = WaitStep::new(Lifetime::seconds(60).unwrap()).unwrap();
        WorkflowGraph::new(
            vec![Node::new(
                NodeKey::new("pause").unwrap(),
                Label::new("name", "Pause").unwrap(),
                NodeKind::Wait(wait),
                Join::All,
            )],
            Vec::new(),
        )
        .unwrap()
    }

    /// A graph loops over at most fifty issues, running two one-minute waits at once.
    fn issue_loop() -> WorkflowGraph {
        let body = issue_wait();
        let each = LoopStep::new(LoopParams {
            over: DataPath::parse("trigger.issues").unwrap(),
            inputs: Mapping::new(Vec::new()).unwrap(),
            body,
            most: 50,
            at_once: 2,
        })
        .unwrap();
        WorkflowGraph::new(
            vec![Node::new(
                NodeKey::new("each").unwrap(),
                Label::new("name", "Each issue").unwrap(),
                NodeKind::Loop(each),
                Join::All,
            )],
            Vec::new(),
        )
        .unwrap()
    }

    /// A graph of one step, `kind`, keyed `key` and called `name`.
    fn one_step(key: &str, name: &str, kind: NodeKind) -> WorkflowGraph {
        WorkflowGraph::new(
            vec![Node::new(
                NodeKey::new(key).unwrap(),
                Label::new("name", name).unwrap(),
                kind,
                Join::All,
            )],
            Vec::new(),
        )
        .unwrap()
    }

    /// A loop over issues whose first step asks one approval for every item.
    fn loop_approving_every_item() -> WorkflowGraph {
        let approval = WorkflowApprovalStep::new(
            ApprovalAction::new("close them").unwrap(),
            DeclaredAction::Undeclared,
            Lifetime::seconds(3600).unwrap(),
        )
        .unwrap()
        .covering(Covering::WholeLoop);
        let body = one_step("approve-all", "Approve all", NodeKind::Approval(approval));
        let each = LoopStep::new(LoopParams {
            over: DataPath::parse("trigger.issues").unwrap(),
            inputs: Mapping::new(Vec::new()).unwrap(),
            body,
            most: 50,
            at_once: 2,
        })
        .unwrap();
        one_step("each", "Each issue", NodeKind::Loop(each))
    }

    /// How [`loop_approving_every_item`] is stored.
    fn loop_approving_every_item_stored() -> Value {
        json!({"v": 1, "value": {
            "nodes": [{
                "key": "each",
                "name": "Each issue",
                "kind": {"loop": {
                    "over": "trigger.issues",
                    "inputs": {"fields": []},
                    "body": {
                        "nodes": [{
                            "key": "approve-all",
                            "name": "Approve all",
                            "kind": {"approval": {
                                "summary": "close them",
                                "action_class": "Undeclared",
                                "window": 3600,
                                "also_ask": "nowhere",
                                "covers": "whole_loop"
                            }},
                            "join": "all"
                        }],
                        "edges": []
                    },
                    "most": 50,
                    "at_once": 2
                }},
                "join": "all"
            }],
            "edges": []
        }})
    }

    /// A loop whose first step asks one approval for every item is written
    /// in the shape pinned here, the approval saying so, and reads back. An
    /// approval asked once per pass leaves `covers` out, as rows written
    /// before the choice did.
    #[test]
    fn an_approval_for_every_item_is_stored_in_its_pinned_shape() {
        let graph = loop_approving_every_item();
        let stored = loop_approving_every_item_stored();

        assert_eq!(GRAPH.open::<WorkflowGraph>(stored.clone()).unwrap(), graph);
        assert_eq!(GRAPH.seal(&graph).unwrap(), stored);
    }

    /// A code step running one sandbox version on no fields is written in
    /// the shape pinned here, naming its version, and reads back.
    #[test]
    fn a_code_step_is_stored_in_its_pinned_shape() {
        let version = SandboxVersionId::from_uuid(Uuid::nil());
        let graph = WorkflowGraph::new(
            vec![Node::new(
                NodeKey::new("clean").unwrap(),
                Label::new("name", "Clean").unwrap(),
                NodeKind::Code(CodeStep::new(version, Mapping::new(Vec::new()).unwrap())),
                Join::All,
            )],
            Vec::new(),
        )
        .unwrap();
        let stored = json!({"v": 1, "value": {
            "nodes": [{
                "key": "clean",
                "name": "Clean",
                "kind": {"code": {
                    "version": "00000000-0000-0000-0000-000000000000",
                    "inputs": {"fields": []}
                }},
                "join": "all"
            }],
            "edges": []
        }});

        assert_eq!(GRAPH.seal(&graph).unwrap(), stored);
        assert_eq!(GRAPH.open::<WorkflowGraph>(stored).unwrap(), graph);
    }

    /// A guardrail checking a draft's answer for banned words, removing what
    /// it finds, is written in the shape pinned here, and reads back.
    #[test]
    fn a_guardrail_step_is_stored_in_its_pinned_shape() {
        let guard = GuardrailStep::new(GuardrailParams {
            text: DataPath::parse("trigger.answer").unwrap(),
            checks: vec![GuardrailCheck::BannedWords],
            personal_from: DataClassLevel::Confidential,
            banned: BannedWords::new(vec![BannedWord::new("guaranteed returns").unwrap()]).unwrap(),
            on_finding: OnFinding::Remove,
        })
        .unwrap();
        let graph = one_step("guard", "Guard", NodeKind::Guardrail(guard));
        let stored = json!({"v": 1, "value": {
            "nodes": [{
                "key": "guard",
                "name": "Guard",
                "kind": {"guardrail": {
                    "text": "trigger.answer",
                    "checks": ["banned_words"],
                    "personal_from": "Confidential",
                    "banned": ["guaranteed returns"],
                    "on_finding": "remove"
                }},
                "join": "all"
            }],
            "edges": []
        }});

        assert_eq!(GRAPH.seal(&graph).unwrap(), stored);
        assert_eq!(GRAPH.open::<WorkflowGraph>(stored).unwrap(), graph);
    }

    /// The people who wrote and published a version are written in the
    /// shape pinned here, and read back.
    #[test]
    fn the_people_are_stored_in_their_pinned_shape() {
        let person = json!({
            "account": {"User": "00000000-0000-0000-0000-000000000000"},
            "person": "ann@acme.example"
        });

        let stored = json!({"v": 1, "value": person.clone()});

        assert_eq!(CREATED_BY.seal(&ann()).unwrap(), stored);
        assert_eq!(EDITED_BY.seal(&ann()).unwrap(), stored);
        assert_eq!(PUBLISHED_BY.seal(&ann()).unwrap(), stored);
        assert_eq!(CREATED_BY.open::<Human>(stored).unwrap(), ann());
        let authors = AUTHORS.seal(&[ann()]).unwrap();
        assert_eq!(authors, json!({"v": 1, "value": [person]}));
        assert_eq!(AUTHORS.open::<Vec<Human>>(authors).unwrap(), [ann()]);
    }

    /// A version's service trigger, on new GitHub issues, is written in the
    /// shape pinned here, and reads back.
    #[test]
    fn the_service_trigger_is_stored_in_its_pinned_shape() {
        let trigger = ServiceTrigger::from_stored(
            IntegrationKey::new("github").unwrap(),
            ServiceEventKey::new("issue-opened").unwrap(),
            IntegrationAccountId::from_uuid(Uuid::nil()),
            Vec::new(),
        )
        .unwrap();
        let stored = json!({"v": 1, "value": {
            "integration": "github",
            "event": "issue-opened",
            "account": "00000000-0000-0000-0000-000000000000",
            "filters": []
        }});

        assert_eq!(
            TRIGGER_SERVICE.seal(&StoredTrigger::of(&trigger)).unwrap(),
            stored
        );
        assert_eq!(
            TRIGGER_SERVICE
                .open::<StoredTrigger>(stored)
                .unwrap()
                .into_trigger(WORKFLOW)
                .unwrap(),
            trigger
        );
    }

    /// A version held because the account its "post" step acts through was
    /// switched off is written in the shape pinned here, and reads back.
    #[test]
    fn the_hold_is_stored_in_its_pinned_shape() {
        let missing = MissingAccount {
            account: IntegrationAccountId::from_uuid(Uuid::nil()),
            at: AccountUse::Step(NodeKey::new("post").unwrap()),
            why: AccountUnusable::Disabled,
        };
        let stored = json!({"v": 1, "value": {
            "account": "00000000-0000-0000-0000-000000000000",
            "step": "post",
            "why": "disabled"
        }});

        assert_eq!(HOLD.seal(&StoredHold::of(&missing)).unwrap(), stored);
        assert_eq!(
            HOLD.open::<StoredHold>(stored)
                .unwrap()
                .into_missing()
                .unwrap(),
            missing
        );
    }
}
