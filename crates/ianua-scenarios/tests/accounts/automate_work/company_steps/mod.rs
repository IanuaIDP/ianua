//! The rest of the company's own steps, each acting on Acme as the run's
//! person through the action that person could take by hand, the audit
//! trail naming the person and the run. A step that changes who can do
//! what waits for two colleagues to say yes, each with a fresh code from
//! their authenticator; a step the run's person could not take by hand
//! fails and changes nothing, whatever was approved before it.
//!
//! - `people`: finding Lee, suspending Lee and inviting Uma in Lee's
//!   place, forgetting Lee's laptop and clearing Lee's authenticator,
//!   ending the keys Tess made, and resuming a paused key.
//! - `access`: asking what Lee may do and who is in Support, moving Lee
//!   from Ops to Support, approving Lee's request and lending Lee Ops for
//!   two hours, and emergency access that a run's person without the
//!   right to hand out rights cannot give.
//! - `agents`: ending an agent's run stuck on its model, taking one
//!   object out of an agent's task, and a pause and a narrowing the run's
//!   person could not make by hand.
//! - `platform`: a sealed audit pack an auditor checks against Acme's
//!   published keys, searching the trail, classifying a field, and
//!   closing an app to workflows.

mod access;
mod agents;
mod people;
mod platform;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{audit, workflows};
use ianua_scenarios::expect::eventually;
use ianua_scenarios::wire::audit::AuditEntry;
use ianua_scenarios::wire::workflows::{
    Edge, Execution, Graph, MappedField, Node, Source, StartExecution, Step, Trigger,
};
use ianua_scenarios::world::World;
use serde_json::{Value, json};

use crate::support::{ApprovalStep, Approver, drafted, published, run};

/// How long an approval before a change to who can do what may wait: ten
/// minutes, longer than two colleagues take, even on a clock the
/// authenticators move on.
const APPROVAL_WINDOW_SECONDS: u32 = 600;

/// One company step `operation`, keyed `key`, of the kind `effect` says,
/// such as `write`, given `inputs`.
pub(crate) fn company_step(
    key: &str,
    operation: &str,
    effect: &str,
    inputs: Vec<(&str, Source)>,
) -> Node {
    Node {
        key: key.to_owned(),
        name: operation.to_owned(),
        step: Step::Action {
            integration: "ianua".to_owned(),
            operation: operation.to_owned(),
            account_id: None,
            effect: effect.to_owned(),
            ceiling: "internal".to_owned(),
            inputs: inputs
                .into_iter()
                .map(|(field, source)| MappedField {
                    field: field.to_owned(),
                    source,
                })
                .collect(),
        },
    }
}

/// `node` taking data up to `limit`, as the builder writes it from the
/// step the platform offers.
pub(crate) fn taking_up_to(mut node: Node, limit: &str) -> Node {
    if let Step::Action { ceiling, .. } = &mut node.step {
        limit.clone_into(ceiling);
    }
    node
}

/// The approval keyed `key` asking for a yes to `summary`, an admin
/// change, which two colleagues must give.
pub(crate) fn yes(key: &str, summary: &str) -> Node {
    Node {
        key: key.to_owned(),
        name: summary.to_owned(),
        step: Step::Approval {
            summary: summary.to_owned(),
            action_class: "admin".to_owned(),
            window_seconds: APPROVAL_WINDOW_SECONDS,
        },
    }
}

/// A graph running `nodes` one after another, in the order given.
pub(crate) fn in_order(nodes: Vec<Node>) -> Graph {
    let edges = nodes
        .windows(2)
        .map(|pair| Edge {
            from: pair[0].key.clone(),
            to: pair[1].key.clone(),
        })
        .collect();
    Graph { nodes, edges }
}

/// Tess drafts `graph`, Ann publishes it, and `person` starts it by hand;
/// the run's id.
pub(crate) async fn started_by(world: &World<'_>, person: &mut Person, graph: Graph) -> String {
    let draft = drafted(world, Trigger::Manual, graph).await;
    let workflow = published(world, &draft).await;
    let start = StartExecution {
        input: json!({}),
        exposure: "internal".to_owned(),
    };
    person
        .send(workflows::start(world.tenant(), &workflow.id, &start))
        .await
        .ok()
        .execution_id
}

/// What the step `key` of `execution` gave back.
pub(crate) fn output(execution: &Execution, key: &str) -> Value {
    execution
        .steps
        .iter()
        .find(|step| step.key == key)
        .and_then(|step| step.output.clone())
        .unwrap_or_else(|| panic!("the step {key} answered: {:?}", execution.steps))
}

/// The phase the step `key` of `execution` ended in, such as `failed`.
pub(crate) fn phase(execution: &Execution, key: &str) -> String {
    execution
        .steps
        .iter()
        .find(|step| step.key == key)
        .map(|step| step.phase.clone())
        .unwrap_or_else(|| panic!("the run has the step {key}"))
}

/// The record of `event_type` that came through the run `execution_id`,
/// as Tess reads the tenant's trail; it names `email` as who acted.
pub(crate) async fn through_run(
    world: &World<'_>,
    event_type: &str,
    execution_id: &str,
    email: &str,
) -> AuditEntry {
    let log = audit::tenant_log(world.tenant(), event_type)
        .send(world.admin().client())
        .await
        .ok();
    let entry = log
        .items
        .into_iter()
        .find(|entry| {
            entry.acted_through.as_ref().is_some_and(|through| {
                through.kind == "workflow_run"
                    && through.execution_id.as_deref() == Some(execution_id)
            })
        })
        .unwrap_or_else(|| panic!("{event_type} names the run it came through"));
    assert!(entry.actor.contains(email), "{}", entry.actor);
    entry
}

/// Waits until the run `execution_id` waits at its approval `key`.
pub(crate) async fn waiting_at(world: &World<'_>, execution_id: &str, key: &str) {
    let held = eventually("the run to wait for a yes, or end", || async {
        let execution = run(world, execution_id).await;
        let waiting = execution
            .steps
            .iter()
            .any(|step| step.key == key && step.phase == "running");
        (waiting || execution.status != "running").then_some(execution)
    })
    .await;
    assert_eq!(held.status, "running", "the run waits for a yes: {held:?}");
}

/// Bea and Cal, administrators of the organization who wrote none of the
/// workflows and are no run's person, each with an authenticator app.
pub(crate) struct TwoApprovers {
    bea: Approver,
    cal: Approver,
}

impl TwoApprovers {
    /// Bea and Cal, invited by Ann, signed in and with their apps set up.
    pub(crate) async fn joined(world: &World<'_>) -> Self {
        Self {
            bea: Approver::joined(world, "bea", "Bea Approver").await,
            cal: Approver::joined(world, "cal", "Cal Approver").await,
        }
    }

    /// Once the run `execution_id` waits at its approval `key`, Bea and
    /// then Cal approve exactly what it shows, each with a fresh code.
    pub(crate) async fn approve(&mut self, world: &World<'_>, execution_id: &str, key: &str) {
        waiting_at(world, execution_id, key).await;
        let shown = workflows::approval(world.tenant(), execution_id, key)
            .send(world.owner().client())
            .await
            .ok();
        let target = ApprovalStep {
            execution_id,
            step: key,
        };
        self.bea.approve(world, target, &shown.shown).await;
        self.cal.approve(world, target, &shown.shown).await;
    }
}
