//! Executions as the workflows tests start them.

use ianua_domain::domains::agents::authority::delegation::HeldResources;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::{FieldName, FlowData};
use ianua_domain::domains::workflows::design::node::Node;
use ianua_domain::domains::workflows::design::workflow::Workflow;
use ianua_domain::domains::workflows::execution::{ManualStartParams, WorkflowExecution};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{ActionClass, Human};

use crate::test_support::workflows::graphs::{
    approval_step, draft_by, managing, next, published_by, step, tidy_step,
};

/// The data every execution these tests start is handed: `{"ok": true}`.
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

/// An execution of `workflow` that `person` started by hand, with
/// [`trigger_data`] at internal.
///
/// # Panics
///
/// Panics if `workflow` is not published or does not start by hand.
#[must_use]
pub fn started_by(
    person: &Human,
    workflow: &Workflow<ResolvedTenant>,
) -> WorkflowExecution<ResolvedTenant> {
    let (execution, _) = WorkflowExecution::start_by_hand(
        workflow,
        managing(person),
        ManualStartParams {
            resources: HeldResources::answered(person.principal(), Vec::new()),
            input: trigger_data(),
            exposure: DataClassLevel::Internal,
        },
    )
    .expect("someone managing workflows starts a published one");
    execution
}

/// A workflow `author` wrote and published: an approval step called
/// `check`, for actions of `class`, before a step called `after`.
#[must_use]
pub fn approval_workflow(author: &Human, class: ActionClass) -> Workflow<ResolvedTenant> {
    let nodes: Vec<Node> = vec![approval_step("check", class), tidy_step("after")];
    published_by(
        author,
        draft_by(author, nodes, vec![next("check", "after")]),
    )
}

/// An execution `acting_for` started of [`approval_workflow`], which
/// `author` wrote, waiting at `check` for a decision.
///
/// # Panics
///
/// Panics if the approval cannot be asked for.
#[must_use]
pub fn awaiting_approval(
    author: &Human,
    acting_for: &Human,
    class: ActionClass,
) -> WorkflowExecution<ResolvedTenant> {
    let mut execution = started_by(acting_for, &approval_workflow(author, class));
    execution
        .request_approval(&step("check"))
        .expect("the approval step is ready");
    execution
}
