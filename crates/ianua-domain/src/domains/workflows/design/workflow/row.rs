//! What a workflow version is made from and stored as, and the rules a
//! stored version is read back against.

use time::OffsetDateTime;

use crate::domains::workflows::design::authors::Authors;
use crate::domains::workflows::design::graph::WorkflowGraph;
use crate::domains::workflows::design::publish_rules::{
    ensure_checks_are_of_other_agents, ensure_guardrails_read_text,
    ensure_high_risk_actions_approved, ensure_item_approvals_in_loops,
    ensure_paths_name_earlier_steps,
};
use crate::domains::workflows::design::workflow::flow::holds_only_flow_steps;
use crate::domains::workflows::design::workflow::{
    CanvasLayout, FailureAlert, Hold, Publication, RunLimit, WorkflowOrigin, WorkflowStatus,
};
use crate::domains::workflows::triggers::Trigger;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::types::{Human, Label, Text, WorkflowId};

/// The values a workflow starts from.
pub struct CreateWorkflowParams {
    /// The display label used to identify the automation in lists and records.
    pub name: Label,
    /// What it does, as its author describes it.
    pub description: Option<Text>,
    /// Its steps and edges.
    pub graph: WorkflowGraph,
    /// Where its steps sit on the canvas.
    pub layout: CanvasLayout,
    /// What starts it.
    pub trigger: Trigger,
    /// How long one execution may run.
    pub run_limit: RunLimit,
    /// Who is told when one of its runs fails.
    pub failure_alert: FailureAlert,
}

/// One version of a workflow, as stored.
pub struct WorkflowRow {
    /// The workflow every version belongs to.
    pub id: WorkflowId,
    /// Which version this is, counting from one.
    pub version: u32,
    /// The persisted display label for this particular revision.
    pub name: Label,
    /// What it does.
    pub description: Option<Text>,
    /// Its steps and edges.
    pub graph: WorkflowGraph,
    /// Where its steps sit on the canvas.
    pub layout: CanvasLayout,
    /// What starts it.
    pub trigger: Trigger,
    /// How long one execution may run.
    pub run_limit: RunLimit,
    /// Who is told when one of its runs fails.
    pub failure_alert: FailureAlert,
    /// Where it stands.
    pub status: WorkflowStatus,
    /// The person who drafted this version.
    pub created_by: Human,
    /// The person who last edited it.
    pub edited_by: Human,
    /// Everyone who shaped its steps.
    pub authors: Authors,
    /// Whether it was published, and by whom.
    pub publication: Publication,
    /// Whether a person designed it or it is an agent flow.
    pub origin: WorkflowOrigin,
    /// Whether it is held for want of an account.
    pub hold: Hold,
    /// When this version was drafted.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// Refuses a stored row that breaks a rule a version keeps.
pub(super) fn ensure_consistent(row: &WorkflowRow) -> Result<(), DomainError> {
    let check = RowCheck::of("workflow")
        .holds(row.version >= 1, "a version below one")
        .in_order(
            row.created_at,
            row.updated_at,
            "changed before it was drafted",
        )
        .holds(
            publication_fits(row.status, &row.publication),
            "a publication its status contradicts",
        )
        .holds(
            lists_every_author(row),
            "a drafter, editor or publisher missing from its authors",
        );
    graph_keeps_its_rules(check, row).finish()
}

/// Adds the rules a version's graph, origin, hold and layout keep, as a
/// draft or in service, to `check`.
fn graph_keeps_its_rules(check: RowCheck, row: &WorkflowRow) -> RowCheck {
    let in_service = row.status != WorkflowStatus::Draft;
    check
        .holds(
            !in_service || graph_may_serve(&row.graph),
            "a high-risk action in service without an approval right before it, or a step reading one that cannot come before it",
        )
        .holds(
            origin_fits(row),
            "a flow that is not one published version of agent runs, started by hand",
        )
        .holds(
            in_service || row.hold == Hold::Clear,
            "a draft held for want of an account",
        )
        .holds(
            row.layout.ensure_fits(&row.graph).is_ok(),
            "a layout placing a step its graph does not have",
        )
}

/// Whether `graph` may be in service: every high-risk action has an
/// approval right before it, every step reads only steps that can come
/// before it, every check is of another agent's earlier work, no
/// approval for every item sits outside a loop, and every guardrail reads
/// a step that hands on text.
fn graph_may_serve(graph: &WorkflowGraph) -> bool {
    ensure_high_risk_actions_approved(graph).is_ok()
        && ensure_paths_name_earlier_steps(graph).is_ok()
        && ensure_checks_are_of_other_agents(graph).is_ok()
        && ensure_item_approvals_in_loops(graph).is_ok()
        && ensure_guardrails_read_text(graph).is_ok()
}

/// Whether a version in `status` could have `publication`.
///
/// A draft was never published. A published version was. An archived one
/// may have been either.
pub(super) fn publication_fits(status: WorkflowStatus, publication: &Publication) -> bool {
    match (status, publication) {
        (WorkflowStatus::Draft, Publication::Unpublished)
        | (WorkflowStatus::Published, Publication::PublishedBy(_))
        | (WorkflowStatus::Archived, _) => true,
        (WorkflowStatus::Draft, Publication::PublishedBy(_))
        | (WorkflowStatus::Published, Publication::Unpublished) => false,
    }
}

/// Whether a stored version's authors name who drafted it, who last edited
/// it and who published it.
pub(super) fn lists_every_author(row: &WorkflowRow) -> bool {
    let publisher = match &row.publication {
        Publication::PublishedBy(publisher) => Some(publisher),
        Publication::Unpublished => None,
    };
    [&row.created_by, &row.edited_by]
        .into_iter()
        .chain(publisher)
        .all(|person| row.authors.includes(person))
}

/// Whether a stored version is what its origin makes.
///
/// A designed workflow may be anything the rules above allow. A flow is
/// its first and only version, published when it was made, started by
/// hand, and holds only agent runs and the steps that gather their answers.
fn origin_fits(row: &WorkflowRow) -> bool {
    match row.origin {
        WorkflowOrigin::Designed => true,
        WorkflowOrigin::Flow(_) => {
            row.version == 1
                && row.trigger == Trigger::Manual
                && matches!(row.publication, Publication::PublishedBy(_))
                && holds_only_flow_steps(&row.graph)
        }
    }
}
