//! Loop steps: a group of steps run once for each item of a list an earlier
//! step gave back.
//!
//! Each pass runs the loop's own steps as an execution of its own, so every
//! rule an execution keeps holds inside a pass: its approvals, its retries,
//! its time limit and its audit trail.

use crate::domains::workflows::data::{DataPath, FieldName, FlowData, FlowValue};
use crate::domains::workflows::design::graph::WorkflowGraph;
use crate::domains::workflows::design::node::{
    Covering, Mapping, Node, NodeKind, WorkflowApprovalStep,
};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_range;

/// The most items one loop goes through.
pub(crate) const MAX_LOOP_ITEMS: u32 = 1000;

/// The most passes of one loop that run at the same time.
pub(crate) const MAX_PASSES_AT_ONCE: u32 = 10;

/// The field of a pass's trigger data its item is found under.
pub(crate) const ITEM_FIELD: &str = "item";

/// The field of a pass's trigger data its position, counted from zero, is
/// found under.
pub(crate) const INDEX_FIELD: &str = "index";

/// The values to make a loop step of, before they are checked.
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
pub struct LoopParams {
    /// Where the list is found in the step's input.
    pub over: DataPath,
    /// What else of the step's input each pass is given, beside its item
    /// and position.
    pub inputs: Mapping,
    /// The steps each pass runs.
    pub body: WorkflowGraph,
    /// The most items the list may hold.
    pub most: u32,
    /// How many passes may run at the same time.
    pub at_once: u32,
}

/// A group of steps run once for each item of a list.
///
/// Each pass starts with its item under `ITEM_FIELD`, its position under
/// `INDEX_FIELD` and the fields [`inputs`](Self::inputs) maps, all as its
/// trigger's data: a step inside reads `trigger.item`. Nothing else from
/// before the loop reaches the pass. The step gives back a list holding
/// what each pass gave back, in the order of the items.
///
/// A list longer than [`most`](Self::most) fails the step rather than being
/// cut short, so no item is silently left out. A pass that fails fails the
/// step, and the passes still running are stopped.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "LoopParams"))]
pub struct LoopStep {
    over: DataPath,
    inputs: Mapping,
    body: WorkflowGraph,
    most: u32,
    at_once: u32,
}

impl LoopStep {
    /// A loop step.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the most items is outside
    ///   `1..=MAX_LOOP_ITEMS`.
    /// - [`DomainError::Validation`] when the passes at once are outside
    ///   `1..=MAX_PASSES_AT_ONCE`.
    /// - [`DomainError::Validation`] when its steps hold another loop.
    /// - [`DomainError::Validation`] when its inputs set the item's or the
    ///   position's field.
    /// - [`DomainError::Validation`] when more than one of its steps asks
    ///   one approval for every item, or one that does has a step before it.
    pub fn new(params: LoopParams) -> Result<Self, DomainError> {
        validate_range("loop_most", params.most, 1..=MAX_LOOP_ITEMS)?;
        validate_range("loop_at_once", params.at_once, 1..=MAX_PASSES_AT_ONCE)?;
        ensure_no_loop_inside(&params.body)?;
        ensure_item_and_index_free(&params.inputs)?;
        ensure_items_approval_comes_first(&params.body)?;
        Ok(Self {
            over: params.over,
            inputs: params.inputs,
            body: params.body,
            most: params.most,
            at_once: params.at_once,
        })
    }

    /// Where the list is found in the step's input.
    #[must_use]
    pub fn over(&self) -> &DataPath {
        &self.over
    }

    /// What else of the step's input each pass is given.
    #[must_use]
    pub fn inputs(&self) -> &Mapping {
        &self.inputs
    }

    /// The steps each pass runs.
    #[must_use]
    pub fn body(&self) -> &WorkflowGraph {
        &self.body
    }

    /// The most items the list may hold.
    #[must_use]
    pub fn most(&self) -> u32 {
        self.most
    }

    /// How many passes may run at the same time.
    #[must_use]
    pub fn at_once(&self) -> u32 {
        self.at_once
    }

    /// The paths in the step's input it reads: the list, then what its
    /// inputs map.
    #[must_use]
    pub fn paths(&self) -> Vec<&DataPath> {
        std::iter::once(&self.over)
            .chain(self.inputs.paths())
            .collect()
    }

    /// The one approval among its steps asked once for every item, before
    /// any pass starts; `None` when each pass asks about its own item, if
    /// at all.
    #[must_use]
    pub fn items_approval(&self) -> Option<(&Node, &WorkflowApprovalStep)> {
        items_approvals(&self.body).next()
    }
}

/// The approvals among `body` asked once for every item.
fn items_approvals(body: &WorkflowGraph) -> impl Iterator<Item = (&Node, &WorkflowApprovalStep)> {
    body.nodes().iter().filter_map(|node| match node.kind() {
        NodeKind::Approval(step) if step.covers_items() == Covering::WholeLoop => {
            Some((node, step))
        }
        NodeKind::AgentRun(_)
        | NodeKind::Action(_)
        | NodeKind::Condition(_)
        | NodeKind::Transform(_)
        | NodeKind::Approval(_)
        | NodeKind::Wait(_)
        | NodeKind::Loop(_)
        | NodeKind::Code(_)
        | NodeKind::Guardrail(_) => None,
    })
}

/// Refuses a second approval asked for every item, and one with a step
/// before it.
///
/// What a pass's approval lets through is what came before it in the pass.
/// Asked first, that is the item, its position and the mapped fields, which
/// is exactly what the approver is shown in the list, so no pass acts on
/// data its approver did not see.
fn ensure_items_approval_comes_first(body: &WorkflowGraph) -> Result<(), DomainError> {
    let mut approvals = items_approvals(body);
    let first = approvals.next();
    if approvals.next().is_some() {
        return Err(DomainError::invalid(message!(
            "workflows-a-loop-asks-one-approval-for-every-item-at-most-once",
            "a loop may ask one approval for every item at most once"
        )));
    }
    let Some((node, _)) = first.filter(|(node, _)| !body.is_entry(node.key())) else {
        return Ok(());
    };
    Err(DomainError::invalid(message!(
        "workflows-an-approval-for-every-item-comes-first",
        format!(
            "{} asks one approval for every item, so it must be the loop's first step",
            node.key()
        )
    )))
}

/// The trigger data pass `index` starts with: `item`, its position, and the
/// fields `shared` holds, which the loop's inputs mapped from its input.
///
/// # Errors
///
/// - [`DomainError::Validation`] when it is larger than workflow data may
///   be.
pub(crate) fn pass_input(
    shared: &FlowData,
    item: FlowData,
    index: u32,
) -> Result<FlowData, DomainError> {
    let mut fields = vec![
        (FieldName::new(ITEM_FIELD)?, item),
        (
            FieldName::new(INDEX_FIELD)?,
            FlowData::number(f64::from(index))?,
        ),
    ];
    if let FlowValue::Map(entries) = shared.value() {
        fields.extend(entries.iter().cloned());
    }
    FlowData::map(fields)
}

/// Refuses steps that hold a loop of their own.
///
/// A loop inside a loop would multiply the passes beyond what anyone set
/// out to run.
fn ensure_no_loop_inside(body: &WorkflowGraph) -> Result<(), DomainError> {
    let Some(inner) = body
        .nodes()
        .iter()
        .find(|node| matches!(node.kind(), NodeKind::Loop(_)))
    else {
        return Ok(());
    };
    Err(DomainError::invalid(message!(
        "workflows-a-loop-may-not-hold-another-loop",
        format!(
            "{} is a loop inside a loop, which is not allowed",
            inner.key()
        )
    )))
}

/// Refuses inputs that set the field the item or the position goes under,
/// since the pass would read the mapped value where it expects its own.
fn ensure_item_and_index_free(inputs: &Mapping) -> Result<(), DomainError> {
    let Some((taken, _)) = inputs
        .fields()
        .iter()
        .find(|(name, _)| name.as_str() == ITEM_FIELD || name.as_str() == INDEX_FIELD)
    else {
        return Ok(());
    };
    Err(DomainError::invalid(message!(
        "workflows-a-loop-input-may-not-be-named",
        format!("a loop's input may not be named {taken}, which each pass sets itself")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::oversight::approval::ApprovalAction;
    use crate::domains::workflows::design::graph::Edge;
    use crate::domains::workflows::design::node::{Join, NodeKey, Port, Source};
    use crate::types::{DeclaredAction, Label, Lifetime};

    fn field(name: &str) -> FieldName {
        FieldName::new(name).unwrap()
    }

    fn transform_named(name: &str) -> Node {
        let mapping =
            Mapping::new(vec![(field("seen"), Source::Literal(FlowData::bool(true)))]).unwrap();
        Node::new(
            NodeKey::new(name).unwrap(),
            Label::new("name", name).unwrap(),
            NodeKind::Transform(mapping),
            Join::All,
        )
    }

    fn loop_body() -> WorkflowGraph {
        WorkflowGraph::new(vec![transform_named("comment")], Vec::new()).unwrap()
    }

    fn loop_of(body: WorkflowGraph, most: u32, at_once: u32) -> Result<LoopStep, DomainError> {
        LoopStep::new(LoopParams {
            over: DataPath::parse("search.issues").unwrap(),
            inputs: Mapping::new(Vec::new()).unwrap(),
            body,
            most,
            at_once,
        })
    }

    /// A loop going through at most 1,000 items, ten at a time, is made. One
    /// allowed 1,001 items, or eleven at a time, is refused.
    #[test]
    fn a_loop_keeps_to_its_limits() {
        let fits = loop_of(loop_body(), MAX_LOOP_ITEMS, MAX_PASSES_AT_ONCE);
        let too_many = loop_of(loop_body(), MAX_LOOP_ITEMS + 1, 1);
        let too_wide = loop_of(loop_body(), 10, MAX_PASSES_AT_ONCE + 1);

        assert!(fits.is_ok());
        assert!(matches!(too_many, Err(DomainError::Validation(_))));
        assert!(matches!(too_wide, Err(DomainError::Validation(_))));
    }

    /// Loop construction rejects a body containing another loop, even when
    /// each loop individually stays within the item and concurrency limits.
    #[test]
    fn a_loop_inside_a_loop_is_refused() {
        let inner = loop_of(loop_body(), 10, 1).unwrap();
        let body = WorkflowGraph::new(
            vec![Node::new(
                NodeKey::new("inner").unwrap(),
                Label::new("name", "inner").unwrap(),
                NodeKind::Loop(inner),
                Join::All,
            )],
            Vec::new(),
        )
        .unwrap();

        assert!(matches!(
            loop_of(body, 10, 1),
            Err(DomainError::Validation(_))
        ));
    }

    /// A loop input mapping cannot use the reserved `item` field supplied to
    /// each pass.
    #[test]
    fn a_loop_input_named_like_the_item_is_refused() {
        let inputs =
            Mapping::new(vec![(field(ITEM_FIELD), Source::Literal(FlowData::null()))]).unwrap();

        let made = LoopStep::new(LoopParams {
            over: DataPath::parse("search.issues").unwrap(),
            inputs,
            body: loop_body(),
            most: 10,
            at_once: 1,
        });

        assert!(matches!(made, Err(DomainError::Validation(_))));
    }

    fn approval_named(name: &str, covers: Covering) -> Node {
        let step = WorkflowApprovalStep::new(
            ApprovalAction::new("close the issues").unwrap(),
            DeclaredAction::Undeclared,
            Lifetime::seconds(3600).unwrap(),
        )
        .unwrap()
        .covering(covers);
        Node::new(
            NodeKey::new(name).unwrap(),
            Label::new("name", name).unwrap(),
            NodeKind::Approval(step),
            Join::All,
        )
    }

    fn edge_to(from: &str, to: &str) -> Edge {
        Edge::new(
            NodeKey::new(from).unwrap(),
            Port::Next,
            NodeKey::new(to).unwrap(),
        )
    }

    /// Ann's loop asks one approval for every issue as its first step, then
    /// comments on each. It is made, and names that approval as the one
    /// asked for every item.
    #[test]
    fn a_loop_whose_first_step_approves_every_item_names_it() {
        let body = WorkflowGraph::new(
            vec![
                approval_named("approve-all", Covering::WholeLoop),
                transform_named("comment"),
            ],
            vec![edge_to("approve-all", "comment")],
        )
        .unwrap();

        let made = loop_of(body, 10, 1).unwrap();

        assert_eq!(
            made.items_approval().map(|(node, _)| node.key().as_str()),
            Some("approve-all")
        );
    }

    /// An approval for every item placed after the comment step, or two such
    /// approvals, are refused: the first would approve data the list never
    /// showed, the second would ask the same people twice.
    #[test]
    fn an_approval_for_every_item_must_come_first_and_only_once() {
        let late = WorkflowGraph::new(
            vec![
                transform_named("comment"),
                approval_named("approve-all", Covering::WholeLoop),
            ],
            vec![edge_to("comment", "approve-all")],
        )
        .unwrap();
        let twice = WorkflowGraph::new(
            vec![
                approval_named("first", Covering::WholeLoop),
                approval_named("second", Covering::WholeLoop),
            ],
            Vec::new(),
        )
        .unwrap();

        assert!(matches!(
            loop_of(late, 10, 1),
            Err(DomainError::Validation(_))
        ));
        assert!(matches!(
            loop_of(twice, 10, 1),
            Err(DomainError::Validation(_))
        ));
    }

    /// A loop whose approval is asked once per pass names no approval for
    /// every item.
    #[test]
    fn a_loop_asking_each_pass_names_no_approval_for_every_item() {
        let body = WorkflowGraph::new(
            vec![approval_named("check", Covering::EachPass)],
            Vec::new(),
        )
        .unwrap();

        assert!(loop_of(body, 10, 1).unwrap().items_approval().is_none());
    }

    /// The third pass over issues, with the channel mapped from the loop's
    /// input, starts with the issue under `item`, 2 under `index` and the
    /// channel beside them.
    #[test]
    fn a_pass_starts_with_its_item_its_position_and_the_mapped_fields() {
        let shared =
            FlowData::map(vec![(field("channel"), FlowData::text("ops").unwrap())]).unwrap();
        let issue = FlowData::text("issue 3").unwrap();

        let input = pass_input(&shared, issue.clone(), 2).unwrap();

        assert_eq!(input.field(&field(ITEM_FIELD)), Some(&issue));
        assert_eq!(
            input.field(&field(INDEX_FIELD)),
            Some(&FlowData::number(2.0).unwrap())
        );
        assert_eq!(
            input.field(&field("channel")),
            Some(&FlowData::text("ops").unwrap())
        );
    }
}
