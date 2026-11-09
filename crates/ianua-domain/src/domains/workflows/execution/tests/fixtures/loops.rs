//! The loop tests build on: a step listing issues, and a loop over them.

use crate::domains::workflows::data::FlowData;
use crate::domains::workflows::design::graph::WorkflowGraph;
use crate::domains::workflows::design::node::{
    Covering, Join, LoopParams, LoopStep, Mapping, Node, NodeKind, Source,
};
use crate::domains::workflows::execution::tests::fixtures::{approval_of, field, node, path};
use crate::types::DeclaredAction;

/// A transform giving back `items` as a list of texts under `issues`.
pub(crate) fn listing(name: &str, items: &[&str]) -> Node {
    let list = FlowData::list(
        items
            .iter()
            .map(|item| FlowData::text(*item).unwrap())
            .collect(),
    )
    .unwrap();
    let mapping = Mapping::new(vec![(field("issues"), Source::Literal(list))]).unwrap();
    node(name, NodeKind::Transform(mapping), Join::All)
}

/// A loop over the list at `over`, running `body` for each item, `at_once`
/// at a time, for at most ten items.
pub(crate) fn each(name: &str, over: &str, body: Vec<Node>, at_once: u32) -> Node {
    each_running(
        name,
        over,
        WorkflowGraph::new(body, Vec::new()).unwrap(),
        at_once,
    )
}

/// A loop over the list at `over`, running the steps and edges of `body`
/// for each item, `at_once` at a time, for at most ten items.
pub(crate) fn each_running(name: &str, over: &str, body: WorkflowGraph, at_once: u32) -> Node {
    let step = LoopStep::new(LoopParams {
        over: path(over),
        inputs: Mapping::new(Vec::new()).unwrap(),
        body,
        most: 10,
        at_once,
    })
    .unwrap();
    node(name, NodeKind::Loop(step), Join::All)
}

/// An approval of `class` asked once for every item, as a loop's first
/// step.
pub(crate) fn approving_every_item(name: &str, class: DeclaredAction) -> Node {
    let NodeKind::Approval(step) = approval_of(name, class).kind().clone() else {
        unreachable!("an approval fixture is an approval step");
    };
    node(
        name,
        NodeKind::Approval(step.covering(Covering::WholeLoop)),
        Join::All,
    )
}
