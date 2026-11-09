//! The shape of a workflow: its steps and the edges between them.
//!
//! A directed graph without cycles. Every step with no edge into it starts
//! from the trigger. Every other step waits for the steps before it, as its
//! [`Join`](crate::domains::workflows::design::node::Join) says. Without cycles, every execution ends.

use std::collections::VecDeque;

use crate::domains::workflows::design::node::{
    AgentRunParams, CodeStep, Node, NodeKey, NodeKind, Port,
};
use crate::domains::workflows::design::stages::laid_out;
use crate::domains::workflows::integration::ActionStep;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;

/// The most steps one workflow may hold.
pub(crate) const MAX_NODES: usize = 64;

/// The most edges one workflow may hold.
pub(crate) const MAX_EDGES: usize = 256;

/// One edge: when `from` leaves by `port`, `to` may start.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Edge {
    from: NodeKey,
    port: Port,
    to: NodeKey,
}

impl Edge {
    /// An edge from `from`, leaving by `port`, to `to`.
    #[must_use]
    pub fn new(from: NodeKey, port: Port, to: NodeKey) -> Self {
        Self { from, port, to }
    }

    /// The step it leaves.
    #[must_use]
    pub fn from(&self) -> &NodeKey {
        &self.from
    }

    /// The way out of that step it leaves by.
    #[must_use]
    pub fn port(&self) -> Port {
        self.port
    }

    /// The step it leads to.
    #[must_use]
    pub fn to(&self) -> &NodeKey {
        &self.to
    }
}

/// A workflow's steps and edges, checked to form a graph that runs.
///
/// A stored graph is read back through [`WorkflowGraph::new`], so one that
/// no longer forms a graph that runs is refused.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "crate::domains::workflows::stored::GraphWire")
)]
pub struct WorkflowGraph {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
}

impl WorkflowGraph {
    /// A graph of `nodes` and `edges`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] for a step count outside `1..=MAX_NODES`,
    /// more than `MAX_EDGES` edges, repeated step keys (including loop steps) or edges,
    /// unknown endpoints, self-edges, nonexistent output branches, or a cycle.
    pub fn new(nodes: Vec<Node>, edges: Vec<Edge>) -> Result<Self, DomainError> {
        validate_count("workflow_nodes", nodes.len(), 1..=MAX_NODES)?;
        validate_count("workflow_edges", edges.len(), 0..=MAX_EDGES)?;
        let graph = Self { nodes, edges };
        if let Some(twice) = first_repeat(graph.every_node().map(Node::key)) {
            return Err(DomainError::invalid(message!(
                "workflows-the-step-is-named-twice",
                format!("the step {twice} is named twice")
            )));
        }
        graph.ensure_edges_fit()?;
        graph.ensure_acyclic()?;
        Ok(graph)
    }

    /// Builds an agent flow whose stages wait for every run in the preceding stage.
    /// Gathering transforms pass answers under `EARLIER_FIELD`.
    /// Run keys use `stage-1-run-1`; gathering keys use `stage-1-answers` and count toward `MAX_NODES`.
    ///
    /// # Errors
    /// [`DomainError::Validation`] for no stages or empty stages, invalid agent runs,
    /// reserved answer fields in later inputs, or exceeding `MAX_NODES` or `MAX_EDGES`.
    pub fn staged(stages: Vec<Vec<AgentRunParams>>) -> Result<Self, DomainError> {
        let (nodes, edges) = laid_out(stages)?;
        Self::new(nodes, edges)
    }

    fn ensure_edges_fit(&self) -> Result<(), DomainError> {
        if first_repeat(&self.edges).is_some() {
            return Err(DomainError::invalid(message!(
                "workflows-an-edge-is-drawn-twice",
                "an edge is drawn twice"
            )));
        }
        self.edges
            .iter()
            .try_for_each(|edge| self.ensure_edge_fits(edge))
    }

    fn ensure_edge_fits(&self, edge: &Edge) -> Result<(), DomainError> {
        let Some(from) = self.node(&edge.from) else {
            return Err(DomainError::invalid(message!(
                "workflows-an-edge-leaves-which-is-not",
                format!(
                    "an edge leaves {}, which is not a step of this workflow",
                    edge.from
                )
            )));
        };
        self.ensure_edge_leads_elsewhere(edge)?;
        if !from.kind().ports().contains(&edge.port) {
            return Err(DomainError::invalid(message!(
                "workflows-has-no-way-out-by",
                format!("{} has no way out by {:?}", edge.from, edge.port)
            )));
        }
        Ok(())
    }

    /// Refuses an edge to a step the workflow does not have, or back to
    /// the step it leaves.
    fn ensure_edge_leads_elsewhere(&self, edge: &Edge) -> Result<(), DomainError> {
        if self.node(&edge.to).is_none() {
            return Err(DomainError::invalid(message!(
                "workflows-an-edge-leads-to-which-is",
                format!(
                    "an edge leads to {}, which is not a step of this workflow",
                    edge.to
                )
            )));
        }
        if edge.from == edge.to {
            return Err(DomainError::invalid(message!(
                "workflows-an-edge-leads-from-back-to",
                format!("an edge leads from {} back to itself", edge.from)
            )));
        }
        Ok(())
    }

    /// Refuses a cycle, using Kahn's walk.
    ///
    /// When every step can be put after all the steps before it, there is
    /// no cycle.
    fn ensure_acyclic(&self) -> Result<(), DomainError> {
        if self.in_order().len() == self.nodes.len() {
            return Ok(());
        }
        Err(DomainError::invalid(message!(
            "workflows-the-workflow-s-edges-form-a",
            "the workflow's edges form a cycle, so it would never end"
        )))
    }

    /// Every step, each after every step with an edge into it.
    ///
    /// A built graph has no cycle, so every step is in the list.
    #[must_use]
    pub fn in_order(&self) -> Vec<&NodeKey> {
        let mut waiting: Vec<usize> = self
            .nodes
            .iter()
            .map(|node| self.incoming(node.key()).count())
            .collect();
        let mut ready: VecDeque<usize> = waiting
            .iter()
            .enumerate()
            .filter(|(_, count)| **count == 0)
            .map(|(index, _)| index)
            .collect();
        let mut order = Vec::with_capacity(self.nodes.len());
        while let Some(index) = ready.pop_front() {
            let Some(node) = self.nodes.get(index) else {
                break;
            };
            order.push(node.key());
            for target in self.successor_positions(node.key()) {
                let Some(count) = waiting.get_mut(target) else {
                    continue;
                };
                *count = count.saturating_sub(1);
                if *count == 0 {
                    ready.push_back(target);
                }
            }
        }
        order
    }

    /// The positions, in the step list, of the steps the edges out of `key`
    /// lead to.
    fn successor_positions(&self, key: &NodeKey) -> Vec<usize> {
        self.outgoing(key)
            .filter_map(|edge| self.nodes.iter().position(|node| node.key() == edge.to()))
            .collect()
    }

    /// The steps, in the order they were given.
    #[must_use]
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// Every step, each loop followed by the steps it runs for each item.
    ///
    /// A loop's steps hold no loop of their own, so one level is all there
    /// is. Step keys are unique across all of them, so a key names one step
    /// of the whole workflow.
    pub fn every_node(&self) -> impl Iterator<Item = &Node> {
        self.nodes.iter().flat_map(|node| {
            std::iter::once(node).chain(
                node.kind()
                    .body()
                    .into_iter()
                    .flat_map(|body| body.nodes().iter()),
            )
        })
    }

    /// Every action step, a loop's own steps included, with the step that
    /// holds it.
    pub fn action_steps(&self) -> impl Iterator<Item = (&Node, &ActionStep)> {
        self.every_node().filter_map(|node| match node.kind() {
            NodeKind::Action(step) => Some((node, step)),
            NodeKind::AgentRun(_)
            | NodeKind::Condition(_)
            | NodeKind::Transform(_)
            | NodeKind::Approval(_)
            | NodeKind::Wait(_)
            | NodeKind::Loop(_)
            | NodeKind::Code(_)
            | NodeKind::Guardrail(_) => None,
        })
    }

    /// Every code step, a loop's own steps included, with the step that
    /// holds it.
    pub fn code_steps(&self) -> impl Iterator<Item = (&Node, &CodeStep)> {
        self.every_node().filter_map(|node| match node.kind() {
            NodeKind::Code(step) => Some((node, step)),
            NodeKind::AgentRun(_)
            | NodeKind::Action(_)
            | NodeKind::Condition(_)
            | NodeKind::Transform(_)
            | NodeKind::Approval(_)
            | NodeKind::Wait(_)
            | NodeKind::Loop(_)
            | NodeKind::Guardrail(_) => None,
        })
    }

    /// The validated dependencies connecting step outputs to later inputs.
    #[must_use]
    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }

    /// The step called `key`, if there is one.
    #[must_use]
    pub fn node(&self, key: &NodeKey) -> Option<&Node> {
        self.nodes.iter().find(|node| node.key() == key)
    }

    /// The edges into `key`.
    pub fn incoming<'a>(&'a self, key: &'a NodeKey) -> impl Iterator<Item = &'a Edge> + 'a {
        self.edges.iter().filter(move |edge| edge.to() == key)
    }

    /// The edges out of `key`.
    pub fn outgoing<'a>(&'a self, key: &'a NodeKey) -> impl Iterator<Item = &'a Edge> + 'a {
        self.edges.iter().filter(move |edge| edge.from() == key)
    }

    /// Every step from which some path leads to `key`, in the order the
    /// steps were given.
    #[must_use]
    pub fn ancestors(&self, key: &NodeKey) -> Vec<&Node> {
        let mut found: Vec<&NodeKey> = Vec::new();
        let mut frontier: Vec<&NodeKey> = vec![key];
        while let Some(next) = frontier.pop() {
            for edge in self.incoming(next) {
                if !found.contains(&edge.from()) {
                    found.push(edge.from());
                    frontier.push(edge.from());
                }
            }
        }
        self.nodes
            .iter()
            .filter(|node| found.contains(&node.key()))
            .collect()
    }

    /// Whether the trigger starts `key`, because no edge leads into it.
    #[must_use]
    pub fn is_entry(&self, key: &NodeKey) -> bool {
        self.incoming(key).next().is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::data::{DataPath, FieldName, FlowData};
    use crate::domains::workflows::design::condition::{Clause, ConditionRule, Matching, Test};
    use crate::domains::workflows::design::node::{
        Join, LoopParams, LoopStep, Mapping, NodeKind, Source,
    };
    use crate::types::Label;

    fn key(name: &str) -> NodeKey {
        NodeKey::new(name).unwrap()
    }

    fn transform(name: &str) -> Node {
        let mapping = Mapping::new(vec![(
            FieldName::new("seen").unwrap(),
            Source::Literal(FlowData::bool(true)),
        )])
        .unwrap();
        Node::new(
            key(name),
            Label::new("name", name).unwrap(),
            NodeKind::Transform(mapping),
            Join::All,
        )
    }

    fn condition(name: &str) -> Node {
        let rule = ConditionRule::new(
            Matching::All,
            vec![Clause::new(DataPath::parse("trigger.ok").unwrap(), Test::Exists).unwrap()],
        )
        .unwrap();
        Node::new(
            key(name),
            Label::new("name", name).unwrap(),
            NodeKind::Condition(rule),
            Join::All,
        )
    }

    fn edge(from: &str, port: Port, to: &str) -> Edge {
        Edge::new(key(from), port, key(to))
    }

    /// A check branches to "yes" and "no", and both lead to "end". The
    /// graph is accepted, the check is the only start, and "end" has two
    /// edges in.
    #[test]
    fn a_branching_graph_without_cycles_is_accepted() {
        let graph = WorkflowGraph::new(
            vec![
                condition("check"),
                transform("yes"),
                transform("no"),
                transform("end"),
            ],
            vec![
                edge("check", Port::WhenTrue, "yes"),
                edge("check", Port::WhenFalse, "no"),
                edge("yes", Port::Next, "end"),
                edge("no", Port::Next, "end"),
            ],
        )
        .unwrap();

        assert!(graph.is_entry(&key("check")));
        assert!(!graph.is_entry(&key("yes")));
        assert_eq!(graph.incoming(&key("end")).count(), 2);
    }

    /// Step "a" leads to "b", "b" to "c", and "c" back to "b". The graph is
    /// refused, since a run could loop between "b" and "c" forever.
    #[test]
    fn a_graph_with_a_cycle_is_refused() {
        let cycle = WorkflowGraph::new(
            vec![transform("a"), transform("b"), transform("c")],
            vec![
                edge("a", Port::Next, "b"),
                edge("b", Port::Next, "c"),
                edge("c", Port::Next, "b"),
            ],
        );

        assert!(cycle.is_err());
    }

    /// An edge from "a" to a step "ghost" that does not exist is refused.
    /// So is an edge from "a" back to "a".
    #[test]
    fn an_edge_to_an_unknown_step_or_back_to_its_own_is_refused() {
        let unknown =
            WorkflowGraph::new(vec![transform("a")], vec![edge("a", Port::Next, "ghost")]);
        let own = WorkflowGraph::new(vec![transform("a")], vec![edge("a", Port::Next, "a")]);

        assert!(unknown.is_err());
        assert!(own.is_err());
    }

    /// A transform with a "when true" edge is refused, since that edge
    /// would never be taken. A condition with a plain `Next` edge is
    /// refused, since it would be taken whichever way the condition went.
    #[test]
    fn an_edge_by_a_way_out_its_step_lacks_is_refused() {
        let true_from_transform = WorkflowGraph::new(
            vec![transform("a"), transform("b")],
            vec![edge("a", Port::WhenTrue, "b")],
        );
        let next_from_condition = WorkflowGraph::new(
            vec![condition("a"), transform("b")],
            vec![edge("a", Port::Next, "b")],
        );

        assert!(true_from_transform.is_err());
        assert!(next_from_condition.is_err());
    }

    /// A graph with no steps is refused. So is one with two steps called
    /// "a", and one with the same edge from "a" to "b" drawn twice.
    #[test]
    fn a_graph_without_steps_or_with_a_key_twice_or_an_edge_twice_is_refused() {
        let twice_edge = WorkflowGraph::new(
            vec![transform("a"), transform("b")],
            vec![edge("a", Port::Next, "b"), edge("a", Port::Next, "b")],
        );

        assert!(WorkflowGraph::new(Vec::new(), Vec::new()).is_err());
        assert!(WorkflowGraph::new(vec![transform("a"), transform("a")], Vec::new()).is_err());
        assert!(twice_edge.is_err());
    }

    fn looping(name: &str, inner: &str) -> Node {
        let step = LoopStep::new(LoopParams {
            over: DataPath::parse("trigger.issues").unwrap(),
            inputs: Mapping::new(Vec::new()).unwrap(),
            body: WorkflowGraph::new(vec![transform(inner)], Vec::new()).unwrap(),
            most: 10,
            at_once: 1,
        })
        .unwrap();
        Node::new(
            key(name),
            Label::new("name", name).unwrap(),
            NodeKind::Loop(step),
            Join::All,
        )
    }

    /// A loop "each" runs "comment" for every issue, beside a step called
    /// "notify". The graph lists all three. A loop whose own step is also
    /// called "notify" is refused, since the key would name two steps.
    #[test]
    fn a_key_names_one_step_across_a_loop_and_its_own_steps() {
        let graph = WorkflowGraph::new(
            vec![looping("each", "comment"), transform("notify")],
            Vec::new(),
        )
        .unwrap();
        let clash = WorkflowGraph::new(
            vec![looping("each", "notify"), transform("notify")],
            Vec::new(),
        );

        let keys: Vec<&str> = graph.every_node().map(|node| node.key().as_str()).collect();

        assert_eq!(keys, ["each", "comment", "notify"]);
        assert!(clash.is_err());
    }

    /// In a check that branches to "yes" and "no" before "end", the steps
    /// before "end" are check, yes and no, in the order given. The check
    /// and an unconnected "aside" have none.
    #[test]
    fn a_steps_ancestors_are_every_step_a_path_leads_from() {
        let graph = WorkflowGraph::new(
            vec![
                condition("check"),
                transform("yes"),
                transform("no"),
                transform("end"),
                transform("aside"),
            ],
            vec![
                edge("check", Port::WhenTrue, "yes"),
                edge("check", Port::WhenFalse, "no"),
                edge("yes", Port::Next, "end"),
                edge("no", Port::Next, "end"),
            ],
        )
        .unwrap();

        let names = |of: &str| -> Vec<String> {
            graph
                .ancestors(&key(of))
                .iter()
                .map(|node| node.key().as_str().to_owned())
                .collect()
        };

        assert_eq!(names("end"), ["check", "yes", "no"]);
        assert_eq!(names("yes"), ["check"]);
        assert!(names("check").is_empty());
        assert!(names("aside").is_empty());
    }
}
