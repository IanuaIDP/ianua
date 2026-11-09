//! When a waiting step may start, what it starts with, and when no path will
//! ever reach it.
//!
//! These are pure functions of the graph and the state of every step. So
//! the rule can be tested on its own, and the execution only applies what
//! it says.

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::data::{FieldName, FlowData};
use crate::domains::workflows::design::graph::{Edge, WorkflowGraph};
use crate::domains::workflows::design::node::{Join, Node, NodeKey, TRIGGER_FIELD};
use crate::domains::workflows::execution::step::StepState;
use crate::shared::errors::DomainError;

/// What happens next to a step that is waiting.
#[derive(Debug, Clone, PartialEq)]
pub(in crate::domains::workflows::execution) enum Readiness {
    /// Steps before it have not finished yet.
    Wait,
    /// No path will lead to it.
    Skip,
    /// It may start with this.
    Start(StepInput),
    /// What it would start with is more than workflow data may hold.
    InputTooLarge,
}

/// What a step starts with.
#[derive(Debug, Clone, PartialEq)]
pub(in crate::domains::workflows::execution) struct StepInput {
    /// What the earlier steps it sees produced, and the trigger's data.
    pub(in crate::domains::workflows::execution) data: FlowData,
    /// The most sensitive data in it.
    pub(in crate::domains::workflows::execution) exposure: DataClassLevel,
    /// The earlier steps it sees.
    pub(in crate::domains::workflows::execution) seen: Vec<NodeKey>,
}

/// The trigger's data, which every step's input carries.
#[derive(Debug, Clone, Copy)]
pub(in crate::domains::workflows::execution) struct TriggerData<'a> {
    pub(in crate::domains::workflows::execution) input: &'a FlowData,
    pub(in crate::domains::workflows::execution) exposure: DataClassLevel,
}

/// How an edge into a step stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EdgeState {
    /// Its step has not finished.
    Pending,
    /// Its step finished without leading this way.
    Dead,
    /// Its step led this way.
    Active,
}

/// What happens next to `node`, waiting in `graph`.
///
/// `states` holds one state per step, in the graph's order.
pub(in crate::domains::workflows::execution) fn readiness(
    graph: &WorkflowGraph,
    states: &[StepState],
    node: &Node,
    trigger: TriggerData<'_>,
) -> Readiness {
    let edges: Vec<EdgeState> = graph
        .incoming(node.key())
        .map(|edge| edge_state(graph, states, edge))
        .collect();
    let pending = edges.contains(&EdgeState::Pending);
    let active = edges.contains(&EdgeState::Active);
    if edges.is_empty() {
        return start_with(graph, states, node, trigger);
    }
    match node.join() {
        Join::All if pending => Readiness::Wait,
        Join::All | Join::Any if active => start_with(graph, states, node, trigger),
        Join::Any if pending => Readiness::Wait,
        Join::All | Join::Any => Readiness::Skip,
    }
}

/// Whether some edge into `node` comes from a step that has not finished.
pub(in crate::domains::workflows::execution) fn has_pending_lead(
    graph: &WorkflowGraph,
    states: &[StepState],
    node: &Node,
) -> bool {
    graph
        .incoming(node.key())
        .any(|edge| edge_state(graph, states, edge) == EdgeState::Pending)
}

/// Whether `node` was reached: it is an entry step, or some edge into it
/// is one its step led along.
pub(in crate::domains::workflows::execution) fn is_led_to(
    graph: &WorkflowGraph,
    states: &[StepState],
    node: &Node,
) -> bool {
    graph.is_entry(node.key())
        || graph
            .incoming(node.key())
            .any(|edge| edge_state(graph, states, edge) == EdgeState::Active)
}

fn edge_state(graph: &WorkflowGraph, states: &[StepState], edge: &Edge) -> EdgeState {
    let Some((_, state)) = graph
        .nodes()
        .iter()
        .zip(states)
        .find(|(node, _)| node.key() == edge.from())
    else {
        return EdgeState::Dead;
    };
    match state {
        StepState::Succeeded { port, .. } if *port == edge.port() => EdgeState::Active,
        StepState::Succeeded { .. }
        | StepState::Failed(_)
        | StepState::Skipped
        | StepState::Stopped
        | StepState::Abandoned { .. } => EdgeState::Dead,
        StepState::Waiting | StepState::Ready { .. } | StepState::Running { .. } => {
            EdgeState::Pending
        }
    }
}

/// The input a step starts with: the trigger's data, and the output of
/// every earlier step it sees.
///
/// Each output sits under its step's key. So a step names any of them
/// directly, as `check.answer`, however far back it ran.
///
/// A step sees each step that led it here, and everything that step saw.
/// What it sees is fixed the moment it starts. So a step after an approval
/// reads exactly what the approval was asked about, and nothing that
/// finished later on another branch. Its exposure is the most sensitive of
/// the trigger and the steps that led it here. Each of those already
/// carries the exposure of what it saw.
fn start_with(
    graph: &WorkflowGraph,
    states: &[StepState],
    node: &Node,
    trigger: TriggerData<'_>,
) -> Readiness {
    let mut exposure = trigger.exposure;
    let mut seen: Vec<NodeKey> = Vec::new();
    for (led_from, state) in leading_steps(graph, states, node) {
        let StepState::Succeeded {
            exposure: carried,
            seen: before,
            ..
        } = state
        else {
            continue;
        };
        exposure = exposure.max(*carried);
        for key in before.iter().chain([led_from.key()]) {
            if !seen.contains(key) {
                seen.push(key.clone());
            }
        }
    }
    let seen = in_graph_order(graph, &seen);
    match input_of(graph, states, &seen, trigger) {
        Ok(data) => Readiness::Start(StepInput {
            data,
            exposure,
            seen,
        }),
        Err(_) => Readiness::InputTooLarge,
    }
}

/// The steps an active edge leads from into `node`, with their states.
pub(in crate::domains::workflows::execution) fn leading_steps<'a>(
    graph: &'a WorkflowGraph,
    states: &'a [StepState],
    node: &Node,
) -> Vec<(&'a Node, &'a StepState)> {
    graph
        .incoming(node.key())
        .filter(|edge| edge_state(graph, states, edge) == EdgeState::Active)
        .filter_map(|edge| {
            graph
                .nodes()
                .iter()
                .zip(states)
                .find(|(each, _)| each.key() == edge.from())
        })
        .collect()
}

/// Orders the visible predecessors as they occur in the published graph.
fn in_graph_order(graph: &WorkflowGraph, keys: &[NodeKey]) -> Vec<NodeKey> {
    graph
        .nodes()
        .iter()
        .map(Node::key)
        .filter(|key| keys.contains(key))
        .cloned()
        .collect()
}

/// The trigger's data and the outputs of the `seen` steps, as one map.
pub(in crate::domains::workflows::execution) fn input_of(
    graph: &WorkflowGraph,
    states: &[StepState],
    seen: &[NodeKey],
    trigger: TriggerData<'_>,
) -> Result<FlowData, DomainError> {
    let mut fields = vec![(FieldName::new(TRIGGER_FIELD)?, trigger.input.clone())];
    for (node, state) in graph.nodes().iter().zip(states) {
        let StepState::Succeeded { output, .. } = state else {
            continue;
        };
        if seen.contains(node.key()) {
            fields.push((node.key().as_field().clone(), output.clone()));
        }
    }
    FlowData::map(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::data::DataPath;
    use crate::domains::workflows::design::graph::Edge;
    use crate::domains::workflows::design::node::{Mapping, NodeKey, NodeKind, Port, Source};
    use crate::domains::workflows::execution::step::{CallTries, Underway};
    use crate::types::{ActionCallId, Label};

    fn key(name: &str) -> NodeKey {
        NodeKey::new(name).unwrap()
    }

    fn node(name: &str, join: Join) -> Node {
        let mapping = Mapping::new(vec![(
            FieldName::new("seen").unwrap(),
            Source::Literal(FlowData::bool(true)),
        )])
        .unwrap();
        Node::new(
            key(name),
            Label::new("name", name).unwrap(),
            NodeKind::Transform(mapping),
            join,
        )
    }

    fn succeeded(text: &str, exposure: DataClassLevel) -> StepState {
        StepState::Succeeded {
            output: FlowData::text(text).unwrap(),
            exposure,
            seen: Vec::new(),
            port: Port::Next,
            holds: crate::domains::workflows::execution::step::Holding::ForGood,
        }
    }

    /// An action that keeps its outgoing edges pending until it settles.
    fn running_action() -> StepState {
        StepState::Running {
            exposure: DataClassLevel::Public,
            seen: Vec::new(),
            underway: Underway::Action {
                call_id: ActionCallId::new(),
                tries: CallTries::FIRST,
            },
            started_at: crate::shared::clock::now(),
        }
    }

    fn diamond(join: Join) -> WorkflowGraph {
        WorkflowGraph::new(
            vec![
                node("a", Join::All),
                node("b", Join::All),
                node("c", Join::All),
                node("d", join),
            ],
            vec![
                Edge::new(key("a"), Port::Next, key("b")),
                Edge::new(key("a"), Port::Next, key("c")),
                Edge::new(key("b"), Port::Next, key("d")),
                Edge::new(key("c"), Port::Next, key("d")),
            ],
        )
        .unwrap()
    }

    fn trigger(input: &FlowData) -> TriggerData<'_> {
        TriggerData {
            input,
            exposure: DataClassLevel::Public,
        }
    }

    fn at(graph: &WorkflowGraph, name: &str) -> Node {
        graph.node(&key(name)).unwrap().clone()
    }

    /// In a diamond where "a" leads to "b" and "c" and both lead to "d",
    /// step "a" has no edge in. It may start at once, with the trigger's
    /// "hello" under `trigger`.
    #[test]
    fn an_entry_step_starts_with_the_trigger_data() {
        let graph = diamond(Join::All);
        let data = FlowData::text("hello").unwrap();
        let states = vec![StepState::Waiting; 4];

        let Readiness::Start(input) = readiness(&graph, &states, &at(&graph, "a"), trigger(&data))
        else {
            panic!("an entry step starts at once");
        };
        assert_eq!(
            input.data.at(&DataPath::parse("trigger").unwrap()),
            Some(&data)
        );
    }

    /// Step "d" waits for both "b" and "c". While "c" still runs, "d" waits.
    /// Once "c" is done, "d" starts with the output of both and with the
    /// confidential level "b" carried.
    #[test]
    fn a_join_of_all_waits_for_every_step_before_it() {
        let graph = diamond(Join::All);
        let data = FlowData::null();
        let half = vec![
            succeeded("a", DataClassLevel::Public),
            succeeded("b", DataClassLevel::Confidential),
            running_action(),
            StepState::Waiting,
        ];
        let both = vec![
            succeeded("a", DataClassLevel::Public),
            succeeded("b", DataClassLevel::Confidential),
            succeeded("c", DataClassLevel::Internal),
            StepState::Waiting,
        ];

        assert_eq!(
            readiness(&graph, &half, &at(&graph, "d"), trigger(&data)),
            Readiness::Wait
        );
        let Readiness::Start(input) = readiness(&graph, &both, &at(&graph, "d"), trigger(&data))
        else {
            panic!("every step before it settled");
        };
        assert_eq!(input.exposure, DataClassLevel::Confidential);
        assert!(input.data.at(&DataPath::parse("b").unwrap()).is_some());
        assert!(input.data.at(&DataPath::parse("c").unwrap()).is_some());
        assert_eq!(input.seen, vec![key("b"), key("c")]);
    }

    /// Step "d" waits for any one of "b" and "c". Once "b" is done, "d"
    /// starts without waiting for "c".
    #[test]
    fn a_join_of_any_starts_with_the_first_step_that_leads_to_it() {
        let graph = diamond(Join::Any);
        let data = FlowData::null();
        let states = vec![
            succeeded("a", DataClassLevel::Public),
            succeeded("b", DataClassLevel::Public),
            StepState::Waiting,
            StepState::Waiting,
        ];

        assert!(matches!(
            readiness(&graph, &states, &at(&graph, "d"), trigger(&data)),
            Readiness::Start { .. }
        ));
    }

    /// Steps "b" and "c" were both skipped, so no path reaches "d". It is
    /// skipped too, and the execution is not left waiting on it.
    #[test]
    fn a_step_every_path_to_which_is_dead_is_skipped() {
        let graph = diamond(Join::All);
        let data = FlowData::null();
        let states = vec![
            succeeded("a", DataClassLevel::Public),
            StepState::Skipped,
            StepState::Skipped,
            StepState::Waiting,
        ];

        assert_eq!(
            readiness(&graph, &states, &at(&graph, "d"), trigger(&data)),
            Readiness::Skip
        );
    }
}
