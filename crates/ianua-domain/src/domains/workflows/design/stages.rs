//! How an agent flow's stages are laid out as a workflow graph.
//!
//! Each stage's runs start together. Between two stages, one transform
//! gathers every answer of the first stage and feeds each run of the next.
//! That takes one edge per run on each side, where joining every run to
//! every run would take the square of the width, so a wide flow stays
//! inside `MAX_EDGES`.

use crate::domains::workflows::data::{DataPath, FieldName};
use crate::domains::workflows::design::graph::{Edge, MAX_NODES};
use crate::domains::workflows::design::node::{
    AgentRunParams, AgentRunStep, Join, Mapping, Node, NodeKey, NodeKind, Port, Source,
};
use crate::domains::workflows::execution::ANSWER_FIELD;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_count;
use crate::types::Label;

/// The field each run of a later stage finds the stage before's answers
/// under, beside its own inputs.
pub(crate) const EARLIER_FIELD: &str = "earlier";

/// What the runs of a stage start from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum StageFeed {
    /// The trigger: this is the first stage.
    Trigger,
    /// This step, which gathered every answer of the stage before.
    Gathered(NodeKey),
}

/// A flow's steps and edges as they are laid out, stage by stage.
#[derive(Debug, Default)]
struct FlowLayout {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    latest_runs: Vec<NodeKey>,
}

impl FlowLayout {
    /// Lays out the runs of stage number `stage`, counting from one, after
    /// the stages already laid out.
    fn add_stage(&mut self, stage: usize, runs: Vec<AgentRunParams>) -> Result<(), DomainError> {
        validate_count("flow_stage_runs", runs.len(), 1..=MAX_NODES)?;
        let feed = self.gather(stage)?;
        let mut keys = Vec::with_capacity(runs.len());
        for (index, params) in runs.into_iter().enumerate() {
            let place = index.saturating_add(1);
            let key = NodeKey::new(format!("stage-{stage}-run-{place}"))?;
            let name = Label::new("name", format!("Stage {stage}, run {place}"))?;
            self.nodes.push(run_node(key.clone(), name, params, &feed)?);
            if let StageFeed::Gathered(from) = &feed {
                self.edges
                    .push(Edge::new(from.clone(), Port::Next, key.clone()));
            }
            keys.push(key);
        }
        self.latest_runs = keys;
        Ok(())
    }

    /// The step that gathers every answer of the stage before `stage`, laid
    /// out with its edges in, or the trigger for the first stage.
    fn gather(&mut self, stage: usize) -> Result<StageFeed, DomainError> {
        if self.latest_runs.is_empty() {
            return Ok(StageFeed::Trigger);
        }
        let before = stage.saturating_sub(1);
        let key = NodeKey::new(format!("stage-{before}-answers"))?;
        let name = Label::new("name", format!("Stage {before} answers"))?;
        let answers = self
            .latest_runs
            .iter()
            .map(|run| {
                let answer = DataPath::parse(&format!("{run}.{ANSWER_FIELD}"))?;
                Ok((run.as_field().clone(), Source::Input(answer)))
            })
            .collect::<Result<Vec<_>, DomainError>>()?;
        let mapping = NodeKind::Transform(Mapping::new(answers)?);
        self.nodes
            .push(Node::new(key.clone(), name, mapping, Join::All));
        for run in &self.latest_runs {
            self.edges
                .push(Edge::new(run.clone(), Port::Next, key.clone()));
        }
        Ok(StageFeed::Gathered(key))
    }
}

/// The steps and edges of a flow of `stages`.
///
/// # Errors
///
/// - [`DomainError::Validation`] when there is no stage, a stage has no
///   run, or either is more than `MAX_NODES`.
/// - [`DomainError::Validation`] when a run is not one an agent run step
///   allows, or a later run's own inputs already set `EARLIER_FIELD`.
pub(in crate::domains::workflows) fn laid_out(
    stages: Vec<Vec<AgentRunParams>>,
) -> Result<(Vec<Node>, Vec<Edge>), DomainError> {
    validate_count("flow_stages", stages.len(), 1..=MAX_NODES)?;
    let mut layout = FlowLayout::default();
    for (index, runs) in stages.into_iter().enumerate() {
        layout.add_stage(index.saturating_add(1), runs)?;
    }
    Ok((layout.nodes, layout.edges))
}

/// The stage, counting from one, of the flow run step `key` names, as
/// [`laid_out`] names its run steps; `None` for any other step, such as
/// one that gathers a stage's answers.
#[must_use]
pub fn stage_of(key: &NodeKey) -> Option<usize> {
    let rest = key.as_str().strip_prefix("stage-")?;
    let (stage, place) = rest.split_once("-run-")?;
    place.parse::<usize>().ok()?;
    stage.parse().ok()
}

/// The step of one agent run, named `key` and `name`, started from `feed`.
fn run_node(
    key: NodeKey,
    name: Label,
    params: AgentRunParams,
    feed: &StageFeed,
) -> Result<Node, DomainError> {
    let params = AgentRunParams {
        inputs: fed_inputs(&params.inputs, feed)?,
        ..params
    };
    let step = AgentRunStep::new(params)?;
    Ok(Node::new(key, name, NodeKind::AgentRun(step), Join::All))
}

/// `inputs`, and for a later stage the answers `feed` gathered, under
/// `EARLIER_FIELD`.
fn fed_inputs(inputs: &Mapping, feed: &StageFeed) -> Result<Mapping, DomainError> {
    let StageFeed::Gathered(from) = feed else {
        return Ok(inputs.clone());
    };
    let mut fields = inputs.fields().to_vec();
    fields.push((
        FieldName::new(EARLIER_FIELD)?,
        Source::Input(DataPath::parse(from.as_str())?),
    ));
    Mapping::new(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::design::graph::{MAX_EDGES, WorkflowGraph};
    use crate::domains::workflows::execution::tests::fixtures::{field, key, path, stage_run};

    /// `width` runs in one stage.
    fn stage(width: usize) -> Vec<AgentRunParams> {
        (0..width).map(|_| stage_run()).collect()
    }

    /// Each run step of a laid-out flow reads back the stage it was laid out
    /// in, and the step that gathers a stage's answers reads as none.
    #[test]
    fn each_run_step_names_its_stage() {
        let graph = WorkflowGraph::staged(vec![stage(2), stage(1)]).unwrap();

        let mut stages: Vec<Option<usize>> = graph
            .nodes()
            .iter()
            .map(|node| stage_of(node.key()))
            .collect();
        stages.sort_unstable();

        assert_eq!(stages, vec![None, Some(1), Some(1), Some(2)]);
    }

    /// Two runs side by side, then one. The graph holds the two runs, the
    /// step that gathers their answers and the last run: three edges, and
    /// the last run is handed what the first two answered.
    #[test]
    fn two_stages_meet_at_a_step_that_gathers_their_answers() {
        let graph = WorkflowGraph::staged(vec![stage(2), stage(1)]).unwrap();

        let NodeKind::AgentRun(last) = graph.node(&key("stage-2-run-1")).unwrap().kind() else {
            panic!("the last step is not an agent run");
        };
        let NodeKind::Transform(gathered) = graph.node(&key("stage-1-answers")).unwrap().kind()
        else {
            panic!("the answers are not gathered by a transform");
        };

        assert_eq!(graph.nodes().len(), 4);
        assert_eq!(graph.edges().len(), 3);
        assert_eq!(graph.incoming(&key("stage-1-answers")).count(), 2);
        assert_eq!(
            last.inputs().fields(),
            [(field(EARLIER_FIELD), Source::Input(path("stage-1-answers")))]
        );
        assert_eq!(
            gathered.fields().first(),
            Some(&(
                field("stage-1-run-1"),
                Source::Input(path("stage-1-run-1.answer"))
            ))
        );
    }

    /// One stage of three runs is three steps with no edge: they all start
    /// from the trigger.
    #[test]
    fn a_single_stage_starts_every_run_from_the_trigger() {
        let graph = WorkflowGraph::staged(vec![stage(3)]).unwrap();

        assert_eq!(graph.nodes().len(), 3);
        assert!(graph.edges().is_empty());
        assert!(graph.is_entry(&key("stage-1-run-3")));
    }

    /// A flow with no stage, and one whose second stage has no run, are
    /// both refused.
    #[test]
    fn a_flow_without_a_stage_or_with_an_empty_stage_is_refused() {
        assert!(matches!(
            WorkflowGraph::staged(Vec::new()),
            Err(DomainError::Validation(_))
        ));
        assert!(matches!(
            WorkflowGraph::staged(vec![stage(1), Vec::new()]),
            Err(DomainError::Validation(_))
        ));
    }

    /// Two stages of 31 runs fit: 63 steps, and 62 edges where joining
    /// every run to every run would take 961. Two stages of 32 need 65
    /// steps, the gathering step counted, and are refused.
    #[test]
    fn a_wide_flow_fits_its_edges_and_counts_its_gathering_steps() {
        let fits = WorkflowGraph::staged(vec![stage(31), stage(31)]).unwrap();
        let too_wide = WorkflowGraph::staged(vec![stage(32), stage(32)]);

        assert_eq!(fits.nodes().len(), MAX_NODES.saturating_sub(1));
        assert!(fits.edges().len() <= MAX_EDGES);
        assert!(matches!(too_wide, Err(DomainError::Validation(_))));
    }

    /// A run of the second stage whose own inputs already set `earlier` is
    /// refused, since the gathered answers would overwrite it.
    #[test]
    fn a_later_run_setting_the_earlier_field_itself_is_refused() {
        let mut clashing = stage_run();
        clashing.inputs =
            Mapping::new(vec![(field(EARLIER_FIELD), Source::Input(path("trigger")))]).unwrap();

        let staged = WorkflowGraph::staged(vec![stage(1), vec![clashing]]);

        assert!(matches!(staged, Err(DomainError::Validation(_))));
    }
}
