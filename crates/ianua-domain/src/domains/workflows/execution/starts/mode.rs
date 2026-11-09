//! Whether an execution is a real run or a test of a draft, and which of a
//! test's steps answer with a stand-in instead of doing their work.
//!
//! A test runs a draft on example input so its builder sees what each step
//! would do. Nothing outside may change: a step that writes, sends,
//! deletes or is undeclared, an agent run, an approval, a wait, and code
//! that reaches the network all stand in. A stand-in settles its step at
//! once and records what the step would have used, so the builder sees
//! "would have posted to #support" and Slack receives nothing. Steps that
//! only read, decide or reshape data run for real, as does code that
//! reaches no network.

use crate::domains::authorization::permission::WorkflowAction;
use crate::domains::workflows::control::WorkflowControl;
use crate::domains::workflows::design::graph::WorkflowGraph;
use crate::domains::workflows::design::node::{Node, NodeKey, NodeKind};
use crate::domains::workflows::design::publish_rules::ensure_paths_name_earlier_steps;
use crate::domains::workflows::design::workflow::{
    CodeReach, RunnableCode, Workflow, WorkflowStatus,
};
use crate::domains::workflows::evaluation::case::EvaluationCase;
use crate::domains::workflows::execution::record::ExecutionRecord;
use crate::domains::workflows::execution::{
    ActingAuthority, Cause, ManualStartParams, StartExecutionParams, WorkflowExecution,
};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::chain::ChainDepth;
use crate::types::{ActionClass, DeclaredAction};

/// Whether an execution does its work, or tests a draft.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ExecutionMode {
    /// A real run: every step does its work.
    #[default]
    Live,
    /// A test: the steps the plan names stand in.
    Test(TestPlan),
}

impl ExecutionMode {
    /// The mode's stored name.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Test(_) => "test",
        }
    }

    /// Whether the step `key` stands in instead of doing its work.
    #[must_use]
    pub fn stands_in(&self, key: &NodeKey) -> bool {
        match self {
            Self::Live => false,
            Self::Test(plan) => plan.stands_in(key),
        }
    }

    /// Whether this is a test.
    #[must_use]
    pub fn is_test(&self) -> bool {
        matches!(self, Self::Test(_))
    }

    /// The same mode for a run of `graph` alone, such as a loop's pass of
    /// its own steps: a test stands in only for the steps `graph` has.
    pub(in crate::domains::workflows::execution) fn within(&self, graph: &WorkflowGraph) -> Self {
        let Self::Test(plan) = self else {
            return Self::Live;
        };
        let stand_ins = plan
            .stand_ins
            .iter()
            .filter(|key| graph.every_node().any(|node| node.key() == *key))
            .cloned()
            .collect();
        Self::Test(TestPlan { stand_ins })
    }
}

/// Which steps of a tested draft stand in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestPlan {
    stand_ins: Vec<NodeKey>,
}

impl TestPlan {
    /// The plan for testing `graph`: every step that could change something
    /// outside, or keep the test waiting, stands in, the steps of its loops
    /// included. `runnable` says which code versions reach the network; a
    /// code step whose version it does not list stands in too.
    #[must_use]
    pub fn for_graph(graph: &WorkflowGraph, runnable: &[RunnableCode]) -> Self {
        let stand_ins = graph
            .every_node()
            .filter(|node| stands_in(node, runnable))
            .map(|node| node.key().clone())
            .collect();
        Self { stand_ins }
    }

    /// Whether the step `key` stands in.
    #[must_use]
    pub fn stands_in(&self, key: &NodeKey) -> bool {
        self.stand_ins.contains(key)
    }

    /// The steps that stand in.
    #[must_use]
    pub fn stand_ins(&self) -> &[NodeKey] {
        &self.stand_ins
    }
}

impl<T: TenantScope> WorkflowExecution<T> {
    /// `tester` tests `workflow` on example input, acting for themselves,
    /// and every step runs or stands in as far as it goes.
    ///
    /// A draft is tested before it is published, and a published version
    /// may be tested again. Nothing outside changes: the steps
    /// [`TestPlan::for_graph`] names stand in, settling at once with what
    /// they would have used. `runnable` says which code versions reach the
    /// network, as publishing is told.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `tester` may not edit or run
    ///   workflows.
    /// - [`DomainError::Forbidden`] when `params.resources` was answered
    ///   for someone else.
    /// - [`DomainError::Conflict`] when `workflow` is archived.
    /// - [`DomainError::Validation`] when a step reads a path that starts
    ///   at neither the trigger nor a step before it.
    pub fn start_test(
        workflow: &Workflow<T>,
        tester: WorkflowControl<'_>,
        params: ManualStartParams,
        runnable: &[RunnableCode],
    ) -> Result<(Self, Vec<ExecutionRecord>), DomainError> {
        tester.ensure_may(WorkflowAction::Update)?;
        tester.ensure_may(WorkflowAction::Run)?;
        let acting_for = ActingAuthority::of_signed_in(tester.authority(), &params.resources)?;
        let start = StartExecutionParams {
            acting_for,
            cause: Cause::Manual,
            input: params.input,
            exposure: params.exposure,
        };
        Self::tested(workflow, start, runnable)
    }

    /// The test run of one case of an evaluation of `workflow`, acting for
    /// `evaluator`, the person who started the evaluation, as they hold
    /// rights now. It starts on the case's input, and runs or stands in as
    /// [`start_test`](Self::start_test) does.
    ///
    /// The evaluation runs its cases in turn, long after its person asked
    /// for it. Bob starts one and is then refused the right to edit
    /// workflows. Were his rights of the moment he asked counted, the
    /// cases still waiting would go on reading real services as him.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `evaluator` may no longer edit or
    ///   run workflows.
    /// - [`DomainError::Conflict`] when `workflow` is archived.
    /// - [`DomainError::Validation`] when a step reads a path that starts
    ///   at neither the trigger nor a step before it.
    pub fn start_case(
        workflow: &Workflow<T>,
        evaluator: ActingAuthority,
        case: &EvaluationCase,
        runnable: &[RunnableCode],
    ) -> Result<(Self, Vec<ExecutionRecord>), DomainError> {
        if !evaluator.may_test() {
            return Err(DomainError::forbidden(message!(
                "workflows-the-evaluator-may-no-longer-test",
                "the person who started the evaluation may no longer test workflows"
            )));
        }
        let start = StartExecutionParams {
            acting_for: evaluator,
            cause: Cause::Manual,
            input: case.input().clone(),
            exposure: case.exposure(),
        };
        Self::tested(workflow, start, runnable)
    }

    /// A test of `workflow` as `start` says, with the steps
    /// [`TestPlan::for_graph`] names standing in, run as far as it goes.
    fn tested(
        workflow: &Workflow<T>,
        start: StartExecutionParams,
        runnable: &[RunnableCode],
    ) -> Result<(Self, Vec<ExecutionRecord>), DomainError> {
        if workflow.status() == WorkflowStatus::Archived {
            return Err(DomainError::conflict(message!(
                "workflows-an-archived-version-is-not-tested",
                "an archived version is not tested; draft the next one"
            )));
        }
        ensure_paths_name_earlier_steps(workflow.graph())?;
        let mut execution = Self::fresh(workflow, start, ChainDepth::FIRST);
        execution.mode = ExecutionMode::Test(TestPlan::for_graph(workflow.graph(), runnable));
        let mut records = vec![ExecutionRecord::Started];
        execution.advance(&mut records);
        Ok((execution, records))
    }
}

/// Whether a stored run is real or a test, as its row keeps it: a test
/// with the steps it stood in for, which the run's own checks hold to its
/// graph when it is read back.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum StoredMode {
    /// A real run.
    #[default]
    Live,
    /// A rehearsal retaining which nodes used supplied results instead of real work.
    Test {
        /// The steps it stood in for.
        stand_ins: Vec<NodeKey>,
    },
}

impl From<&ExecutionMode> for StoredMode {
    fn from(mode: &ExecutionMode) -> Self {
        match mode {
            ExecutionMode::Live => Self::Live,
            ExecutionMode::Test(plan) => Self::Test {
                stand_ins: plan.stand_ins.clone(),
            },
        }
    }
}

impl StoredMode {
    /// The mode it keeps.
    pub(in crate::domains::workflows::execution) fn mode(&self) -> ExecutionMode {
        match self {
            Self::Live => ExecutionMode::Live,
            Self::Test { stand_ins } => ExecutionMode::Test(TestPlan {
                stand_ins: stand_ins.clone(),
            }),
        }
    }
}

/// Whether `node` stands in when its draft is tested.
fn stands_in(node: &Node, runnable: &[RunnableCode]) -> bool {
    match node.kind() {
        NodeKind::Action(step) => step.effect() != DeclaredAction::Declared(ActionClass::Read),
        NodeKind::Code(step) => !runnable
            .iter()
            .any(|code| code.version == step.version() && code.reach == CodeReach::Closed),
        NodeKind::AgentRun(_) | NodeKind::Approval(_) | NodeKind::Wait(_) => true,
        NodeKind::Condition(_)
        | NodeKind::Transform(_)
        | NodeKind::Loop(_)
        | NodeKind::Guardrail(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::authority::capability::CapabilitySet;
    use crate::domains::authorization::permission::SystemPermission;
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::domains::workflows::data::{DataPath, FlowData, FlowValue};
    use crate::domains::workflows::design::node::{Join, Port};
    use crate::domains::workflows::design::workflow::Workflow;
    use crate::domains::workflows::evaluation::case::{CaseName, CaseParams};
    use crate::domains::workflows::evaluation::check::{Expectation, ExpectedText};
    use crate::domains::workflows::execution::progress::STOOD_IN_FIELD;
    use crate::domains::workflows::execution::record::{ExecutionEnd, ExecutionRecord, StepRecord};
    use crate::domains::workflows::execution::step::StepState;
    use crate::domains::workflows::execution::tests::fixtures::{
        ann, approval, bob, by_hand, draft, edge, managing, state, stored, transform, viewing, wait,
    };
    use crate::domains::workflows::execution::{
        ExecutionStatus, WorkflowExecution, WorkflowExecutionRow,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::errors::DomainError;
    use crate::shared::model::row_check::refused_as_corrupt;

    fn key(value: &str) -> NodeKey {
        NodeKey::new(value).unwrap()
    }

    /// Ann tests a draft that tidies data, asks for an approval and waits.
    /// The approval and the wait stand in, so the test neither asks anyone
    /// nor waits; the tidying runs for real.
    #[test]
    fn a_test_stands_in_for_whatever_would_reach_out_or_wait() {
        let graph = WorkflowGraph::new(
            vec![
                transform("tidy", Join::All),
                approval("check"),
                wait("later"),
            ],
            vec![
                edge("tidy", Port::Next, "check"),
                edge("check", Port::Next, "later"),
            ],
        )
        .unwrap();

        let plan = TestPlan::for_graph(&graph, &[]);

        assert!(!plan.stands_in(&key("tidy")));
        assert!(plan.stands_in(&key("check")));
        assert!(plan.stands_in(&key("later")));
    }

    /// A real run stands in for nothing.
    #[test]
    fn a_live_run_stands_in_for_nothing() {
        assert!(!ExecutionMode::Live.stands_in(&key("check")));
    }

    fn tidy_check_later() -> Workflow<ResolvedTenant> {
        draft(
            vec![
                transform("tidy", Join::All),
                approval("check"),
                wait("later"),
            ],
            vec![
                edge("tidy", Port::Next, "check"),
                edge("check", Port::Next, "later"),
            ],
        )
    }

    /// Ann tests her unpublished draft. The tidying runs, the approval and
    /// the wait stand in at once, saying they stood in, and the test ends
    /// as succeeded without asking anyone or waiting an hour.
    #[test]
    fn a_draft_is_tested_with_its_reaching_steps_standing_in() {
        let workflow = tidy_check_later();

        let (test, records) = WorkflowExecution::start_test(
            &workflow,
            managing(&ann()),
            by_hand(DataClassLevel::Internal),
            &[],
        )
        .unwrap();

        assert!(test.mode().is_test());
        assert_eq!(
            test.status(),
            ExecutionStatus::Ended(ExecutionEnd::Succeeded)
        );
        let stood_in = records.iter().filter(|record| is_stand_in(record)).count();
        assert_eq!(stood_in, 2);
        let StepState::Succeeded { output, .. } = state(&test, "check") else {
            panic!("the approval stood in");
        };
        let flag = output
            .at(&DataPath::parse(STOOD_IN_FIELD).unwrap())
            .map(FlowData::value);
        assert_eq!(flag, Some(FlowValue::Bool(true)));
    }

    /// Identifies completed stand-ins, excluding the run and ordinary step records.
    fn is_stand_in(record: &ExecutionRecord) -> bool {
        matches!(
            record,
            ExecutionRecord::Step {
                happened: StepRecord::StoodIn,
                ..
            }
        )
    }

    /// Workflow view rights cannot start a draft test, and even a manager
    /// cannot test an archived version. The attempts return forbidden and
    /// conflict errors respectively.
    #[test]
    fn testing_needs_the_right_and_a_version_in_reach() {
        let workflow = tidy_check_later();
        let mut archived = tidy_check_later();
        archived.archive(&managing(&ann())).unwrap();

        let by_viewer = WorkflowExecution::start_test(
            &workflow,
            viewing(&bob()),
            by_hand(DataClassLevel::Internal),
            &[],
        );
        let of_archived = WorkflowExecution::start_test(
            &archived,
            managing(&ann()),
            by_hand(DataClassLevel::Internal),
            &[],
        );

        assert!(matches!(by_viewer, Err(DomainError::Forbidden(_))));
        assert!(matches!(of_archived, Err(DomainError::Conflict(_))));
    }

    /// One sample case on its own input, for whoever tests it.
    fn sample_case() -> EvaluationCase {
        EvaluationCase::new(CaseParams {
            name: CaseName::new("ok").unwrap(),
            input: FlowData::text("sample").unwrap(),
            exposure: DataClassLevel::Internal,
            checks: vec![Expectation::Contains {
                at: DataPath::parse("trigger").unwrap(),
                text: ExpectedText::new("sample").unwrap(),
            }],
        })
        .unwrap()
    }

    /// Ann's evaluation runs a case as a test on the case's input, acting
    /// for her as she holds rights now. Once she may only run workflows,
    /// the next case is refused.
    #[test]
    fn a_case_runs_as_a_test_for_an_evaluator_who_may_still_test() {
        let workflow = tidy_check_later();
        let tests_workflows = CapabilitySet::new(
            vec![
                SystemPermission::Workflows(WorkflowAction::Update),
                SystemPermission::Workflows(WorkflowAction::Run),
            ],
            Vec::new(),
        );
        let runs_only = CapabilitySet::new(
            vec![SystemPermission::Workflows(WorkflowAction::Run)],
            Vec::new(),
        );

        let (test, _) = WorkflowExecution::start_case(
            &workflow,
            ActingAuthority::assumed(ann(), tests_workflows),
            &sample_case(),
            &[],
        )
        .unwrap();
        let refused = WorkflowExecution::<ResolvedTenant>::start_case(
            &workflow,
            ActingAuthority::assumed(ann(), runs_only),
            &sample_case(),
            &[],
        );

        assert!(test.mode().is_test());
        assert_eq!(test.input(), &FlowData::text("sample").unwrap());
        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// A stored test reads back with its stand-ins. A stand-in naming a
    /// step absent from its graph makes the stored execution corrupt.
    #[test]
    fn a_stored_test_reads_back_and_refuses_strays() {
        let (test, _) = WorkflowExecution::start_test(
            &tidy_check_later(),
            managing(&ann()),
            by_hand(DataClassLevel::Internal),
            &[],
        )
        .unwrap();
        let row = stored(&test);
        let stray = WorkflowExecutionRow {
            mode: StoredMode::Test {
                stand_ins: vec![key("gone")],
            },
            ..stored(&test)
        };

        assert!(WorkflowExecution::<ResolvedTenant>::reconstitute(row).is_ok());
        assert!(refused_as_corrupt(
            &WorkflowExecution::<ResolvedTenant>::reconstitute(stray)
        ));
    }
}
