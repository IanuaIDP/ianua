//! Code steps: one run of a sandbox version's code on the fields its
//! mapping hands it.
//!
//! The code runs with no network, so it reads nothing but its input, and
//! its output carries exactly the input's sensitivity. A run is made only
//! while the person the execution acts for may still run workflows, and
//! while an approval right before the step still holds.

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::data::FlowData;
use crate::domains::workflows::design::node::{CodeStep, NodeKey, NodeKind};
use crate::domains::workflows::execution::WorkflowExecution;
use crate::domains::workflows::execution::acting::ActingAuthority;
use crate::domains::workflows::execution::record::ExecutionRecord;
use crate::domains::workflows::execution::step::{
    CodeOutcome, CodeWork, StepFailure, StepRefusal, StepState, Underway,
};
use crate::domains::workflows::execution::steps::work::{ReadyStep, Settled};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{CodeRunId, SandboxVersionId};

/// One run of a sandbox version's code, for its runner to make.
#[derive(Debug, Clone, PartialEq)]
pub struct CodeRun {
    /// The run, which its outcome is reported under.
    pub run_id: CodeRunId,
    /// The version whose code runs.
    pub version: SandboxVersionId,
    /// What the code is given.
    pub input: FlowData,
    /// The most sensitive data in it.
    pub exposure: DataClassLevel,
}

/// What starting a code step came to.
#[derive(Debug)]
pub enum CodeStart {
    /// Make this run. The step waits for its outcome.
    Run(CodeRun, Vec<ExecutionRecord>),
    /// The step failed before any code ran.
    Stopped(Vec<ExecutionRecord>),
}

impl<T: TenantScope> WorkflowExecution<T> {
    /// Starts the ready code step `key`.
    ///
    /// The step fails, with a record and without any run, when `acting`
    /// shows the person the execution acts for may not run workflows now,
    /// when an approval right before the step has lapsed, or when what its
    /// mapping hands the code is too large.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NotFound`] when the workflow has no such step.
    /// - [`DomainError::InvalidTransition`] when the step is not ready.
    /// - [`DomainError::InvalidTransition`] when the execution has ended.
    /// - [`DomainError::Conflict`] once the execution ran out of time.
    /// - [`DomainError::Validation`] when it is not a code step.
    pub fn begin_code(
        &mut self,
        key: &NodeKey,
        acting: &ActingAuthority,
    ) -> Result<CodeStart, DomainError> {
        let ready = self.ready_step(key)?;
        let NodeKind::Code(step) = ready.node.kind() else {
            return Err(DomainError::invalid(message!(
                "workflows-this-step-does-not-run-code",
                "this step does not run code"
            )));
        };
        let version = step.version();
        let input = match self.code_input(step, &ready, acting) {
            Ok(input) => input,
            Err(failure) => return Ok(CodeStart::Stopped(self.fail(ready.index, failure))),
        };
        let run = CodeRun {
            run_id: CodeRunId::new(),
            version,
            input,
            exposure: ready.exposure,
        };
        let work = CodeWork {
            run_id: run.run_id,
            input: run.input.clone(),
        };
        let records = self.begin_step(ready, Underway::Code(work), crate::shared::clock::now());
        Ok(CodeStart::Run(run, records))
    }

    /// What the ready code step `step` hands its code, once it may run now:
    /// the person may still run workflows, an approval right before it
    /// still holds, and what it maps fits workflow data.
    fn code_input(
        &self,
        step: &CodeStep,
        ready: &ReadyStep,
        acting: &ActingAuthority,
    ) -> Result<FlowData, StepFailure> {
        if !acting.may_run_for(&self.acting_for) {
            return Err(StepFailure::Refused(StepRefusal::PersonLacksAuthority));
        }
        if !self.approvals_before_still_hold(&ready.node) {
            return Err(StepFailure::ApprovalLapsed);
        }
        step.inputs()
            .apply(&ready.input)
            .map_err(|_| StepFailure::InputTooLarge)
    }

    /// Settles the code step `key` from how its run `run_id` went.
    ///
    /// Its output carries the sensitivity of its input, since the code
    /// read nothing else. A run still under way when the execution ended
    /// is recorded, and nothing goes on from it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NotFound`] when the workflow has no such step.
    /// - [`DomainError::InvalidTransition`] when the step is neither
    ///   running nor abandoned.
    /// - [`DomainError::Conflict`] once a running execution ran out of
    ///   time.
    /// - [`DomainError::Forbidden`] when `run_id` is not the step's run.
    pub fn settle_code(
        &mut self,
        key: &NodeKey,
        run_id: CodeRunId,
        outcome: CodeOutcome,
    ) -> Result<Vec<ExecutionRecord>, DomainError> {
        let step = self.reporting_step(key)?;
        let Underway::Code(work) = &step.underway else {
            return Err(not_its_run());
        };
        if work.run_id != run_id {
            return Err(not_its_run());
        }
        let settled = match outcome {
            CodeOutcome::Succeeded(output) => Settled::Output(output, step.exposure),
            CodeOutcome::Failed(failure) => Settled::Failure(failure.into()),
        };
        Ok(self.settle_reported(step, settled))
    }

    /// The run the code step `key` is waiting on. `None` when it is not
    /// running code.
    #[must_use]
    pub fn code_run(&self, key: &NodeKey) -> Option<CodeRun> {
        let (node, state) = self.steps().find(|(node, _)| node.key() == key)?;
        let NodeKind::Code(step) = node.kind() else {
            return None;
        };
        let StepState::Running {
            underway: Underway::Code(work),
            exposure,
            ..
        } = state
        else {
            return None;
        };
        Some(CodeRun {
            run_id: work.run_id,
            version: step.version(),
            input: work.input.clone(),
            exposure: *exposure,
        })
    }
}

/// The refusal of an outcome reported under a run the step is not waiting
/// on.
fn not_its_run() -> DomainError {
    DomainError::forbidden(message!(
        "workflows-this-is-not-the-step-s-run",
        "this is not the step's run"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::authority::capability::CapabilitySet;
    use crate::domains::workflows::data::FieldName;
    use crate::domains::workflows::execution::step::CodeFailure;
    use crate::domains::workflows::execution::tests::fixtures::{
        Execution, acting, ann, code, key, started, state,
    };
    use crate::types::UntrustedText;

    fn begun(execution: &mut Execution) -> CodeRun {
        let CodeStart::Run(run, _) = execution
            .begin_code(&key("clean"), &acting(&ann()))
            .unwrap()
        else {
            panic!("the code did not start");
        };
        run
    }

    /// Ann's workflow cleans the trigger's data with code. The run is handed
    /// only the field the step maps, at the input's sensitivity, and the
    /// step waits on exactly that run.
    #[test]
    fn a_code_run_is_handed_only_what_its_step_maps() {
        let mut execution = started(vec![code("clean")], Vec::new());

        let run = begun(&mut execution);

        assert_eq!(
            run.input.field(&FieldName::new("ok").unwrap()),
            Some(&FlowData::bool(true))
        );
        assert_eq!(run.exposure, DataClassLevel::Internal);
        assert_eq!(execution.code_run(&key("clean")), Some(run));
    }

    /// The code gives back a cleaned title. It is the step's output, at the
    /// input's sensitivity, and the step no longer waits on a run.
    #[test]
    fn what_the_code_gives_back_is_the_output() {
        let mut execution = started(vec![code("clean")], Vec::new());
        let run = begun(&mut execution);
        let answer = FlowData::text("Fix login").unwrap();

        execution
            .settle_code(
                &key("clean"),
                run.run_id,
                CodeOutcome::Succeeded(answer.clone()),
            )
            .unwrap();

        let StepState::Succeeded {
            output, exposure, ..
        } = state(&execution, "clean")
        else {
            panic!("the code step did not succeed");
        };
        assert_eq!((output, exposure), (answer, DataClassLevel::Internal));
        assert_eq!(execution.code_run(&key("clean")), None);
    }

    /// A reported code timeout settles the running step as `CodeTimedOut`.
    #[test]
    fn code_past_its_limit_fails_the_step() {
        let mut execution = started(vec![code("clean")], Vec::new());
        let run = begun(&mut execution);

        execution
            .settle_code(
                &key("clean"),
                run.run_id,
                CodeOutcome::Failed(CodeFailure::TimedOut),
            )
            .unwrap();

        assert_eq!(
            state(&execution, "clean"),
            StepState::Failed(StepFailure::CodeTimedOut)
        );
    }

    /// Reporting another code run's failure returns a forbidden error and
    /// leaves the step waiting on its original run.
    #[test]
    fn an_outcome_of_another_run_is_refused() {
        let mut execution = started(vec![code("clean")], Vec::new());
        let run = begun(&mut execution);

        let result = execution.settle_code(
            &key("clean"),
            CodeRunId::new(),
            CodeOutcome::Failed(CodeFailure::Raised(UntrustedText::record("boom"))),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(execution.code_run(&key("clean")), Some(run));
    }

    /// Losing workflow run rights prevents Ann's code step from starting
    /// and fails it for lack of authority.
    #[test]
    fn no_code_runs_for_a_person_who_may_not_run_workflows() {
        let mut execution = started(vec![code("clean")], Vec::new());
        let barred = ActingAuthority::assumed(ann(), CapabilitySet::new(Vec::new(), Vec::new()));

        let start = execution.begin_code(&key("clean"), &barred).unwrap();

        assert!(matches!(start, CodeStart::Stopped(_)));
        assert_eq!(
            state(&execution, "clean"),
            StepState::Failed(StepFailure::Refused(StepRefusal::PersonLacksAuthority))
        );
    }
}
