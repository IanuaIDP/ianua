//! A plan of steps and what each waits on, and a run of it.
//!
//! The platform's own multi-step processes, such as a tenant's setup and
//! its teardown, are planned with it: every step names the steps it waits
//! on, and the plan is refused when a step is listed twice, waits on a step
//! it does not hold, or waits on itself through others, so every run of a
//! plan ends. A run says which steps are done, which are ready to go
//! (everything they wait on is done), and whether it finished or failed. It
//! keeps no time and does no work: whoever runs the steps asks it what is
//! next.

use crate::message;
use crate::shared::errors::DomainError;
use crate::types::UntrustedText;

/// A kind of step a process is planned with: a closed set, each step known
/// by the name it is recorded and queued under.
pub trait PlanStep: Copy + Eq + Send + Sync + 'static {
    /// Every step of the kind, in the order they are planned.
    const ALL: &'static [Self];

    /// The name the step is known by in records.
    fn as_str(self) -> &'static str;

    /// The step `name` names, as [`as_str`](Self::as_str) writes it.
    #[must_use]
    fn named(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|step| step.as_str() == name)
    }
}

/// One step of a plan and the steps it waits on.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Planned<S> {
    step: S,
    after: Vec<S>,
}

/// A checked plan: its steps, each with what it waits on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StepPlan<S> {
    steps: Vec<Planned<S>>,
}

impl<S: Copy + Eq> StepPlan<S> {
    /// The plan of `steps`, each with the steps it waits on.
    ///
    /// # Errors
    ///
    /// [`DomainError::Validation`] when the plan holds no step, lists a
    /// step twice, has a step wait on one it does not hold, or has steps
    /// that wait on each other.
    pub(crate) fn new(steps: impl IntoIterator<Item = (S, Vec<S>)>) -> Result<Self, DomainError> {
        let steps: Vec<Planned<S>> = steps
            .into_iter()
            .map(|(step, after)| Planned { step, after })
            .collect();
        let plan = Self { steps };
        plan.ensure_well_formed()?;
        Ok(plan)
    }

    fn ensure_well_formed(&self) -> Result<(), DomainError> {
        if self.steps.is_empty() {
            return Err(DomainError::invalid(message!(
                "values-a-plan-holds-at-least-one",
                "a plan holds at least one step"
            )));
        }
        if self.lists_a_step_twice() {
            return Err(DomainError::invalid(message!(
                "values-a-plan-lists-each-step-once",
                "a plan lists each step once"
            )));
        }
        if self.waits_on_unknown() {
            return Err(DomainError::invalid(message!(
                "values-a-step-waits-only-on-steps",
                "a step waits only on steps of its plan"
            )));
        }
        if !self.ends() {
            return Err(DomainError::invalid(message!(
                "values-the-steps-of-a-plan-never",
                "the steps of a plan never wait on each other"
            )));
        }
        Ok(())
    }

    /// Whether a step is planned more than once.
    fn lists_a_step_twice(&self) -> bool {
        self.steps.iter().enumerate().any(|(at, planned)| {
            self.steps
                .iter()
                .skip(at.saturating_add(1))
                .any(|other| other.step == planned.step)
        })
    }

    /// Whether a step waits on one the plan does not hold.
    fn waits_on_unknown(&self) -> bool {
        self.steps
            .iter()
            .flat_map(|planned| planned.after.iter())
            .any(|step| !self.holds(*step))
    }

    /// Whether every step can be reached: the steps are taken in order,
    /// each once everything it waits on was taken, and none is left over.
    fn ends(&self) -> bool {
        let mut taken: Vec<S> = Vec::with_capacity(self.steps.len());
        while taken.len() < self.steps.len() {
            let next = self.steps.iter().find(|planned| {
                !taken.contains(&planned.step)
                    && planned.after.iter().all(|step| taken.contains(step))
            });
            let Some(next) = next else {
                return false;
            };
            taken.push(next.step);
        }
        true
    }

    /// Whether the plan holds `step`.
    #[must_use]
    pub(crate) fn holds(&self, step: S) -> bool {
        self.steps.iter().any(|planned| planned.step == step)
    }

    /// The plan's steps, in the order they were planned.
    pub(crate) fn steps(&self) -> impl Iterator<Item = S> + '_ {
        self.steps.iter().map(|planned| planned.step)
    }

    /// The steps `step` waits on; none for a step the plan does not hold.
    #[must_use]
    pub(crate) fn waits_on(&self, step: S) -> &[S] {
        self.steps
            .iter()
            .find(|planned| planned.step == step)
            .map_or(&[], |planned| planned.after.as_slice())
    }
}

/// How a run stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    /// Steps are left to do.
    Running,
    /// Every step is done.
    Done,
    /// A step failed; no step runs after it.
    Failed,
}

/// What finishing a step came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finished {
    /// The step is done now.
    Now,
    /// The step was done already, by an earlier try that ran it too.
    Already,
}

/// Whether a run failed, and at which step and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunFailure<S> {
    /// No step failed.
    NotFailed,
    /// `step` failed for good, for `why`, and no step runs after it.
    FailedAt {
        /// The step that failed.
        step: S,
        /// Why it failed, as the step reported it.
        why: UntrustedText,
    },
}

impl<S: Copy> RunFailure<S> {
    /// The step that failed and why, if one did.
    #[must_use]
    pub fn step_and_why(&self) -> Option<(S, &UntrustedText)> {
        match self {
            Self::NotFailed => None,
            Self::FailedAt { step, why } => Some((*step, why)),
        }
    }
}

/// A run of a plan: the steps done, in the order they were done, and the
/// step that failed, if one did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StepRun<S> {
    plan: StepPlan<S>,
    done: Vec<S>,
    failed: RunFailure<S>,
}

impl<S: Copy + Eq> StepRun<S> {
    /// A run of `plan` with nothing done.
    #[must_use]
    pub(crate) fn start(plan: StepPlan<S>) -> Self {
        Self {
            plan,
            done: Vec::new(),
            failed: RunFailure::NotFailed,
        }
    }

    /// A run of `plan` as it was kept, or `None` when what was kept cannot
    /// have happened: a step done twice, a step not in the plan, a step done
    /// before what it waits on, or a failed step that was also done or was
    /// never ready.
    #[must_use]
    pub(crate) fn restored(plan: StepPlan<S>, done: Vec<S>, failed: RunFailure<S>) -> Option<Self> {
        let mut run = Self::start(plan);
        for step in done {
            if !run.is_ready(step) {
                return None;
            }
            run.done.push(step);
        }
        let failed_when_ready = failed
            .step_and_why()
            .is_none_or(|(step, _)| run.is_ready(step));
        if !failed_when_ready {
            return None;
        }
        run.failed = failed;
        Some(run)
    }

    fn is_ready(&self, step: S) -> bool {
        self.failed == RunFailure::NotFailed
            && self.plan.holds(step)
            && !self.done.contains(&step)
            && self
                .plan
                .waits_on(step)
                .iter()
                .all(|before| self.done.contains(before))
    }

    /// The plan the run follows.
    #[must_use]
    pub(crate) fn plan(&self) -> &StepPlan<S> {
        &self.plan
    }

    /// The steps done, in the order they were done.
    #[must_use]
    pub(crate) fn done(&self) -> &[S] {
        &self.done
    }

    /// The step that failed and why, if one did.
    #[must_use]
    pub(crate) fn failure(&self) -> Option<(S, &UntrustedText)> {
        self.failed.step_and_why()
    }

    /// Whether the run failed, as storage keeps it.
    #[must_use]
    pub(crate) fn failed(&self) -> &RunFailure<S> {
        &self.failed
    }

    /// The steps ready to go now: not done, and everything they wait on
    /// done. None once a step failed.
    #[must_use]
    pub(crate) fn ready(&self) -> Vec<S> {
        self.plan
            .steps()
            .filter(|step| self.is_ready(*step))
            .collect()
    }

    /// How the run stands.
    #[must_use]
    pub(crate) fn outcome(&self) -> RunOutcome {
        if self.failed != RunFailure::NotFailed {
            return RunOutcome::Failed;
        }
        match self.plan.steps().all(|step| self.done.contains(&step)) {
            true => RunOutcome::Done,
            false => RunOutcome::Running,
        }
    }

    /// Marks `step` done. A step done already stays done, so a step run
    /// twice by a retry finishes once.
    ///
    /// # Errors
    ///
    /// [`DomainError::InvalidTransition`] when the run failed, the plan
    /// does not hold the step, or the step waits on one not yet done.
    pub(crate) fn finish(&mut self, step: S) -> Result<Finished, DomainError> {
        if self.failed == RunFailure::NotFailed && self.done.contains(&step) {
            return Ok(Finished::Already);
        }
        if !self.is_ready(step) {
            return Err(DomainError::invalid_transition(message!(
                "values-only-a-ready-step-is-finished",
                "only a ready step is finished"
            )));
        }
        self.done.push(step);
        Ok(Finished::Now)
    }

    /// Marks `step` failed for `why`: the run fails, and no step runs after.
    ///
    /// # Errors
    ///
    /// [`DomainError::InvalidTransition`] when the run failed already, the
    /// plan does not hold the step, or the step is done or not yet ready.
    pub(crate) fn fail(&mut self, step: S, why: UntrustedText) -> Result<(), DomainError> {
        if !self.is_ready(step) {
            return Err(DomainError::invalid_transition(message!(
                "values-only-a-ready-step-fails",
                "only a ready step fails"
            )));
        }
        self.failed = RunFailure::FailedAt { step, why };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Step {
        Database,
        Key,
        Roles,
        Activate,
    }

    fn plan() -> StepPlan<Step> {
        StepPlan::new([
            (Step::Database, vec![]),
            (Step::Key, vec![]),
            (Step::Roles, vec![Step::Database]),
            (Step::Activate, vec![Step::Database, Step::Key, Step::Roles]),
        ])
        .unwrap()
    }

    fn why() -> UntrustedText {
        UntrustedText::record("the database did not answer")
    }

    /// Cyclic, duplicate, missing-dependency and empty plans all fail validation
    /// before a run can begin with an impossible step order.
    #[test]
    fn a_plan_that_could_not_end_is_refused() {
        let cycle = StepPlan::new([
            (Step::Key, vec![Step::Roles]),
            (Step::Roles, vec![Step::Key]),
        ]);
        let twice = StepPlan::new([(Step::Key, vec![]), (Step::Key, vec![])]);
        let unknown = StepPlan::new([(Step::Key, vec![Step::Database])]);
        let empty = StepPlan::<Step>::new([]);

        for refused in [cycle, twice, unknown, empty] {
            assert!(matches!(refused, Err(DomainError::Validation(_))));
        }
    }

    /// A new run's ready steps are those that wait on nothing; once they
    /// are done, the steps waiting on them are ready.
    #[test]
    fn steps_become_ready_once_what_they_wait_on_is_done() {
        let mut run = StepRun::start(plan());

        let first = run.ready();
        run.finish(Step::Database).unwrap();
        let after_database = run.ready();

        assert_eq!(first, [Step::Database, Step::Key]);
        assert_eq!(after_database, [Step::Key, Step::Roles]);
        assert_eq!(run.outcome(), RunOutcome::Running);
    }

    /// A run with every step done is done.
    #[test]
    fn a_run_with_every_step_done_is_done() {
        let mut run = StepRun::start(plan());

        for step in [Step::Database, Step::Key, Step::Roles, Step::Activate] {
            run.finish(step).unwrap();
        }

        assert_eq!(run.outcome(), RunOutcome::Done);
        assert!(run.ready().is_empty());
    }

    /// A step a retry ran twice finishes once.
    #[test]
    fn a_step_finished_twice_finishes_once() {
        let mut run = StepRun::start(plan());

        let first = run.finish(Step::Key).unwrap();
        let again = run.finish(Step::Key).unwrap();

        assert_eq!((first, again), (Finished::Now, Finished::Already));
        assert_eq!(run.done(), [Step::Key]);
    }

    /// Finishing activation before its required setup steps is rejected as an
    /// invalid transition.
    #[test]
    fn a_step_is_not_finished_before_what_it_waits_on() {
        let mut run = StepRun::start(plan());

        let early = run.finish(Step::Activate);

        assert!(matches!(early, Err(DomainError::InvalidTransition(_))));
    }

    /// A failed step fails the run: nothing is ready after it, and no step
    /// is finished.
    #[test]
    fn a_failed_step_fails_the_run() {
        let mut run = StepRun::start(plan());

        run.fail(Step::Database, why()).unwrap();

        assert_eq!(run.outcome(), RunOutcome::Failed);
        assert!(run.ready().is_empty());
        assert!(run.finish(Step::Key).is_err());
        assert_eq!(run.failure().map(|(step, _)| step), Some(Step::Database));
    }

    /// A run reads back as it was kept.
    #[test]
    fn a_kept_run_reads_back() {
        let restored = StepRun::restored(
            plan(),
            vec![Step::Key, Step::Database],
            RunFailure::NotFailed,
        )
        .unwrap();

        assert_eq!(restored.ready(), [Step::Roles]);
    }

    /// Stored runs with skipped prerequisites, duplicate completions or a step
    /// both completed and failed are refused during restoration.
    #[test]
    fn a_run_that_cannot_have_happened_does_not_read_back() {
        let skipped = StepRun::restored(plan(), vec![Step::Activate], RunFailure::NotFailed);
        let twice = StepRun::restored(plan(), vec![Step::Key, Step::Key], RunFailure::NotFailed);
        let failed_and_done = StepRun::restored(
            plan(),
            vec![Step::Key],
            RunFailure::FailedAt {
                step: Step::Key,
                why: why(),
            },
        );

        assert!(skipped.is_none());
        assert!(twice.is_none());
        assert!(failed_and_done.is_none());
    }
}
