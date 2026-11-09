//! The check a run's answer may be held to: a sandbox version's code that
//! reads the answer and says whether it keeps the company's rules.
//!
//! A run held to a check does not complete on its model's answer. The
//! answer is recorded, the check runs on it, and only an answer that passes
//! completes the run. An answer that breaks a rule goes back to the model
//! with what the check said, so it may fix its work, up to the run's tries;
//! an answer that breaks one on the last try fails the run. A check that
//! cannot run, or gives back no verdict, never lets an answer through: it
//! fails the run.
//!
//! Every try is part of the same run, so the run's step cap, spend limit,
//! approvals and call checks hold across all of them.

use crate::domains::agents::execution::run::AgentRun;
use crate::domains::agents::execution::run::call::{StepCall, StepOutcome};
use crate::domains::agents::execution::run::params::AgentRunRow;
use crate::domains::agents::execution::run::status::{RunState, RunStatus};
use crate::domains::data_classification::level::DataClassLevel;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_range;
use crate::types::{SandboxVersionId, UntrustedText};

/// The most answers a run held to a check may give, the first included.
/// Each try costs a model call and a run of the check, so a few are enough
/// to fix what a check found, and an agent that cannot is stopped soon.
pub const MAX_CHECK_TRIES: u8 = 3;

/// How many answers a run held to a check may give before it fails: from
/// one to [`MAX_CHECK_TRIES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u8", into = "u8"))]
pub struct CheckTries(u8);

impl CheckTries {
    /// At most `tries` answers.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `tries` is outside
    ///   1..=[`MAX_CHECK_TRIES`].
    pub fn new(tries: u8) -> Result<Self, DomainError> {
        validate_range("tries", tries, 1..=MAX_CHECK_TRIES)?;
        Ok(Self(tries))
    }

    /// Reads a stored count.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] for a count outside
    ///   1..=[`MAX_CHECK_TRIES`].
    pub fn from_stored(tries: u8) -> Result<Self, DomainError> {
        Self::new(tries).map_err(|_| {
            DomainError::corrupt_row("agent run", "a check try count outside its range")
        })
    }

    /// The count.
    #[must_use]
    pub fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for CheckTries {
    type Error = DomainError;

    fn try_from(tries: u8) -> Result<Self, Self::Error> {
        Self::new(tries)
    }
}

impl From<CheckTries> for u8 {
    fn from(tries: CheckTries) -> Self {
        tries.0
    }
}

/// What a run's answer is held to before the run completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunCheck {
    /// Nothing: the run completes on its model's answer.
    Unchecked,
    /// The code of this sandbox version, given this many tries.
    Sandbox {
        /// The version whose code checks each answer.
        version: SandboxVersionId,
        /// How many answers the run may give.
        tries: CheckTries,
    },
}

/// What a check said of an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckVerdict {
    /// The answer keeps every rule.
    Passed,
    /// The answer broke a rule. This is what the check said is wrong, which
    /// the model reads before it tries again.
    Broken(UntrustedText),
    /// The check could not run, or gave back no verdict. This is why.
    NotRun(UntrustedText),
}

/// An answer waiting for its check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DueCheck<'a> {
    /// The version whose code checks it.
    pub version: SandboxVersionId,
    /// The answer, as the model gave it.
    pub answer: &'a str,
    /// Which try it is, counted from one.
    pub attempt: u8,
}

impl<T: TenantScope> AgentRun<T> {
    /// The run, its answers held to `check` before it completes.
    #[must_use]
    pub(crate) fn checked_by(self, check: RunCheck) -> Self {
        Self { check, ..self }
    }

    /// What the run's answers are held to.
    #[must_use]
    pub fn check(&self) -> RunCheck {
        self.check
    }

    /// Records the model's final answer. A run held to no check completes
    /// on it; a run held to one waits, still running, for its check.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the run is not running.
    pub fn record_answer(&mut self, answer: impl Into<String>) -> Result<(), DomainError> {
        if self.check == RunCheck::Unchecked {
            return self.complete(answer);
        }
        self.push(
            StepCall::Model,
            StepOutcome::Answered(answer.into()),
            DataClassLevel::Public,
        )
    }

    /// The answer waiting for its check: the last step of a running run
    /// held to a check, when that step is an answer. `None` otherwise.
    #[must_use]
    pub fn due_check(&self) -> Option<DueCheck<'_>> {
        let RunCheck::Sandbox { version, .. } = self.check else {
            return None;
        };
        if self.status() != RunStatus::Running {
            return None;
        }
        let StepOutcome::Answered(answer) = self.steps.last()?.outcome() else {
            return None;
        };
        Some(DueCheck {
            version,
            answer,
            attempt: self.failed_checks().saturating_add(1),
        })
    }

    /// Records what the check said of the answer waiting for it.
    ///
    /// An answer that passed completes the run. One that broke a rule is
    /// recorded with what the check said, for the model to read next, and
    /// fails the run once it was the last try. A check that did not run
    /// fails the run, its reason recorded.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when no answer waits for its
    ///   check.
    pub fn record_check(&mut self, verdict: CheckVerdict) -> Result<(), DomainError> {
        let Some(due) = self.due_check() else {
            return Err(DomainError::invalid_transition(message!(
                "agents-no-answer-waits-for-its-check",
                "no answer of the run waits for its check"
            )));
        };
        let last_try = self.tries().is_none_or(|tries| due.attempt >= tries.get());
        match verdict {
            CheckVerdict::Passed => self.pass_check(),
            CheckVerdict::Broken(said) => {
                self.record_failed_check(&said)?;
                if last_try {
                    self.fail();
                }
                Ok(())
            }
            CheckVerdict::NotRun(why) => {
                self.record_failed_check(&why)?;
                self.fail();
                Ok(())
            }
        }
    }

    /// How many answers a check turned back so far.
    #[must_use]
    pub fn failed_checks(&self) -> u8 {
        let failed = self
            .steps
            .iter()
            .filter(|step| matches!(step.outcome(), StepOutcome::CheckFailed(_)))
            .count();
        u8::try_from(failed).unwrap_or(u8::MAX)
    }

    /// How many answers the run may give, when it is held to a check.
    fn tries(&self) -> Option<CheckTries> {
        match self.check {
            RunCheck::Unchecked => None,
            RunCheck::Sandbox { tries, .. } => Some(tries),
        }
    }

    /// Completes the run on the answer its check passed.
    fn pass_check(&mut self) -> Result<(), DomainError> {
        self.status().try_transition(RunStatus::Completed)?;
        self.state = RunState::Completed;
        self.touch();
        Ok(())
    }

    /// Records what the check said of the answer it turned back.
    fn record_failed_check(&mut self, said: &UntrustedText) -> Result<(), DomainError> {
        self.push(
            StepCall::Model,
            StepOutcome::CheckFailed(said.as_str().to_owned()),
            DataClassLevel::Public,
        )
    }
}

/// Whether a stored run's turned-back answers fit its check: none on a run
/// held to no check, and no more than its tries on one held to a check.
pub(super) fn checks_fit(row: &AgentRunRow) -> bool {
    let failed = row
        .steps
        .iter()
        .filter(|step| matches!(step.outcome(), StepOutcome::CheckFailed(_)))
        .count();
    match row.check {
        RunCheck::Unchecked => failed == 0,
        RunCheck::Sandbox { tries, .. } => failed <= usize::from(tries.get()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::execution::run::RunStep;
    use crate::domains::agents::execution::run::tests::fixtures::run;

    fn held(tries: u8) -> AgentRun<crate::isolation::scope::ResolvedTenant> {
        let (r, _) = run(10);
        r.checked_by(RunCheck::Sandbox {
            version: SandboxVersionId::new(),
            tries: CheckTries::new(tries).unwrap(),
        })
    }

    fn broken(said: &str) -> CheckVerdict {
        CheckVerdict::Broken(UntrustedText::record(said))
    }

    /// One to three tries are allowed. None, or a fourth, is refused.
    #[test]
    fn a_check_gives_one_to_three_tries() {
        assert!(CheckTries::new(1).is_ok());
        assert!(CheckTries::new(MAX_CHECK_TRIES).is_ok());
        assert!(CheckTries::new(0).is_err());
        assert!(CheckTries::new(MAX_CHECK_TRIES + 1).is_err());
    }

    /// A drafted reply held to a check is recorded, and the run waits,
    /// still running, for the check on its first try.
    #[test]
    fn a_checked_answer_waits_for_its_check() {
        let mut r = held(3);

        r.record_answer("Dear Pat, refund approved.").unwrap();

        assert_eq!(r.status(), RunStatus::Running);
        let due = r.due_check().unwrap();
        assert_eq!((due.answer, due.attempt), ("Dear Pat, refund approved.", 1));
        assert_eq!(r.answer(), None);
    }

    /// The check passes the answer. The run completes with it.
    #[test]
    fn an_answer_that_passes_its_check_completes_the_run() {
        let mut r = held(3);
        r.record_answer("Dear Pat, we are looking into it.")
            .unwrap();

        r.record_check(CheckVerdict::Passed).unwrap();

        assert_eq!(r.status(), RunStatus::Completed);
        assert_eq!(r.answer(), Some("Dear Pat, we are looking into it."));
    }

    /// The check finds a promised refund. What it said is recorded for the
    /// model, the run goes on, and the next answer is the second try.
    #[test]
    fn a_broken_rule_goes_back_to_the_model() {
        let mut r = held(3);
        r.record_answer("Refund approved.").unwrap();

        r.record_check(broken("no promises of refunds")).unwrap();
        r.record_answer("We are looking into it.").unwrap();

        assert_eq!(r.status(), RunStatus::Running);
        assert_eq!(r.failed_checks(), 1);
        assert_eq!(r.due_check().unwrap().attempt, 2);
    }

    /// The agent breaks the rule on both of its two tries. The second
    /// broken answer fails the run with what the check said recorded.
    #[test]
    fn breaking_a_rule_on_the_last_try_fails_the_run() {
        let mut r = held(2);
        r.record_answer("Refund approved.").unwrap();
        r.record_check(broken("no promises of refunds")).unwrap();
        r.record_answer("Refund approved, really.").unwrap();

        r.record_check(broken("no promises of refunds")).unwrap();

        assert_eq!(r.status(), RunStatus::Failed);
        assert!(matches!(
            r.steps().last().map(RunStep::outcome),
            Some(StepOutcome::CheckFailed(said)) if said == "no promises of refunds"
        ));
    }

    /// The check's container could not start. Nothing lets the answer
    /// through: the run fails on the first try, with the reason recorded.
    #[test]
    fn a_check_that_did_not_run_fails_the_run() {
        let mut r = held(3);
        r.record_answer("Refund approved.").unwrap();

        r.record_check(CheckVerdict::NotRun(UntrustedText::record("no sandbox")))
            .unwrap();

        assert_eq!(r.status(), RunStatus::Failed);
        assert_eq!(r.answer(), None);
    }

    /// A run held to a check cannot be completed around it, and a verdict
    /// with no answer waiting is refused.
    #[test]
    fn a_checked_run_completes_only_through_its_check() {
        let mut r = held(3);

        let around = r.complete("Refund approved.");
        let early = r.record_check(CheckVerdict::Passed);

        assert!(matches!(around, Err(DomainError::InvalidTransition(_))));
        assert!(matches!(early, Err(DomainError::InvalidTransition(_))));
        assert_eq!(r.status(), RunStatus::Running);
    }

    /// A run held to no check completes on its answer, with none due.
    #[test]
    fn an_unchecked_run_completes_on_its_answer() {
        let (mut r, _) = run(10);

        r.record_answer("The total is 42.").unwrap();

        assert_eq!(r.status(), RunStatus::Completed);
        assert_eq!(r.due_check(), None);
    }
}
