//! The words a workflow run's choices are stored as.
//!
//! What started a run and where it stands carry values of their own, an
//! event, the run it starts again or who stopped it, which have columns of
//! their own, so their cases are stored apart, as a [`CauseKind`] and a
//! [`StatusKind`]; so is whether it is a test, a [`ModeKind`], whose
//! stand-ins have a column of their own.

use ianua_app::ports::workflows::RunKind;
use ianua_domain::domains::workflows::execution::record::ExecutionEnd;
use ianua_domain::domains::workflows::execution::{
    Cause, ExecutionMode, ExecutionStatus, RestartFrom,
};

use crate::postgres::foundation::stored::stored_words;

/// Which case of [`Cause`] started a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CauseKind {
    /// A person started it by hand.
    Manual,
    /// Its schedule came round.
    Schedule,
    /// Its webhook was called.
    Webhook,
    /// An event happened.
    Event,
    /// An integration's service sent the event it waits for.
    Service,
    /// It starts an earlier run again.
    Restart,
    /// A change is about to happen, and it decides it.
    Before,
}

impl CauseKind {
    /// The case `cause` is.
    pub(super) fn of(cause: Cause) -> Self {
        match cause {
            Cause::Manual => Self::Manual,
            Cause::Schedule => Self::Schedule,
            Cause::Webhook => Self::Webhook,
            Cause::Event { .. } => Self::Event,
            Cause::Service => Self::Service,
            Cause::Restart { .. } => Self::Restart,
            Cause::Before { .. } => Self::Before,
        }
    }
}

stored_words! {
    CauseKind as "workflow run cause" {
        Manual => "manual",
        Schedule => "schedule",
        Webhook => "webhook",
        Event => "event",
        Service => "service",
        Restart => "restart",
        Before => "before",
    }
}

stored_words! {
    RestartFrom as "workflow restart" {
        Beginning => "rerun",
        FailedStep => "retry",
    }
}

/// Which case of [`ExecutionStatus`] a run stands in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StatusKind {
    /// Steps are still to run.
    Running,
    /// Every step reached finished without failing.
    Succeeded,
    /// A step failed.
    Failed,
    /// A person stopped it.
    Cancelled,
    /// It ran past its run limit.
    TimedOut,
    /// It was a pass of a loop that failed or ended first.
    LoopEnded,
}

impl StatusKind {
    /// The case `status` is.
    pub(super) fn of(status: ExecutionStatus) -> Self {
        match status {
            ExecutionStatus::Running => Self::Running,
            ExecutionStatus::Ended(ExecutionEnd::Succeeded) => Self::Succeeded,
            ExecutionStatus::Ended(ExecutionEnd::Failed) => Self::Failed,
            ExecutionStatus::Ended(ExecutionEnd::Cancelled(_)) => Self::Cancelled,
            ExecutionStatus::Ended(ExecutionEnd::TimedOut) => Self::TimedOut,
            ExecutionStatus::Ended(ExecutionEnd::LoopEnded) => Self::LoopEnded,
        }
    }
}

stored_words! {
    StatusKind as "workflow run status" {
        Running => "running",
        Succeeded => "succeeded",
        Failed => "failed",
        Cancelled => "cancelled",
        TimedOut => "timed_out",
        LoopEnded => "loop_ended",
    }
}

/// Which case of [`ExecutionMode`] a run is. A test's stand-ins have a
/// column of their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ModeKind {
    /// A real run.
    Live,
    /// A test of a draft.
    Test,
}

impl ModeKind {
    /// The case `mode` is.
    pub(super) fn of(mode: &ExecutionMode) -> Self {
        match mode {
            ExecutionMode::Live => Self::Live,
            ExecutionMode::Test(_) => Self::Test,
        }
    }

    /// The mode a listing of `kind` keeps.
    pub(super) fn listed(kind: RunKind) -> Self {
        match kind {
            RunKind::Real => Self::Live,
            RunKind::Tests => Self::Test,
        }
    }
}

stored_words! {
    ModeKind as "workflow run mode" {
        Live => "live",
        Test => "test",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every cause, restart and status reads back from the word it is
    /// written as, and a restart is written as the domain names it.
    #[test]
    fn every_choice_reads_back_from_its_word() {
        for kind in [
            CauseKind::Manual,
            CauseKind::Schedule,
            CauseKind::Webhook,
            CauseKind::Event,
            CauseKind::Service,
            CauseKind::Restart,
            CauseKind::Before,
        ] {
            assert_eq!(CauseKind::from_word(kind.word()), Some(kind));
        }
        for from in [RestartFrom::Beginning, RestartFrom::FailedStep] {
            assert_eq!(RestartFrom::from_word(from.word()), Some(from));
            assert_eq!(from.word(), from.as_str());
        }
        for kind in [
            StatusKind::Running,
            StatusKind::Succeeded,
            StatusKind::Failed,
            StatusKind::Cancelled,
            StatusKind::TimedOut,
            StatusKind::LoopEnded,
        ] {
            assert_eq!(StatusKind::from_word(kind.word()), Some(kind));
        }
    }
}
