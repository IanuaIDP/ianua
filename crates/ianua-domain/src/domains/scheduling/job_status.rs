//! Where a scheduled job is in its life, and the moves between states.

use crate::shared::model::transition::{InvalidTransition, checked};

/// Where a scheduled job is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    /// Waiting for a worker to pick it up.
    Pending,
    /// A worker is running it.
    Running,
    /// Finished successfully.
    Completed,
    /// Failed. It goes back to pending or ends as dead.
    Failed,
    /// Used up its attempts. It is not retried unless an operator gives it
    /// one more attempt.
    Dead,
    /// Given up, then done after all by a later job queued for the same
    /// work, as a setup step whose worker crashed and which the platform
    /// handed out again. Nothing is left to retry.
    Superseded,
}

impl JobStatus {
    /// Moves to `to` if the move is allowed.
    ///
    /// Allowed moves: pending to running, running to completed or failed,
    /// failed to pending or dead, dead to pending when an operator retries
    /// it, and dead to superseded once a later job did its work.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] for any other move.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| {
            matches!(
                (from, to),
                (Self::Pending, Self::Running)
                    | (Self::Running, Self::Completed | Self::Failed)
                    | (Self::Failed, Self::Pending | Self::Dead)
                    | (Self::Dead, Self::Pending | Self::Superseded)
            )
        })
    }
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Dead => "dead",
            Self::Superseded => "superseded",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A worker picks up a waiting job. Pending moves to running.
    #[test]
    fn pending_to_running_allowed() {
        let result = JobStatus::Pending.try_transition(JobStatus::Running);
        assert_eq!(result.unwrap(), JobStatus::Running);
    }

    /// A running job finishes without error. Running moves to completed.
    #[test]
    fn running_to_completed_allowed() {
        let result = JobStatus::Running.try_transition(JobStatus::Completed);
        assert_eq!(result.unwrap(), JobStatus::Completed);
    }

    /// A running job hits an error. Running moves to failed.
    #[test]
    fn running_to_failed_allowed() {
        let result = JobStatus::Running.try_transition(JobStatus::Failed);
        assert_eq!(result.unwrap(), JobStatus::Failed);
    }

    /// A failed job with attempts left is queued again. Failed moves back to
    /// pending.
    #[test]
    fn failed_to_pending_retry_allowed() {
        let result = JobStatus::Failed.try_transition(JobStatus::Pending);
        assert_eq!(result.unwrap(), JobStatus::Pending);
    }

    /// A failed job with no attempts left gives up. Failed moves to dead.
    #[test]
    fn failed_to_dead_allowed() {
        let result = JobStatus::Failed.try_transition(JobStatus::Dead);
        assert_eq!(result.unwrap(), JobStatus::Dead);
    }

    /// A job that never ran cannot be marked completed. It must pass through
    /// running first.
    #[test]
    fn pending_to_completed_rejected() {
        let result = JobStatus::Pending.try_transition(JobStatus::Completed);
        assert!(result.is_err());
    }

    /// A completed job cannot start running again, so finished work is never
    /// done twice.
    #[test]
    fn completed_to_running_rejected() {
        let result = JobStatus::Completed.try_transition(JobStatus::Running);
        assert!(result.is_err());
    }

    /// Bob, an operator, retries a job that used up its attempts. Dead
    /// moves back to pending.
    #[test]
    fn dead_to_pending_allowed_for_a_retry() {
        let result = JobStatus::Dead.try_transition(JobStatus::Pending);
        assert_eq!(result.unwrap(), JobStatus::Pending);
    }

    /// A dead job is never picked up as it is: it must be put back first.
    #[test]
    fn dead_to_running_rejected() {
        let result = JobStatus::Dead.try_transition(JobStatus::Running);
        assert!(result.is_err());
    }

    /// A setup step whose worker crashed was given up, then a later job did
    /// the step. Dead moves to superseded, and nothing moves on from there.
    #[test]
    fn dead_to_superseded_allowed_and_final() {
        let result = JobStatus::Dead.try_transition(JobStatus::Superseded);
        assert_eq!(result.unwrap(), JobStatus::Superseded);
        for to in [JobStatus::Pending, JobStatus::Running, JobStatus::Dead] {
            assert!(JobStatus::Superseded.try_transition(to).is_err());
        }
    }

    /// Only a job given up can be superseded: a completed one did its work
    /// itself.
    #[test]
    fn completed_to_superseded_rejected() {
        let result = JobStatus::Completed.try_transition(JobStatus::Superseded);
        assert!(result.is_err());
    }

    /// A running job cannot jump back to pending. It must fail first, so the
    /// failure is counted.
    #[test]
    fn running_to_pending_rejected() {
        let result = JobStatus::Running.try_transition(JobStatus::Pending);
        assert!(result.is_err());
    }
}
