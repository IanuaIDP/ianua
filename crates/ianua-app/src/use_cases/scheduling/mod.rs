//! Scheduling use cases: running the jobs that are due, lane by lane;
//! claiming each sweep's round for one worker; reading how a job stands
//! and which jobs died, and an operator giving a dead job one more
//! attempt; handing out again the work left half-done; removing ended
//! jobs once their keys need holding no longer; and running a
//! tenant's multi-step processes one step per job.

pub(crate) mod claim_due;
pub(crate) mod handler;
pub(crate) mod jobs;
pub(crate) mod lanes;
pub(crate) mod list_dead;
mod lookup;
pub(crate) mod process_jobs;
pub(crate) mod reconcile;
pub(crate) mod remove_ended;
pub(crate) mod retry_dead;
pub(crate) mod steps;
pub(crate) mod sweeps;

pub use claim_due::{ClaimDuePorts, ClaimDueUseCase};
pub use handler::{Handled, JobHandler, RetryWhen};
pub(crate) use handler::{done_unless_failed, unless_gone};
pub use jobs::PlanReport;
pub(crate) use jobs::{NewJob, key_of, payload_of};
pub use lanes::{Backoff, JobKind, Lane};
pub use list_dead::{DeadJob, ListDeadPorts, ListDeadUseCase};
pub use process_jobs::{ProcessJobsPorts, ProcessJobsUseCase};
pub use reconcile::{ReconcilePorts, ReconcileReport, ReconcileSettings, ReconcileUseCase};
pub use remove_ended::{ENDED_JOBS_KEPT_DAYS, RemoveEndedJobsPorts, RemoveEndedJobsUseCase};
pub use retry_dead::{RetryDeadPorts, RetryDeadUseCase};
pub use steps::{StepFailure, StepJobHandler, StepJobs, StepRequest};
pub use sweeps::{Sweep, sweeps};
