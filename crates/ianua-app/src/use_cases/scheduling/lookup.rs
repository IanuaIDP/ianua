//! Loading the job a scheduling use case names, failing with not-found
//! when the queue holds no such job.

use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::message;
use ianua_domain::types::JobId;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::scheduling::JobQueue;

/// The job with `job_id`, wherever it is in its life.
///
/// # Errors
///
/// - `AppError::NotFound` if the queue holds no such job.
/// - `AppError::Internal` when the queue cannot be read.
pub(super) async fn existing_job(
    queue: &dyn JobQueue,
    job_id: &JobId,
) -> Result<ScheduledJob, AppError> {
    queue
        .find(job_id)
        .await
        .or_internal()?
        .or_not_found(message!("scheduling-job-not-found", "job not found"))
}
