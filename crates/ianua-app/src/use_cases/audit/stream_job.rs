//! The job that sends one audit record along one stream: queued by the
//! planning of the record's event, and tried again on the queue's backoff
//! while the destination refuses it.

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_key::KeyHold;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AuditRecordId, AuditStreamId, TenantId};

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::scheduling::{Enqueued, JobQueue};
use crate::use_case::Command as _;
use crate::use_cases::audit::{StreamRecordRequest, StreamRecordUseCase, Streamed};
use crate::use_cases::scheduling::{Handled, JobHandler, NewJob, RetryWhen, key_of, payload_of};

/// The job type that sends a record along a stream.
pub const STREAM_RECORD_JOB: &str = "audit.stream_record";

/// Why a stream job runs again.
const REFUSED: &str = "the destination did not take the record";

/// What a stream job carries: which record along which stream of which
/// tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct StreamJob {
    tenant_id: TenantId,
    stream_id: AuditStreamId,
    record_id: AuditRecordId,
}

/// Where stream jobs are queued, and how many tries each gets.
#[derive(Clone)]
pub struct StreamJobs {
    /// Persists deliveries for workers to send audit records.
    pub queue: Arc<dyn JobQueue>,
    /// Tries a stream job gets before it is given up.
    pub attempts: NonZeroU32,
}

impl StreamJobs {
    /// Queues the job sending the record `record_id` of `tenant_id` along
    /// the stream `stream_id`, once for that record and stream.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub(crate) async fn queue(
        &self,
        tenant_id: TenantId,
        stream_id: AuditStreamId,
        record_id: AuditRecordId,
    ) -> Result<Enqueued, AppError> {
        NewJob {
            job_type: STREAM_RECORD_JOB,
            payload: &StreamJob {
                tenant_id,
                stream_id,
                record_id,
            },
            tenant_id,
            key: key_of(record_id, stream_id)?,
            hold: KeyHold::WhileKept,
            run_at: clock::now(),
            attempts: self.attempts,
        }
        .queue(self.queue.as_ref())
        .await
    }
}

/// Runs stream jobs through [`StreamRecordUseCase`].
pub struct StreamRecordHandler {
    job_type: JobType,
    stream: Arc<StreamRecordUseCase>,
}

impl StreamRecordHandler {
    /// A handler streaming records through `stream`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(stream: Arc<StreamRecordUseCase>) -> Result<Self, DomainError> {
        let job_type = JobType::new(STREAM_RECORD_JOB)?;
        Ok(Self { job_type, stream })
    }
}

#[async_trait]
impl JobHandler for StreamRecordHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Sends the record along its stream. A refusal is tried again on the
    /// queue's backoff until the stream pauses itself; a stream or record
    /// that is gone, or a paused stream, is done with.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let payload: StreamJob = payload_of(job)?;
        let request = StreamRecordRequest {
            tenant_id: payload.tenant_id,
            stream_id: payload.stream_id,
            record_id: payload.record_id,
        };
        let streamed = self.stream.execute(&(), auditor, request).await?;
        Ok(after_streaming(streamed))
    }
}

/// What a send that went as `streamed` leaves to do.
fn after_streaming(streamed: Streamed) -> Handled {
    match streamed {
        Streamed::Failed => Handled::Retry {
            reason: REFUSED,
            when: RetryWhen::OnBackoff,
        },
        Streamed::Delivered | Streamed::Skipped => Handled::Done,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A destination that refused is tried again on the backoff; one that
    /// took the record, or a stream that is gone or paused, is done.
    #[test]
    fn only_a_refused_send_is_tried_again() {
        assert!(matches!(
            after_streaming(Streamed::Failed),
            Handled::Retry {
                when: RetryWhen::OnBackoff,
                ..
            }
        ));
        assert_eq!(after_streaming(Streamed::Delivered), Handled::Done);
        assert_eq!(after_streaming(Streamed::Skipped), Handled::Done);
    }
}
