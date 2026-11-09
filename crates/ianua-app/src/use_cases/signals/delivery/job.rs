//! The job that hands one signal to one stream: queued by the planning of
//! the event the signal came from, and tried again on the queue's backoff
//! while the receiver does not take it.

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_key::KeyHold;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::domains::signals::signal::{
    SecuritySignal, SecuritySignalRow, SignalEvent, SignalSubject,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AuditRecordId, SignalId, SignalStreamId, TenantId};
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::scheduling::{Enqueued, JobQueue};
use crate::use_case::Command as _;
use crate::use_cases::scheduling::{
    Handled, JobHandler, NewJob, RetryWhen, key_of, payload_of, unless_gone,
};
use crate::use_cases::signals::delivery::{
    DispatchSignalRequest, DispatchSignalUseCase, Dispatched,
};

/// The job type that hands a signal to a stream.
pub const DISPATCH_SIGNAL_JOB: &str = "signals.dispatch";

/// Why a signal job runs again.
const NOT_TAKEN: &str = "the receiver did not take the signal";

/// What a signal job carries: the stream, and the signal under the id it
/// was raised with.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct SignalJob {
    stream_id: SignalStreamId,
    signal_id: SignalId,
    tenant_id: TenantId,
    subject: SignalSubject,
    event: SignalEvent,
    occurred_at: OffsetDateTime,
}

impl SignalJob {
    /// The job carrying `signal` to `stream_id`.
    fn of(stream_id: SignalStreamId, signal: &SecuritySignal) -> Self {
        Self {
            stream_id,
            signal_id: *signal.id(),
            tenant_id: *signal.tenant_id(),
            subject: *signal.subject(),
            event: signal.event().clone(),
            occurred_at: signal.occurred_at(),
        }
    }

    /// The signal the job carries, read back.
    fn signal(self) -> Result<SecuritySignal, DomainError> {
        SecuritySignal::reconstitute(SecuritySignalRow {
            id: self.signal_id,
            tenant_id: self.tenant_id,
            subject: self.subject,
            event: self.event,
            occurred_at: self.occurred_at,
        })
    }
}

/// Where signal jobs are queued, and how many tries each gets.
#[derive(Clone)]
pub struct SignalJobs {
    /// Persists work for workers to deliver security events.
    pub queue: Arc<dyn JobQueue>,
    /// Tries a signal job gets before it is given up.
    pub attempts: NonZeroU32,
}

impl SignalJobs {
    /// Queues the job handing `signal`, which the event `event_id` means,
    /// to the stream `stream_id`, once for that event, subject and stream.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub(crate) async fn queue(
        &self,
        event_id: AuditRecordId,
        stream_id: SignalStreamId,
        signal: &SecuritySignal,
    ) -> Result<Enqueued, AppError> {
        let what = format!("{event_id}:{}", subject_id(signal.subject()));
        NewJob {
            job_type: DISPATCH_SIGNAL_JOB,
            payload: &SignalJob::of(stream_id, signal),
            tenant_id: *signal.tenant_id(),
            key: key_of(what, stream_id)?,
            hold: KeyHold::WhileKept,
            run_at: clock::now(),
            attempts: self.attempts,
        }
        .queue(self.queue.as_ref())
        .await
    }
}

/// Runs signal jobs through [`DispatchSignalUseCase`].
pub struct DispatchSignalHandler {
    job_type: JobType,
    dispatch: Arc<DispatchSignalUseCase>,
}

impl DispatchSignalHandler {
    /// A handler dispatching signals through `dispatch`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(dispatch: Arc<DispatchSignalUseCase>) -> Result<Self, DomainError> {
        let job_type = JobType::new(DISPATCH_SIGNAL_JOB)?;
        Ok(Self { job_type, dispatch })
    }
}

#[async_trait]
impl JobHandler for DispatchSignalHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Hands the signal to its stream. A receiver that did not take it is
    /// tried again on the queue's backoff; a stream that is gone, switched
    /// off or no longer takes it is done with.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let payload: SignalJob = payload_of(job)?;
        let stream_id = payload.stream_id;
        let signal = payload.signal().map_err(AppError::internal)?;
        let auditor = auditor.with_tenant(*signal.tenant_id());
        let request = DispatchSignalRequest { stream_id, signal };
        let dispatched = unless_gone(self.dispatch.execute(&(), &auditor, request).await)?;
        Ok(after_dispatch(dispatched))
    }
}

/// What a dispatch that went as `dispatched` leaves to do.
fn after_dispatch(dispatched: Option<Dispatched>) -> Handled {
    match dispatched {
        Some(Dispatched::Failed) => Handled::Retry {
            reason: NOT_TAKEN,
            when: RetryWhen::OnBackoff,
        },
        Some(
            Dispatched::Delivered
            | Dispatched::Queued
            | Dispatched::SwitchedOff
            | Dispatched::Skipped,
        )
        | None => Handled::Done,
    }
}

/// The id of the user or agent `subject` names.
fn subject_id(subject: &SignalSubject) -> String {
    match subject {
        SignalSubject::User(id) => id.to_string(),
        SignalSubject::Agent(id) => id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::signals::signal::NewSecuritySignal;
    use ianua_domain::types::AgentId;

    use super::*;
    use crate::test_support::block_on;
    use crate::test_support::scheduling::FakeJobQueue;

    fn suspended_agent() -> SecuritySignal {
        SecuritySignal::new(NewSecuritySignal {
            tenant_id: TenantId::new(),
            subject: SignalSubject::Agent(AgentId::new()),
            event: SignalEvent::SessionSuspended,
            occurred_at: clock::now(),
        })
        .unwrap()
    }

    /// A signal kept in its job reads back under the same id, so every try
    /// carries the same token id and the receiver drops a repeat.
    #[test]
    fn a_signal_job_reads_back_the_same_signal() {
        let queue = Arc::new(FakeJobQueue::new());
        let jobs = SignalJobs {
            queue: queue.clone(),
            attempts: NonZeroU32::new(5).unwrap(),
        };
        let signal = suspended_agent();

        block_on(jobs.queue(AuditRecordId::new(), SignalStreamId::new(), &signal)).unwrap();

        let job = queue.jobs_of(DISPATCH_SIGNAL_JOB).remove(0);
        let read = payload_of::<SignalJob>(&job).unwrap().signal().unwrap();
        assert_eq!(read.id(), signal.id());
        assert_eq!(read.event(), signal.event());
    }

    /// A push the receiver did not take is tried again on the backoff;
    /// one that was taken, held, or whose stream is gone, is done.
    #[test]
    fn only_a_failed_push_is_tried_again() {
        assert!(matches!(
            after_dispatch(Some(Dispatched::Failed)),
            Handled::Retry {
                when: RetryWhen::OnBackoff,
                ..
            }
        ));
        for done in [
            Some(Dispatched::Delivered),
            Some(Dispatched::Queued),
            Some(Dispatched::SwitchedOff),
            Some(Dispatched::Skipped),
            None,
        ] {
            assert_eq!(after_dispatch(done), Handled::Done);
        }
    }
}
