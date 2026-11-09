//! The job that posts what waits for one push subscription: queued by the
//! planning of a publication, and run again while messages come round or
//! more wait.

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_key::KeyHold;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AuditRecordId, MessageSubscriptionId, TenantId};

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::scheduling::{Enqueued, JobQueue};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query as _;
use crate::use_cases::messaging::broker::pushing::pending::{
    PushNext, PushPendingRequest, PushPendingUseCase,
};
use crate::use_cases::scheduling::{
    Handled, JobHandler, NewJob, RetryWhen, key_of, payload_of, unless_gone,
};

/// The job type that posts a push subscription's waiting messages.
pub const PUSH_MESSAGES_JOB: &str = "messaging.push";

/// Why a push job runs again.
const MORE_TO_POST: &str = "messages still wait for the endpoint";

/// What a push job carries: which subscription of which tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct PushJob {
    tenant_id: TenantId,
    subscription_id: MessageSubscriptionId,
}

/// Where push jobs are queued, and how many runs each gets.
#[derive(Clone)]
pub struct PushJobs {
    /// Persists deliveries for workers to drain push backlogs.
    pub queue: Arc<dyn JobQueue>,
    /// Runs a push job gets. A long backlog is drained over them and over
    /// the jobs later publications plan.
    pub attempts: NonZeroU32,
}

impl PushJobs {
    /// Queues the job posting what waits for `subscription_id` of
    /// `tenant_id`, once for the event `event_id` and the subscription.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub(crate) async fn queue(
        &self,
        event_id: AuditRecordId,
        tenant_id: TenantId,
        subscription_id: MessageSubscriptionId,
    ) -> Result<Enqueued, AppError> {
        NewJob {
            job_type: PUSH_MESSAGES_JOB,
            payload: &PushJob {
                tenant_id,
                subscription_id,
            },
            tenant_id,
            key: key_of(event_id, subscription_id)?,
            hold: KeyHold::WhileKept,
            run_at: clock::now(),
            attempts: self.attempts,
        }
        .queue(self.queue.as_ref())
        .await
    }
}

/// Runs push jobs through [`PushPendingUseCase`].
pub struct PushMessagesHandler {
    job_type: JobType,
    push: Arc<PushPendingUseCase>,
}

impl PushMessagesHandler {
    /// A handler posting through `push`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(push: Arc<PushPendingUseCase>) -> Result<Self, DomainError> {
        let job_type = JobType::new(PUSH_MESSAGES_JOB)?;
        Ok(Self { job_type, push })
    }
}

#[async_trait]
impl JobHandler for PushMessagesHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Posts a batch of what waits. A post that failed runs again once its
    /// message comes round, a full batch runs again at once, and a
    /// subscription that is gone is done with. Settling changes no record,
    /// so `_auditor` is not used.
    async fn handle(
        &self,
        job: &ScheduledJob,
        _auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let payload: PushJob = payload_of(job)?;
        let tenant = ScopedTenant::for_background(payload.tenant_id);
        let request = PushPendingRequest {
            subscription_id: payload.subscription_id,
        };
        let next = unless_gone(self.push.execute(&tenant, request).await)?;
        Ok(after_pushing(next))
    }
}

/// What a run that left `next` leaves to do.
fn after_pushing(next: Option<PushNext>) -> Handled {
    match next {
        Some(PushNext::Again { after }) => Handled::Retry {
            reason: MORE_TO_POST,
            when: RetryWhen::After(after),
        },
        Some(PushNext::Drained) | None => Handled::Done,
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;

    /// A post failed and its message comes round in thirty seconds. The job
    /// runs again then.
    #[test]
    fn a_run_leaving_work_runs_again_when_it_says() {
        let next = Some(PushNext::Again {
            after: Duration::seconds(30),
        });

        assert_eq!(
            after_pushing(next),
            Handled::Retry {
                reason: MORE_TO_POST,
                when: RetryWhen::After(Duration::seconds(30)),
            }
        );
    }

    /// Everything waiting was posted, or the subscription is gone. The job
    /// is done.
    #[test]
    fn a_drained_or_gone_subscription_is_done() {
        assert_eq!(after_pushing(Some(PushNext::Drained)), Handled::Done);
        assert_eq!(after_pushing(None), Handled::Done);
    }
}
