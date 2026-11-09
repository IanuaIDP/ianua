//! The job that sends one event to one webhook: queued by the planning of
//! the event, its message kept beside it, and tried again when the
//! subscription's retry policy says.
//!
//! Each try of the job is a try of the delivery: the job's attempt number
//! is the delivery's, so the receiver and the delivery history see the same
//! count.

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_key::KeyHold;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::domains::webhooks::subscription::WebhookSubscription;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AuditRecordId, TenantId, WebhookMessageId, WebhookSubscriptionId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::scheduling::{Enqueued, JobQueue};
use crate::ports::webhooks::WebhookStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command as _;
use crate::use_cases::scheduling::{
    Handled, JobHandler, NewJob, RetryWhen, key_of, payload_of, unless_gone,
};
use crate::use_cases::webhooks::delivery::{
    DeliverWebhookRequest, DeliverWebhookUseCase, DeliveryReport, NextTry,
};

/// The job type that sends an event to a webhook.
pub const DELIVER_WEBHOOK_JOB: &str = "webhooks.deliver";

/// Tries a delivery job gets beyond its policy's, for a store or the
/// platform failing under it rather than the endpoint.
const TRIES_FOR_ERRORS: u32 = 3;

/// Why a delivery job runs again.
const NOT_TAKEN: &str = "the endpoint did not take the event";

/// What a delivery job carries: the subscription and the message kept for
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct WebhookJob {
    tenant_id: TenantId,
    subscription_id: WebhookSubscriptionId,
    message_id: WebhookMessageId,
}

/// Where delivery jobs are queued.
#[derive(Clone)]
pub struct WebhookJobs {
    /// Persists work for workers to deliver webhook messages.
    pub queue: Arc<dyn JobQueue>,
}

impl WebhookJobs {
    /// Queues the job sending the message `message_id`, which the event
    /// `event_id` became, to `subscription`, once for that event and
    /// subscription. It gets as many tries as the subscription's policy
    /// allows, and a few more for errors of the platform's own.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub(crate) async fn queue(
        &self,
        event_id: AuditRecordId,
        tenant_id: TenantId,
        subscription: &WebhookSubscription<ResolvedTenant>,
        message_id: WebhookMessageId,
    ) -> Result<Enqueued, AppError> {
        let tries = u32::from(subscription.retry().policy().max_retries())
            .saturating_add(1)
            .saturating_add(TRIES_FOR_ERRORS);
        NewJob {
            job_type: DELIVER_WEBHOOK_JOB,
            payload: &WebhookJob {
                tenant_id,
                subscription_id: *subscription.id(),
                message_id,
            },
            tenant_id,
            key: key_of(event_id, subscription.id())?,
            hold: KeyHold::WhileKept,
            run_at: clock::now(),
            attempts: NonZeroU32::new(tries).unwrap_or(NonZeroU32::MIN),
        }
        .queue(self.queue.as_ref())
        .await
    }
}

/// Runs delivery jobs through [`DeliverWebhookUseCase`].
pub struct DeliverWebhookHandler {
    job_type: JobType,
    deliver: Arc<DeliverWebhookUseCase>,
    messages: Arc<dyn WebhookStore>,
}

impl DeliverWebhookHandler {
    /// A handler delivering through `deliver`, reading the kept message
    /// from `messages`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(
        deliver: Arc<DeliverWebhookUseCase>,
        messages: Arc<dyn WebhookStore>,
    ) -> Result<Self, DomainError> {
        let job_type = JobType::new(DELIVER_WEBHOOK_JOB)?;
        Ok(Self {
            job_type,
            deliver,
            messages,
        })
    }
}

#[async_trait]
impl JobHandler for DeliverWebhookHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Sends the kept message as the job's try. A failure the policy
    /// retries runs again after the policy's wait; a subscription or
    /// message that is gone, or no longer takes the event, is done with.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let payload: WebhookJob = payload_of(job)?;
        let tenant = ScopedTenant::for_background(payload.tenant_id);
        let found = self
            .messages
            .find_message(&tenant, &payload.subscription_id, &payload.message_id)
            .await
            .or_internal()?;
        let Some(message) = found else {
            return Ok(Handled::Done);
        };
        let request = DeliverWebhookRequest {
            message,
            attempt_number: try_number(job),
        };
        let auditor = auditor.with_tenant(payload.tenant_id);
        let report = unless_gone(self.deliver.execute(&tenant, &auditor, request).await)?;
        Ok(after_delivery(report.flatten()))
    }
}

/// The delivery try `job` makes: the first is 0.
fn try_number(job: &ScheduledJob) -> u8 {
    u8::try_from(job.attempt().saturating_sub(1)).unwrap_or(u8::MAX)
}

/// What a delivery that came out as `report` leaves to do.
fn after_delivery(report: Option<DeliveryReport>) -> Handled {
    match report.map(|report| report.next) {
        Some(NextTry::Retry { after, .. }) => Handled::Retry {
            reason: NOT_TAKEN,
            when: RetryWhen::After(after.duration()),
        },
        Some(NextTry::Done) | None => Handled::Done,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::webhooks::subscription_status::WebhookSubscriptionStatus;
    use ianua_domain::types::Seconds;

    use super::*;
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::webhooks::{
        FakeWebhookStore, test_attempt, test_message, test_subscription,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::webhooks::delivery::DeliverWebhookPorts;

    /// Ann's webhook keeps the standard policy of five retries. Its job is
    /// tried as often, once for the first try and a few more for errors of
    /// the platform's own.
    #[test]
    fn a_delivery_job_is_tried_as_often_as_its_policy_and_a_few_more() {
        let queue = Arc::new(FakeJobQueue::new());
        let jobs = WebhookJobs {
            queue: queue.clone(),
        };
        let subscription = test_subscription(
            "https://hooks.acme.com/events",
            WebhookSubscriptionStatus::Active,
        );
        let retries = u32::from(subscription.retry().policy().max_retries());

        block_on(jobs.queue(
            AuditRecordId::new(),
            TenantId::new(),
            &subscription,
            WebhookMessageId::new(),
        ))
        .unwrap();

        let job = queue.jobs_of(DELIVER_WEBHOOK_JOB).remove(0);
        assert_eq!(job.max_attempts().get(), retries + 1 + TRIES_FOR_ERRORS);
    }

    /// Ann's endpoint answered 503 and her policy says to try again in ten
    /// seconds. The job runs again then, not on the queue's own backoff.
    #[test]
    fn a_retry_the_policy_asks_for_runs_after_its_wait() {
        let message = test_message(WebhookSubscriptionId::new());
        let report = DeliveryReport {
            attempt: test_attempt(&message, 503),
            next: NextTry::Retry {
                attempt_number: 1,
                after: Seconds::new(10),
            },
        };

        assert_eq!(
            after_delivery(Some(report)),
            Handled::Retry {
                reason: NOT_TAKEN,
                when: RetryWhen::After(time::Duration::seconds(10)),
            }
        );
    }

    /// A delivery that got through, or that the subscription no longer
    /// takes, leaves nothing to do.
    #[test]
    fn a_delivery_with_no_next_try_is_done() {
        let message = test_message(WebhookSubscriptionId::new());
        let report = DeliveryReport {
            attempt: test_attempt(&message, 200),
            next: NextTry::Done,
        };

        assert_eq!(after_delivery(Some(report)), Handled::Done);
        assert_eq!(after_delivery(None), Handled::Done);
    }

    /// Ann deleted her webhook while its delivery waited, and its messages
    /// went with it. The job is done, not failed again and again.
    #[test]
    fn a_job_whose_message_is_gone_is_done() {
        let queue = Arc::new(FakeJobQueue::new());
        let subscription = test_subscription(
            "https://hooks.acme.com/events",
            WebhookSubscriptionStatus::Active,
        );
        let jobs = WebhookJobs {
            queue: queue.clone(),
        };
        block_on(jobs.queue(
            AuditRecordId::new(),
            TenantId::new(),
            &subscription,
            WebhookMessageId::new(),
        ))
        .unwrap();
        let job = queue.jobs_of(DELIVER_WEBHOOK_JOB).remove(0);
        let handler = DeliverWebhookHandler::new(
            Arc::new(DeliverWebhookUseCase::new(DeliverWebhookPorts::fakes())),
            Arc::new(FakeWebhookStore::empty()),
        )
        .unwrap();

        let handled =
            block_on(handler.handle(&job, &test_auditor(Arc::new(FakeEventDispatcher::new()))))
                .unwrap();

        assert_eq!(handled, Handled::Done);
    }
}
