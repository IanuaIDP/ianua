//! Push pending: take a batch of what waits for one push subscription on
//! the bus and post each message to the subscription's endpoint, and say
//! whether more is to come.

use std::sync::Arc;

use ianua_domain::domains::messaging::delivery::{MessageFate, SubscriptionDelivery};
use ianua_domain::domains::messaging::subscription::Subscription;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::MessageSubscriptionId;
use time::Duration;

use crate::error::{AppError, OrInternal};
use crate::ports::messaging::{
    ConsumerRead, MessageConsumer, PendingMessage, SubscriptionStore, TopicStore,
};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::messaging::broker::{PushMessageRequest, PushMessageUseCase, PushReport};
use crate::use_cases::messaging::bus::consumer_name;
use crate::use_cases::messaging::lookup::{existing_named_topic, existing_subscription};

/// The most messages one run posts.
const BATCH: usize = 100;

/// The ports [`PushPendingUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PushPendingPorts {
    /// Where subscriptions are kept.
    pub subscription_store: Arc<dyn SubscriptionStore>,
    /// The topics, whose retention is read as it stands now.
    pub topic_store: Arc<dyn TopicStore>,
    /// The bus the messages wait on.
    pub message_consumer: Arc<dyn MessageConsumer>,
    /// Posts one message and settles it.
    pub push: Arc<PushMessageUseCase>,
}

/// Which push subscription to post the waiting messages of.
pub struct PushPendingRequest {
    /// The push destination whose backlog should be drained.
    pub subscription_id: MessageSubscriptionId,
}

/// Whether more is to be posted after a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushNext {
    /// Nothing waits that this run did not settle.
    Drained,
    /// Run again once this has passed: a post failed and its message comes
    /// round again after its deadline, or a full batch left more waiting.
    Again {
        /// How long to wait.
        after: Duration,
    },
}

/// Posts the messages waiting for one push subscription.
pub struct PushPendingUseCase {
    ports: PushPendingPorts,
}

impl PushPendingUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: PushPendingPorts) -> Self {
        Self { ports }
    }

    /// A batch of what waits for `sub` and its topic still keeps.
    async fn waiting(
        &self,
        tenant: &ScopedTenant,
        sub: &Subscription<ResolvedTenant>,
    ) -> Result<Vec<PendingMessage>, AppError> {
        let topic =
            existing_named_topic(self.ports.topic_store.as_ref(), tenant, sub.topic_name()).await?;
        let name = consumer_name(sub);
        let read = ConsumerRead {
            topic_name: sub.topic_name(),
            consumer_name: &name,
            retention: topic.retention(),
        };
        self.ports
            .message_consumer
            .fetch_pending(tenant, read, BATCH)
            .await
            .or_internal()
    }
}

impl Query for PushPendingUseCase {
    type Caller = ScopedTenant;
    type Input = PushPendingRequest;
    type Output = Result<PushNext, AppError>;

    /// Takes up to a batch of the messages waiting for the subscription
    /// and posts each, as [`PushMessageUseCase`] does. What the topic's
    /// retention no longer keeps is not handed out. A paused or pulled
    /// subscription posts nothing. Settling changes no record of the
    /// tenant's, so nothing is put on record.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the tenant has no such subscription or
    ///   its topic is gone.
    /// - `AppError::Internal` on storage, secret or bus failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        request: PushPendingRequest,
    ) -> Result<PushNext, AppError> {
        let store = self.ports.subscription_store.as_ref();
        let sub = existing_subscription(store, tenant, &request.subscription_id).await?;
        let SubscriptionDelivery::Push(_) = sub.delivery() else {
            return Ok(PushNext::Drained);
        };
        if !sub.is_active() {
            return Ok(PushNext::Drained);
        }
        let pending = self.waiting(tenant, &sub).await?;
        let mut reports = Vec::with_capacity(pending.len());
        for message in pending {
            let pushed = PushMessageRequest {
                subscription_id: request.subscription_id,
                message,
            };
            reports.push(self.ports.push.execute(tenant, pushed).await?);
        }
        let deadline = sub.ack_policy().ack_deadline().duration();
        Ok(next_after(&reports, deadline))
    }
}

/// What follows a run whose posts came out as `reports`: a failed post's
/// message comes round again after `deadline`, and a full batch may have
/// left more waiting.
fn next_after(reports: &[PushReport], deadline: Duration) -> PushNext {
    if reports.contains(&PushReport::Failed(MessageFate::Redeliver)) {
        return PushNext::Again { after: deadline };
    }
    if reports.len() >= BATCH {
        return PushNext::Again {
            after: Duration::ZERO,
        };
    }
    PushNext::Drained
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A post failed, and its message comes round after its thirty-second
    /// deadline. The next run waits that long.
    #[test]
    fn a_failed_post_runs_again_after_its_deadline() {
        let reports = [
            PushReport::Taken,
            PushReport::Failed(MessageFate::Redeliver),
        ];

        let next = next_after(&reports, Duration::seconds(30));

        assert_eq!(
            next,
            PushNext::Again {
                after: Duration::seconds(30)
            }
        );
    }

    /// A full batch was posted, so more may wait: the next run follows at
    /// once. A short batch drained what waited.
    #[test]
    fn a_full_batch_runs_again_at_once_and_a_short_one_is_drained() {
        let full = vec![PushReport::Taken; BATCH];

        assert_eq!(
            next_after(&full, Duration::seconds(30)),
            PushNext::Again {
                after: Duration::ZERO
            }
        );
        assert_eq!(
            next_after(&[PushReport::Taken], Duration::seconds(30)),
            PushNext::Drained
        );
    }

    /// A message whose deliveries ran out was set aside, not failed: it is
    /// not waited on again.
    #[test]
    fn a_message_set_aside_is_not_waited_on() {
        let reports = [PushReport::Failed(MessageFate::DeadLetter)];

        assert_eq!(
            next_after(&reports, Duration::seconds(30)),
            PushNext::Drained
        );
    }
}
