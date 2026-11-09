//! Plan pushes: a message published to a topic, a subscription resumed or
//! a dead letter replayed becomes one push job for each of the topic's
//! push subscriptions, keyed by the event and the subscription, so a
//! repeated delivery of the event plans nothing twice.
//!
//! The bus keeps each subscription's messages and their deliveries; a job
//! posts what waits for its subscription when it runs.

use std::sync::Arc;

use ianua_domain::domains::messaging::delivery::SubscriptionDelivery;
use ianua_domain::domains::messaging::subscription::Subscription;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::event_type::{EventType, MessagingEvent};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest, SortOrder};
use crate::ports::messaging::SubscriptionStore;
use crate::ports::shared::PublishedEvent;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::messaging::broker::pushing::job::PushJobs;
use crate::use_cases::scheduling::PlanReport;

/// How many of a topic's subscriptions are read at a time.
const PAGE: u32 = 200;

/// The ports [`PlanPushesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PlanPushesPorts {
    /// Where subscriptions are kept.
    pub subscription_store: Arc<dyn SubscriptionStore>,
    /// Where push jobs are queued.
    pub jobs: PushJobs,
}

/// Plans the push jobs a messaging event means.
///
/// The event pipeline runs it, for nobody, so its caller is `()`.
pub struct PlanPushesUseCase {
    ports: PlanPushesPorts,
}

impl PlanPushesUseCase {
    /// A planner over `ports`.
    #[must_use]
    pub fn new(ports: PlanPushesPorts) -> Self {
        Self { ports }
    }

    /// The active push subscriptions to `topic`, read a page at a time.
    async fn pushed_to(
        &self,
        tenant: &ScopedTenant,
        topic: &TopicName,
    ) -> Result<Vec<Subscription<ResolvedTenant>>, AppError> {
        let store = self.ports.subscription_store.as_ref();
        let sort = SortOrder::default();
        let mut pushed = Vec::new();
        let mut next = Some(PageRequest::first(Limit::internal(PAGE)));
        while let Some(asked) = next.take() {
            let page = store
                .list_by_topic(tenant, topic, &sort, &asked)
                .await
                .or_internal()?;
            next = asked.following(&page);
            pushed.extend(page.items.into_iter().filter(is_pushed));
        }
        Ok(pushed)
    }
}

impl Command for PlanPushesUseCase {
    type Caller = ();
    type Input = PublishedEvent;
    type Output = Result<PlanReport, AppError>;

    /// Queues one push job for each active push subscription to the topic
    /// `event` names, when it is a publication, a resumed subscription or a
    /// replayed dead letter. Any other event plans nothing. Records
    /// nothing: planning only queues work.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the subscriptions cannot be read or a
    ///   job cannot be queued. The pipeline delivers the event again, and
    ///   what was queued is not queued twice.
    async fn execute(
        &self,
        (): &(),
        _auditor: &RequestAuditor,
        event: PublishedEvent,
    ) -> Result<PlanReport, AppError> {
        let (Some(tenant_id), Some(topic)) =
            (event.event.tenant_id().copied(), topic_of(&event.event))
        else {
            return Ok(PlanReport::default());
        };
        let tenant = ScopedTenant::for_background(tenant_id);
        let mut report = PlanReport::default();
        for sub in self.pushed_to(&tenant, &topic).await? {
            let enqueued = self
                .ports
                .jobs
                .queue(event.id, tenant_id, *sub.id())
                .await?;
            report = report.counting(enqueued);
        }
        Ok(report)
    }
}

/// Whether `sub` is pushed to now: it pushes, and it is not paused.
fn is_pushed(sub: &Subscription<ResolvedTenant>) -> bool {
    sub.is_active() && matches!(sub.delivery(), SubscriptionDelivery::Push(_))
}

/// The topic `event` names, when it is one that leaves messages waiting to
/// be pushed.
fn topic_of(event: &DomainEvent) -> Option<TopicName> {
    let EventType::Messaging(
        MessagingEvent::MessagePublished
        | MessagingEvent::SubscriptionResumed
        | MessagingEvent::DeadLetterReplayed,
    ) = event.event_type()
    else {
        return None;
    };
    TopicName::new(event.payload().get("topic_name")?).ok()
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::test_support::events::{sample_message_published, sample_tenant_event};
    use ianua_domain::types::AuditRecordId;

    use super::*;
    use crate::test_support::consumers::billing_sync;
    use crate::test_support::messaging::{
        FakeSubscriptionStore, push_subscription_of, subscription_of, topic_named,
    };
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::messaging::broker::pushing::job::PUSH_MESSAGES_JOB;

    struct Setup {
        uc: PlanPushesUseCase,
        queue: Arc<FakeJobQueue>,
    }

    /// `orders.created` with one push and one pull subscription.
    fn setup() -> Setup {
        let topic = topic_named("orders.created");
        let service = billing_sync();
        let store = FakeSubscriptionStore::of_test_tenant([
            push_subscription_of(&service, &topic),
            subscription_of(&service, &topic),
        ]);
        let queue = Arc::new(FakeJobQueue::new());
        let uc = PlanPushesUseCase::new(PlanPushesPorts {
            subscription_store: store,
            jobs: PushJobs {
                queue: queue.clone(),
                attempts: NonZeroU32::new(20).unwrap(),
            },
        });
        Setup { uc, queue }
    }

    fn published(id: AuditRecordId) -> PublishedEvent {
        PublishedEvent {
            id,
            event: sample_message_published(test_ctx().tenant_id(), "orders.created"),
            context: AuditContext::system(),
        }
    }

    fn plan(setup: &Setup, event: PublishedEvent) -> PlanReport {
        block_on(setup.uc.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            event,
        ))
        .unwrap()
    }

    /// A message is published to `orders.created`. The push subscription
    /// gets a job; the pulled one gets none, since its service fetches.
    #[test]
    fn each_push_subscription_to_the_topic_gets_one_job() {
        let setup = setup();

        let report = plan(&setup, published(AuditRecordId::new()));

        assert_eq!(report.queued, 1);
        assert_eq!(setup.queue.jobs_of(PUSH_MESSAGES_JOB).len(), 1);
    }

    /// The pipeline delivers the publication twice. The second planning
    /// queues nothing.
    #[test]
    fn a_repeated_event_plans_nothing_twice() {
        let setup = setup();
        let id = AuditRecordId::new();

        plan(&setup, published(id));
        let second = plan(&setup, published(id));

        assert_eq!((second.queued, second.already_queued), (0, 1));
    }

    /// A topic was paused: nothing waits to be pushed, so nothing is
    /// planned.
    #[test]
    fn an_event_leaving_nothing_to_push_plans_nothing() {
        let setup = setup();
        let event = PublishedEvent {
            id: AuditRecordId::new(),
            event: sample_tenant_event(test_ctx().tenant_id()),
            context: AuditContext::system(),
        };

        assert_eq!(plan(&setup, event), PlanReport::default());
    }
}
