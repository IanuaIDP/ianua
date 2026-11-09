//! Plan webhooks: a recorded event becomes one delivery job per active
//! subscription that lists it, keyed by the event and the subscription, so
//! a repeated delivery of the event plans nothing twice.
//!
//! Each subscription is given its own message, under an id every try of it
//! carries, kept with its job in one unit: a job never waits on a message
//! that was not kept, and a message is never kept for a job that was not
//! queued. Whether the creator may still see the event is decided when the
//! job runs, not here.

use std::sync::Arc;

use ianua_domain::domains::webhooks::subscription::WebhookSubscription;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::WebhookMessageId;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::scheduling::Enqueued;
use crate::ports::shared::PublishedEvent;
use crate::ports::webhooks::{WebhookBodies, WebhookMessage, WebhookStore};
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::scheduling::PlanReport;
use crate::use_cases::webhooks::delivery::job::WebhookJobs;

/// The ports [`PlanUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PlanPorts {
    /// Where subscriptions and their messages are kept.
    pub webhook_store: Arc<dyn WebhookStore>,
    /// Writes the body the event is sent as.
    pub bodies: Arc<dyn WebhookBodies>,
    /// Where delivery jobs are queued.
    pub jobs: WebhookJobs,
    /// Keeps each job and its message together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Plans the webhook deliveries a recorded event means.
///
/// The event pipeline runs it, for nobody, so its caller is `()`.
pub struct PlanUseCase {
    ports: PlanPorts,
}

/// One delivery to plan: the event, the subscription and the message made
/// for it.
struct Planned<'a> {
    event: &'a PublishedEvent,
    tenant: &'a ScopedTenant,
    subscription: &'a WebhookSubscription<ResolvedTenant>,
    message: WebhookMessage,
}

impl PlanUseCase {
    /// A planner over `ports`.
    #[must_use]
    pub fn new(ports: PlanPorts) -> Self {
        Self { ports }
    }

    /// Queues one delivery of `event`, with the body `body`, to each of
    /// `subscriptions`, each job and its message kept together.
    async fn queued_for_each(
        &self,
        event: &PublishedEvent,
        tenant: &ScopedTenant,
        subscriptions: &[WebhookSubscription<ResolvedTenant>],
        body: &[u8],
    ) -> Result<PlanReport, AppError> {
        let mut report = PlanReport::default();
        for subscription in subscriptions {
            let planned = Planned {
                event,
                tenant,
                subscription,
                message: WebhookMessage {
                    id: WebhookMessageId::new(),
                    subscription_id: *subscription.id(),
                    event_type: event.event.event_type(),
                    payload: body.to_vec(),
                },
            };
            let unit = self.ports.unit_of_work.as_ref();
            let enqueued = kept_together(unit, self.queued(planned)).await?;
            report = report.counting(enqueued);
        }
        Ok(report)
    }

    /// Queues `planned`'s job and, when it was queued now, keeps its
    /// message.
    async fn queued(&self, planned: Planned<'_>) -> Result<Enqueued, AppError> {
        let enqueued = self
            .ports
            .jobs
            .queue(
                planned.event.id,
                **planned.tenant,
                planned.subscription,
                planned.message.id,
            )
            .await?;
        if enqueued == Enqueued::AlreadyQueued {
            return Ok(enqueued);
        }
        self.ports
            .webhook_store
            .keep_message(planned.tenant, &planned.message)
            .await
            .or_internal()?;
        Ok(enqueued)
    }
}

impl Command for PlanUseCase {
    type Caller = ();
    type Input = PublishedEvent;
    type Output = Result<PlanReport, AppError>;

    /// Queues one delivery job for each of the tenant's active
    /// subscriptions that list `event`'s type, each with its message kept.
    /// An event of no tenant, or one no subscription lists, plans nothing.
    /// Records nothing: planning only queues work, and each delivery
    /// records its attempt.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the subscriptions cannot be read, the
    ///   body cannot be written, or a job or its message cannot be kept.
    ///   The pipeline delivers the event again, and what was planned is not
    ///   planned twice.
    async fn execute(
        &self,
        (): &(),
        _auditor: &RequestAuditor,
        event: PublishedEvent,
    ) -> Result<PlanReport, AppError> {
        let Some(tenant_id) = event.event.tenant_id().copied() else {
            return Ok(PlanReport::default());
        };
        let tenant = ScopedTenant::for_background(tenant_id);
        let event_type = event.event.event_type();
        let subscriptions = self
            .ports
            .webhook_store
            .list_receiving(&tenant, event_type)
            .await
            .or_internal()?;
        if subscriptions.is_empty() {
            return Ok(PlanReport::default());
        }
        let body = self.ports.bodies.body(&event).or_internal()?;
        self.queued_for_each(&event, &tenant, &subscriptions, &body)
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::webhooks::control::WebhookControl;
    use ianua_domain::domains::webhooks::subscription::WebhookUpdate;
    use ianua_domain::domains::webhooks::subscription_status::WebhookSubscriptionStatus;
    use ianua_domain::test_support::authority::anyone_holding;
    use ianua_domain::test_support::events::sample_tenant_event;
    use ianua_domain::types::AuditRecordId;
    use ianua_domain::types::event_type::{EventType, MessagingEvent};

    use super::*;
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::webhooks::{FakeWebhookStore, test_subscription};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::webhooks::delivery::job::DELIVER_WEBHOOK_JOB;

    struct Setup {
        uc: PlanUseCase,
        store: Arc<FakeWebhookStore>,
        queue: Arc<FakeJobQueue>,
    }

    /// Acme's webhooks in `statuses`, each listing paused topics.
    fn setup(statuses: &[WebhookSubscriptionStatus]) -> Setup {
        let store = Arc::new(FakeWebhookStore::empty());
        for status in statuses {
            let subscription = listing_paused_topics(*status);
            block_on(store.save(&test_ctx().tenant(), &subscription)).unwrap();
        }
        let queue = Arc::new(FakeJobQueue::new());
        let uc = PlanUseCase::new(PlanPorts {
            webhook_store: store.clone(),
            jobs: WebhookJobs {
                queue: queue.clone(),
            },
            ..PlanPorts::fakes()
        });
        Setup { uc, store, queue }
    }

    /// Ann's webhook in `status`, listing paused topics.
    fn listing_paused_topics(
        status: WebhookSubscriptionStatus,
    ) -> WebhookSubscription<ResolvedTenant> {
        let mut subscription = test_subscription("https://hooks.acme.com/events", status);
        let control = WebhookControl::new(anyone_holding(SystemPermission::all()));
        let update = WebhookUpdate {
            url: None,
            event_types: Some(vec![EventType::from(MessagingEvent::TopicPaused)]),
            description: None,
            retry: None,
        };
        subscription.update(update, &control).unwrap();
        subscription
    }

    /// A topic of Acme's was paused, recorded under `id`.
    fn topic_paused(id: AuditRecordId) -> PublishedEvent {
        PublishedEvent {
            id,
            event: sample_tenant_event(test_ctx().tenant_id()),
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

    /// A topic is paused, and Acme has two active webhooks listing that and
    /// a paused one. Each active one gets a job and a kept message; the
    /// paused one gets nothing.
    #[test]
    fn each_active_subscription_listing_the_event_gets_one_job() {
        let setup = setup(&[
            WebhookSubscriptionStatus::Active,
            WebhookSubscriptionStatus::Active,
            WebhookSubscriptionStatus::Paused,
        ]);

        let report = plan(&setup, topic_paused(AuditRecordId::new()));

        assert_eq!(report.queued, 2);
        assert_eq!(setup.queue.jobs_of(DELIVER_WEBHOOK_JOB).len(), 2);
        assert_eq!(setup.store.messages.lock().unwrap().len(), 2);
    }

    /// The pipeline delivers the same event twice. The second planning
    /// queues nothing and keeps no second message.
    #[test]
    fn a_repeated_event_plans_nothing_twice() {
        let setup = setup(&[WebhookSubscriptionStatus::Active]);
        let id = AuditRecordId::new();

        plan(&setup, topic_paused(id));
        let second = plan(&setup, topic_paused(id));

        assert_eq!((second.queued, second.already_queued), (0, 1));
        assert_eq!(setup.store.messages.lock().unwrap().len(), 1);
    }

    /// No webhook of Acme's lists the event: nothing is planned.
    #[test]
    fn an_event_no_subscription_lists_plans_nothing() {
        let setup = setup(&[]);

        let report = plan(&setup, topic_paused(AuditRecordId::new()));

        assert_eq!(report, PlanReport::default());
    }
}
