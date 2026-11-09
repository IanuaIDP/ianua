//! The event consumers: one for each sink, each turning a published event
//! into the jobs it means, one job per target, and one for each monitor
//! acting on an event itself.
//!
//! Each consumer reads its own durable share of the events on the bus, so
//! it is handed every event at least once, whichever worker it lands on,
//! and an event handed to one worker is not handed to another unless the
//! first failed on it or stopped. An event is acted on only once its seal
//! holds. A planner queues each job under the event's id and the job's
//! target, and a monitor notes the event with what it changed, so an event
//! handed out twice queues and changes nothing twice.

mod monitors;
mod planners;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::auditor::RequestAuditor;
use ianua_app::error::AppError;
use ianua_app::ports::shared::PublishedEvent;
use ianua_app::use_case::Command;
use ianua_app::use_cases::notifications::{FanOutUseCase, RecordedEvent};
use ianua_boot::shutdown::Shutdown;
use ianua_infra::bus::{Bus, EventShare, Handed, HeardEvent, HeardEvents, SharedFeed, Unheard};

use crate::config::serving::worker::EventConfig;
use crate::error::ServerError;
use crate::worker::parts::Parts;

/// The subjects of the tenants' events, under the deployment's namespace.
const TENANT_EVENTS: &str = "tenant.>";

/// The subjects of the organizations' events, under the deployment's
/// namespace.
const ORGANIZATION_EVENTS: &str = "org.>";

/// The subjects of the platform's own events, under the deployment's
/// namespace.
const PLATFORM_EVENTS: &str = "platform.>";

/// The shortest pause before a consumer whose share could not be read, or
/// ended, reads it again, so a bus that is down is not asked in a loop.
const SHARE_PAUSE: Duration = Duration::from_secs(1);

/// The events a planner hears.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Hears {
    /// The tenants' events alone.
    Tenants,
    /// Every event: the tenants', the organizations' and the platform's.
    Everything,
}

/// One sink's planner, turning an event into the jobs it means.
#[async_trait]
pub(super) trait Planner: Send + Sync {
    /// What it is called, which names its share of the events on the bus;
    /// lowercase letters and `_` only, and never changed once deployed,
    /// or its share starts again from the events published after.
    fn name(&self) -> &'static str;

    /// The events it hears.
    fn hears(&self) -> Hears;

    /// Plans `event`'s jobs, and says what it came to, for the log.
    ///
    /// # Errors
    ///
    /// The [`AppError`] it failed with; the event is handed out again.
    async fn plan(
        &self,
        event: PublishedEvent,
        auditor: &RequestAuditor,
    ) -> Result<String, AppError>;
}

/// A planning use case as a [`Planner`].
pub(super) struct Planned<U> {
    name: &'static str,
    hears: Hears,
    use_case: U,
}

impl<U> Planned<U>
where
    Self: Planner + 'static,
{
    /// `use_case`, planning the events it `hears` under `name`.
    pub(super) fn of(name: &'static str, hears: Hears, use_case: U) -> Arc<dyn Planner> {
        Arc::new(Self {
            name,
            hears,
            use_case,
        })
    }
}

#[async_trait]
impl<U, T> Planner for Planned<U>
where
    U: Command<Caller = (), Input = PublishedEvent, Output = Result<T, AppError>> + Send + Sync,
    T: std::fmt::Debug + Send,
{
    fn name(&self) -> &'static str {
        self.name
    }

    fn hears(&self) -> Hears {
        self.hears
    }

    async fn plan(
        &self,
        event: PublishedEvent,
        auditor: &RequestAuditor,
    ) -> Result<String, AppError> {
        let came_to = self.use_case.execute(&(), auditor, event).await?;
        Ok(format!("{came_to:?}"))
    }
}

/// The notification fan-out as a [`Planner`]: it hears every event, since
/// organizations and operators are told about their own.
pub(super) struct Told(FanOutUseCase);

impl Told {
    /// `fan_out`, telling people about every event.
    pub(super) fn of(fan_out: FanOutUseCase) -> Arc<dyn Planner> {
        Arc::new(Self(fan_out))
    }
}

#[async_trait]
impl Planner for Told {
    fn name(&self) -> &'static str {
        "notifications"
    }

    fn hears(&self) -> Hears {
        Hears::Everything
    }

    async fn plan(
        &self,
        event: PublishedEvent,
        auditor: &RequestAuditor,
    ) -> Result<String, AppError> {
        let recorded = RecordedEvent {
            record_id: event.id,
            event: event.event,
            context: event.context,
        };
        let told = self.0.execute(&(), auditor, recorded).await?;
        Ok(format!("{told} told"))
    }
}

/// What becomes of an event handed to a consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// It is done with: its jobs are queued, or it means none.
    Done,
    /// It is handed out again after the retry delay.
    Again,
    /// It can never be acted on, and is not handed out again.
    SetAside,
}

/// What becomes of an event that could not be read back.
fn unheard(consumer: &'static str, why: &Unheard) -> Outcome {
    match why {
        Unheard::Unsealed => {
            tracing::warn!(consumer, "an event whose seal does not hold was set aside");
            Outcome::SetAside
        }
        Unheard::Unreadable(error) => {
            tracing::error!(consumer, %error, "an event that does not read was set aside");
            Outcome::SetAside
        }
        Unheard::Unread(error) => {
            tracing::warn!(consumer, %error, "an event's record could not be read; it comes again");
            Outcome::Again
        }
    }
}

/// What becomes of an event once its planner ran, or ran out of time.
fn planned(consumer: &'static str, ran: Option<Result<String, AppError>>) -> Outcome {
    let Some(ran) = ran else {
        tracing::warn!(
            consumer,
            "planning an event ran out of time; it comes again"
        );
        return Outcome::Again;
    };
    match ran {
        Ok(came_to) => {
            tracing::debug!(consumer, %came_to, "an event was planned");
            Outcome::Done
        }
        Err(error) if error.is_server_error() => {
            tracing::warn!(consumer, %error, "planning an event failed; it comes again");
            Outcome::Again
        }
        Err(error @ AppError::Conflict(_)) => {
            tracing::debug!(consumer, %error, "an event met a change under way; it comes again");
            Outcome::Again
        }
        Err(error) => {
            tracing::warn!(consumer, %error, "an event was refused by its planner; nothing is queued");
            Outcome::Done
        }
    }
}

/// The subjects a planner that `hears` reads.
fn subjects(hears: Hears) -> Vec<String> {
    let subjects: &[&str] = match hears {
        Hears::Tenants => &[TENANT_EVENTS],
        Hears::Everything => &[TENANT_EVENTS, ORGANIZATION_EVENTS, PLATFORM_EVENTS],
    };
    subjects
        .iter()
        .map(|subject| (*subject).to_owned())
        .collect()
}

/// The share of the events `planner` reads, the same on every worker of
/// the deployment. The bus server keeps it inside the namespace's own
/// events stream, so two deployments' workers never read one share.
fn share_of(planner: &dyn Planner, events: &EventConfig) -> EventShare {
    EventShare {
        name: format!("worker-{}", planner.name()),
        subjects: subjects(planner.hears()),
        max_deliver: events.max_deliver,
        ack_wait: events.ack_wait,
    }
}

/// Starts a consumer for every planner.
///
/// # Errors
///
/// [`ServerError`] when a planner cannot be built.
pub(super) fn start(parts: &Parts<'_>, shutdown: &Shutdown) -> Result<(), ServerError> {
    let platform = parts.platform;
    let events = parts.config.worker.events;
    let heard = Arc::new(HeardEvents::new(
        platform.keys.event_check.clone(),
        Arc::clone(&parts.recorded_events),
    ));
    let consumers = [planners::planners(parts), monitors::monitors(parts)?].concat();
    for planner in consumers {
        let consumer = Consumer {
            share: share_of(planner.as_ref(), &events),
            planner,
            heard: Arc::clone(&heard),
            bus: Arc::clone(&platform.bus),
            auditor: parts.system_auditor(),
            retry_delay: events.retry_delay,
        };
        shutdown.spawn(consumer.planner.name(), consumer.run(shutdown.clone()));
    }
    Ok(())
}

/// One sink's consumer: its planner over its share of the events.
struct Consumer {
    planner: Arc<dyn Planner>,
    heard: Arc<HeardEvents>,
    bus: Arc<dyn Bus>,
    share: EventShare,
    auditor: RequestAuditor,
    retry_delay: Duration,
}

impl Consumer {
    /// Reads the share until `shutdown` stops it, reading it again after a
    /// pause whenever it could not be read or the bus ended it.
    async fn run(self, shutdown: Shutdown) {
        let pause = self.retry_delay.max(SHARE_PAUSE);
        while !shutdown.is_stopping() {
            let shared = tokio::select! {
                () = shutdown.stopping() => return,
                shared = self.bus.share(&self.share) => shared,
            };
            match shared {
                Ok(feed) => self.read(feed, &shutdown).await,
                Err(error) => tracing::warn!(
                    consumer = self.planner.name(),
                    %error,
                    "the consumer's share of the events could not be read; it tries again"
                ),
            }
            tokio::select! {
                () = shutdown.stopping() => return,
                () = tokio::time::sleep(pause) => {}
            }
        }
    }

    /// Settles each event `feed` hands out until `shutdown` stops it or
    /// the feed ends. An event in hand when the stop comes is settled
    /// first.
    async fn read(&self, mut feed: Box<dyn SharedFeed>, shutdown: &Shutdown) {
        loop {
            let handed = tokio::select! {
                () = shutdown.stopping() => return,
                handed = feed.next() => handed,
            };
            let Some(handed) = handed else {
                return;
            };
            self.settle(handed).await;
        }
    }

    /// Plans `handed` and settles it by how that went. The last time it is
    /// handed out, a failure sets it aside, loudly, as the bus would.
    async fn settle(&self, handed: Handed) {
        let consumer = self.planner.name();
        let outcome = self.outcome(&handed.event).await;
        let settled = match (outcome, handed.last) {
            (Outcome::Done, _) => handed.acknowledge().await,
            (Outcome::SetAside, _) => handed.set_aside().await,
            (Outcome::Again, false) => handed.again_after(self.retry_delay).await,
            (Outcome::Again, true) => {
                tracing::error!(
                    consumer,
                    subject = %handed.event.subject,
                    delivery = handed.delivery,
                    "an event failed on its last delivery and was set aside; its jobs were not all queued"
                );
                handed.set_aside().await
            }
        };
        if let Err(error) = settled {
            tracing::warn!(consumer, %error, "an event could not be settled; the bus hands it out again");
        }
    }

    /// What becomes of `event`: read back, then planned, each step's
    /// failure told apart.
    async fn outcome(&self, event: &HeardEvent) -> Outcome {
        let consumer = self.planner.name();
        let published = match self.heard.published(event).await {
            Ok(Some(published)) => published,
            Ok(None) => return Outcome::Done,
            Err(why) => return unheard(consumer, &why),
        };
        let ran = tokio::time::timeout(
            self.share.ack_wait.saturating_sub(self.share.ack_wait / 5),
            self.planner.plan(published, &self.auditor),
        )
        .await
        .ok();
        planned(consumer, ran)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_app::test_support::scheduling::FakeJobQueue;
    use ianua_app::test_support::tenant::{
        FakeAuditStreamStore, FakeRecordedEvents, test_audit_record, test_audit_stream,
    };
    use ianua_app::test_support::{FakeEventDispatcher, FakeEventReactions, RecordingUnitOfWork};
    use ianua_app::use_cases::agents::intent::{
        HearEgressDenialUseCase, HeardPorts, RespondToEgressDenialPorts,
        RespondToEgressDenialUseCase,
    };
    use ianua_app::use_cases::audit::{PlanStreamsPorts, PlanStreamsUseCase, StreamJobs};
    use ianua_domain::domains::audit::record::AuditRecord;
    use ianua_domain::domains::audit::streaming::StreamFilter;
    use ianua_domain::shared::events::data::EventData;
    use ianua_domain::types::{AgentId, DelegationId, EventType, TenantId};
    use ianua_infra::bus::{EventEnvelope, EventScope, MemoryBus, SealedEvent};
    use ianua_infra::crypto::{EventCheck, EventSeal, RootSecret};

    use super::*;

    const SIGNED_IN: &str = "authentication.login_succeeded";

    fn root(byte: u8) -> RootSecret {
        RootSecret::parse(&format!("{byte:064x}")).unwrap()
    }

    fn control_plane() -> EventSeal {
        EventSeal::control_plane(&root(2))
    }

    struct Fixture {
        consumer: Consumer,
        bus: Arc<MemoryBus>,
        queue: Arc<FakeJobQueue>,
        record: AuditRecord,
    }

    /// A consumer of Acme's audit streams, Splunk and Datadog both taking
    /// sign-ins, over a bus in memory, with Acme's sign-in on the trail.
    fn fixture(ack_wait: Duration) -> Fixture {
        let tenant = TenantId::new();
        let record = test_audit_record(tenant, SIGNED_IN);
        let streams = audit_streams(tenant);
        let queue = Arc::new(FakeJobQueue::new());
        let planner = stream_planner(streams, &queue);
        let bus = Arc::new(MemoryBus::new(100));
        let share = test_share("worker-audit_streams", ack_wait);
        Fixture {
            consumer: Consumer {
                heard: Arc::new(HeardEvents::new(
                    EventCheck::new(control_plane(), EventSeal::data_plane(&root(1))),
                    Arc::new(FakeRecordedEvents::holding([record.clone()])),
                )),
                bus: Arc::clone(&bus) as _,
                auditor: RequestAuditor::system(Arc::new(FakeEventDispatcher::new())),
                retry_delay: Duration::ZERO,
                planner,
                share,
            },
            bus,
            queue,
            record,
        }
    }

    /// Gives Acme two destinations subscribed to the same sign-in event.
    fn audit_streams(tenant: TenantId) -> FakeAuditStreamStore {
        let sign_ins = || StreamFilter::only(vec![EventType::parse(SIGNED_IN).unwrap()]).unwrap();
        FakeAuditStreamStore::holding(
            tenant,
            [
                test_audit_stream("splunk", sign_ins()),
                test_audit_stream("datadog", sign_ins()),
            ],
        )
    }

    /// Plans the fixture's stream deliveries on its observable in-memory queue.
    fn stream_planner(
        streams: FakeAuditStreamStore,
        queue: &Arc<FakeJobQueue>,
    ) -> Arc<dyn Planner> {
        Planned::of(
            "audit_streams",
            Hears::Tenants,
            PlanStreamsUseCase::new(PlanStreamsPorts {
                stream_store: Arc::new(streams),
                jobs: StreamJobs {
                    queue: Arc::clone(queue) as _,
                    attempts: NonZeroU32::MIN,
                },
            }),
        )
    }

    /// Configures a durable tenant-event share with the test's acknowledgement deadline.
    fn test_share(name: &str, ack_wait: Duration) -> EventShare {
        EventShare {
            name: name.to_owned(),
            subjects: subjects(Hears::Tenants),
            max_deliver: 5,
            ack_wait,
        }
    }

    /// Publishes `record`'s event on the bus as the relay does.
    async fn relayed(bus: &MemoryBus, record: &AuditRecord, seal: &EventSeal) {
        let tenant = record.scope.tenant_id().unwrap();
        let envelope = EventEnvelope {
            id: *record.id.as_uuid(),
            scope: EventScope::Tenant(*tenant.as_uuid()),
            organization_id: None,
            event_type: record.event_type.to_string(),
            actor: record.actor.audit_label(),
            payload: serde_json::Value::Null,
            occurred_at: record.occurred_at,
            chain_depth: 0,
        };
        let payload = serde_json::to_vec(&envelope).unwrap();
        let subject = envelope.subject();
        bus.publish(&SealedEvent {
            subject: &subject,
            id: &envelope.id.to_string(),
            payload: &payload,
            seal: &seal.seal(&subject, &payload),
        })
        .await
        .unwrap();
    }

    async fn next(feed: &mut Box<dyn SharedFeed>) -> Handed {
        tokio::time::timeout(Duration::from_secs(5), feed.next())
            .await
            .unwrap()
            .unwrap()
    }

    /// One sign-in on the bus becomes one stream job for each of the two
    /// streams that take it.
    #[tokio::test]
    async fn an_event_becomes_one_job_per_target() {
        let fx = fixture(Duration::from_secs(60));
        let mut feed = fx.bus.share(&fx.consumer.share).await.unwrap();
        relayed(&fx.bus, &fx.record, &control_plane()).await;

        fx.consumer.settle(next(&mut feed).await).await;

        assert_eq!(fx.queue.count(), 2);
    }

    /// An event planned without acknowledgement is delivered a second
    /// time, and settling that delivery leaves exactly the original two
    /// stream jobs queued.
    #[tokio::test]
    async fn a_redelivered_event_adds_no_job() {
        let fx = fixture(Duration::from_millis(20));
        let mut feed = fx.bus.share(&fx.consumer.share).await.unwrap();
        relayed(&fx.bus, &fx.record, &control_plane()).await;
        let first = next(&mut feed).await;
        let planned_first = fx.consumer.outcome(&first.event).await;
        drop(first);

        let again = next(&mut feed).await;
        let delivery = again.delivery;
        fx.consumer.settle(again).await;

        assert_eq!(planned_first, Outcome::Done);
        assert_eq!(delivery, 2);
        assert_eq!(fx.queue.count(), 2);
    }

    /// An event sealed with another control-plane root produces a
    /// set-aside outcome and queues no stream jobs.
    #[tokio::test]
    async fn an_event_sealed_by_another_key_is_set_aside() {
        let fx = fixture(Duration::from_secs(60));
        let mut feed = fx.bus.share(&fx.consumer.share).await.unwrap();
        relayed(&fx.bus, &fx.record, &EventSeal::control_plane(&root(9))).await;

        let outcome = fx.consumer.outcome(&next(&mut feed).await.event).await;

        assert_eq!(outcome, Outcome::SetAside);
        assert_eq!(fx.queue.count(), 0);
    }

    /// A planner's failure of the platform's own is tried again; a refusal
    /// ends the event, and a planner out of time is tried again.
    #[test]
    fn failures_are_tried_again_and_refusals_end_the_event() {
        let failed = Some(Err(AppError::internal_msg("store down")));
        let refused = Some(Err(AppError::NotFound("tenant".to_owned().into())));

        assert_eq!(planned("test", failed), Outcome::Again);
        assert_eq!(planned("test", refused), Outcome::Done);
        assert_eq!(planned("test", None), Outcome::Again);
        assert_eq!(planned("test", Some(Ok(String::new()))), Outcome::Done);
    }

    /// A planner conflict produces a retry outcome so its event can be
    /// delivered again.
    #[test]
    fn a_conflict_hears_the_event_again() {
        let busy = Some(Err(AppError::Conflict(
            "a worker is driving".to_owned().into(),
        )));

        assert_eq!(planned("test", busy), Outcome::Again);
    }

    /// The fan-out hears every scope; the other planners the tenants'.
    #[test]
    fn every_scope_is_heard_only_where_asked() {
        assert_eq!(subjects(Hears::Tenants), [TENANT_EVENTS]);
        assert_eq!(
            subjects(Hears::Everything),
            [TENANT_EVENTS, ORGANIZATION_EVENTS, PLATFORM_EVENTS]
        );
    }

    /// The egress monitor over a bus in memory: what it records, the
    /// refused way out it hears, and a sign-in it should ignore, both on
    /// the trail.
    struct Monitor {
        consumer: Consumer,
        bus: Arc<MemoryBus>,
        recorded: Arc<FakeEventDispatcher>,
        refused: AuditRecord,
        signed_in: AuditRecord,
    }

    /// The gateway refused a way out an agent's request caused, and
    /// someone signed in, both in one tenant.
    fn monitor(ack_wait: Duration) -> Monitor {
        let tenant = TenantId::new();
        let mut refused = test_audit_record(tenant, "agents.egress_denied");
        refused.payload = EventData::new()
            .field("agent_id", AgentId::new().to_string())
            .field("delegation_id", DelegationId::new().to_string());
        let signed_in = test_audit_record(tenant, SIGNED_IN);
        let planner = denial_planner();
        let bus = Arc::new(MemoryBus::new(100));
        let recorded = Arc::new(FakeEventDispatcher::new());
        Monitor {
            consumer: Consumer {
                planner,
                heard: Arc::new(HeardEvents::new(
                    EventCheck::new(control_plane(), data_plane()),
                    Arc::new(FakeRecordedEvents::holding([
                        refused.clone(),
                        signed_in.clone(),
                    ])),
                )),
                bus: Arc::clone(&bus) as _,
                auditor: RequestAuditor::system(recorded.clone()),
                retry_delay: Duration::ZERO,
                share: test_share("worker-agent_egress_denials", ack_wait),
            },
            bus,
            recorded,
            refused,
            signed_in,
        }
    }

    /// A planner answering denied egress through fakes that keep the
    /// event's reaction once.
    fn denial_planner() -> Arc<dyn Planner> {
        let respond = RespondToEgressDenialUseCase::new(RespondToEgressDenialPorts::fakes());
        let heard = HeardPorts {
            reactions: Arc::new(FakeEventReactions::default()),
            unit_of_work: Arc::new(RecordingUnitOfWork::default()),
        };
        Planned::of(
            "agent_egress_denials",
            Hears::Tenants,
            HearEgressDenialUseCase::new(Arc::new(respond), heard),
        )
    }

    fn data_plane() -> EventSeal {
        EventSeal::data_plane(&root(1))
    }

    fn drifts(monitor: &Monitor) -> usize {
        monitor.recorded.records.lock().unwrap().len()
    }

    /// A way out the gateway refused, sealed by the gateway, is held
    /// against the agent once: one drift recorded.
    #[tokio::test]
    async fn a_refused_way_out_is_held_against_its_agent_once() {
        let fx = monitor(Duration::from_secs(60));
        let mut feed = fx.bus.share(&fx.consumer.share).await.unwrap();
        relayed(&fx.bus, &fx.refused, &data_plane()).await;

        fx.consumer.settle(next(&mut feed).await).await;

        assert_eq!(drifts(&fx), 1);
    }

    /// An egress refusal handled without acknowledgement is delivered
    /// again, and settling that delivery leaves exactly one drift record.
    #[tokio::test]
    async fn a_refusal_handed_out_again_changes_nothing() {
        let fx = monitor(Duration::from_millis(20));
        let mut feed = fx.bus.share(&fx.consumer.share).await.unwrap();
        relayed(&fx.bus, &fx.refused, &data_plane()).await;
        let first = next(&mut feed).await;
        let acted = fx.consumer.outcome(&first.event).await;
        drop(first);

        let again = next(&mut feed).await;
        fx.consumer.settle(again).await;

        assert_eq!(acted, Outcome::Done);
        assert_eq!(drifts(&fx), 1);
    }

    /// An event the monitor does not watch is done with, and changes
    /// nothing.
    #[tokio::test]
    async fn an_event_the_monitor_does_not_watch_is_ignored() {
        let fx = monitor(Duration::from_secs(60));
        let mut feed = fx.bus.share(&fx.consumer.share).await.unwrap();
        relayed(&fx.bus, &fx.signed_in, &control_plane()).await;

        let outcome = fx.consumer.outcome(&next(&mut feed).await.event).await;

        assert_eq!(outcome, Outcome::Done);
        assert_eq!(drifts(&fx), 0);
    }
}
