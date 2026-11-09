//! Plan streams: a recorded tenant event becomes one stream job for each of
//! the tenant's streams that is sending and whose filter admits it, keyed
//! by the record and the stream, so a repeated delivery of the event plans
//! nothing twice.

use std::sync::Arc;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::audit::AuditStreamStore;
use crate::ports::shared::PublishedEvent;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::audit::stream_job::StreamJobs;
use crate::use_cases::scheduling::PlanReport;

/// The ports [`PlanStreamsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PlanStreamsPorts {
    /// Where the tenant's streams are kept.
    pub stream_store: Arc<dyn AuditStreamStore>,
    /// Where stream jobs are queued.
    pub jobs: StreamJobs,
}

/// Plans the stream jobs a recorded event means.
///
/// The event pipeline runs it, for nobody, so its caller is `()`.
pub struct PlanStreamsUseCase {
    ports: PlanStreamsPorts,
}

impl PlanStreamsUseCase {
    /// A planner over `ports`.
    #[must_use]
    pub fn new(ports: PlanStreamsPorts) -> Self {
        Self { ports }
    }
}

impl Command for PlanStreamsUseCase {
    type Caller = ();
    type Input = PublishedEvent;
    type Output = Result<PlanReport, AppError>;

    /// Queues one job for each of the tenant's sending streams whose
    /// filter admits `event`'s type. A record of no tenant goes nowhere.
    /// Records nothing: planning only queues work, and each send notes how
    /// it went on its stream.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the streams cannot be read or a job
    ///   cannot be queued. The pipeline delivers the event again, and what
    ///   was queued is not queued twice.
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
        let streams = self.ports.stream_store.list(&tenant).await.or_internal()?;
        let mut report = PlanReport::default();
        for stream in streams
            .iter()
            .filter(|stream| stream.is_sending() && stream.filter().admits(event_type))
        {
            let enqueued = self
                .ports
                .jobs
                .queue(tenant_id, *stream.id(), event.id)
                .await?;
            report = report.counting(enqueued);
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::domains::audit::streaming::StreamFilter;
    use ianua_domain::domains::tenant::audit_streams::{PauseReason, StreamState};
    use ianua_domain::shared::clock;
    use ianua_domain::test_support::events::{sample_platform_event, sample_tenant_event};
    use ianua_domain::types::{AuditRecordId, EventType};

    use super::*;
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::tenant::{
        FakeAuditStreamStore, audit_stream_in_state, test_audit_stream,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::audit::stream_job::STREAM_RECORD_JOB;

    struct Setup {
        uc: PlanStreamsUseCase,
        queue: Arc<FakeJobQueue>,
    }

    /// A planner over Acme's streams: Splunk taking everything, Datadog
    /// taking sign-ins only, and a paused SIEM.
    fn setup() -> Setup {
        let sign_ins = StreamFilter::only(vec![
            EventType::parse("authentication.login_succeeded").unwrap(),
        ])
        .unwrap();
        let paused = StreamState::Paused {
            reason: PauseReason::ByAdministrator,
            at: clock::now(),
        };
        let streams = FakeAuditStreamStore::holding(
            test_ctx().tenant_id(),
            vec![
                test_audit_stream("Splunk", StreamFilter::everything()),
                test_audit_stream("Datadog", sign_ins),
                audit_stream_in_state("SIEM", StreamFilter::everything(), paused),
            ],
        );
        let queue = Arc::new(FakeJobQueue::new());
        let uc = PlanStreamsUseCase::new(PlanStreamsPorts {
            stream_store: Arc::new(streams),
            jobs: StreamJobs {
                queue: queue.clone(),
                attempts: NonZeroU32::new(5).unwrap(),
            },
        });
        Setup { uc, queue }
    }

    fn plan(setup: &Setup, event: PublishedEvent) -> PlanReport {
        block_on(setup.uc.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            event,
        ))
        .unwrap()
    }

    fn topic_paused(id: AuditRecordId) -> PublishedEvent {
        PublishedEvent {
            id,
            event: sample_tenant_event(test_ctx().tenant_id()),
            context: AuditContext::system(),
        }
    }

    /// A topic is paused. Splunk, which takes everything, gets a job; the
    /// sign-in stream and the paused one get none.
    #[test]
    fn each_sending_stream_admitting_the_event_gets_one_job() {
        let setup = setup();

        let report = plan(&setup, topic_paused(AuditRecordId::new()));

        assert_eq!(report.queued, 1);
        assert_eq!(setup.queue.jobs_of(STREAM_RECORD_JOB).len(), 1);
    }

    /// The pipeline delivers the event twice. The second planning queues
    /// nothing.
    #[test]
    fn a_repeated_event_plans_nothing_twice() {
        let setup = setup();
        let id = AuditRecordId::new();

        plan(&setup, topic_paused(id));
        let second = plan(&setup, topic_paused(id));

        assert_eq!((second.queued, second.already_queued), (0, 1));
    }

    /// A platform event belongs to no tenant, and goes nowhere.
    #[test]
    fn an_event_of_no_tenant_plans_nothing() {
        let setup = setup();
        let event = PublishedEvent {
            id: AuditRecordId::new(),
            event: sample_platform_event(),
            context: AuditContext::system(),
        };

        assert_eq!(plan(&setup, event), PlanReport::default());
    }
}
