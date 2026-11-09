//! Plan signals: a recorded event becomes the security signals it means,
//! and each signal one job per stream that takes it, keyed by the event,
//! the signal's subject and the stream, so a repeated delivery of the event
//! plans nothing twice.
//!
//! An agents event means at most one signal. A tenant-wide stop of every
//! agent means one for each agent it suspended: the stop records only how
//! many, so the agents are read back, and every receiver hears of each as
//! it would of one agent suspended.
//!
//! Every other event is asked what it means for a person or an agent of
//! the tenant: a session ended, a credential changed, an account locked or
//! deleted, or what they hold changed. A change to what they hold is sent
//! with every permission they hold once it is planned. Some events offer
//! several signals, the most precise first, and each stream is sent the
//! first one it takes.

use std::num::NonZeroU32;
use std::sync::Arc;

use ianua_domain::domains::signals::signal::{
    NewSecuritySignal, SecuritySignal, SignalEvent, SignalSubject,
};
use ianua_domain::domains::signals::stream::SignalStream;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::event_type::{AgentsEvent, EventType};
use ianua_domain::types::{AgentId, AuditRecordId, PrincipalRef, TenantId};
use time::{Duration, OffsetDateTime};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{AccessRecordStore, Holder};
use crate::ports::shared::PublishedEvent;
use crate::ports::signals::{SignalStreamStore, SuspendedAgents};
use crate::services::signals::agent::agent_signal;
use crate::services::signals::choice::SignalChoice;
use crate::services::signals::user::{Change, SubjectChange, user_change};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::scheduling::PlanReport;
use crate::use_cases::signals::delivery::job::SignalJobs;

/// How long before a tenant-wide stop was recorded its agents may have
/// been stamped suspended. The stop stamps them, then records itself.
const FLEET_STOP_WINDOW: Duration = Duration::minutes(5);

/// The ports [`PlanUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PlanPorts {
    /// Where streams are kept.
    pub stream_store: Arc<dyn SignalStreamStore>,
    /// The agents a tenant-wide stop suspended.
    pub suspended_agents: Arc<dyn SuspendedAgents>,
    /// What a person or an agent holds now, sent when it changed.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Where signal jobs are queued.
    pub jobs: SignalJobs,
}

/// Plans the signal jobs a recorded event means.
///
/// The event pipeline runs it, for nobody, so its caller is `()`.
pub struct PlanUseCase {
    ports: PlanPorts,
    fleet_limit: NonZeroU32,
}

impl PlanUseCase {
    /// A planner over `ports`, signalling at most `fleet_limit` agents of
    /// one tenant-wide stop.
    #[must_use]
    pub fn new(ports: PlanPorts, fleet_limit: NonZeroU32) -> Self {
        Self { ports, fleet_limit }
    }

    /// The signals `published` means in `tenant`, one choice per subject.
    async fn choices_of(
        &self,
        tenant: &ScopedTenant,
        published: &PublishedEvent,
    ) -> Result<Vec<SignalChoice>, AppError> {
        let event = &published.event;
        match event.event_type() {
            EventType::Agents(AgentsEvent::AllAgentsSuspended) => {
                self.fleet_stop(tenant, event).await
            }
            EventType::Agents(_) => Ok(agent_signal(event)
                .map(SignalChoice::only)
                .into_iter()
                .collect()),
            _ => self.user_choice(tenant, published).await,
        }
    }

    /// One suspended session for each agent the tenant-wide stop `event`
    /// suspended.
    async fn fleet_stop(
        &self,
        tenant: &ScopedTenant,
        event: &DomainEvent,
    ) -> Result<Vec<SignalChoice>, AppError> {
        let since = event.occurred_at() - FLEET_STOP_WINDOW;
        let agents = self
            .ports
            .suspended_agents
            .suspended_since(tenant, since, self.fleet_limit)
            .await
            .or_internal()?;
        Ok(agents
            .into_iter()
            .filter_map(|agent| suspended(**tenant, agent, event))
            .map(SignalChoice::only)
            .collect())
    }

    /// What `published` means for the person or agent it happened to.
    async fn user_choice(
        &self,
        tenant: &ScopedTenant,
        published: &PublishedEvent,
    ) -> Result<Vec<SignalChoice>, AppError> {
        let Some(SubjectChange { subject, change }) =
            user_change(&published.event, &published.context)
        else {
            return Ok(Vec::new());
        };
        let events = match change {
            Change::Signals(events) => events,
            Change::Holdings => vec![self.held_now(tenant, subject).await?],
        };
        let occurred_at = published.event.occurred_at();
        let signals = events
            .into_iter()
            .filter_map(|event| signal(**tenant, subject, event, occurred_at))
            .collect();
        Ok(SignalChoice::of(signals).into_iter().collect())
    }

    /// The change to what `subject` holds, carrying every permission they
    /// hold in `tenant` now.
    async fn held_now(
        &self,
        tenant: &ScopedTenant,
        subject: SignalSubject,
    ) -> Result<SignalEvent, AppError> {
        let principal = match subject {
            SignalSubject::User(user) => PrincipalRef::User(user),
            SignalSubject::Agent(agent) => PrincipalRef::Agent(agent),
        };
        let held = self
            .ports
            .access_records
            .load_held_by(tenant, Holder::of(principal))
            .await
            .or_internal()?;
        let holdings = held
            .access(**tenant)
            .permissions_held_by(principal, clock::now())
            .or_internal()?;
        Ok(SignalEvent::PermissionsChanged {
            permissions: holdings.names(),
        })
    }

    /// Queues, for each of `choices`, one job per stream of `streams` that
    /// takes a signal from it, each keyed by the event `event_id`.
    async fn queued_for_streams(
        &self,
        event_id: AuditRecordId,
        choices: &[SignalChoice],
        streams: &[SignalStream<ResolvedTenant>],
    ) -> Result<PlanReport, AppError> {
        let mut report = PlanReport::default();
        for choice in choices {
            for (stream, signal) in streams
                .iter()
                .filter_map(|stream| Some((stream, choice.for_stream(stream)?)))
            {
                let enqueued = self
                    .ports
                    .jobs
                    .queue(event_id, *stream.id(), signal)
                    .await?;
                report = report.counting(enqueued);
            }
        }
        Ok(report)
    }
}

impl Command for PlanUseCase {
    type Caller = ();
    type Input = PublishedEvent;
    type Output = Result<PlanReport, AppError>;

    /// Queues one job for each signal `event` means and each stream that
    /// takes it now. An event of no tenant, or one that means no signal,
    /// plans nothing. Records nothing: planning only queues work, and each
    /// job records what it changes.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the streams, the suspended agents or
    ///   what a subject holds cannot be read, or a job cannot be queued.
    ///   The pipeline delivers the event again, and what was queued is not
    ///   queued twice.
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
        let choices = self.choices_of(&tenant, &event).await?;
        if choices.is_empty() {
            return Ok(PlanReport::default());
        }
        let streams = self
            .ports
            .stream_store
            .list_active(&tenant)
            .await
            .or_internal()?;
        self.queued_for_streams(event.id, &choices, &streams).await
    }
}

/// The signal that `agent` of `tenant` was suspended by `event`.
fn suspended(tenant: TenantId, agent: AgentId, event: &DomainEvent) -> Option<SecuritySignal> {
    signal(
        tenant,
        SignalSubject::Agent(agent),
        SignalEvent::SessionSuspended,
        event.occurred_at(),
    )
}

/// The signal that `event` happened to `subject` of `tenant` at
/// `occurred_at`, or `None` when it cannot be about that subject.
fn signal(
    tenant: TenantId,
    subject: SignalSubject,
    event: SignalEvent,
    occurred_at: OffsetDateTime,
) -> Option<SecuritySignal> {
    SecuritySignal::new(NewSecuritySignal {
        tenant_id: tenant,
        subject,
        event,
        occurred_at,
    })
    .ok()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::signals::signal::SecuritySignalType;
    use ianua_domain::domains::signals::stream::{
        SignalStreamRow, StreamStatus, StreamVerificationStatus,
    };
    use ianua_domain::domains::signals::subjects::{DefaultSubjects, StreamSubjects};
    use ianua_domain::test_support::events::{
        sample_event_about, sample_fleet_suspension, sample_role_assigned, sample_session_revoked,
        sample_tenant_event, sample_user_deleted,
    };
    use ianua_domain::types::{AuditRecordId, RoleId, SessionId, UserId};

    use super::*;
    use crate::ports::authorization::AccessRecords;
    use crate::test_support::authorization::{
        FakeAccessRecordStore, stored_assignment, stored_role,
    };
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::signals::{FakeSignalStreamStore, FakeSuspendedAgents, test_stream};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::signals::delivery::job::DISPATCH_SIGNAL_JOB;

    struct Setup {
        uc: PlanUseCase,
        queue: Arc<FakeJobQueue>,
        agents: Arc<FakeSuspendedAgents>,
    }

    /// A verified, active stream of Acme's taking `listed`.
    fn stream_taking(listed: SecuritySignalType) -> SignalStreamRow {
        let mut row = test_stream(StreamStatus::Active, StreamVerificationStatus::Verified);
        row.signal_types = vec![listed];
        row
    }

    /// A planner over Acme's verified streams, one listing each type of
    /// `streams`, where the fleet stop suspended `agents`.
    fn setup(streams: &[SecuritySignalType], agents: &[AgentId]) -> Setup {
        let rows = streams.iter().copied().map(stream_taking).collect();
        planner(rows, agents, AccessRecords::default())
    }

    /// A planner over `rows`, where the fleet stop suspended `agents` and
    /// Acme's access records are `records`.
    fn planner(rows: Vec<SignalStreamRow>, agents: &[AgentId], records: AccessRecords) -> Setup {
        let tenant = test_ctx().tenant_id();
        let store = FakeSignalStreamStore::holding_all(tenant, rows);
        let queue = Arc::new(FakeJobQueue::new());
        let agents = Arc::new(FakeSuspendedAgents::of(tenant, agents));
        let uc = PlanUseCase::new(
            PlanPorts {
                stream_store: Arc::new(store),
                suspended_agents: agents.clone(),
                access_records: Arc::new(FakeAccessRecordStore::holding(tenant, records)),
                jobs: SignalJobs {
                    queue: queue.clone(),
                    attempts: NonZeroU32::new(5).unwrap(),
                },
            },
            NonZeroU32::new(1000).unwrap(),
        );
        Setup { uc, queue, agents }
    }

    fn plan(setup: &Setup, event: PublishedEvent) -> PlanReport {
        block_on(setup.uc.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            event,
        ))
        .unwrap()
    }

    /// `event`, recorded by the platform.
    fn published(event: DomainEvent) -> PublishedEvent {
        PublishedEvent {
            id: AuditRecordId::new(),
            event,
            context: AuditContext::system(),
        }
    }

    /// What each queued signal job carries, in the order queued.
    fn queued(setup: &Setup) -> Vec<String> {
        setup
            .queue
            .jobs_of(DISPATCH_SIGNAL_JOB)
            .iter()
            .map(|job| job.payload().to_owned())
            .collect()
    }

    /// Acme's tenant-wide stop recorded at `at` under the record `id`.
    fn fleet_stop_at(id: AuditRecordId, at: OffsetDateTime) -> PublishedEvent {
        PublishedEvent {
            id,
            event: sample_fleet_suspension(test_ctx().tenant_id(), at),
            context: AuditContext::system(),
        }
    }

    /// Acme's tenant-wide stop, recorded now.
    fn fleet_stop() -> PublishedEvent {
        fleet_stop_at(AuditRecordId::new(), clock::now())
    }

    /// Bob stops every agent of Acme, and the store suspends three. Each
    /// of the two streams for suspended sessions is sent a signal for each
    /// agent: six jobs, so no receiver keeps trusting one of them.
    #[test]
    fn a_fleet_stop_signals_every_suspended_agent_to_every_receiver() {
        let agents = [AgentId::new(), AgentId::new(), AgentId::new()];
        let setup = setup(
            &[
                SecuritySignalType::SessionSuspended,
                SecuritySignalType::SessionSuspended,
            ],
            &agents,
        );

        let report = plan(&setup, fleet_stop());

        assert_eq!(report.queued, 6);
        assert_eq!(setup.queue.jobs_of(DISPATCH_SIGNAL_JOB).len(), 6);
    }

    /// The stop is read back from a little before it was recorded, since
    /// the store stamps the agents first.
    #[test]
    fn a_fleet_stop_reads_the_agents_stamped_just_before_it() {
        let setup = setup(&[SecuritySignalType::SessionSuspended], &[AgentId::new()]);
        let recorded = clock::now();

        plan(&setup, fleet_stop_at(AuditRecordId::new(), recorded));

        assert_eq!(setup.agents.asked_since(), [recorded - FLEET_STOP_WINDOW]);
    }

    /// The pipeline delivers the stop twice. The second planning queues
    /// nothing new.
    #[test]
    fn a_repeated_event_plans_nothing_twice() {
        let setup = setup(&[SecuritySignalType::SessionSuspended], &[AgentId::new()]);
        let (id, at) = (AuditRecordId::new(), clock::now());

        let first = plan(&setup, fleet_stop_at(id, at));
        let second = plan(&setup, fleet_stop_at(id, at));

        assert_eq!((first.queued, second.queued), (1, 0));
        assert_eq!(second.already_queued, 1);
    }

    /// A stream for locked accounts takes no suspended session, and is
    /// planned no job.
    #[test]
    fn a_stream_not_taking_the_signal_gets_no_job() {
        let setup = setup(&[SecuritySignalType::AccountLocked], &[AgentId::new()]);

        let report = plan(&setup, fleet_stop());

        assert_eq!(report.queued, 0);
    }

    /// A topic was paused: no signal means that, so nothing is planned.
    #[test]
    fn an_event_meaning_no_signal_plans_nothing() {
        let setup = setup(&[SecuritySignalType::SessionSuspended], &[]);

        let report = plan(
            &setup,
            published(sample_tenant_event(test_ctx().tenant_id())),
        );

        assert_eq!(report, PlanReport::default());
    }

    /// An admin revokes Ann's session. Acme's stream for revoked sessions
    /// is sent one signal naming Ann.
    #[test]
    fn a_revoked_session_is_planned_for_the_stream_taking_it() {
        let ann = UserId::new();
        let setup = setup(&[SecuritySignalType::SessionRevoked], &[]);
        let event = sample_session_revoked(test_ctx().tenant_id(), ann, SessionId::new());

        let report = plan(&setup, published(event));

        let jobs = queued(&setup);
        assert_eq!(report.queued, 1);
        assert!(jobs[0].contains(&ann.to_string()), "{}", jobs[0]);
    }

    /// An admin locks Ann's account. The stream for locked accounts is sent
    /// it; the one for revoked sessions is not.
    #[test]
    fn a_locked_account_reaches_only_the_streams_taking_it() {
        let setup = setup(
            &[
                SecuritySignalType::AccountLocked,
                SecuritySignalType::SessionRevoked,
            ],
            &[],
        );

        let report = plan(
            &setup,
            published(sample_event_about(test_ctx().tenant_id(), UserId::new())),
        );

        assert_eq!(report.queued, 1);
        assert!(queued(&setup)[0].contains("AccountLocked"));
    }

    /// Ann's account is deleted. A stream for purged accounts hears it was
    /// purged; a stream only for disabled ones still hears it was disabled,
    /// so neither keeps letting her in.
    #[test]
    fn each_stream_is_sent_the_most_precise_signal_it_takes() {
        let setup = setup(
            &[
                SecuritySignalType::AccountPurged,
                SecuritySignalType::AccountDisabled,
            ],
            &[],
        );

        plan(
            &setup,
            published(sample_user_deleted(test_ctx().tenant_id(), UserId::new())),
        );

        let jobs = queued(&setup);
        assert_eq!(jobs.len(), 2);
        assert!(jobs.iter().any(|job| job.contains("AccountPurged")));
        assert!(jobs.iter().any(|job| job.contains("AccountDisabled")));
    }

    /// Ann is given the viewer role. The stream for permission changes is
    /// sent what she holds now: viewing users.
    #[test]
    fn a_role_given_sends_what_the_holder_holds_now() {
        let ann = UserId::new();
        let viewer = stored_role(
            "viewer",
            vec![SystemPermission::Users(UserAction::View)],
            Vec::new(),
        );
        let records = AccessRecords {
            assignments: vec![stored_assignment(PrincipalRef::User(ann), *viewer.id())],
            roles: vec![viewer],
            ..AccessRecords::default()
        };
        let setup = planner(
            vec![stream_taking(SecuritySignalType::PermissionsChanged)],
            &[],
            records,
        );
        let event = sample_role_assigned(
            test_ctx().tenant_id(),
            PrincipalRef::User(ann),
            RoleId::new(),
        );

        plan(&setup, published(event));

        let jobs = queued(&setup);
        assert_eq!(jobs.len(), 1);
        assert!(jobs[0].contains("idp:users:view"), "{}", jobs[0]);
    }

    /// An account-lock event queues no delivery for a stream that excludes
    /// its subject, even when the stream accepts that signal type.
    #[test]
    fn a_stream_not_hearing_the_subject_gets_no_job() {
        let mut row = stream_taking(SecuritySignalType::AccountLocked);
        row.subjects = StreamSubjects::starting_with(DefaultSubjects::None);
        let setup = planner(vec![row], &[], AccessRecords::default());

        let report = plan(
            &setup,
            published(sample_event_about(test_ctx().tenant_id(), UserId::new())),
        );

        assert_eq!(report.queued, 0);
    }
}
