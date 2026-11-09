//! Stream audit record: the worker sends one tenant record along one of the
//! tenant's streams, and records how the send went.
//!
//! A stream job runs it, one per record and stream, so one stream's
//! failure never keeps the record from the others. A destination that
//! refuses is noted on its stream and the job tries again later; after
//! enough refusals in a row the stream pauses itself, so a dead collector
//! is not called forever.
//!
//! It runs outside any request, for nobody, so no one's rights are asked.

use std::sync::Arc;

use ianua_domain::domains::audit::record::AuditRecord;
use ianua_domain::domains::tenant::audit_streams::AuditStream;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, AuditRecordId, AuditStreamId, TenantId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::audit::{AuditStreamSender, AuditStreamStore};
use crate::ports::shared::RecordedEvents;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::tenant::audit_streams::destination::credentials_place;

/// The ports [`StreamRecordUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StreamRecordPorts {
    /// Where the tenant's streams are kept.
    pub stream_store: Arc<dyn AuditStreamStore>,
    /// Sends a record to a stream's destination, with a timeout and the
    /// destination's address checked again.
    pub sender: Arc<dyn AuditStreamSender>,
    /// The tenant's recorded events, read back by id.
    pub records: Arc<dyn RecordedEvents>,
}

/// Which record to send along which stream of which tenant.
pub struct StreamRecordRequest {
    /// The owner of the destination and the record being delivered.
    pub tenant_id: TenantId,
    /// The configured destination that should receive the audit event.
    pub stream_id: AuditStreamId,
    /// The persisted audit entry to deliver.
    pub record_id: AuditRecordId,
}

/// How sending one record along one stream went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Streamed {
    /// The destination took the record.
    Delivered,
    /// The destination refused it or could not be reached.
    Failed,
    /// Nothing was sent: the stream or the record is gone, the stream is
    /// paused, or its filter does not admit the record.
    Skipped,
}

/// Sends a tenant audit record along one of the tenant's streams.
pub struct StreamRecordUseCase {
    ports: StreamRecordPorts,
}

impl StreamRecordUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: StreamRecordPorts) -> Self {
        Self { ports }
    }

    /// The stream `id` of `tenant`, while it is sending.
    async fn sending_stream(
        &self,
        tenant: &ScopedTenant,
        id: &AuditStreamId,
    ) -> Result<Option<AuditStream<ResolvedTenant>>, AppError> {
        let stream = self
            .ports
            .stream_store
            .find(tenant, id)
            .await
            .or_internal()?;
        Ok(stream.filter(AuditStream::is_sending))
    }

    /// The record `id` of `tenant`, when `stream`'s filter admits it.
    async fn admitted_record(
        &self,
        tenant: &ScopedTenant,
        id: &AuditRecordId,
        stream: &AuditStream<ResolvedTenant>,
    ) -> Result<Option<AuditRecord>, AppError> {
        let record = self.ports.records.find(tenant, id).await.or_internal()?;
        Ok(record.filter(|record| stream.filter().admits(record.event_type)))
    }

    /// Sends `record` along `stream`, notes how it went on the stream, and
    /// saves and records the stream when that changed it.
    async fn stream_one(
        &self,
        tenant: &ScopedTenant,
        mut stream: AuditStream<ResolvedTenant>,
        record: &AuditRecord,
        auditor: &RequestAuditor,
    ) -> Result<Streamed, AppError> {
        let sent = self.send(tenant, &stream, record).await;
        let before = stream.state();
        note(&mut stream, sent)?;
        if stream.state() == before {
            return Ok(sent);
        }
        self.ports
            .stream_store
            .save(tenant, &stream)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ActorRef::System, stream.take_events(tenant))
            .await
            .or_internal()?;
        Ok(sent)
    }

    /// Sends `record` to the destination of `tenant`'s `stream`. A refusal
    /// is logged by the stream's id and kind only, never with what the
    /// destination said.
    async fn send(
        &self,
        tenant: &ScopedTenant,
        stream: &AuditStream<ResolvedTenant>,
        record: &AuditRecord,
    ) -> Streamed {
        let credentials = credentials_place(tenant, stream.id());
        let sent = self
            .ports
            .sender
            .send(stream.destination(), &credentials, record)
            .await;
        let Err(error) = sent else {
            return Streamed::Delivered;
        };
        tracing::warn!(
            stream_id = %stream.id(),
            kind = %stream.destination().kind(),
            %error,
            "audit stream: record not delivered"
        );
        Streamed::Failed
    }
}

impl Command for StreamRecordUseCase {
    type Caller = ();
    type Input = StreamRecordRequest;
    type Output = Result<Streamed, AppError>;

    /// Sends the record along the stream when the stream is sending and its
    /// filter admits the record, and says how it went. A stream that
    /// refuses enough records in a row pauses itself and records
    /// `tenant.audit_stream_paused`.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the stream or the record cannot be
    ///   read, or the stream or its record cannot be saved. The job runs
    ///   again.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        request: StreamRecordRequest,
    ) -> Result<Streamed, AppError> {
        let tenant = ScopedTenant::for_background(request.tenant_id);
        let Some(stream) = self.sending_stream(&tenant, &request.stream_id).await? else {
            return Ok(Streamed::Skipped);
        };
        let found = self
            .admitted_record(&tenant, &request.record_id, &stream)
            .await?;
        let Some(record) = found else {
            return Ok(Streamed::Skipped);
        };
        let auditor = auditor.with_tenant(request.tenant_id);
        self.stream_one(&tenant, stream, &record, &auditor).await
    }
}

/// Notes on `stream` how a send along it went.
///
/// # Errors
///
/// - `AppError::Conflict` when the stream was paused, which the stream's
///   sending check has already ruled out.
fn note(stream: &mut AuditStream<ResolvedTenant>, sent: Streamed) -> Result<(), AppError> {
    let noted = match sent {
        Streamed::Delivered => stream.record_delivered(),
        Streamed::Failed => stream.record_failed(),
        Streamed::Skipped => Ok(()),
    };
    noted.map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::streaming::StreamFilter;
    use ianua_domain::domains::tenant::audit_streams::{
        FAILURES_BEFORE_PAUSE, PauseReason, StreamState,
    };
    use ianua_domain::types::EventType;

    use super::*;
    use crate::test_support::tenant::{
        FakeAuditStreamSender, FakeAuditStreamStore, FakeRecordedEvents, audit_stream_in_state,
        test_audit_record, test_audit_stream,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const EVENT: &str = "tenant.compliance_changed";

    struct Setup {
        uc: StreamRecordUseCase,
        streams: Arc<FakeAuditStreamStore>,
        sender: Arc<FakeAuditStreamSender>,
        audit: Arc<FakeEventDispatcher>,
        record: AuditRecordId,
    }

    impl Setup {
        fn over(streams: Vec<AuditStream<ResolvedTenant>>, sender: FakeAuditStreamSender) -> Self {
            let streams = Arc::new(FakeAuditStreamStore::holding(
                test_ctx().tenant_id(),
                streams,
            ));
            let record = test_audit_record(test_ctx().tenant_id(), EVENT);
            let record_id = record.id;
            let sender = Arc::new(sender);
            Self {
                uc: StreamRecordUseCase::new(StreamRecordPorts {
                    stream_store: streams.clone(),
                    sender: sender.clone(),
                    records: Arc::new(FakeRecordedEvents::holding([record])),
                }),
                streams,
                sender,
                audit: Arc::new(FakeEventDispatcher::new()),
                record: record_id,
            }
        }

        fn stream_along(&self, stream_id: AuditStreamId) -> Streamed {
            let request = StreamRecordRequest {
                tenant_id: test_ctx().tenant_id(),
                stream_id,
                record_id: self.record,
            };
            block_on(
                self.uc
                    .execute(&(), &test_auditor(self.audit.clone()), request),
            )
            .unwrap()
        }

        fn state_of(&self, id: &AuditStreamId) -> StreamState {
            self.streams
                .stored(test_ctx().tenant_id(), id)
                .unwrap()
                .state()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Acme streams everything to Splunk and only sign-ins to Datadog. A
    /// compliance change goes to Splunk, and not to Datadog.
    #[test]
    fn a_record_goes_only_along_a_stream_whose_filter_admits_it() {
        let sign_ins = StreamFilter::only(vec![
            EventType::parse("authentication.login_succeeded").unwrap(),
        ])
        .unwrap();
        let splunk = test_audit_stream("Splunk", StreamFilter::everything());
        let datadog = test_audit_stream("Datadog", sign_ins);
        let ids = (*splunk.id(), *datadog.id());
        let setup = Setup::over(vec![splunk, datadog], FakeAuditStreamSender::delivering());

        let to_splunk = setup.stream_along(ids.0);
        let to_datadog = setup.stream_along(ids.1);

        assert_eq!(
            (to_splunk, to_datadog),
            (Streamed::Delivered, Streamed::Skipped)
        );
        assert_eq!(setup.sender.sent(), 1);
    }

    /// Ann paused the stream. Nothing is sent along it.
    #[test]
    fn a_paused_stream_sends_nothing() {
        let paused = StreamState::Paused {
            reason: PauseReason::ByAdministrator,
            at: ianua_domain::shared::clock::now(),
        };
        let stream = audit_stream_in_state("SIEM", StreamFilter::everything(), paused);
        let id = *stream.id();
        let setup = Setup::over(vec![stream], FakeAuditStreamSender::delivering());

        assert_eq!(setup.stream_along(id), Streamed::Skipped);
        assert_eq!(setup.sender.sent(), 0);
    }

    /// Ann deleted the stream while the record waited. Nothing is sent, and
    /// the job ends.
    #[test]
    fn a_stream_that_is_gone_sends_nothing() {
        let setup = Setup::over(Vec::new(), FakeAuditStreamSender::delivering());

        assert_eq!(setup.stream_along(AuditStreamId::new()), Streamed::Skipped);
    }

    /// The collector refuses the record. The stream is noted as failing,
    /// and nothing is recorded yet.
    #[test]
    fn a_refused_record_marks_the_stream_failing() {
        let stream = test_audit_stream("SIEM", StreamFilter::everything());
        let id = *stream.id();
        let setup = Setup::over(vec![stream], FakeAuditStreamSender::refusing());

        assert_eq!(setup.stream_along(id), Streamed::Failed);
        assert!(matches!(
            setup.state_of(&id),
            StreamState::Failing { failures: 1, .. }
        ));
        assert!(setup.recorded().is_empty());
    }

    /// The collector has refused every record but one short of the limit.
    /// It refuses this one too, and the stream pauses itself, which is
    /// recorded.
    #[test]
    fn enough_refusals_in_a_row_pause_the_stream() {
        let failing = StreamState::Failing {
            since: ianua_domain::shared::clock::now(),
            failures: FAILURES_BEFORE_PAUSE - 1,
        };
        let stream = audit_stream_in_state("SIEM", StreamFilter::everything(), failing);
        let id = *stream.id();
        let setup = Setup::over(vec![stream], FakeAuditStreamSender::refusing());

        setup.stream_along(id);

        assert!(matches!(
            setup.state_of(&id),
            StreamState::Paused {
                reason: PauseReason::AfterFailures,
                ..
            }
        ));
        assert_eq!(setup.recorded(), vec!["tenant.audit_stream_paused"]);
    }

    /// The collector was failing and takes the record again. The stream is
    /// active again.
    #[test]
    fn a_delivered_record_clears_the_failures() {
        let failing = StreamState::Failing {
            since: ianua_domain::shared::clock::now(),
            failures: 3,
        };
        let stream = audit_stream_in_state("SIEM", StreamFilter::everything(), failing);
        let id = *stream.id();
        let setup = Setup::over(vec![stream], FakeAuditStreamSender::delivering());

        setup.stream_along(id);

        assert_eq!(setup.state_of(&id), StreamState::Active);
    }
}
