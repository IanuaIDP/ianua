//! Fakes for audit streams: where they are kept, what sends records along
//! them, and the streams and records tests use.

use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::audit::builder::ActedThrough;
use ianua_domain::domains::audit::record::{AuditRecord, AuditScope, AuditTarget};
use ianua_domain::domains::audit::streaming::{
    HttpAuthorization, HttpTarget, StreamDestination, StreamFilter,
};
use ianua_domain::domains::tenant::audit_streams::{AuditStream, AuditStreamRow, StreamState};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::data::EventData;
use ianua_domain::types::{
    ActorRef, AuditRecordId, AuditStreamId, EventType, Fact, Label, PublicHttpsUrl, TenantId,
};

use crate::ports::TenantScoped;
use crate::ports::audit::{AuditStreamSender, AuditStreamStore};
use crate::ports::authentication::SealedFor;
use crate::ports::shared::RecordedEvents;
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::scheduling::FakeJobQueue;
use crate::use_cases::audit::StreamJobs;

/// In-memory audit stream store, keeping each stream as its row under its
/// tenant.
#[derive(Default)]
pub struct FakeAuditStreamStore {
    streams: Mutex<Vec<(TenantId, AuditStreamRow)>>,
}

impl TenantScoped for FakeAuditStreamStore {}

impl FakeAuditStreamStore {
    /// A store holding no stream.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `streams` for `tenant`.
    #[must_use]
    pub fn holding(
        tenant: TenantId,
        streams: impl IntoIterator<Item = AuditStream<ResolvedTenant>>,
    ) -> Self {
        let store = Self::empty();
        store
            .streams
            .lock()
            .unwrap()
            .extend(streams.into_iter().map(|stream| (tenant, row_of(&stream))));
        store
    }

    /// The stream `id` of `tenant` as last saved.
    ///
    /// # Panics
    ///
    /// If the saved row no longer reads back, which a fake never stores.
    #[must_use]
    pub fn stored(
        &self,
        tenant: TenantId,
        id: &AuditStreamId,
    ) -> Option<AuditStream<ResolvedTenant>> {
        self.rows(tenant)
            .into_iter()
            .find(|row| row.id == *id)
            .map(|row| AuditStream::reconstitute(row).expect("a saved stream reads back"))
    }

    /// How many streams `tenant` keeps.
    #[must_use]
    pub fn count(&self, tenant: TenantId) -> usize {
        self.rows(tenant).len()
    }

    /// Copies of the rows `tenant` keeps, oldest first.
    fn rows(&self, tenant: TenantId) -> Vec<AuditStreamRow> {
        self.streams
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, _)| *owner == tenant)
            .map(|(_, row)| copy_row(row))
            .collect()
    }
}

#[async_trait]
impl AuditStreamStore for FakeAuditStreamStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        id: &AuditStreamId,
    ) -> Result<Option<AuditStream<ResolvedTenant>>, DomainError> {
        self.rows(**tenant_id)
            .into_iter()
            .find(|row| row.id == *id)
            .map(AuditStream::reconstitute)
            .transpose()
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<AuditStream<ResolvedTenant>>, DomainError> {
        self.rows(**tenant_id)
            .into_iter()
            .map(AuditStream::reconstitute)
            .collect()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        stream: &AuditStream<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut streams = self.streams.lock().unwrap();
        let row = row_of(stream);
        match streams
            .iter_mut()
            .find(|(owner, kept)| owner == &**tenant_id && kept.id == row.id)
        {
            Some(entry) => entry.1 = row,
            None => streams.push((**tenant_id, row)),
        }
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &AuditStreamId,
    ) -> Result<(), DomainError> {
        self.streams
            .lock()
            .unwrap()
            .retain(|(owner, row)| !(owner == &**tenant_id && row.id == *id));
        Ok(())
    }
}

impl Fake for Arc<dyn AuditStreamStore> {
    fn fake() -> Self {
        Arc::new(FakeAuditStreamStore::empty())
    }
}

/// A stream as storage would write it.
fn row_of(stream: &AuditStream<ResolvedTenant>) -> AuditStreamRow {
    AuditStreamRow {
        id: *stream.id(),
        name: stream.name().clone(),
        destination: stream.destination().clone(),
        filter: stream.filter().clone(),
        state: stream.state(),
        created_at: stream.created_at(),
        updated_at: stream.updated_at(),
    }
}

/// A second copy of a stored row.
fn copy_row(row: &AuditStreamRow) -> AuditStreamRow {
    AuditStreamRow {
        id: row.id,
        name: row.name.clone(),
        destination: row.destination.clone(),
        filter: row.filter.clone(),
        state: row.state,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

/// An active stream named `name` sending the records `filter` admits to an
/// HTTPS endpoint that asks for nothing.
///
/// # Panics
///
/// If `name` is not a valid label. Tests pass literals that are.
#[must_use]
pub fn test_audit_stream(name: &str, filter: StreamFilter) -> AuditStream<ResolvedTenant> {
    audit_stream_in_state(name, filter, StreamState::Active)
}

/// [`test_audit_stream`], sending everything, in `state`.
///
/// # Panics
///
/// If `name` is not a valid label, or `state` counts failures a stream
/// never holds. Tests pass ones that are.
#[must_use]
pub fn audit_stream_in_state(
    name: &str,
    filter: StreamFilter,
    state: StreamState,
) -> AuditStream<ResolvedTenant> {
    let now = clock::now();
    AuditStream::reconstitute(AuditStreamRow {
        id: AuditStreamId::new(),
        name: Label::new("name", name).expect("a valid name"),
        destination: test_stream_destination(),
        filter,
        state,
        created_at: now,
        updated_at: now,
    })
    .expect("a consistent stream")
}

/// An HTTPS endpoint on the public internet that asks for nothing.
///
/// # Panics
///
/// Never: the address is a fixed, valid public URL.
#[must_use]
pub fn test_stream_destination() -> StreamDestination {
    StreamDestination::Http(HttpTarget::new(
        PublicHttpsUrl::new("https://siem.acme.com/ingest").expect("a public HTTPS URL"),
        HttpAuthorization::Unauthenticated,
    ))
}

/// An audit record of `event_type` in `tenant`, as the worker streams it.
///
/// # Panics
///
/// If `event_type` names no event. Tests pass ones that do.
#[must_use]
pub fn test_audit_record(tenant: TenantId, event_type: &str) -> AuditRecord {
    AuditRecord {
        id: AuditRecordId::new(),
        scope: AuditScope::Tenant {
            organization: Fact::Unknown,
            tenant,
        },
        actor: ActorRef::System,
        event_type: EventType::parse(event_type).expect("a known event type"),
        target: AuditTarget::Untargeted,
        ip_address: Fact::Unknown,
        user_agent: Fact::Unknown,
        payload: EventData::new(),
        acted_through: ActedThrough::Directly,
        occurred_at: clock::now(),
    }
}

/// Sends records by noting them, or refuses every one.
#[derive(Default)]
pub struct FakeAuditStreamSender {
    sent: Mutex<Vec<AuditRecordId>>,
    refusing: bool,
}

impl FakeAuditStreamSender {
    /// A sender whose every destination takes the record.
    #[must_use]
    pub fn delivering() -> Self {
        Self::default()
    }

    /// A sender whose every destination refuses the record.
    #[must_use]
    pub fn refusing() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            refusing: true,
        }
    }

    /// How many records were taken.
    #[must_use]
    pub fn sent(&self) -> usize {
        self.sent.lock().unwrap().len()
    }
}

#[async_trait]
impl AuditStreamSender for FakeAuditStreamSender {
    async fn send(
        &self,
        _: &StreamDestination,
        _: &SealedFor,
        record: &AuditRecord,
    ) -> Result<(), DomainError> {
        if self.refusing {
            return Err(DomainError::infra_msg("the collector refused the record"));
        }
        self.sent.lock().unwrap().push(record.id);
        Ok(())
    }
}

impl Fake for Arc<dyn AuditStreamSender> {
    fn fake() -> Self {
        Arc::new(FakeAuditStreamSender::delivering())
    }
}

/// Recorded events a test lays out, found by their tenant and id.
#[derive(Default)]
pub struct FakeRecordedEvents {
    records: Vec<AuditRecord>,
}

impl FakeRecordedEvents {
    /// Holding `records`, each under the tenant its scope names.
    #[must_use]
    pub fn holding(records: impl IntoIterator<Item = AuditRecord>) -> Self {
        Self {
            records: records.into_iter().collect(),
        }
    }
}

impl TenantScoped for FakeRecordedEvents {}

#[async_trait]
impl RecordedEvents for FakeRecordedEvents {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        id: &AuditRecordId,
    ) -> Result<Option<AuditRecord>, DomainError> {
        Ok(self
            .records
            .iter()
            .find(|record| record.id == *id && record.scope.tenant_id() == Some(&**tenant_id))
            .cloned())
    }
}

impl Fake for Arc<dyn RecordedEvents> {
    fn fake() -> Self {
        Arc::new(FakeRecordedEvents::default())
    }
}

impl Fake for StreamJobs {
    fn fake() -> Self {
        StreamJobs {
            queue: Arc::new(FakeJobQueue::new()),
            attempts: NonZeroU32::MIN,
        }
    }
}
