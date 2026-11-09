//! Fakes for the audit ports: chain verifiers, kept chain verdicts, an
//! evidence store holding three records of one agent, empty audit logs,
//! exports with their records and files, and records removed once their
//! retention ends.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::audit::access::AuditLogOf;
use ianua_domain::domains::audit::checkpoint::{ChainCheckpoint, ChainHash, ChainStart};
use ianua_domain::domains::audit::evidence::EvidenceRecord;
use ianua_domain::domains::audit::export::filter::{AuditExportFilter, AuditExportFormat};
use ianua_domain::domains::audit::export::seal::{ExportSeal, FileDigest};
use ianua_domain::domains::audit::export::state::AuditExportState;
use ianua_domain::domains::audit::export::{
    AuditLogExport, AuditLogExportRow, DOWNLOAD_WINDOW, WRITE_DEADLINE,
};
use ianua_domain::domains::audit::record::AuditTarget;
use ianua_domain::domains::audit::verdict::{ChainVerdict, ChainVerdictRow};
use ianua_domain::domains::audit::walk::{ChainStanding, ChainStretch};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::data::EventData;
use ianua_domain::types::{
    ActorRef, AgentId, AuditExportId, AuditRecordId, EventType, EvidenceId, HttpsUrl, OperatorId,
    TenantId, UserId,
};
use time::OffsetDateTime;

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::audit::{
    AuditChainVerdictStore, AuditChainVerifier, AuditExportFiles, AuditExportSource,
    AuditExportStore, AuditExportUpload, AuditLogEntry, AuditLogFilter, AuditLogPage,
    AuditLogSortField, EvidenceStore, ExportPage, ExportPageStart, OrgAuditLogStore,
    PlatformAuditLogStore, TenantAuditLogStore,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// The sequence numbers of the records a [`FakeEvidenceStore`] holds.
const EVIDENCE_SEQS: std::ops::RangeInclusive<i64> = 1..=3;

/// Audit-chain verifier whose every stretch finds the chain at its end.
pub struct FakeAuditChainVerifier;

impl TenantScoped for FakeAuditChainVerifier {}

#[async_trait]
impl AuditChainVerifier for FakeAuditChainVerifier {
    async fn verify_stretch(
        &self,
        _: &ScopedTenant,
        _: &ChainStart,
        _: NonZeroU32,
    ) -> Result<ChainStretch, DomainError> {
        Ok(ChainStretch::Ended)
    }
}

/// The link at `seq` of a fake chain.
///
/// # Panics
///
/// When `seq` is below 1, which no chain holds.
#[must_use]
pub fn chain_link(seq: i64) -> ChainCheckpoint {
    let hash = ChainHash::from_stored(&[9; 32]).expect("32 bytes is a hash");
    ChainCheckpoint::from_stored(seq, hash).expect("a chain's records start at 1")
}

/// Chains per tenant, as long as a test says, broken where it says, or
/// unreachable; counts how many records its stretches rehashed.
#[derive(Default)]
pub struct ScriptedChain {
    lengths: Mutex<HashMap<TenantId, i64>>,
    breaks: Mutex<HashMap<TenantId, i64>>,
    unreachable: Mutex<Vec<TenantId>>,
    read: Mutex<u64>,
}

impl ScriptedChain {
    /// `tenant`'s chain holds records 1 to `length`.
    pub fn holding(&self, tenant: TenantId, length: i64) {
        self.lengths.lock().unwrap().insert(tenant, length);
    }

    /// `tenant`'s record `seq` no longer rehashes.
    pub fn breaking(&self, tenant: TenantId, seq: i64) {
        self.breaks.lock().unwrap().insert(tenant, seq);
    }

    /// `tenant`'s chain cannot be read.
    pub fn unreachable(&self, tenant: TenantId) {
        self.unreachable.lock().unwrap().push(tenant);
    }

    /// How many records the stretches rehashed so far.
    #[must_use]
    pub fn records_read(&self) -> u64 {
        *self.read.lock().unwrap()
    }

    /// Starts counting rehashed records again.
    pub fn forget_reads(&self) {
        *self.read.lock().unwrap() = 0;
    }

    fn counted(&self, records: i64) {
        *self.read.lock().unwrap() += u64::try_from(records).unwrap_or(0);
    }

    /// The stretch of `tenant`'s chain after `from`, at most `limit` long.
    fn stretch(&self, tenant: TenantId, from: i64, limit: i64) -> ChainStretch {
        let length = self
            .lengths
            .lock()
            .unwrap()
            .get(&tenant)
            .copied()
            .unwrap_or(0);
        if from >= length {
            return ChainStretch::Ended;
        }
        let end = length.min(from + limit);
        let broken = self.breaks.lock().unwrap().get(&tenant).copied();
        if let Some(seq) = broken.filter(|seq| *seq > from && *seq <= end) {
            self.counted(seq - from);
            return ChainStretch::Broken {
                checked: u64::try_from(seq - from - 1).unwrap_or(0),
                at_seq: seq,
            };
        }
        self.counted(end - from);
        ChainStretch::Intact {
            checked: u64::try_from(end - from).unwrap_or(0),
            last: chain_link(end),
        }
    }
}

impl TenantScoped for ScriptedChain {}

#[async_trait]
impl AuditChainVerifier for ScriptedChain {
    async fn verify_stretch(
        &self,
        tenant_id: &ScopedTenant,
        start: &ChainStart,
        limit: NonZeroU32,
    ) -> Result<ChainStretch, DomainError> {
        if self.unreachable.lock().unwrap().contains(&**tenant_id) {
            return Err(DomainError::infra_msg("database unreachable"));
        }
        let from = start.verified_through().unwrap_or(0);
        Ok(self.stretch(**tenant_id, from, i64::from(limit.get())))
    }
}

/// Verdicts kept per tenant, or a store that cannot be read.
#[derive(Default)]
pub struct FakeChainVerdictStore {
    kept: Mutex<HashMap<TenantId, ChainVerdict>>,
    failing: bool,
}

impl FakeChainVerdictStore {
    /// A store that fails every read and write.
    #[must_use]
    pub fn failing() -> Self {
        Self {
            kept: Mutex::default(),
            failing: true,
        }
    }

    /// A store keeping, as `tenant`'s last, a verdict found just now that
    /// the chain stands as `standing`.
    ///
    /// # Panics
    ///
    /// Never: a verdict from the start of the chain is always whole.
    #[must_use]
    pub fn holding(tenant: TenantId, standing: ChainStanding) -> Self {
        let store = Self::default();
        let verdict = ChainVerdict::reconstitute(ChainVerdictRow {
            verified_at: clock::now(),
            standing,
            checkpoint: ChainStart::Genesis,
        })
        .expect("a verdict from the start of the chain is whole");
        store.keep(tenant, verdict);
        store
    }

    /// Keeps `verdict` as `tenant`'s last.
    pub fn keep(&self, tenant: TenantId, verdict: ChainVerdict) {
        self.kept.lock().unwrap().insert(tenant, verdict);
    }

    /// `tenant`'s last kept verdict.
    #[must_use]
    pub fn kept(&self, tenant: TenantId) -> Option<ChainVerdict> {
        self.kept.lock().unwrap().get(&tenant).cloned()
    }

    fn reachable(&self) -> Result<(), DomainError> {
        unless_failing(self.failing, "the verdict store")
    }
}

/// Fails as `what` being unreachable when `failing`.
fn unless_failing(failing: bool, what: &str) -> Result<(), DomainError> {
    if failing {
        return Err(DomainError::infra_msg(format!("{what} is unreachable")));
    }
    Ok(())
}

impl TenantScoped for FakeChainVerdictStore {}

#[async_trait]
impl AuditChainVerdictStore for FakeChainVerdictStore {
    async fn find(&self, tenant_id: &ScopedTenant) -> Result<Option<ChainVerdict>, DomainError> {
        self.reachable()?;
        Ok(self.kept(**tenant_id))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        verdict: &ChainVerdict,
    ) -> Result<(), DomainError> {
        self.reachable()?;
        self.keep(**tenant_id, verdict.clone());
        Ok(())
    }
}

impl Fake for Arc<dyn AuditChainVerdictStore> {
    fn fake() -> Self {
        Arc::new(FakeChainVerdictStore::default())
    }
}

/// Who asks for an export of `log` in the fakes: an operator for the
/// platform's, a person for any other.
fn asker_of(log: AuditLogOf) -> ActorRef {
    match log {
        AuditLogOf::Platform => ActorRef::Operator(OperatorId::new()),
        AuditLogOf::Organization(_) | AuditLogOf::Tenant(_) => ActorRef::User(UserId::new()),
    }
}

/// The digest every fake export file comes to.
///
/// # Panics
///
/// Never: 32 bytes are a SHA-256.
#[must_use]
pub fn fake_file_digest() -> FileDigest {
    FileDigest::from_bytes(&[9; 32]).expect("32 bytes are a SHA-256")
}

/// An export of `log` in `state`, asked for at `requested_at`, sealed when
/// it is a ready tenant export.
///
/// # Panics
///
/// When the export does not rebuild, which a fake never asks.
fn export_in(
    log: AuditLogOf,
    state: AuditExportState,
    requested_at: time::OffsetDateTime,
) -> AuditLogExport {
    let sealed =
        matches!(log, AuditLogOf::Tenant(_)) && matches!(state, AuditExportState::Ready { .. });
    AuditLogExport::reconstitute(AuditLogExportRow {
        id: AuditExportId::new(),
        log,
        requested_by: asker_of(log),
        filter: AuditExportFilter::default(),
        format: AuditExportFormat::Csv,
        state,
        seal: sealed.then(|| ExportSeal::new("eyJh.eyJi.c2ln").expect("a compact JWS")),
        requested_at,
    })
    .expect("a fresh export rebuilds")
}

/// An export of `log` the worker is still writing, asked for just now.
#[must_use]
pub fn pending_export_of(log: AuditLogOf) -> AuditLogExport {
    export_in(log, AuditExportState::Pending, clock::now())
}

/// An export of `log` asked for a minute ago and written just now,
/// holding three records.
#[must_use]
pub fn written_export_of(log: AuditLogOf) -> AuditLogExport {
    let now = clock::now();
    export_in(
        log,
        AuditExportState::Ready {
            at: now,
            available_until: now + DOWNLOAD_WINDOW,
            rows: 3,
            digest: fake_file_digest(),
        },
        now - time::Duration::minutes(1),
    )
}

/// A copy of `export`, which does not implement `Clone`, read back as a
/// real store would.
fn copy_export(export: &AuditLogExport) -> Result<AuditLogExport, DomainError> {
    AuditLogExport::reconstitute(AuditLogExportRow {
        id: *export.id(),
        log: export.log(),
        requested_by: export.requested_by().clone(),
        filter: export.filter().clone(),
        format: export.format(),
        state: export.state(),
        seal: export.seal().cloned(),
        requested_at: export.requested_at(),
    })
}

/// Exports kept in memory, found only under their own log.
#[derive(Default)]
pub struct FakeAuditExportStore {
    kept: Mutex<Vec<AuditLogExport>>,
}

impl FakeAuditExportStore {
    /// A store holding `export`.
    #[must_use]
    pub fn holding(export: AuditLogExport) -> Self {
        Self {
            kept: Mutex::new(vec![export]),
        }
    }

    /// The export `id` as last saved, whatever its log.
    ///
    /// # Panics
    ///
    /// When a kept export does not rebuild.
    #[must_use]
    pub fn stored(&self, id: &AuditExportId) -> Option<AuditLogExport> {
        self.kept
            .lock()
            .unwrap()
            .iter()
            .find(|export| export.id() == id)
            .map(|export| copy_export(export).unwrap())
    }

    /// How many exports are kept.
    #[must_use]
    pub fn count(&self) -> usize {
        self.kept.lock().unwrap().len()
    }
}

#[async_trait]
impl AuditExportStore for FakeAuditExportStore {
    async fn save(&self, export: &AuditLogExport) -> Result<(), DomainError> {
        let copy = copy_export(export)?;
        let mut kept = self.kept.lock().unwrap();
        kept.retain(|existing| existing.id() != export.id());
        kept.push(copy);
        Ok(())
    }

    async fn find(
        &self,
        log: AuditLogOf,
        id: &AuditExportId,
    ) -> Result<Option<AuditLogExport>, DomainError> {
        let kept = self.kept.lock().unwrap();
        kept.iter()
            .find(|export| export.id() == id && export.log() == log)
            .map(copy_export)
            .transpose()
    }

    async fn pending_count(&self, log: AuditLogOf) -> Result<u64, DomainError> {
        let kept = self.kept.lock().unwrap();
        let pending = kept
            .iter()
            .filter(|export| export.log() == log && export.is_pending())
            .count();
        Ok(u64::try_from(pending).unwrap_or(u64::MAX))
    }

    async fn due_to_end(
        &self,
        now: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<AuditLogExport>, DomainError> {
        let kept = self.kept.lock().unwrap();
        kept.iter()
            .filter(|export| is_due(export, now))
            .take(usize::try_from(limit.get()).unwrap_or(usize::MAX))
            .map(copy_export)
            .collect()
    }
}

/// Whether `export` is due to end at `now`.
fn is_due(export: &AuditLogExport, now: OffsetDateTime) -> bool {
    match export.state() {
        AuditExportState::Pending => now >= export.requested_at() + WRITE_DEADLINE,
        AuditExportState::Ready {
            available_until, ..
        } => now >= available_until,
        AuditExportState::Failed { .. } | AuditExportState::Expired => false,
    }
}

impl Fake for Arc<dyn AuditExportStore> {
    fn fake() -> Self {
        Arc::new(FakeAuditExportStore::default())
    }
}

/// A log of so many records, one a second back from now, handed out a
/// keyset page at a time; counts the pages read.
#[derive(Default)]
pub struct FakeAuditExportSource {
    records: u128,
    failing: bool,
    pages: Mutex<u64>,
}

impl FakeAuditExportSource {
    /// A log holding `records` records.
    #[must_use]
    pub fn holding(records: usize) -> Self {
        Self {
            records: u128::try_from(records).unwrap_or(u128::MAX),
            ..Self::default()
        }
    }

    /// A log that cannot be read.
    #[must_use]
    pub fn failing() -> Self {
        Self {
            records: 0,
            failing: true,
            pages: Mutex::default(),
        }
    }

    /// How many pages were read.
    #[must_use]
    pub fn pages_read(&self) -> u64 {
        *self.pages.lock().unwrap()
    }
}

/// The record at `index`, newest first, of a fake log.
fn entry_at(index: u128, newest: OffsetDateTime) -> AuditLogEntry {
    let seconds = i64::try_from(index).unwrap_or(i64::MAX);
    AuditLogEntry {
        id: AuditRecordId::from_uuid(uuid::Uuid::from_u128(index + 1)),
        event_type: EventType::parse("tenant.audit_chain_broken").expect("a known event type"),
        actor_display: "System".to_owned(),
        tenant_id: None,
        tenant_slug: None,
        tenant_name: None,
        target: AuditTarget::Untargeted,
        ip_address: None,
        payload: EventData::new(),
        acted_through: ianua_domain::domains::audit::builder::ActedThrough::Directly,
        occurred_at: newest - time::Duration::seconds(seconds),
    }
}

#[async_trait]
impl AuditExportSource for FakeAuditExportSource {
    async fn page(&self, page: ExportPage<'_>) -> Result<Vec<AuditLogEntry>, DomainError> {
        if self.failing {
            return Err(DomainError::infra_msg("the audit log is unreachable"));
        }
        *self.pages.lock().unwrap() += 1;
        let first = match page.start {
            ExportPageStart::Newest => 0,
            ExportPageStart::OlderThan(cursor) => cursor.id.as_uuid().as_u128(),
        };
        let last = self.records.min(first + u128::from(page.limit.get()));
        Ok((first..last)
            .map(|index| entry_at(index, page.until))
            .collect())
    }
}

impl Fake for Arc<dyn AuditExportSource> {
    fn fake() -> Self {
        Arc::new(FakeAuditExportSource::default())
    }
}

/// What a [`FakeAuditExportFiles`] holds of one file.
#[derive(Debug, Clone, Copy, Default)]
struct FileState {
    rows: u64,
    finished: bool,
    deleted: bool,
}

/// Export files kept as counts: how many records each holds, whether it
/// was finished, whether it was deleted. Or a store that is down.
#[derive(Default)]
pub struct FakeAuditExportFiles {
    files: Arc<Mutex<HashMap<AuditExportId, FileState>>>,
    failing: bool,
}

impl FakeAuditExportFiles {
    /// A store that fails every call.
    #[must_use]
    pub fn failing() -> Self {
        Self {
            files: Arc::default(),
            failing: true,
        }
    }

    /// How many records were written into the file of `id`.
    #[must_use]
    pub fn rows_written(&self, id: &AuditExportId) -> u64 {
        self.state(id).rows
    }

    /// Whether the file of `id` was finished.
    #[must_use]
    pub fn finished(&self, id: &AuditExportId) -> bool {
        self.state(id).finished
    }

    /// Whether the file of `id` was deleted.
    #[must_use]
    pub fn deleted(&self, id: &AuditExportId) -> bool {
        self.state(id).deleted
    }

    fn state(&self, id: &AuditExportId) -> FileState {
        self.files
            .lock()
            .unwrap()
            .get(id)
            .copied()
            .unwrap_or_default()
    }
}

/// What a failing [`FakeAuditExportFiles`] says is unreachable.
const FILE_STORE: &str = "the file store";

/// One fake file being written.
struct FakeUpload {
    id: AuditExportId,
    files: Arc<Mutex<HashMap<AuditExportId, FileState>>>,
}

#[async_trait]
impl AuditExportUpload for FakeUpload {
    async fn append(&mut self, entries: &[AuditLogEntry]) -> Result<(), DomainError> {
        let added = u64::try_from(entries.len()).unwrap_or(u64::MAX);
        let mut files = self.files.lock().unwrap();
        let file = files.entry(self.id).or_default();
        file.rows = file.rows.saturating_add(added);
        Ok(())
    }

    async fn finish(self: Box<Self>) -> Result<FileDigest, DomainError> {
        self.files
            .lock()
            .unwrap()
            .entry(self.id)
            .or_default()
            .finished = true;
        Ok(fake_file_digest())
    }
}

#[async_trait]
impl AuditExportFiles for FakeAuditExportFiles {
    async fn create(
        &self,
        id: &AuditExportId,
        _: AuditExportFormat,
    ) -> Result<Box<dyn AuditExportUpload>, DomainError> {
        unless_failing(self.failing, FILE_STORE)?;
        self.files.lock().unwrap().insert(*id, FileState::default());
        Ok(Box::new(FakeUpload {
            id: *id,
            files: self.files.clone(),
        }))
    }

    async fn download_link(
        &self,
        id: &AuditExportId,
        _: OffsetDateTime,
    ) -> Result<HttpsUrl, DomainError> {
        unless_failing(self.failing, FILE_STORE)?;
        HttpsUrl::new(format!("https://files.ianua.test/audit-exports/{id}"))
            .map_err(DomainError::from)
    }

    async fn delete(&self, id: &AuditExportId) -> Result<(), DomainError> {
        unless_failing(self.failing, FILE_STORE)?;
        self.files.lock().unwrap().entry(*id).or_default().deleted = true;
        Ok(())
    }
}

impl Fake for Arc<dyn AuditExportFiles> {
    fn fake() -> Self {
        Arc::new(FakeAuditExportFiles::default())
    }
}

impl Fake for Arc<dyn AuditChainVerifier> {
    fn fake() -> Self {
        Arc::new(FakeAuditChainVerifier)
    }
}

/// Evidence store whose chain holds records 1 to 3, all of the one agent it
/// names. Every other agent has none.
pub struct FakeEvidenceStore(pub AgentId);

impl TenantScoped for FakeEvidenceStore {}

#[async_trait]
impl EvidenceStore for FakeEvidenceStore {
    async fn agent_records(
        &self,
        _: &ScopedTenant,
        agent: &AgentId,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<EvidenceRecord>, DomainError> {
        if *agent != self.0 {
            return Ok(Vec::new());
        }
        Ok(EVIDENCE_SEQS
            .filter(|seq| *seq > after_seq)
            .take(limit as usize)
            .map(evidence_record)
            .collect())
    }

    async fn records_of(
        &self,
        _: &ScopedTenant,
        agent: &AgentId,
        seqs: &[i64],
    ) -> Result<Vec<i64>, DomainError> {
        if *agent != self.0 {
            return Ok(Vec::new());
        }
        Ok(seqs
            .iter()
            .copied()
            .filter(|seq| EVIDENCE_SEQS.contains(seq))
            .collect())
    }
}

impl Fake for Arc<dyn EvidenceStore> {
    fn fake() -> Self {
        Arc::new(FakeEvidenceStore(AgentId::new()))
    }
}

/// The record at `seq` in a fake chain: an authorized agent action.
fn evidence_record(seq: i64) -> EvidenceRecord {
    EvidenceRecord {
        seq,
        id: EvidenceId::new(),
        event_type: EventType::parse("agents.action_authorized").expect("a known event type"),
        payload: EventData::new(),
        occurred_at: clock::now(),
        entry_hash: vec![1; 32],
        prev_hash: vec![0; 32],
    }
}

/// Organization audit log with no entries.
pub struct NoopOrgAuditLogStore;

#[async_trait]
impl OrgAuditLogStore for NoopOrgAuditLogStore {
    async fn query(
        &self,
        _: &ianua_domain::domains::audit::access::OrgLogView,
        _: &AuditLogFilter,
        _: &SortOrder<AuditLogSortField>,
        page: &PageRequest,
    ) -> Result<AuditLogPage, DomainError> {
        Ok(Page::last(Vec::new(), page.limit()))
    }
}

impl Fake for Arc<dyn OrgAuditLogStore> {
    fn fake() -> Self {
        Arc::new(NoopOrgAuditLogStore)
    }
}

/// Tenant and platform audit logs that note whose log was asked for, with
/// what filter, and hold no entries.
#[derive(Default)]
pub struct WatchedAuditLog {
    asked: Mutex<Vec<(Option<TenantId>, AuditLogFilter)>>,
}

impl WatchedAuditLog {
    /// Whose log each query read, `None` for the whole platform's, with the
    /// filter it was asked with, in order.
    #[must_use]
    pub fn asked(&self) -> Vec<(Option<TenantId>, AuditLogFilter)> {
        self.asked.lock().unwrap().clone()
    }

    /// Notes one query and answers it with no entries.
    fn answer(
        &self,
        tenant: Option<TenantId>,
        filter: &AuditLogFilter,
        page: &PageRequest,
    ) -> AuditLogPage {
        self.asked.lock().unwrap().push((tenant, filter.clone()));
        Page::last(Vec::new(), page.limit())
    }
}

impl TenantScoped for WatchedAuditLog {}

#[async_trait]
impl TenantAuditLogStore for WatchedAuditLog {
    async fn query(
        &self,
        tenant_id: &ScopedTenant,
        filter: &AuditLogFilter,
        _: &SortOrder<AuditLogSortField>,
        page: &PageRequest,
    ) -> Result<AuditLogPage, DomainError> {
        Ok(self.answer(Some(**tenant_id), filter, page))
    }
}

#[async_trait]
impl PlatformAuditLogStore for WatchedAuditLog {
    async fn query(
        &self,
        filter: &AuditLogFilter,
        _: &SortOrder<AuditLogSortField>,
        page: &PageRequest,
    ) -> Result<AuditLogPage, DomainError> {
        Ok(self.answer(None, filter, page))
    }
}

impl Fake for Arc<dyn TenantAuditLogStore> {
    fn fake() -> Self {
        Arc::new(WatchedAuditLog::default())
    }
}

impl Fake for Arc<dyn PlatformAuditLogStore> {
    fn fake() -> Self {
        Arc::new(WatchedAuditLog::default())
    }
}
