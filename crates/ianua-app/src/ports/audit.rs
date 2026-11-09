//! Audit ports: the chain's integrity and its kept verdicts, reading the
//! log, exporting it in the background, streaming records to a SIEM,
//! removing them once their retention ends, and moving a deleted tenant's
//! trail to the platform's database.

use std::num::NonZeroU32;

use async_trait::async_trait;
use ianua_domain::domains::audit::access::{AuditLogOf, OrgLogView};
use ianua_domain::domains::audit::builder::ActedThrough;
use ianua_domain::domains::audit::checkpoint::ChainStart;
use ianua_domain::domains::audit::evidence::EvidenceRecord;
use ianua_domain::domains::audit::export::AuditLogExport;
use ianua_domain::domains::audit::export::filter::{AuditExportFilter, AuditExportFormat};
use ianua_domain::domains::audit::export::seal::FileDigest;
use ianua_domain::domains::audit::record::{AuditRecord, AuditTarget};
use ianua_domain::domains::audit::streaming::StreamDestination;
use ianua_domain::domains::audit::verdict::ChainVerdict;
use ianua_domain::domains::audit::walk::ChainStretch;
use ianua_domain::domains::tenant::audit_streams::AuditStream;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::data::EventData;
use ianua_domain::types::{
    ActorRef, AgentId, AuditExportId, AuditRecordId, AuditStreamId, DisplayName, Email, EventType,
    HttpsUrl, IpAddress, TenantId, TenantSlug, UserId,
};
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::authentication::SealedFor;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for verifying a tenant's tamper-evident audit chain.
///
/// The adapter rehashes the tenant's hash-linked records in order; any
/// removed, reordered, or edited record breaks the chain. Only the scheduled
/// sweep walks it, a bounded stretch at a time, and keeps its verdict in
/// [`AuditChainVerdictStore`]; a request reads that verdict and never walks
/// the chain itself.
#[async_trait]
pub trait AuditChainVerifier: Send + Sync + TenantScoped {
    /// Rehashes at most `limit` records of the tenant's chain after
    /// `start`, oldest first, in one bounded read.
    ///
    /// From [`ChainStart::After`] the adapter takes the checkpoint's hash
    /// as the link before the first record it reads. When a retention purge
    /// removed records past the checkpoint, it starts from the anchor the
    /// purge left instead. With no record after `start` it checks the
    /// chain's signed head against the last link, answering
    /// [`ChainStretch::Ended`] when it matches and a break when the newest
    /// records were cut off. It gives up after a few seconds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the chain cannot be read
    /// in time.
    async fn verify_stretch(
        &self,
        tenant_id: &ScopedTenant,
        start: &ChainStart,
        limit: NonZeroU32,
    ) -> Result<ChainStretch, DomainError>;
}

/// Dyn-safe port keeping the last verdict of each tenant's audit chain.
#[async_trait]
pub trait AuditChainVerdictStore: Send + Sync + TenantScoped {
    /// The tenant's last verdict, or `None` before the first sweep.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure, or when the
    /// stored row breaks a rule the verdict keeps.
    async fn find(&self, tenant_id: &ScopedTenant) -> Result<Option<ChainVerdict>, DomainError>;

    /// Keeps `verdict` as the tenant's last, replacing the one before.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        verdict: &ChainVerdict,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port for reading an agent's audit records as evidence.
#[async_trait]
pub trait EvidenceStore: Send + Sync + TenantScoped {
    /// The agent's records after `after_seq`, oldest first, at most `limit`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn agent_records(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<EvidenceRecord>, DomainError>;

    /// Which of `seqs` are records of `agent` in the tenant's chain.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn records_of(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
        seqs: &[i64],
    ) -> Result<Vec<i64>, DomainError>;
}

define_sort_field! {
    /// Field an audit-log listing can be ordered by.
    pub enum AuditLogSortField {
        /// Order by when the event occurred.
        OccurredAt => "occurred_at",
        /// Order by event type.
        EventType => "event_type",
    }
    default = OccurredAt;
    default direction = Desc;
}

/// Filter options for audit log queries. Each field left `None` narrows
/// nothing.
#[derive(Debug, Clone, Default)]
pub struct AuditLogFilter {
    /// Filter by event type prefix (e.g. "organization.org_user").
    pub event_type: Option<String>,
    /// Only events after this time.
    pub after: Option<OffsetDateTime>,
    /// Only events before this time.
    pub before: Option<OffsetDateTime>,
    /// Only events this actor performed.
    pub actor: Option<ActorRef>,
    /// Only events in this tenant. A tenant's own log is always its own,
    /// whatever this says.
    pub tenant_id: Option<TenantId>,
    /// Only events that affected this entity, by id.
    pub target: Option<String>,
    /// Only events from this address.
    pub ip_address: Option<IpAddress>,
    /// Only events whose details name this person, for the records about
    /// someone that they did not make themselves, such as a failed sign-in
    /// at their address.
    pub names: Option<NamedInRecord>,
    /// Only the records of this person's sign-ins, as [`SignInsOf`] says.
    pub sign_ins_of: Option<SignInsOf>,
    /// Only what was done while acting as this person: by an operator
    /// impersonating them, or by an admin acting as them for support.
    pub acting_as: Option<UserId>,
}

/// Whose sign-ins a log is narrowed to: the sign-ins the person made, the
/// lockouts of their account, and the failed attempts typed with an address
/// while their account held it. A failed attempt names only the address
/// typed, and nobody signed in to make it, so the address and the time are
/// all that tie it to the person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInsOf {
    /// The account.
    pub user: UserId,
    /// Every address the account held, each with when.
    pub addresses: Vec<HeldAddress>,
}

/// An address an account held, and over what time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldAddress {
    /// The mailbox held during this interval.
    pub address: Email,
    /// When the account took it, or `None` when it held it from before
    /// anything the trail keeps.
    pub since: Option<OffsetDateTime>,
    /// When the account gave it up, or `None` while it still holds it.
    pub until: Option<OffsetDateTime>,
}

/// How a record's details name a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamedInRecord {
    /// By the address given for them, such as the one typed into a failed
    /// sign-in. Compared without regard to case.
    Address(Email),
    /// By a reference to their account, under the `user` detail, such as
    /// the account a lockout locked.
    Account(UserId),
}

/// A single audit log entry with human-readable actor name.
pub struct AuditLogEntry {
    /// Unique record ID.
    pub id: AuditRecordId,
    /// The kind of action captured by this record.
    pub event_type: EventType,
    /// Human-readable actor name (e.g. "Ada Lovelace (ada@acme.com)").
    pub actor_display: String,
    /// The tenant the event occurred in, or `None` for org- or platform-level
    /// events.
    pub tenant_id: Option<TenantId>,
    /// The tenant's URL slug, when the event is tenant-scoped.
    pub tenant_slug: Option<TenantSlug>,
    /// The tenant's display name, when the event is tenant-scoped.
    pub tenant_name: Option<DisplayName>,
    /// The entity the event affected, if any.
    pub target: AuditTarget,
    /// Source IP.
    pub ip_address: Option<IpAddress>,
    /// Event payload.
    pub payload: EventData,
    /// Whom or what the actor acted through: in their own name, as an
    /// operator or administrator impersonating someone, or as the person a
    /// workflow run acts for, through that run.
    pub acted_through: ActedThrough,
    /// When the event occurred.
    pub occurred_at: OffsetDateTime,
}

impl SortKeys<AuditLogSortField> for AuditLogEntry {
    fn sort_key(&self, field: AuditLogSortField) -> SortKey {
        match field {
            AuditLogSortField::OccurredAt => self.occurred_at.into(),
            AuditLogSortField::EventType => self.event_type.as_str().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id.as_uuid().into()
    }
}

/// One page of an audit log query, the entries with resolved actor names.
pub type AuditLogPage = Page<AuditLogEntry>;

/// Port for querying the org-scoped audit log.
#[async_trait]
pub trait OrgAuditLogStore: Send + Sync {
    /// The entries of `view`'s organization that `filter` admits, with
    /// actor names resolved: its own records and those of the tenants
    /// `view` reaches. A filter naming a tenant it does not reach admits
    /// nothing.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn query(
        &self,
        view: &OrgLogView,
        filter: &AuditLogFilter,
        sort: &SortOrder<AuditLogSortField>,
        page: &PageRequest,
    ) -> Result<AuditLogPage, DomainError>;
}

/// Port for querying one tenant's own audit log.
#[async_trait]
pub trait TenantAuditLogStore: Send + Sync + TenantScoped {
    /// The tenant's audit log entries `filter` admits, with actor names
    /// resolved. Never an entry of another tenant, whatever the filter's
    /// tenant says.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn query(
        &self,
        tenant_id: &ScopedTenant,
        filter: &AuditLogFilter,
        sort: &SortOrder<AuditLogSortField>,
        page: &PageRequest,
    ) -> Result<AuditLogPage, DomainError>;
}

/// Port for querying the audit log across the whole platform, for
/// operators.
#[async_trait]
pub trait PlatformAuditLogStore: Send + Sync {
    /// Every audit log entry `filter` admits, platform, organization and
    /// tenant alike, with actor names resolved.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn query(
        &self,
        filter: &AuditLogFilter,
        sort: &SortOrder<AuditLogSortField>,
        page: &PageRequest,
    ) -> Result<AuditLogPage, DomainError>;
}

/// Dyn-safe port for the streams that send a tenant's audit records to a
/// SIEM.
#[async_trait]
pub trait AuditStreamStore: Send + Sync + TenantScoped {
    /// The tenant's stream `id`, or `None` when it has none.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure, or when the
    /// stored row breaks a rule the stream keeps.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        id: &AuditStreamId,
    ) -> Result<Option<AuditStream<ResolvedTenant>>, DomainError>;

    /// Every stream of the tenant, oldest first. A tenant keeps a handful
    /// at most, so there is no page.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<AuditStream<ResolvedTenant>>, DomainError>;

    /// Saves a new or changed stream.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        stream: &AuditStream<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes the stream `id`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(&self, tenant_id: &ScopedTenant, id: &AuditStreamId)
    -> Result<(), DomainError>;
}

/// Dyn-safe port sending one audit record to a stream's destination:
/// Splunk's event collector, Datadog's log intake, a syslog collector over
/// TLS, or an HTTPS endpoint.
///
/// The adapter must:
/// - bound every send with a timeout, connecting and in all, so a
///   destination that hangs never holds the worker;
/// - resolve the destination's host again on every send and refuse an
///   address that is not public (loopback, private, link-local, metadata),
///   so a name that once pointed outside cannot be turned inward later;
/// - follow no redirect;
/// - open the sealed credentials only to send, and never log them, the
///   record's body, or the destination's answer.
#[async_trait]
pub trait AuditStreamSender: Send + Sync {
    /// Sends `record` to `destination`, opening its sealed credentials for
    /// `credentials`, the place the stream keeps them.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when the destination's host no
    /// longer resolves to a public address, and
    /// `DomainError::Infrastructure` when a credential does not open there,
    /// or the destination cannot be reached in time or refuses the record.
    async fn send(
        &self,
        destination: &StreamDestination,
        credentials: &SealedFor,
        record: &AuditRecord,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port removing a tenant's audit records once their retention
/// ended.
#[async_trait]
pub trait AuditRetentionStore: Send + Sync + TenantScoped {
    /// Removes the tenant's audit records that happened before `cutoff`,
    /// and returns how many went.
    ///
    /// The adapter keeps the tenant's chain verifiable: it records the hash
    /// of the last record removed as the chain's new anchor in the same
    /// transaction, so a purge never reads as a broken chain and a record
    /// removed any other way still does.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure; nothing
    /// is removed then.
    async fn purge_before(
        &self,
        tenant_id: &ScopedTenant,
        cutoff: OffsetDateTime,
    ) -> Result<u64, DomainError>;
}

/// Dyn-safe port moving a deleted tenant's audit trail out of the database
/// of its own, which its teardown removes next.
///
/// Not [`TenantScoped`]: it reads from the tenant's database and writes to
/// the platform's.
#[async_trait]
pub trait AuditTrailMover: Send + Sync {
    /// Copies every audit record of `tenant_id`, with its chain's head and
    /// anchor, from the tenant's own database to the platform's, so the
    /// chain still verifies there and its retention still runs. A record
    /// moved already is not moved twice, so a retry is safe; a tenant on
    /// the platform's database has nothing to move.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a database does not
    /// answer; the tenant's own copy is kept until every record arrived.
    async fn move_to_platform(&self, tenant_id: &TenantId) -> Result<(), DomainError>;
}

/// Dyn-safe port keeping exports of the audit logs.
///
/// An export is found only under the log it exports, so an id from one
/// log never finds another log's export.
#[async_trait]
pub trait AuditExportStore: Send + Sync {
    /// Saves a new or changed export.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(&self, export: &AuditLogExport) -> Result<(), DomainError>;

    /// The export `id` of `log`, or `None` when that log has none.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure, or when the
    /// stored row breaks a rule the export keeps.
    async fn find(
        &self,
        log: AuditLogOf,
        id: &AuditExportId,
    ) -> Result<Option<AuditLogExport>, DomainError>;

    /// How many of `log`'s exports the worker is still writing.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn pending_count(&self, log: AuditLogOf) -> Result<u64, DomainError>;

    /// At most `limit` exports of any log due to end at `now`, oldest
    /// first: pending past their write deadline, or ready past their
    /// download window.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn due_to_end(
        &self,
        now: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<AuditLogExport>, DomainError>;
}

/// The last record an export page held, which the next page starts
/// strictly older than.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditLogCursor {
    /// When the record happened.
    pub occurred_at: OffsetDateTime,
    /// The record's id, which orders records of the same moment.
    pub id: AuditRecordId,
}

impl AuditLogCursor {
    /// The cursor just past `entry`.
    #[must_use]
    pub fn past(entry: &AuditLogEntry) -> Self {
        Self {
            occurred_at: entry.occurred_at,
            id: entry.id,
        }
    }
}

/// Where a page of an export starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportPageStart {
    /// At the newest record the export covers.
    Newest,
    /// Just older than the last record written.
    OlderThan(AuditLogCursor),
}

/// One page of the records an export holds.
pub struct ExportPage<'a> {
    /// The log read.
    pub log: AuditLogOf,
    /// Which records it holds.
    pub filter: &'a AuditExportFilter,
    /// The newest moment it covers.
    pub until: OffsetDateTime,
    /// Where the page starts.
    pub start: ExportPageStart,
    /// The most records the page holds.
    pub limit: NonZeroU32,
}

/// Dyn-safe port reading an audit log for an export, a keyset page at a
/// time.
#[async_trait]
pub trait AuditExportSource: Send + Sync {
    /// The records of `page.log` its filter admits, at or before
    /// `page.until`, newest first by when they happened and then by id,
    /// from `page.start`, at most `page.limit`, with actor names resolved.
    /// A tenant's log is always its own, whatever the filter's tenant
    /// says. One bounded read, given up after a few seconds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the log cannot be read in
    /// time.
    async fn page(&self, page: ExportPage<'_>) -> Result<Vec<AuditLogEntry>, DomainError>;
}

/// Dyn-safe port for the files audit log exports are kept in, in private
/// storage.
#[async_trait]
pub trait AuditExportFiles: Send + Sync {
    /// Starts the file of export `id`, written as `format`, replacing any
    /// half-written one a failed attempt left.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the file cannot be
    /// started.
    async fn create(
        &self,
        id: &AuditExportId,
        format: AuditExportFormat,
    ) -> Result<Box<dyn AuditExportUpload>, DomainError>;

    /// A link that downloads the file of export `id` once, signed by the
    /// adapter and working for a few minutes and never past
    /// `available_until`. It carries no secret of the caller.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the file is gone or no link
    /// can be made.
    async fn download_link(
        &self,
        id: &AuditExportId,
        available_until: OffsetDateTime,
    ) -> Result<HttpsUrl, DomainError>;

    /// Deletes the file of export `id`. Deleting one already gone succeeds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the file cannot be deleted.
    async fn delete(&self, id: &AuditExportId) -> Result<(), DomainError>;
}

/// One export file being written, a page at a time. Each call gives up
/// after a few seconds.
#[async_trait]
pub trait AuditExportUpload: Send {
    /// Writes `entries` after those written before, in the file's format.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be written.
    async fn append(&mut self, entries: &[AuditLogEntry]) -> Result<(), DomainError>;

    /// Closes the file, so it can be downloaded whole, and answers the
    /// SHA-256 of every byte written into it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be closed.
    async fn finish(self: Box<Self>) -> Result<FileDigest, DomainError>;
}
