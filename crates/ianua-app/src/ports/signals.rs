//! Signals-specific ports.

use std::num::NonZeroU32;

use async_trait::async_trait;
use ianua_domain::domains::signals::delivery::{SignalDeliveryAttempt, SignalDeliveryStatus};
use ianua_domain::domains::signals::stream::{ChallengeToSend, SignalStream, StreamStatus};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::shared::validation::numeric::validate_range;
use ianua_domain::types::{
    AgentId, DeliveryOutcome, PublicHttpsUrl, SignalId, SignalStreamId, TokenHash,
};
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field a signal stream listing can be ordered by.
    pub enum StreamSortField {
        /// Order by registration time.
        CreatedAt => "created_at",
        /// Order by delivery status.
        Status => "status",
        /// Order by receiver endpoint URL.
        Endpoint => "endpoint",
    }
    default = CreatedAt;
    default direction = Desc;
}

define_sort_field! {
    /// Field a signal delivery-attempt listing can be ordered by.
    pub enum StreamDeliverySortField {
        /// Order by when the attempt was made.
        AttemptedAt => "attempted_at",
        /// Order by delivery outcome.
        Status => "status",
    }
    default = AttemptedAt;
    default direction = Desc;
}

impl SortKeys<StreamSortField> for SignalStream<ResolvedTenant> {
    fn sort_key(&self, field: StreamSortField) -> SortKey {
        match field {
            StreamSortField::CreatedAt => self.created_at().into(),
            StreamSortField::Status => stream_status_word(self.status()).into(),
            StreamSortField::Endpoint => self.endpoint().as_str().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// The word a stream's status sorts by, as it is stored.
fn stream_status_word(status: StreamStatus) -> &'static str {
    match status {
        StreamStatus::Active => "active",
        StreamStatus::Paused => "paused",
        StreamStatus::Disabled => "disabled",
    }
}

impl SortKeys<StreamDeliverySortField> for SignalDeliveryAttempt {
    fn sort_key(&self, field: StreamDeliverySortField) -> SortKey {
        match field {
            StreamDeliverySortField::AttemptedAt => self.attempted_at.into(),
            StreamDeliverySortField::Status => delivery_status_word(self.delivery.status()).into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id.as_uuid().into()
    }
}

/// The word a signal delivery's outcome sorts by, as it is stored.
fn delivery_status_word(status: SignalDeliveryStatus) -> &'static str {
    match status {
        SignalDeliveryStatus::Success => "success",
        SignalDeliveryStatus::Failed => "failed",
        SignalDeliveryStatus::Timeout => "timeout",
        SignalDeliveryStatus::Unreachable => "unreachable",
        SignalDeliveryStatus::Queued => "queued",
    }
}

/// The endpoint challenge a save writes with a stream.
///
/// A stream never hands its challenge back. It goes out once, as the
/// [`ChallengeToSend`] that registering the stream or moving its endpoint
/// returns, so the save after either passes it here. Every other save keeps
/// what is stored.
#[derive(Debug, Clone, Copy)]
pub enum StreamChallenge<'a> {
    /// Keep the stored challenge while the endpoint is still pending, and
    /// drop it once the stream says its endpoint is verified.
    Kept,
    /// Store this challenge, just handed out for the stream's endpoint.
    Issued(&'a ChallengeToSend),
}

/// Dyn-safe port for persisting and retrieving signal streams and their
/// delivery history.
#[async_trait]
pub trait SignalStreamStore: Send + Sync + TenantScoped {
    /// Finds a stream by its ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SignalStreamId,
    ) -> Result<Option<SignalStream<ResolvedTenant>>, DomainError>;

    /// Lists streams for the tenant with optional status filter, ordering, and
    /// pagination.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<StreamStatus>,
        sort: &SortOrder<StreamSortField>,
        page: &PageRequest,
    ) -> Result<Page<SignalStream<ResolvedTenant>>, DomainError>;

    /// Lists every active stream for the tenant, unpaginated.
    ///
    /// Signal dispatch fans out to *all* matching receivers in one pass, so
    /// there is no use for a partial page here, unlike the admin-facing
    /// `list_all`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_active(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<SignalStream<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated stream, with the endpoint challenge
    /// `challenge` says to write.
    ///
    /// The stored row holds the challenge while the endpoint is pending, so
    /// a stream read back later can still confirm the echo.
    ///
    /// # Errors
    ///
    /// - `DomainError::Validation` when `challenge` was issued for another
    ///   endpoint than the stream's, or a stream waiting on its endpoint is
    ///   saved with no challenge issued or stored for it.
    /// - `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        stream: &SignalStream<ResolvedTenant>,
        challenge: StreamChallenge<'_>,
    ) -> Result<(), DomainError>;

    /// Deletes a stream by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &SignalStreamId,
    ) -> Result<(), DomainError>;

    /// Lists delivery attempts for a stream with ordering and pagination.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_deliveries(
        &self,
        tenant_id: &ScopedTenant,
        stream_id: &SignalStreamId,
        sort: &SortOrder<StreamDeliverySortField>,
        page: &PageRequest,
    ) -> Result<Page<SignalDeliveryAttempt>, DomainError>;

    /// Records a delivery attempt.
    ///
    /// `attempt.stream_id` is scoped to `tenant_id` via a join through
    /// `signal_streams`: a cross-tenant id silently writes nothing rather
    /// than trusting the caller's `tenant_id` directly.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn record_delivery(
        &self,
        tenant_id: &ScopedTenant,
        attempt: &SignalDeliveryAttempt,
    ) -> Result<(), DomainError>;
}

/// Outcome of an outbound signal push.
#[derive(Debug, Clone, Copy)]
pub struct SignalDeliveryOutcome {
    /// How the push ended, with the code the receiver answered with.
    pub outcome: DeliveryOutcome,
    /// Round-trip duration in milliseconds.
    pub duration_ms: u32,
}

/// A signed Security Event Token in compact JWS form, ready to push or to
/// hold for a receiver that polls.
///
/// It names a user or agent and what happened to them, so its `Debug` shows
/// nothing of it and it is never logged.
#[derive(Clone, PartialEq, Eq)]
pub struct SecurityEventToken(String);

impl SecurityEventToken {
    /// The token `jws`, as the JWT signer returned it.
    #[must_use]
    pub fn new(jws: String) -> Self {
        Self(jws)
    }

    /// The compact JWS, to send as the request body.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecurityEventToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecurityEventToken(..)")
    }
}

/// What one push sends in the `Authorization` header, opened from the
/// stream's sealed copy for that push alone.
///
/// The value is the receiver's own credential. The adapter sets it as the
/// header and never logs it or puts it in an error.
#[derive(Debug, Clone)]
pub enum ReceiverCredential {
    /// The receiver asked for no header, so none is sent.
    Omitted,
    /// The header value to send.
    Header(Secret),
}

/// One push of a Security Event Token to a stream's endpoint.
#[derive(Debug, Clone, Copy)]
pub struct SetPush<'a> {
    /// Where the token goes.
    pub endpoint: &'a PublicHttpsUrl,
    /// The signed token, sent as `application/secevent+jwt`.
    pub token: &'a SecurityEventToken,
    /// What to send in the `Authorization` header.
    pub credential: &'a ReceiverCredential,
}

/// Dyn-safe port for pushing a signed Security Event Token to a receiver
/// (RFC 8935).
///
/// Unlike webhooks' HMAC-over-JSON, the SET's own signature is the
/// authenticity mechanism. The receiver's `Authorization` header, when it
/// asked for one, tells it the push comes from the transmitter it set up.
/// Verification events, the endpoint challenge among them, go out the same
/// way as signals.
#[async_trait]
pub trait SignalDeliverer: Send + Sync {
    /// POSTs `push.token` to `push.endpoint`, with the `Authorization`
    /// header `push.credential` names.
    ///
    /// The adapter checks again, when it connects, that the endpoint
    /// resolves to a public address, and gives up after a fixed timeout so a
    /// receiver that hangs cannot hold the dispatch. A timeout is reported
    /// as [`DeliveryOutcome::TimedOut`].
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` if the URL resolves to a blocked
    /// address. Transport failures are reported in the returned
    /// [`SignalDeliveryOutcome`], not as `Err`.
    async fn deliver(&self, push: SetPush<'_>) -> Result<SignalDeliveryOutcome, DomainError>;
}

/// A Security Event Token held for a poll stream until its receiver
/// acknowledges it (RFC 8936).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedEvent {
    /// The token's `jti`, which the receiver acknowledges it by.
    pub jti: SignalId,
    /// The signed token.
    pub token: SecurityEventToken,
}

/// How many events one poll hands back at most: from 1 to
/// [`PollBatch::MOST`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollBatch(u16);

impl PollBatch {
    /// The most events one poll hands back.
    pub const MOST: u16 = 100;

    /// A batch of at most `count` events.
    ///
    /// # Errors
    ///
    /// `DomainError::Validation` when `count` is 0 or above
    /// [`PollBatch::MOST`].
    pub fn new(count: u16) -> Result<Self, DomainError> {
        validate_range("max_events", count, 1..=Self::MOST)?;
        Ok(Self(count))
    }

    /// The largest batch, for a poll that names no size.
    #[must_use]
    pub fn largest() -> Self {
        Self(Self::MOST)
    }

    /// How many events, at most.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }
}

/// Whether more events wait after the ones a poll handed back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backlog {
    /// Every waiting event was handed back.
    Drained,
    /// More wait; the receiver polls again.
    MoreWaiting,
}

/// What one poll hands back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolledEvents {
    /// The events not yet acknowledged, oldest first.
    pub events: Vec<QueuedEvent>,
    /// Whether more wait beyond them.
    pub backlog: Backlog,
}

/// Dyn-safe port holding the events of poll streams until their receivers
/// acknowledge them (RFC 8936).
///
/// Every call is scoped to the tenant through the stream it names, so a
/// stream id from another tenant reads and changes nothing. Deleting a
/// stream drops what it held.
#[async_trait]
pub trait SignalPollQueue: Send + Sync + TenantScoped {
    /// Holds `event` for the stream `stream_id` until it is acknowledged.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn enqueue(
        &self,
        tenant_id: &ScopedTenant,
        stream_id: &SignalStreamId,
        event: &QueuedEvent,
    ) -> Result<(), DomainError>;

    /// Drops the events `jtis` names from the stream's queue. A `jti` the
    /// queue does not hold is passed over.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn acknowledge(
        &self,
        tenant_id: &ScopedTenant,
        stream_id: &SignalStreamId,
        jtis: &[SignalId],
    ) -> Result<(), DomainError>;

    /// The oldest events the stream holds, at most `batch` of them, without
    /// dropping any: an event goes only once it is acknowledged.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn next(
        &self,
        tenant_id: &ScopedTenant,
        stream_id: &SignalStreamId,
        batch: PollBatch,
    ) -> Result<PolledEvents, DomainError>;
}

/// Dyn-safe port letting a stream's receiver ask for a verification event
/// only now and then.
///
/// Each request makes the platform sign a token and call the receiver's
/// endpoint, so without a bound one receiver could turn the transmitter
/// into a source of requests at its own pace. The adapter counts per
/// stream in a short window, held in the process like the API rate limit.
#[async_trait]
pub trait VerificationThrottle: Send + Sync + TenantScoped {
    /// Whether the stream `stream_id` may be sent a verification event it
    /// asked for now. Admitting counts as the window's request.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the allowance cannot be read.
    async fn admit(
        &self,
        tenant_id: &ScopedTenant,
        stream_id: &SignalStreamId,
    ) -> Result<bool, DomainError>;
}

/// Dyn-safe port making the key a stream's receiver manages its stream
/// with, and hashing a presented one.
///
/// The key is handed to the receiver once, when its stream is registered,
/// and only its digest is kept. The receiver presents it to poll its
/// stream, ask for verification events and say whom it hears about, never
/// one of the tenant's API keys.
#[async_trait]
pub trait ReceiverKeys: Send + Sync {
    /// A new random key and the digest it is kept by.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the randomness source
    /// fails.
    async fn generate(&self) -> Result<(Secret, TokenHash), DomainError>;

    /// The digest of a key a receiver presented, under the same key
    /// [`generate`](Self::generate) hashed with.
    fn hash_presented(&self, presented: &Secret) -> TokenHash;
}

/// Dyn-safe port reading which agents a tenant-wide stop suspended, so
/// every receiver hears of each one as it would of one agent suspended.
///
/// The stop suspends every active agent in one statement and records how
/// many, not which. The statement stamps each agent it suspends with its
/// time, and this reads them back by it.
#[async_trait]
pub trait SuspendedAgents: Send + Sync + TenantScoped {
    /// The tenant's agents that are suspended now and were last changed at
    /// or after `since`, at most `limit` of them.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be read, or
    /// the read does not answer within ten seconds.
    async fn suspended_since(
        &self,
        tenant_id: &ScopedTenant,
        since: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<AgentId>, DomainError>;
}
