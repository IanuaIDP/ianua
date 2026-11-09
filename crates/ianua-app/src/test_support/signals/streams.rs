//! The signal stream store fake, and the stream rows tests start from.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::signals::delivery::{ReceiverAuthorization, SignalDeliveryAttempt};
use ianua_domain::domains::signals::signal::SecuritySignalType;
use ianua_domain::domains::signals::stream::{
    ChallengeToSend, DeliveryMethod, EndpointChallenge, EndpointVerification, SignalStream,
    SignalStreamRow, StreamStatus, StreamVerificationStatus,
};
use ianua_domain::domains::signals::subjects::{DefaultSubjects, StreamSubjects};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{PublicHttpsUrl, SignalStreamId, TenantId, TokenHash};
use time::OffsetDateTime;

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::signals::{
    ReceiverKeys, SignalStreamStore, StreamChallenge, StreamDeliverySortField, StreamSortField,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::listing::page;

/// The challenge every [`test_stream`] waiting on its endpoint was sent.
pub const TEST_CHALLENGE: &str = "test-challenge-the-endpoint-was-sent-0001";

/// The key every [`test_stream`]'s receiver manages it with, and the first
/// one [`FakeReceiverKeys`] makes.
pub const TEST_RECEIVER_KEY: &str = "receiver-key-1";

/// Makes `receiver-key-1`, `receiver-key-2` and so on, each kept as
/// `hash:` and the key.
#[derive(Default)]
pub struct FakeReceiverKeys {
    made: Mutex<u32>,
}

impl FakeReceiverKeys {
    /// The digest [`FakeReceiverKeys`] keeps `key` by.
    #[must_use]
    pub fn digest_of(key: &str) -> TokenHash {
        TokenHash::from_stored(format!("hash:{key}"))
    }
}

#[async_trait]
impl ReceiverKeys for FakeReceiverKeys {
    async fn generate(&self) -> Result<(Secret, TokenHash), DomainError> {
        let mut made = self.made.lock().unwrap();
        *made += 1;
        let key = format!("receiver-key-{made}");
        Ok((Secret::new(key.clone()), Self::digest_of(&key)))
    }

    fn hash_presented(&self, presented: &Secret) -> TokenHash {
        Self::digest_of(presented.expose())
    }
}

impl Fake for Arc<dyn ReceiverKeys> {
    fn fake() -> Self {
        Arc::new(FakeReceiverKeys::default())
    }
}

/// A push stream for revoked sessions about every subject, at
/// `https://app.acme.com/sse`, asking for no `Authorization` header, in
/// `status`, whose endpoint is verified or waits on [`TEST_CHALLENGE`].
///
/// # Panics
///
/// Never in practice: every value it sets is a valid one.
#[must_use]
pub fn test_stream(
    status: StreamStatus,
    verification: StreamVerificationStatus,
) -> SignalStreamRow {
    let now = clock::now();
    SignalStreamRow {
        id: SignalStreamId::new(),
        endpoint: PublicHttpsUrl::new("https://app.acme.com/sse").expect("a public HTTPS URL"),
        verification: match verification {
            StreamVerificationStatus::Verified => EndpointVerification::Verified,
            StreamVerificationStatus::Pending => EndpointVerification::Pending(
                EndpointChallenge::new(TEST_CHALLENGE).expect("the test challenge is a token"),
            ),
        },
        delivery_method: DeliveryMethod::Push,
        authorization: ReceiverAuthorization::NotRequired,
        receiver_key: FakeReceiverKeys::digest_of(TEST_RECEIVER_KEY),
        signal_types: vec![SecuritySignalType::SessionRevoked],
        subjects: StreamSubjects::starting_with(DefaultSubjects::All),
        status,
        consecutive_failures: 0,
        created_at: now,
        updated_at: now,
    }
}

/// A signal stream as the fake keeps it: every stored field, the endpoint's
/// challenge included.
#[derive(Clone)]
struct StoredStream {
    tenant_id: TenantId,
    id: SignalStreamId,
    endpoint: PublicHttpsUrl,
    verification: EndpointVerification,
    delivery_method: DeliveryMethod,
    authorization: ReceiverAuthorization,
    receiver_key: TokenHash,
    signal_types: Vec<SecuritySignalType>,
    subjects: StreamSubjects,
    status: StreamStatus,
    consecutive_failures: u32,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl StoredStream {
    /// The stored form of `row` in `tenant_id`.
    fn of(tenant_id: TenantId, row: SignalStreamRow) -> Self {
        Self {
            tenant_id,
            id: row.id,
            endpoint: row.endpoint,
            verification: row.verification,
            delivery_method: row.delivery_method,
            authorization: row.authorization,
            receiver_key: row.receiver_key,
            signal_types: row.signal_types,
            subjects: row.subjects,
            status: row.status,
            consecutive_failures: row.consecutive_failures,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }

    /// The stored form of `stream` in `tenant_id`, with `verification`.
    fn from_stream(
        tenant_id: TenantId,
        stream: &SignalStream<ResolvedTenant>,
        verification: EndpointVerification,
    ) -> Self {
        Self {
            tenant_id,
            id: *stream.id(),
            endpoint: stream.endpoint().clone(),
            verification,
            delivery_method: stream.delivery_method(),
            authorization: stream.authorization().clone(),
            receiver_key: stream.receiver_key().clone(),
            signal_types: stream.signal_types().to_vec(),
            subjects: stream.subjects().clone(),
            status: stream.status(),
            consecutive_failures: stream.consecutive_failures(),
            created_at: stream.created_at(),
            updated_at: stream.updated_at(),
        }
    }

    /// Whether this is the stream `id` of `tenant`.
    fn is(&self, tenant: &ScopedTenant, id: &SignalStreamId) -> bool {
        self.tenant_id == **tenant && self.id == *id
    }

    /// The stream read back, as the store hands it out.
    fn stream(&self) -> SignalStream<ResolvedTenant> {
        SignalStream::reconstitute(SignalStreamRow {
            id: self.id,
            endpoint: self.endpoint.clone(),
            verification: self.verification.clone(),
            delivery_method: self.delivery_method,
            authorization: self.authorization.clone(),
            receiver_key: self.receiver_key.clone(),
            signal_types: self.signal_types.clone(),
            subjects: self.subjects.clone(),
            status: self.status,
            consecutive_failures: self.consecutive_failures,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
        .expect("a stored signal stream reads back as itself")
    }
}

/// The verification to keep for `stream`: verified as it says, or pending
/// on the challenge just issued, or on the one already kept for the same
/// endpoint. A pending stream with neither is refused, as the Postgres
/// store refuses a row with no challenge to confirm.
fn verification_to_keep(
    stream: &SignalStream<ResolvedTenant>,
    kept: Option<&StoredStream>,
    challenge: StreamChallenge<'_>,
) -> Result<EndpointVerification, DomainError> {
    if stream.verification() == StreamVerificationStatus::Verified {
        return Ok(EndpointVerification::Verified);
    }
    match challenge {
        StreamChallenge::Issued(issued) => issued_for(stream, issued),
        StreamChallenge::Kept => kept
            .filter(|held| held.endpoint == *stream.endpoint())
            .map(|held| held.verification.clone())
            .filter(|held| matches!(held, EndpointVerification::Pending(_)))
            .ok_or_else(|| {
                DomainError::invalid("a stream waiting on its endpoint is saved with its challenge")
            }),
    }
}

/// The pending verification `issued` puts `stream` in, when it was issued
/// for the stream's own endpoint.
fn issued_for(
    stream: &SignalStream<ResolvedTenant>,
    issued: &ChallengeToSend,
) -> Result<EndpointVerification, DomainError> {
    if issued.endpoint() != stream.endpoint() {
        return Err(DomainError::invalid(
            "the challenge was issued for another endpoint",
        ));
    }
    Ok(EndpointVerification::Pending(issued.challenge().clone()))
}

/// In-memory signal stream store for tests, keeping each stream and each
/// delivery attempt under the tenant it was saved for.
#[derive(Default)]
pub struct FakeSignalStreamStore {
    streams: Mutex<Vec<StoredStream>>,
    /// Recorded delivery attempts, with the tenant each was recorded for.
    pub attempts: Mutex<Vec<(TenantId, SignalDeliveryAttempt)>>,
}

impl TenantScoped for FakeSignalStreamStore {}

impl FakeSignalStreamStore {
    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding the stream `row` in `tenant`, its endpoint's
    /// challenge included.
    #[must_use]
    pub fn holding(tenant: TenantId, row: SignalStreamRow) -> Self {
        Self {
            streams: Mutex::new(vec![StoredStream::of(tenant, row)]),
            attempts: Mutex::new(Vec::new()),
        }
    }

    /// A store holding each stream of `rows` in `tenant`.
    #[must_use]
    pub fn holding_all(tenant: TenantId, rows: impl IntoIterator<Item = SignalStreamRow>) -> Self {
        Self {
            streams: Mutex::new(
                rows.into_iter()
                    .map(|row| StoredStream::of(tenant, row))
                    .collect(),
            ),
            attempts: Mutex::new(Vec::new()),
        }
    }

    /// Returns the number of stored streams, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.streams.lock().unwrap().len()
    }

    /// The stream `id` of the test tenant, as last saved.
    ///
    /// # Panics
    ///
    /// Panics if the test tenant has no such stream.
    #[must_use]
    pub fn stored(&self, id: &SignalStreamId) -> SignalStream<ResolvedTenant> {
        let tenant = crate::test_support::test_ctx().tenant();
        self.in_tenant(&tenant, |held| held.id == *id)
            .into_iter()
            .next()
            .expect("the stream is stored")
    }

    /// The streams of `tenant` that `wanted` picks.
    fn in_tenant(
        &self,
        tenant: &ScopedTenant,
        wanted: impl Fn(&StoredStream) -> bool,
    ) -> Vec<SignalStream<ResolvedTenant>> {
        self.streams
            .lock()
            .unwrap()
            .iter()
            .filter(|held| held.tenant_id == **tenant && wanted(held))
            .map(StoredStream::stream)
            .collect()
    }
}

#[async_trait]
impl SignalStreamStore for FakeSignalStreamStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SignalStreamId,
    ) -> Result<Option<SignalStream<ResolvedTenant>>, DomainError> {
        Ok(self
            .in_tenant(tenant_id, |held| held.id == *id)
            .into_iter()
            .next())
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<StreamStatus>,
        sort: &SortOrder<StreamSortField>,
        request: &PageRequest,
    ) -> Result<Page<SignalStream<ResolvedTenant>>, DomainError> {
        let all = self.in_tenant(tenant_id, |held| {
            status.is_none_or(|wanted| held.status == wanted)
        });
        page(all, sort, request)
    }

    async fn list_active(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<SignalStream<ResolvedTenant>>, DomainError> {
        Ok(self.in_tenant(tenant_id, |held| held.status == StreamStatus::Active))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        stream: &SignalStream<ResolvedTenant>,
        challenge: StreamChallenge<'_>,
    ) -> Result<(), DomainError> {
        let mut streams = self.streams.lock().unwrap();
        let kept = streams.iter().find(|held| held.is(tenant_id, stream.id()));
        let verification = verification_to_keep(stream, kept, challenge)?;
        streams.retain(|held| !held.is(tenant_id, stream.id()));
        streams.push(StoredStream::from_stream(**tenant_id, stream, verification));
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &SignalStreamId,
    ) -> Result<(), DomainError> {
        self.streams
            .lock()
            .unwrap()
            .retain(|held| !held.is(tenant_id, id));
        Ok(())
    }

    async fn list_deliveries(
        &self,
        tenant_id: &ScopedTenant,
        stream_id: &SignalStreamId,
        sort: &SortOrder<StreamDeliverySortField>,
        request: &PageRequest,
    ) -> Result<Page<SignalDeliveryAttempt>, DomainError> {
        let all: Vec<_> = self
            .attempts
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, attempt)| owner == &**tenant_id && attempt.stream_id == *stream_id)
            .map(|(_, attempt)| attempt.clone())
            .collect();
        page(all, sort, request)
    }

    async fn record_delivery(
        &self,
        tenant_id: &ScopedTenant,
        attempt: &SignalDeliveryAttempt,
    ) -> Result<(), DomainError> {
        let owned = self
            .streams
            .lock()
            .unwrap()
            .iter()
            .any(|held| held.is(tenant_id, &attempt.stream_id));
        if owned {
            self.attempts
                .lock()
                .unwrap()
                .push((**tenant_id, attempt.clone()));
        }
        Ok(())
    }
}

impl Fake for Arc<dyn SignalStreamStore> {
    fn fake() -> Self {
        Arc::new(FakeSignalStreamStore::empty())
    }
}
