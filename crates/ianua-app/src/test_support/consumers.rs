//! Fakes for the consumers use cases, and the consumers, roles and callers
//! their tests share.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authorization::permission::{DataAccessAction, SystemPermission};
use ianua_domain::domains::authorization::role::{DefaultAssignment, NewRole, Role};
use ianua_domain::domains::authorization::role_assignment::RoleAssignment;
use ianua_domain::domains::consumers::consumer::{Consumer, ConsumerRow, CreateConsumerParams};
use ianua_domain::domains::consumers::control::ConsumerControl;
use ianua_domain::domains::consumers::credential::ConsumerCredentialKind;
use ianua_domain::domains::consumers::credentials::{HeldCredential, PreviousCredential};
use ianua_domain::domains::consumers::quota::{ConsumerQuota, QuotaPeriod};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::test_support::authority::anyone_holding;
use ianua_domain::types::{
    CertificateFingerprint, ConsumerId, Expiry, FederatedSubject, HttpsUrl, Issuer, KeyPrefix,
    Label, PrincipalRef, RoleId, TenantId, TokenHash,
};

use crate::acting::ConsumerAuthorities;
use crate::acting::consumer::{ConsumerActing, ConsumerActingPorts};
use crate::context::{ConsumerCaller, PresentedCredential};
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::authorization::AccessRecords;
use crate::ports::consumers::{
    ConsumerKeyGenerator, ConsumerQuotaCounter, ConsumerSortField, ConsumerStore,
};
use crate::ports::shared::GeneratedApiKey;
use crate::tenancy::ScopedTenant;
use crate::test_support::authorization::FakeAccessRecordStore;
use crate::test_support::listing::page;
use crate::test_support::{Fake, test_ctx};

/// The prefix of the API key [`billing_sync`] signs in with.
const TEST_KEY_PREFIX: &str = "sk_live_abc";

/// The prefix of the API key [`billing_sync_overlapping`] used before its
/// rotation.
const OLD_KEY_PREFIX: &str = "sk_live_old";

/// The digest of the API key [`billing_sync`] signs in with.
#[must_use]
pub fn test_key_digest() -> TokenHash {
    TokenHash::from_stored("hash123".to_owned())
}

/// The digest of the API key [`billing_sync_overlapping`] used before its
/// rotation.
#[must_use]
pub fn old_key_digest() -> TokenHash {
    TokenHash::from_stored("old-hash".to_owned())
}

/// The API key [`billing_sync_overlapping`] used before its rotation.
#[must_use]
pub fn old_key() -> ConsumerCredentialKind {
    ConsumerCredentialKind::ApiKey {
        prefix: KeyPrefix::new(OLD_KEY_PREFIX).unwrap(),
        key_hash: old_key_digest(),
    }
}

/// An active consumer, "billing-sync", signing in with the API key whose
/// digest is [`test_key_digest`] and cleared for internal data.
#[must_use]
pub fn billing_sync() -> Consumer<ResolvedTenant> {
    billing_sync_cleared(DataClassLevel::Internal)
}

/// [`billing_sync`], cleared for `clearance`.
#[must_use]
pub fn billing_sync_cleared(clearance: DataClassLevel) -> Consumer<ResolvedTenant> {
    created(key_params("billing-sync", TEST_KEY_PREFIX, clearance))
}

/// An active consumer named `name`, signing in with an API key of its own,
/// prefixed `sk_live_` and its name, and cleared for `clearance`.
#[must_use]
pub fn consumer_named(name: &str, clearance: DataClassLevel) -> Consumer<ResolvedTenant> {
    created(key_params(name, &format!("sk_live_{name}"), clearance))
}

/// The issuer [`partner_feed`] signs its tokens as.
pub const PARTNER_ISSUER: &str = "https://partner.example.test";

/// The subject [`partner_feed`] signs its tokens as.
pub const PARTNER_SUBJECT: &str = "partner-feed";

/// An active consumer, "partner-feed", signing in with tokens it signs
/// itself as [`PARTNER_ISSUER`] and [`PARTNER_SUBJECT`], its keys
/// published under its issuer, and cleared for internal data.
#[must_use]
pub fn partner_feed() -> Consumer<ResolvedTenant> {
    created(CreateConsumerParams {
        name: Label::new("name", PARTNER_SUBJECT).unwrap(),
        description: None,
        credential: ConsumerCredentialKind::JwtBearer {
            issuer: Issuer::new(PARTNER_ISSUER).unwrap(),
            subject: FederatedSubject::new(PARTNER_SUBJECT).unwrap(),
            jwks_uri: HttpsUrl::new(format!("{PARTNER_ISSUER}/jwks")).unwrap(),
        },
        credential_expiry: Expiry::Never,
        quota: ConsumerQuota::Unlimited,
        clearance: DataClassLevel::Internal,
    })
}

/// An active consumer, "edge-device", signing in with the client
/// certificate of `fingerprint`, and cleared for internal data.
#[must_use]
pub fn certificate_holder(fingerprint: CertificateFingerprint) -> Consumer<ResolvedTenant> {
    created(CreateConsumerParams {
        name: Label::new("name", "edge-device").unwrap(),
        description: None,
        credential: ConsumerCredentialKind::ClientCert { fingerprint },
        credential_expiry: Expiry::Never,
        quota: ConsumerQuota::Unlimited,
        clearance: DataClassLevel::Internal,
    })
}

/// [`billing_sync`], allowed `quota`.
#[must_use]
pub fn billing_sync_with_quota(quota: ConsumerQuota) -> Consumer<ResolvedTenant> {
    created(CreateConsumerParams {
        quota,
        ..key_params("billing-sync", TEST_KEY_PREFIX, DataClassLevel::Internal)
    })
}

/// [`billing_sync`] as storage keeps it an hour after it was made, its key
/// working until `expiry`, which may have passed.
#[must_use]
pub fn billing_sync_expiring(expiry: Expiry) -> Consumer<ResolvedTenant> {
    stored_billing_sync(expiry, PreviousCredential::Retired)
}

/// [`billing_sync`] as storage keeps it an hour after a rotation from
/// [`old_key`], which keeps working for another day.
#[must_use]
pub fn billing_sync_overlapping() -> Consumer<ResolvedTenant> {
    let previous = PreviousCredential::Overlapping {
        credential: HeldCredential::new(old_key(), Expiry::Never),
        until: clock::now() + time::Duration::days(1),
    };
    stored_billing_sync(Expiry::Never, previous)
}

/// [`billing_sync`], last changed an hour ago, its key working until
/// `expiry` and `previous` kept from a rotation.
fn stored_billing_sync(expiry: Expiry, previous: PreviousCredential) -> Consumer<ResolvedTenant> {
    let made = billing_sync();
    let an_hour_ago = clock::now() - time::Duration::hours(1);
    Consumer::reconstitute(ConsumerRow {
        id: *made.id(),
        name: made.name().clone(),
        description: None,
        credential: HeldCredential::new(made.credential().clone(), expiry),
        previous_credential: previous,
        quota: made.quota(),
        status: made.status(),
        clearance: made.clearance(),
        created_by: made.created_by().clone(),
        created_at: an_hour_ago,
        updated_at: an_hour_ago,
    })
    .unwrap()
}

/// What an active consumer named `name` is made from: the API key starting
/// with `prefix` whose digest is [`test_key_digest`], never expiring, no
/// quota, cleared for `clearance`.
fn key_params(name: &str, prefix: &str, clearance: DataClassLevel) -> CreateConsumerParams {
    CreateConsumerParams {
        name: Label::new("name", name).unwrap(),
        description: None,
        credential: ConsumerCredentialKind::ApiKey {
            prefix: KeyPrefix::new(prefix).unwrap(),
            key_hash: test_key_digest(),
        },
        credential_expiry: Expiry::Never,
        quota: ConsumerQuota::Unlimited,
        clearance,
    }
}

/// The consumer `params` describes, created by someone who manages
/// consumers.
fn created(params: CreateConsumerParams) -> Consumer<ResolvedTenant> {
    Consumer::create(params, &foreign_issuer(), &consumer_admin()).unwrap()
}

/// [`billing_sync`], disabled after it was created.
#[must_use]
pub fn disabled_billing_sync() -> Consumer<ResolvedTenant> {
    switched_off(billing_sync())
}

/// `consumer`, disabled by someone who manages consumers.
///
/// # Panics
///
/// If the consumer is already disabled. Tests pass an active one.
#[must_use]
pub fn switched_off(mut consumer: Consumer<ResolvedTenant>) -> Consumer<ResolvedTenant> {
    consumer.disable(&consumer_admin()).unwrap();
    consumer
}

/// A store holding `consumer` in the tenant every test caller acts in.
#[must_use]
pub fn consumers_of_test_tenant(consumer: Consumer<ResolvedTenant>) -> Arc<FakeConsumerStore> {
    Arc::new(FakeConsumerStore::holding(test_ctx().tenant_id(), consumer))
}

/// Access records where `consumer` holds one role granting `held`.
#[must_use]
pub fn consumer_holding(consumer: &ConsumerId, held: &[SystemPermission]) -> AccessRecords {
    let role = Role::provisioned(NewRole {
        id: RoleId::new(),
        name: Label::new("name", "integration").unwrap(),
        system_permissions: held.to_vec(),
        custom_permissions: Vec::new(),
        assignment: DefaultAssignment::Manual,
    });
    let assignment = RoleAssignment::create(
        PrincipalRef::Consumer(*consumer),
        &role,
        anyone_holding(SystemPermission::all()),
    )
    .unwrap();
    AccessRecords {
        roles: vec![role],
        assignments: vec![assignment],
        ..AccessRecords::default()
    }
}

/// A consumer calling in the tenant every test caller acts in, with the
/// API key [`billing_sync`] signs in with, its digest given as `digest`.
#[must_use]
pub fn key_caller(digest: TokenHash) -> ConsumerCaller {
    ConsumerCaller::new(
        test_ctx().tenant(),
        PresentedCredential::Key {
            prefix: KeyPrefix::new(TEST_KEY_PREFIX).unwrap(),
            digest,
        },
    )
}

/// Consumers signing in from records where `consumer` is a consumer of the
/// tenant every test caller acts in and holds one role granting `held`.
#[must_use]
pub fn sign_in_of(
    consumer: Consumer<ResolvedTenant>,
    held: &[SystemPermission],
) -> Arc<dyn ConsumerAuthorities> {
    sign_in_counted_by(consumer, held, Arc::new(FakeConsumerQuotaCounter::empty()))
}

/// [`sign_in_of`], with each request counted against the consumer's quota
/// by `counter`.
#[must_use]
pub fn sign_in_counted_by(
    consumer: Consumer<ResolvedTenant>,
    held: &[SystemPermission],
    counter: Arc<dyn ConsumerQuotaCounter>,
) -> Arc<dyn ConsumerAuthorities> {
    let tenant = test_ctx().tenant_id();
    let records = consumer_holding(consumer.id(), held);
    Arc::new(ConsumerActing::new(ConsumerActingPorts {
        consumer_store: Arc::new(FakeConsumerStore::holding(tenant, consumer)),
        access_records: Arc::new(FakeAccessRecordStore::holding(tenant, records)),
        quota_counter: counter,
        ..ConsumerActingPorts::fakes()
    }))
}

/// A consumer calling in the tenant every test caller acts in, with the
/// API key [`billing_sync_overlapping`] used before its rotation.
#[must_use]
pub fn old_key_caller() -> ConsumerCaller {
    ConsumerCaller::new(
        test_ctx().tenant(),
        PresentedCredential::Key {
            prefix: KeyPrefix::new(OLD_KEY_PREFIX).unwrap(),
            digest: old_key_digest(),
        },
    )
}

/// Someone who manages consumers and may see restricted data.
fn consumer_admin() -> ConsumerControl<'static> {
    ConsumerControl::new(anyone_holding(&[
        SystemPermission::ManageConsumers,
        SystemPermission::Data(DataAccessAction::Restricted),
    ]))
}

/// An issuer no test tenant uses as its own.
fn foreign_issuer() -> Issuer {
    Issuer::new("https://tenant.example.test").unwrap()
}

/// In-memory consumer store for tests, keeping each consumer under the
/// tenant it was saved for.
#[derive(Default)]
pub struct FakeConsumerStore {
    /// Stored consumers, with the tenant each belongs to.
    pub consumers: Mutex<Vec<(TenantId, Consumer<ResolvedTenant>)>>,
    id_reads: AtomicUsize,
}

impl TenantScoped for FakeConsumerStore {}

impl FakeConsumerStore {
    /// How many reads looked up consumers by id, independently of batch size.
    #[must_use]
    pub fn id_reads(&self) -> usize {
        self.id_reads.load(Ordering::SeqCst)
    }

    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `consumer` in `tenant`.
    #[must_use]
    pub fn holding(tenant: TenantId, consumer: Consumer<ResolvedTenant>) -> Self {
        Self {
            consumers: Mutex::new(vec![(tenant, consumer)]),
            id_reads: AtomicUsize::new(0),
        }
    }

    /// Returns the number of stored consumers, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.consumers.lock().unwrap().len()
    }

    /// The consumer stored under `id` in any tenant, for asserting on what a
    /// use case saved.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::NotFound` when no consumer has that id.
    pub fn find_by_id_direct(
        &self,
        id: &ConsumerId,
    ) -> Result<Consumer<ResolvedTenant>, DomainError> {
        self.consumers
            .lock()
            .unwrap()
            .iter()
            .find(|(_, consumer)| consumer.id() == id)
            .map(|(_, consumer)| consumer.clone())
            .ok_or(DomainError::NotFound)
    }

    fn find_in(
        &self,
        tenant: &ScopedTenant,
        matches: impl Fn(&Consumer<ResolvedTenant>) -> bool,
    ) -> Option<Consumer<ResolvedTenant>> {
        self.consumers
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, consumer)| owner == &**tenant && matches(consumer))
            .map(|(_, consumer)| consumer.clone())
    }
}

/// Every credential `consumer` holds, working or not: the current one and
/// the one a rotation kept, as the store's finders search them.
fn held_kinds(
    consumer: &Consumer<ResolvedTenant>,
) -> impl Iterator<Item = &ConsumerCredentialKind> {
    let previous = match consumer.credentials().previous() {
        PreviousCredential::Overlapping { credential, .. } => Some(credential.kind()),
        PreviousCredential::Retired => None,
    };
    std::iter::once(consumer.credential()).chain(previous)
}

fn signs_in_with_key(consumer: &Consumer<ResolvedTenant>, wanted: &KeyPrefix) -> bool {
    held_kinds(consumer).any(
        |kind| matches!(kind, ConsumerCredentialKind::ApiKey { prefix, .. } if prefix == wanted),
    )
}

fn signs_in_with_certificate(
    consumer: &Consumer<ResolvedTenant>,
    wanted: &CertificateFingerprint,
) -> bool {
    held_kinds(consumer).any(|kind| {
        matches!(kind, ConsumerCredentialKind::ClientCert { fingerprint } if fingerprint == wanted)
    })
}

fn signs_in_with_token(
    consumer: &Consumer<ResolvedTenant>,
    wanted_issuer: &Issuer,
    wanted_subject: &FederatedSubject,
) -> bool {
    held_kinds(consumer).any(|kind| {
        matches!(
            kind,
            ConsumerCredentialKind::JwtBearer { issuer, subject, .. }
                if issuer == wanted_issuer && subject == wanted_subject
        )
    })
}

/// Whether `kept` signs in with any credential `consumer` holds, as the
/// store's unique credential key compares them.
fn shares_a_credential(
    kept: &Consumer<ResolvedTenant>,
    consumer: &Consumer<ResolvedTenant>,
) -> bool {
    held_kinds(consumer).any(|kind| match kind {
        ConsumerCredentialKind::ApiKey { prefix, .. } => signs_in_with_key(kept, prefix),
        ConsumerCredentialKind::ClientCert { fingerprint } => {
            signs_in_with_certificate(kept, fingerprint)
        }
        ConsumerCredentialKind::JwtBearer {
            issuer, subject, ..
        } => signs_in_with_token(kept, issuer, subject),
    })
}

#[async_trait]
impl ConsumerStore for FakeConsumerStore {
    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[ConsumerId],
    ) -> Result<Vec<Consumer<ResolvedTenant>>, DomainError> {
        self.id_reads.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .consumers
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, consumer)| owner == &**tenant_id && ids.contains(consumer.id()))
            .map(|(_, consumer)| consumer.clone())
            .collect())
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ConsumerId,
    ) -> Result<Option<Consumer<ResolvedTenant>>, DomainError> {
        self.id_reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.find_in(tenant_id, |consumer| consumer.id() == id))
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<ConsumerSortField>,
        request: &PageRequest,
    ) -> Result<Page<Consumer<ResolvedTenant>>, DomainError> {
        let all: Vec<_> = self
            .consumers
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, _)| owner == &**tenant_id)
            .map(|(_, consumer)| consumer.clone())
            .collect();
        page(all, sort, request)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        consumer: &Consumer<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut consumers = self.consumers.lock().unwrap();
        let taken = consumers.iter().any(|(owner, kept)| {
            owner == &**tenant_id
                && kept.id() != consumer.id()
                && shares_a_credential(kept, consumer)
        });
        if taken {
            return Err(DomainError::conflict(
                "another consumer of the tenant signs in with this credential",
            ));
        }
        consumers.retain(|(owner, kept)| !(owner == &**tenant_id && kept.id() == consumer.id()));
        consumers.push((**tenant_id, consumer.clone()));
        Ok(())
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &ConsumerId) -> Result<(), DomainError> {
        self.consumers
            .lock()
            .unwrap()
            .retain(|(owner, consumer)| !(owner == &**tenant_id && consumer.id() == id));
        Ok(())
    }

    async fn find_by_key_prefix(
        &self,
        tenant_id: &ScopedTenant,
        key_prefix: &KeyPrefix,
    ) -> Result<Option<Consumer<ResolvedTenant>>, DomainError> {
        Ok(self.find_in(tenant_id, |consumer| {
            signs_in_with_key(consumer, key_prefix)
        }))
    }

    async fn find_by_cert_fingerprint(
        &self,
        tenant_id: &ScopedTenant,
        fingerprint: &CertificateFingerprint,
    ) -> Result<Option<Consumer<ResolvedTenant>>, DomainError> {
        Ok(self.find_in(tenant_id, |consumer| {
            signs_in_with_certificate(consumer, fingerprint)
        }))
    }

    async fn find_by_jwt_issuer_subject(
        &self,
        tenant_id: &ScopedTenant,
        issuer: &Issuer,
        subject: &FederatedSubject,
    ) -> Result<Option<Consumer<ResolvedTenant>>, DomainError> {
        Ok(self.find_in(tenant_id, |consumer| {
            signs_in_with_token(consumer, issuer, subject)
        }))
    }
}

impl Fake for Arc<dyn ConsumerStore> {
    fn fake() -> Self {
        Arc::new(FakeConsumerStore::empty())
    }
}

/// In-memory quota counter for tests: one count per consumer and period,
/// with the current period never ending.
#[derive(Default)]
pub struct FakeConsumerQuotaCounter {
    /// Requests counted so far, per consumer and period.
    pub counts: Mutex<HashMap<(ConsumerId, QuotaPeriod), u64>>,
}

impl TenantScoped for FakeConsumerQuotaCounter {}

impl FakeConsumerQuotaCounter {
    /// A counter that has counted nothing yet.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A counter that has already counted `used` requests by `consumer` in
    /// the current `period`.
    #[must_use]
    pub fn having_counted(consumer: ConsumerId, period: QuotaPeriod, used: u64) -> Self {
        Self {
            counts: Mutex::new(HashMap::from([((consumer, period), used)])),
        }
    }

    /// How many requests by `consumer` were counted in `period`.
    #[must_use]
    pub fn counted(&self, consumer: ConsumerId, period: QuotaPeriod) -> u64 {
        self.counts
            .lock()
            .unwrap()
            .get(&(consumer, period))
            .copied()
            .unwrap_or(0)
    }
}

#[async_trait]
impl ConsumerQuotaCounter for FakeConsumerQuotaCounter {
    async fn spend(
        &self,
        _tenant_id: &ScopedTenant,
        consumer: &ConsumerId,
        period: QuotaPeriod,
    ) -> Result<u64, DomainError> {
        let mut counts = self.counts.lock().unwrap();
        let count = counts.entry((*consumer, period)).or_insert(0);
        let used = *count;
        *count = used.saturating_add(1);
        Ok(used)
    }
}

impl Fake for Arc<dyn ConsumerQuotaCounter> {
    fn fake() -> Self {
        Arc::new(FakeConsumerQuotaCounter::empty())
    }
}

/// Maker of consumer keys for tests: the `n`th key made is
/// `sk_live_minted<n>.minted-digest-<n>`, found by prefix
/// `sk_live_minted<n>` and kept as digest `minted-digest-<n>`, the shape
/// [`FakeConsumerKeyDigests`](crate::test_support::authentication::FakeConsumerKeyDigests)
/// reads a presented key in.
#[derive(Default)]
pub struct FakeConsumerKeyGenerator {
    made: Mutex<u32>,
}

impl FakeConsumerKeyGenerator {
    /// A generator that has made no key yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many keys it made.
    #[must_use]
    pub fn made(&self) -> u32 {
        *self.made.lock().unwrap()
    }
}

#[async_trait]
impl ConsumerKeyGenerator for FakeConsumerKeyGenerator {
    async fn generate(&self) -> Result<GeneratedApiKey, DomainError> {
        let mut made = self.made.lock().unwrap();
        *made += 1;
        let prefix = format!("sk_live_minted{made}");
        let digest = format!("minted-digest-{made}");
        Ok(GeneratedApiKey {
            raw_key: Secret::new(format!("{prefix}.{digest}")),
            key_prefix: KeyPrefix::new(prefix)?,
            key_hash: TokenHash::from_stored(digest),
        })
    }
}

impl Fake for Arc<dyn ConsumerKeyGenerator> {
    fn fake() -> Self {
        Arc::new(FakeConsumerKeyGenerator::new())
    }
}

/// A maker of consumer keys whose random source fails.
pub struct UnreachableConsumerKeys;

#[async_trait]
impl ConsumerKeyGenerator for UnreachableConsumerKeys {
    async fn generate(&self) -> Result<GeneratedApiKey, DomainError> {
        Err(DomainError::infra_msg("no random key can be made"))
    }
}

/// A quota counter that cannot be reached, as when its store is down.
pub struct UnreachableQuotaCounter;

impl TenantScoped for UnreachableQuotaCounter {}

#[async_trait]
impl ConsumerQuotaCounter for UnreachableQuotaCounter {
    async fn spend(
        &self,
        _tenant_id: &ScopedTenant,
        _consumer: &ConsumerId,
        _period: QuotaPeriod,
    ) -> Result<u64, DomainError> {
        Err(DomainError::infra_msg("the quota counter is unreachable"))
    }
}
