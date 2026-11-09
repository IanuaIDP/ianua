//! Consumer identity ports: where consumers are kept, how their API keys
//! are made, and how their requests are counted against their quota.

use async_trait::async_trait;
use ianua_domain::domains::consumers::consumer::{Consumer, ConsumerStatus};
use ianua_domain::domains::consumers::quota::QuotaPeriod;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{
    CertificateFingerprint, ConsumerId, FederatedSubject, Issuer, KeyPrefix,
};

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::shared::GeneratedApiKey;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field a consumer listing can be ordered by.
    pub enum ConsumerSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by last update time.
        UpdatedAt => "updated_at",
        /// Order by display name.
        Name => "name",
        /// Order by status.
        Status => "status",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<ConsumerSortField> for Consumer<ResolvedTenant> {
    fn sort_key(&self, field: ConsumerSortField) -> SortKey {
        match field {
            ConsumerSortField::CreatedAt => self.created_at().into(),
            ConsumerSortField::UpdatedAt => self.updated_at().into(),
            ConsumerSortField::Name => self.name().as_str().into(),
            ConsumerSortField::Status => consumer_status_word(self.status()).into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// The word a consumer's status sorts by, as it is stored.
fn consumer_status_word(status: ConsumerStatus) -> &'static str {
    match status {
        ConsumerStatus::Active => "active",
        ConsumerStatus::Disabled => "disabled",
    }
}

/// Dyn-safe port for persisting and retrieving tenant consumers.
#[async_trait]
pub trait ConsumerStore: Send + Sync + TenantScoped {
    /// Finds a consumer by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ConsumerId,
    ) -> Result<Option<Consumer<ResolvedTenant>>, DomainError>;

    /// Finds the requested consumers together, in no guaranteed order.
    /// Missing consumers and consumers of other tenants are omitted.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence or reconstitution failure.
    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[ConsumerId],
    ) -> Result<Vec<Consumer<ResolvedTenant>>, DomainError>;

    /// Lists all consumers for a tenant with ordering and pagination.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<ConsumerSortField>,
        page: &PageRequest,
    ) -> Result<Page<Consumer<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated consumer.
    ///
    /// A credential in use names one consumer of the tenant, so a sign-in
    /// never has to pick between two.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when another consumer of the tenant
    /// signs in with the same credential now, or
    /// `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        consumer: &Consumer<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes a consumer by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(&self, tenant_id: &ScopedTenant, id: &ConsumerId) -> Result<(), DomainError>;

    /// Finds a consumer by API key prefix.
    ///
    /// Each finder looks at the current credential and at the previous one
    /// a rotation kept, whether or not it still works. The consumer's own
    /// sign-in check decides that, so an old key is refused for having
    /// expired, not for being unknown.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_key_prefix(
        &self,
        tenant_id: &ScopedTenant,
        key_prefix: &KeyPrefix,
    ) -> Result<Option<Consumer<ResolvedTenant>>, DomainError>;

    /// Finds a consumer by client certificate fingerprint.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_cert_fingerprint(
        &self,
        tenant_id: &ScopedTenant,
        fingerprint: &CertificateFingerprint,
    ) -> Result<Option<Consumer<ResolvedTenant>>, DomainError>;

    /// Finds a consumer by JWT issuer and subject claims.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_jwt_issuer_subject(
        &self,
        tenant_id: &ScopedTenant,
        issuer: &Issuer,
        subject: &FederatedSubject,
    ) -> Result<Option<Consumer<ResolvedTenant>>, DomainError>;
}

/// Dyn-safe port making the API keys consumers sign in with at the
/// gateway.
///
/// Only the platform can make one: the key is kept as its digest under a
/// key derived from the platform secret for consumer keys alone, which the
/// gateway's reader of presented keys digests with too, so no digest a
/// client made could ever match.
#[async_trait]
pub trait ConsumerKeyGenerator: Send + Sync {
    /// A fresh consumer key: the raw key, shown once, the prefix it is
    /// found by, and the digest it is kept as.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if no random key can be made.
    async fn generate(&self) -> Result<GeneratedApiKey, DomainError>;
}

/// Counts each consumer's requests against its quota, per period.
///
/// A period is the calendar minute, hour, day or month, in UTC, that the
/// request falls in. Counts of earlier periods are never read again, so the
/// adapter may let them lapse once the period is over.
///
/// The adapter must count atomically: two requests at once each see the
/// other, so a consumer at its last request never gets two through. It must
/// also time out, since every consumer request waits on it.
#[async_trait]
pub trait ConsumerQuotaCounter: Send + Sync + TenantScoped {
    /// Counts one more request by `consumer` in the current `period`, and
    /// returns how many it had already sent in that period before this one.
    ///
    /// A request the quota then refuses is counted too, so the count only
    /// grows within a period.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the count cannot be read
    /// or written, or does not answer in time.
    async fn spend(
        &self,
        tenant_id: &ScopedTenant,
        consumer: &ConsumerId,
        period: QuotaPeriod,
    ) -> Result<u64, DomainError>;
}
