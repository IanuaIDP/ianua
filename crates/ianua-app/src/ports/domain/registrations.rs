//! Registered custom domains.

use async_trait::async_trait;
use ianua_domain::domains::tenant::custom_domains::registered_domain::{
    ClaimLifetimes, RegisteredDomain,
};
use ianua_domain::domains::tenant::custom_domains::verification_status::VerificationStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainId, DomainName, TenantId};
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field a registered-domain listing can be ordered by.
    pub enum DomainSortField {
        /// Order by registration time.
        CreatedAt => "created_at",
        /// Order by domain name.
        Domain => "domain",
        /// Order by DNS verification status.
        VerificationStatus => "verification_status",
        /// Order by verification completion time.
        VerifiedAt => "verified_at",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<DomainSortField> for RegisteredDomain<ResolvedTenant> {
    fn sort_key(&self, field: DomainSortField) -> SortKey {
        match field {
            DomainSortField::CreatedAt => self.created_at().into(),
            DomainSortField::Domain => self.domain().as_str().into(),
            DomainSortField::VerificationStatus => {
                verification_word(self.verification_status()).into()
            }
            DomainSortField::VerifiedAt => self.verified_at().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// The word a domain's verification status sorts by, as it is stored.
fn verification_word(status: VerificationStatus) -> &'static str {
    match status {
        VerificationStatus::Pending => "pending",
        VerificationStatus::Verified => "verified",
        VerificationStatus::Failed => "failed",
    }
}

/// Dyn-safe port for persisting and retrieving one tenant's registered
/// domains. The cross-tenant questions are on [`CrossTenantDomainStore`].
#[async_trait]
pub trait RegisteredDomainStore: Send + Sync + TenantScoped {
    /// Persists an updated domain registration, or one moved to this
    /// tenant by a handover. A new one is registered through
    /// [`register`](Self::register), which also keeps names above and below
    /// it apart.
    ///
    /// A name is held by one registration across every tenant, and storage
    /// keeps it so with a unique index: of two registrations of one name
    /// arriving together, the second is refused here even though both
    /// found the name free.
    ///
    /// # Errors
    ///
    /// - `DomainError::Conflict` when another registration already holds
    ///   the name.
    /// - `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        domain: &RegisteredDomain<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Registers a new domain: claims its name and writes the
    /// registration, the claim one step no other claim can come between.
    ///
    /// The claim is refused when another registration holds the name
    /// itself, or another tenant's claim that still holds its name at `now`
    /// under `lifetimes` (see [`RegisteredDomain::has_lapsed`]) sits on a
    /// name above or below it, label by label with a leading `*.` set
    /// aside. The tenant's own claims never stand in its way, and a lapsed
    /// claim on the name itself must be released first, through
    /// [`CrossTenantDomainStore::release_lapsed_claim`]. The check and the
    /// claim run under one lock that every overlapping name shares, so of
    /// two tenants claiming `acme.com` and `login.acme.com` at once exactly
    /// one wins.
    ///
    /// # Errors
    ///
    /// - `DomainError::Conflict` when the name, or one above or below it,
    ///   is held.
    /// - `DomainError::Infrastructure` on persistence failure.
    async fn register(
        &self,
        tenant_id: &ScopedTenant,
        domain: &RegisteredDomain<ResolvedTenant>,
        lifetimes: &ClaimLifetimes,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Finds a domain registration by its ID within a tenant.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &DomainId,
    ) -> Result<Option<RegisteredDomain<ResolvedTenant>>, DomainError>;

    /// Lists a tenant's domain registrations with ordering and pagination.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_by_tenant(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<DomainSortField>,
        page: &PageRequest,
    ) -> Result<Page<RegisteredDomain<ResolvedTenant>>, DomainError>;

    /// Deletes a domain registration. Returns `true` if a row was deleted.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(&self, tenant_id: &ScopedTenant, id: &DomainId) -> Result<bool, DomainError>;

    /// Finds the requested names among this tenant's registrations in one
    /// read. Missing names are omitted and the result has no guaranteed order.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup or reconstitution failure.
    async fn find_by_names(
        &self,
        tenant_id: &ScopedTenant,
        domains: &[DomainName],
    ) -> Result<Vec<RegisteredDomain<ResolvedTenant>>, DomainError>;

    /// Finds one of a tenant's domains by name.
    ///
    /// Distinct from [`CrossTenantDomainStore::find_by_domain`], which
    /// answers the global-uniqueness question and so cannot say whose a name
    /// is.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_tenant_and_name(
        &self,
        tenant_id: &ScopedTenant,
        domain: &DomainName,
    ) -> Result<Option<RegisteredDomain<ResolvedTenant>>, DomainError>;
}

/// Dyn-safe port for the registered-domain questions no single tenant owns.
///
/// Not [`TenantScoped`]: a domain name is unique across every tenant, so
/// whether one is taken has to be asked of all of them, and the verification
/// and certificate sweeps run across tenants without a caller to scope them.
#[async_trait]
pub trait CrossTenantDomainStore: Send + Sync {
    /// Finds a domain registration by its name (globally unique).
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_domain(
        &self,
        domain: &DomainName,
    ) -> Result<Option<RegisteredDomain<ResolvedTenant>>, DomainError>;

    /// Every registration whose name overlaps `domain`, whichever tenant
    /// holds it: the same name, a name above it, or a name below it,
    /// compared label by label after a leading `*.` is set aside.
    ///
    /// For `login.acme.com` that is `login.acme.com`, `acme.com`,
    /// `*.acme.com`, `*.login.acme.com` and `eu.login.acme.com`, but not
    /// `blogin.acme.com` or `com`. Each comes with the tenant holding it, so
    /// the caller can leave out its own and ask the domain which still hold
    /// their name.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_overlapping(
        &self,
        domain: &DomainName,
    ) -> Result<Vec<(TenantId, RegisteredDomain<ResolvedTenant>)>, DomainError>;

    /// Removes the claim on `domain`, and the zone opened for it, when it
    /// has lapsed by `now` under `lifetimes`, in one atomic step. Answers
    /// whether a claim was removed: `false` when it was proved meanwhile, or
    /// still holds its name.
    ///
    /// It lapses as [`RegisteredDomain::has_lapsed`] says: never proved and
    /// made before `now - lifetimes.unproved`, or its proof failed before
    /// `now - lifetimes.failed_grace`. A verified claim never lapses.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn release_lapsed_claim(
        &self,
        domain: &DomainName,
        lifetimes: &ClaimLifetimes,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError>;

    /// Finds a domain registration's name by its ID (global, no tenant scope).
    ///
    /// Used by background tasks (certificate renewal) that only have
    /// the domain ID from the certificate store.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_domain_id(&self, id: &DomainId) -> Result<Option<DomainName>, DomainError>;

    /// Updates the `last_checked_at` timestamp for exponential backoff.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn mark_checked(&self, id: &DomainId) -> Result<(), DomainError>;

    /// Lists domains pending verification retry.
    ///
    /// Returns domains with `Pending` or `Failed` verification status created
    /// more than 2 minutes ago and due for another check, backing off as they
    /// age, limited to 100 results.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_pending_verification(
        &self,
    ) -> Result<Vec<(TenantId, RegisteredDomain<ResolvedTenant>)>, DomainError>;

    /// Lists all verified domains.
    ///
    /// Used by the health check worker to re-check DNS records
    /// for domains whose ownership is verified.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_verified(
        &self,
    ) -> Result<Vec<(TenantId, RegisteredDomain<ResolvedTenant>)>, DomainError>;

    /// Lists verified domains still waiting on a certificate, verified longer
    /// than `stale_after_minutes` ago.
    ///
    /// The cutoff belongs in the query rather than the caller: a domain
    /// verified moments ago has an issuance job in flight, and asking an
    /// authority for the same hostname twice at once spends validation
    /// attempts against a rate limit measured in single digits per hour.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_awaiting_certificate(
        &self,
        stale_after_minutes: u32,
    ) -> Result<Vec<(TenantId, RegisteredDomain<ResolvedTenant>)>, DomainError>;
}
