//! An in-memory store of registered domains.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::tenant::custom_domains::registered_domain::{
    ClaimLifetimes, RegisteredDomain, RegisteredDomainRow,
};
use ianua_domain::domains::tenant::custom_domains::verification_status::{
    TlsStatus, VerificationStatus,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainId, DomainName, TenantId};
use time::OffsetDateTime;

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::domain::{CrossTenantDomainStore, DomainSortField, RegisteredDomainStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::listing::page;

struct Entry {
    tenant_id: TenantId,
    domain: RegisteredDomain<ResolvedTenant>,
}

impl Entry {
    fn is(&self, tenant: &ScopedTenant, id: &DomainId) -> bool {
        self.tenant_id == **tenant && self.domain.id() == id
    }

    fn listed(&self) -> (TenantId, RegisteredDomain<ResolvedTenant>) {
        (self.tenant_id, copy_of(&self.domain))
    }
}

/// In-memory registered domain store for use case tests, keeping each
/// registration under the tenant it was saved for.
#[derive(Default)]
pub struct FakeDomainStore {
    entries: Mutex<Vec<Entry>>,
    name_reads: AtomicUsize,
}

impl TenantScoped for FakeDomainStore {}

impl FakeDomainStore {
    /// How many tenant-scoped reads looked up domain names.
    #[must_use]
    pub fn name_reads(&self) -> usize {
        self.name_reads.load(Ordering::SeqCst)
    }

    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `domains`, each registered by `tenant_id`.
    #[must_use]
    pub fn holding(
        tenant_id: TenantId,
        domains: impl IntoIterator<Item = RegisteredDomain<ResolvedTenant>>,
    ) -> Self {
        let store = Self::default();
        store.entries.lock().unwrap().extend(
            domains
                .into_iter()
                .map(|domain| Entry { tenant_id, domain }),
        );
        store
    }

    /// Returns the number of stored domains, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// `tenant_id`'s registration under `id`, as last saved.
    #[must_use]
    pub fn domain_of(
        &self,
        tenant_id: TenantId,
        id: &DomainId,
    ) -> Option<RegisteredDomain<ResolvedTenant>> {
        self.first(|entry| entry.tenant_id == tenant_id && entry.domain.id() == id)
    }

    fn first(&self, wanted: impl Fn(&Entry) -> bool) -> Option<RegisteredDomain<ResolvedTenant>> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .find(|entry| wanted(entry))
            .map(|entry| copy_of(&entry.domain))
    }

    fn every(
        &self,
        wanted: impl Fn(&RegisteredDomain<ResolvedTenant>) -> bool,
    ) -> Vec<(TenantId, RegisteredDomain<ResolvedTenant>)> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|entry| wanted(&entry.domain))
            .map(Entry::listed)
            .collect()
    }
}

fn copy_of(domain: &RegisteredDomain<ResolvedTenant>) -> RegisteredDomain<ResolvedTenant> {
    RegisteredDomain::reconstitute(RegisteredDomainRow {
        id: *domain.id(),
        domain: domain.domain().clone(),
        connection: domain.connection(),
        proof: domain.proof(),
        dns_challenge_token: domain.dns_challenge_token().clone(),
        tls_status: domain.tls_status(),
        created_at: domain.created_at(),
    })
    .expect("a registered domain reads back as itself")
}

/// Whether `a` and `b` are the same name, or one lies beneath the other,
/// label by label, with a leading `*.` set aside.
fn overlaps(a: &DomainName, b: &DomainName) -> bool {
    let (a, b) = (without_wildcard(a), without_wildcard(b));
    a == b || lies_beneath(a, b) || lies_beneath(b, a)
}

fn without_wildcard(name: &DomainName) -> &str {
    name.as_str().strip_prefix("*.").unwrap_or(name.as_str())
}

/// Whether `name` is a whole number of labels beneath `parent`.
fn lies_beneath(name: &str, parent: &str) -> bool {
    name.strip_suffix(parent)
        .is_some_and(|rest| rest.ends_with('.'))
}

fn awaits_certificate(
    domain: &RegisteredDomain<ResolvedTenant>,
    verified_before: OffsetDateTime,
) -> bool {
    domain.verification_status() == VerificationStatus::Verified
        && domain.tls_status() == TlsStatus::Provisioning
        && domain.verified_at().is_some_and(|at| at < verified_before)
}

#[async_trait]
impl RegisteredDomainStore for FakeDomainStore {
    async fn find_by_names(
        &self,
        tenant_id: &ScopedTenant,
        domains: &[DomainName],
    ) -> Result<Vec<RegisteredDomain<ResolvedTenant>>, DomainError> {
        self.name_reads.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .entries
            .lock()
            .unwrap()
            .iter()
            .filter(|entry| {
                entry.tenant_id == **tenant_id && domains.contains(entry.domain.domain())
            })
            .map(|entry| copy_of(&entry.domain))
            .collect())
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        domain: &RegisteredDomain<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut entries = self.entries.lock().unwrap();
        let taken = entries.iter().any(|entry| {
            entry.domain.domain() == domain.domain() && entry.domain.id() != domain.id()
        });
        if taken {
            return Err(DomainError::conflict("domain already claimed"));
        }
        entries.retain(|entry| !entry.is(tenant_id, domain.id()));
        entries.push(Entry {
            tenant_id: **tenant_id,
            domain: copy_of(domain),
        });
        Ok(())
    }

    async fn register(
        &self,
        tenant_id: &ScopedTenant,
        domain: &RegisteredDomain<ResolvedTenant>,
        lifetimes: &ClaimLifetimes,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let mut entries = self.entries.lock().unwrap();
        let blocked = entries.iter().any(|entry| {
            entry.domain.domain() == domain.domain()
                || (entry.tenant_id != **tenant_id
                    && overlaps(entry.domain.domain(), domain.domain())
                    && !entry.domain.has_lapsed(now, lifetimes))
        });
        if blocked {
            return Err(DomainError::conflict(
                "the name, or one above or below it, is already claimed",
            ));
        }
        entries.push(Entry {
            tenant_id: **tenant_id,
            domain: copy_of(domain),
        });
        Ok(())
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &DomainId,
    ) -> Result<Option<RegisteredDomain<ResolvedTenant>>, DomainError> {
        Ok(self.first(|entry| entry.is(tenant_id, id)))
    }

    async fn list_by_tenant(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<DomainSortField>,
        request: &PageRequest,
    ) -> Result<Page<RegisteredDomain<ResolvedTenant>>, DomainError> {
        let all: Vec<_> = self
            .entries
            .lock()
            .unwrap()
            .iter()
            .filter(|entry| entry.tenant_id == **tenant_id)
            .map(|entry| copy_of(&entry.domain))
            .collect();
        page(all, sort, request)
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &DomainId) -> Result<bool, DomainError> {
        let mut entries = self.entries.lock().unwrap();
        let before = entries.len();
        entries.retain(|entry| !entry.is(tenant_id, id));
        Ok(entries.len() < before)
    }

    async fn find_by_tenant_and_name(
        &self,
        tenant_id: &ScopedTenant,
        domain: &DomainName,
    ) -> Result<Option<RegisteredDomain<ResolvedTenant>>, DomainError> {
        self.name_reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.first(|entry| entry.tenant_id == **tenant_id && entry.domain.domain() == domain))
    }
}

#[async_trait]
impl CrossTenantDomainStore for FakeDomainStore {
    async fn find_by_domain(
        &self,
        domain: &DomainName,
    ) -> Result<Option<RegisteredDomain<ResolvedTenant>>, DomainError> {
        Ok(self.first(|entry| entry.domain.domain() == domain))
    }

    async fn find_overlapping(
        &self,
        domain: &DomainName,
    ) -> Result<Vec<(TenantId, RegisteredDomain<ResolvedTenant>)>, DomainError> {
        Ok(self.every(|held| overlaps(held.domain(), domain)))
    }

    async fn release_lapsed_claim(
        &self,
        domain: &DomainName,
        lifetimes: &ClaimLifetimes,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let mut entries = self.entries.lock().unwrap();
        let before = entries.len();
        entries.retain(|entry| {
            !(entry.domain.domain() == domain && entry.domain.has_lapsed(now, lifetimes))
        });
        Ok(entries.len() < before)
    }

    async fn find_by_domain_id(&self, id: &DomainId) -> Result<Option<DomainName>, DomainError> {
        Ok(self
            .first(|entry| entry.domain.id() == id)
            .map(|domain| domain.domain().clone()))
    }

    async fn mark_checked(&self, _id: &DomainId) -> Result<(), DomainError> {
        Ok(())
    }

    async fn list_pending_verification(
        &self,
    ) -> Result<Vec<(TenantId, RegisteredDomain<ResolvedTenant>)>, DomainError> {
        Ok(self.every(|domain| {
            matches!(
                domain.verification_status(),
                VerificationStatus::Pending | VerificationStatus::Failed
            )
        }))
    }

    async fn list_verified(
        &self,
    ) -> Result<Vec<(TenantId, RegisteredDomain<ResolvedTenant>)>, DomainError> {
        Ok(self.every(|domain| domain.verification_status() == VerificationStatus::Verified))
    }

    async fn list_awaiting_certificate(
        &self,
        stale_after_minutes: u32,
    ) -> Result<Vec<(TenantId, RegisteredDomain<ResolvedTenant>)>, DomainError> {
        let cutoff = clock::now() - time::Duration::minutes(i64::from(stale_after_minutes));
        Ok(self.every(|domain| awaits_certificate(domain, cutoff)))
    }
}

impl Fake for Arc<dyn RegisteredDomainStore> {
    fn fake() -> Self {
        Arc::new(FakeDomainStore::empty())
    }
}

impl Fake for Arc<dyn CrossTenantDomainStore> {
    fn fake() -> Self {
        Arc::new(FakeDomainStore::empty())
    }
}
