//! An in-memory tenant store.

use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::domains::tenant::provisioning::infrastructure::{CloudProvider, Placement};
use ianua_domain::domains::tenant::status::TenantStatus;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrgUserId, OrganizationId, TenantId, TenantSlug};
use time::OffsetDateTime;

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::tenant::{TenantSortField, TenantStore};
use crate::test_support::listing::page;
use crate::test_support::{Fake, ReadBeforeWrite};

/// In-memory tenant store: keeps every tenant saved and finds them by id,
/// slug and organization as the real store does, and refuses a second
/// tenant under a slug its organization already holds.
#[derive(Default)]
pub struct FakeTenantStore {
    /// The tenants held.
    pub tenants: Mutex<Vec<Tenant>>,
    /// Which organization members have been let into which tenants.
    pub granted: Mutex<Vec<(OrgUserId, TenantId)>>,
}

impl FakeTenantStore {
    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Creates a store holding `tenant`.
    #[must_use]
    pub fn holding(tenant: Tenant) -> Self {
        Self::holding_all([tenant])
    }

    /// Creates a store holding every one of `tenants`.
    #[must_use]
    pub fn holding_all(tenants: impl IntoIterator<Item = Tenant>) -> Self {
        let store = Self::empty();
        store.tenants.lock().unwrap().extend(tenants);
        store
    }

    /// Returns the number of stored tenants.
    #[must_use]
    pub fn count(&self) -> usize {
        self.tenants.lock().unwrap().len()
    }

    /// Lets the organization member `org_user_id` into `tenant_id`.
    pub fn grant(&self, org_user_id: OrgUserId, tenant_id: TenantId) {
        self.granted.lock().unwrap().push((org_user_id, tenant_id));
    }

    /// The page `request` asks for of the tenants `include` keeps and
    /// `status` admits, ordered by `sort`.
    fn listing(
        &self,
        include: impl Fn(&Tenant) -> bool,
        status: Option<TenantStatus>,
        sort: &SortOrder<TenantSortField>,
        request: &PageRequest,
    ) -> Result<Page<Tenant>, DomainError> {
        let matched: Vec<Tenant> = self
            .tenants
            .lock()
            .unwrap()
            .iter()
            .filter(|tenant| include(tenant) && admits(status, tenant))
            .cloned()
            .collect();
        page(matched, sort, request)
    }

    fn granted_to(&self, org_user_id: &OrgUserId) -> Vec<TenantId> {
        self.granted
            .lock()
            .unwrap()
            .iter()
            .filter(|(member, _)| member == org_user_id)
            .map(|(_, tenant)| *tenant)
            .collect()
    }
}

#[async_trait]
impl TenantStore for FakeTenantStore {
    async fn find_by_id(&self, id: &TenantId) -> Result<Option<Tenant>, DomainError> {
        Ok(self
            .tenants
            .lock()
            .unwrap()
            .iter()
            .find(|tenant| tenant.id() == id)
            .cloned())
    }

    async fn find_by_slug_in_org(
        &self,
        slug: &TenantSlug,
        organization_id: &OrganizationId,
    ) -> Result<Option<Arc<Tenant>>, DomainError> {
        Ok(self
            .tenants
            .lock()
            .unwrap()
            .iter()
            .find(|tenant| tenant.slug() == slug && tenant.organization_id() == organization_id)
            .cloned()
            .map(Arc::new))
    }

    async fn slug_exists_in_org(
        &self,
        slug: &TenantSlug,
        organization_id: &OrganizationId,
    ) -> Result<bool, DomainError> {
        Ok(self
            .tenants
            .lock()
            .unwrap()
            .iter()
            .any(|tenant| tenant.slug() == slug && tenant.organization_id() == organization_id))
    }

    async fn list_by_organization(
        &self,
        organization_id: &OrganizationId,
        status: Option<TenantStatus>,
        sort: &SortOrder<TenantSortField>,
        request: &PageRequest,
    ) -> Result<Page<Tenant>, DomainError> {
        let include = |tenant: &Tenant| tenant.organization_id() == organization_id;
        self.listing(include, status, sort, request)
    }

    async fn list_granted_to_org_user(
        &self,
        org_user_id: &OrgUserId,
        status: Option<TenantStatus>,
        sort: &SortOrder<TenantSortField>,
        request: &PageRequest,
    ) -> Result<Page<Tenant>, DomainError> {
        let visible = self.granted_to(org_user_id);
        let include = |tenant: &Tenant| visible.contains(tenant.id());
        self.listing(include, status, sort, request)
    }

    async fn list_all(
        &self,
        status: Option<TenantStatus>,
        sort: &SortOrder<TenantSortField>,
        request: &PageRequest,
    ) -> Result<Page<Tenant>, DomainError> {
        self.listing(|_| true, status, sort, request)
    }

    async fn list_past_grace(
        &self,
        now: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<Tenant>, DomainError> {
        let mut due: Vec<Tenant> = self
            .tenants
            .lock()
            .unwrap()
            .iter()
            .filter(|tenant| tenant.status() == TenantStatus::Archived)
            .filter(|tenant| tenant.deletable_from().is_some_and(|from| from <= now))
            .cloned()
            .collect();
        due.sort_by_key(Tenant::deletable_from);
        due.truncate(limit.get() as usize);
        Ok(due)
    }

    async fn batch_after(
        &self,
        after: Option<TenantId>,
        size: NonZeroU32,
    ) -> Result<Vec<Tenant>, DomainError> {
        let mut later: Vec<Tenant> = self
            .tenants
            .lock()
            .unwrap()
            .iter()
            .filter(|tenant| after.is_none_or(|seen| tenant.id().as_uuid() > seen.as_uuid()))
            .cloned()
            .collect();
        later.sort_by_key(|tenant| *tenant.id().as_uuid());
        later.truncate(size.get() as usize);
        Ok(later)
    }

    async fn count_in_cloud(
        &self,
        organization_id: &OrganizationId,
        provider: CloudProvider,
    ) -> Result<u64, DomainError> {
        let placed = self
            .tenants
            .lock()
            .unwrap()
            .iter()
            .filter(|tenant| {
                tenant.organization_id() == organization_id
                    && admits(None, tenant)
                    && lives_in(tenant.residency().placement(), provider)
            })
            .count();
        Ok(u64::try_from(placed).expect("a test holds fewer tenants than u64 counts"))
    }

    async fn save(&self, tenant: &Tenant) -> Result<(), DomainError> {
        let mut tenants = self.tenants.lock().unwrap();
        if tenants.iter().any(|kept| holds_the_slug_of(kept, tenant)) {
            return Err(DomainError::conflict(
                "another tenant already has this slug",
            ));
        }
        match tenants.iter_mut().find(|kept| kept.id() == tenant.id()) {
            Some(kept) => *kept = tenant.clone(),
            None => tenants.push(tenant.clone()),
        }
        Ok(())
    }
}

impl Fake for Arc<dyn TenantStore> {
    fn fake() -> Self {
        Arc::new(FakeTenantStore::empty())
    }
}

#[async_trait]
impl TenantStore for ReadBeforeWrite<FakeTenantStore> {
    async fn find_by_id(&self, id: &TenantId) -> Result<Option<Tenant>, DomainError> {
        self.seen.find_by_id(id).await
    }

    async fn find_by_slug_in_org(
        &self,
        slug: &TenantSlug,
        organization_id: &OrganizationId,
    ) -> Result<Option<Arc<Tenant>>, DomainError> {
        self.seen.find_by_slug_in_org(slug, organization_id).await
    }

    async fn slug_exists_in_org(
        &self,
        slug: &TenantSlug,
        organization_id: &OrganizationId,
    ) -> Result<bool, DomainError> {
        self.seen.slug_exists_in_org(slug, organization_id).await
    }

    async fn list_by_organization(
        &self,
        organization_id: &OrganizationId,
        status: Option<TenantStatus>,
        sort: &SortOrder<TenantSortField>,
        request: &PageRequest,
    ) -> Result<Page<Tenant>, DomainError> {
        self.seen
            .list_by_organization(organization_id, status, sort, request)
            .await
    }

    async fn list_granted_to_org_user(
        &self,
        org_user_id: &OrgUserId,
        status: Option<TenantStatus>,
        sort: &SortOrder<TenantSortField>,
        request: &PageRequest,
    ) -> Result<Page<Tenant>, DomainError> {
        self.seen
            .list_granted_to_org_user(org_user_id, status, sort, request)
            .await
    }

    async fn list_all(
        &self,
        status: Option<TenantStatus>,
        sort: &SortOrder<TenantSortField>,
        request: &PageRequest,
    ) -> Result<Page<Tenant>, DomainError> {
        self.seen.list_all(status, sort, request).await
    }

    async fn list_past_grace(
        &self,
        now: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<Tenant>, DomainError> {
        self.seen.list_past_grace(now, limit).await
    }

    async fn batch_after(
        &self,
        after: Option<TenantId>,
        size: NonZeroU32,
    ) -> Result<Vec<Tenant>, DomainError> {
        self.seen.batch_after(after, size).await
    }

    async fn count_in_cloud(
        &self,
        organization_id: &OrganizationId,
        provider: CloudProvider,
    ) -> Result<u64, DomainError> {
        self.seen.count_in_cloud(organization_id, provider).await
    }

    async fn save(&self, tenant: &Tenant) -> Result<(), DomainError> {
        self.live.save(tenant).await
    }
}

/// Whether `kept` is another tenant of `candidate`'s organization under
/// the same slug: one the store refuses to keep beside it, as the real
/// store's unique key on the organization and slug does.
fn holds_the_slug_of(kept: &Tenant, candidate: &Tenant) -> bool {
    kept.id() != candidate.id()
        && kept.organization_id() == candidate.organization_id()
        && kept.slug() == candidate.slug()
}

/// Whether a listing asking for `status` shows `tenant`: the status asked
/// for, or anything not deleted when none is.
fn admits(status: Option<TenantStatus>, tenant: &Tenant) -> bool {
    match status {
        Some(wanted) => tenant.status() == wanted,
        None => tenant.status() != TenantStatus::Deleted,
    }
}

/// Whether a tenant placed at `placement` lives in the customer's own
/// `provider` account.
fn lives_in(placement: &Placement, provider: CloudProvider) -> bool {
    matches!(
        placement,
        Placement::CustomerCloud { provider: placed, .. } if *placed == provider
    )
}
