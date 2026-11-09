//! Organizations as tests need them, the in-memory organization store, and
//! the organization-wide readers that answer with nothing.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::metrics::{
    LatencyMs, LoginOutcomeCounts, MetricsWindow, TimeSeriesPoint,
};
use ianua_domain::domains::organization::access::auth_config::OrganizationAuthConfig;
use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
use ianua_domain::domains::organization::lifecycle::{
    CreateOrganizationParams, Organization, OrganizationRow,
};
use ianua_domain::domains::organization::status::OrganizationStatus;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::password_policy::{CharacterRequirements, CharacterRule};
use ianua_domain::types::{
    DisplayName, Email, Label, OrgUserId, OrganizationId, PasswordPolicy, TenantId, TenantSlug,
};
use time::OffsetDateTime;

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::metrics::{OrganizationMetricsReader, RequestMetrics};
use crate::ports::organization::{
    MemberStanding, MemberStandings, OrganizationSortField, OrganizationStore,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::listing::page;
use crate::test_support::{Fake, ReadBeforeWrite, no_requests};

/// The domain limits tests build values under.
#[must_use]
pub fn cfg() -> DomainLimits {
    DomainLimits::default()
}

/// An active Free organization for tests, under `slug`.
///
/// Everything else is fixed. A test that needs another plan, status or
/// sign-in config changes what comes back the way the product does.
#[must_use]
pub fn test_org(id: OrganizationId, slug: &str) -> Organization {
    test_org_on(id, slug, OrganizationPlan::Free)
}

/// An active organization for tests, under `slug`, founded on `plan`.
///
/// For a test that needs room a Free organization lacks, such as more
/// than one tenant, without going through a subscription.
#[must_use]
pub fn test_org_on(id: OrganizationId, slug: &str, plan: OrganizationPlan) -> Organization {
    let limits = cfg();
    Organization::create(CreateOrganizationParams {
        id,
        slug: TenantSlug::new(slug, &limits.slug).expect("a valid slug"),
        name: Label::new("name", "Acme").expect("a valid name"),
        contact_email: Email::new("a@acme.com").expect("a valid address"),
        display_name: DisplayName::new("Acme", &limits.display_name).expect("a valid name"),
        plan,
    })
    .map(|(organization, _founding)| as_stored(organization))
    .expect("an organization on a sold plan is founded")
}

/// [`test_org`] owning `tenants`, as an organization whose tenants were made
/// through it stands.
///
/// # Panics
///
/// Never in practice: a founded organization owning tenants is a
/// consistent row.
#[must_use]
pub fn test_org_owning(id: OrganizationId, slug: &str, tenants: &[TenantId]) -> Organization {
    let org = test_org(id, slug);
    Organization::reconstitute(OrganizationRow {
        tenant_ids: tenants.to_vec(),
        ..organization_row(&org)
    })
    .expect("a consistent organization row")
}

/// `organization` as a store gives it back: having raised nothing, since
/// loading it is no change.
#[must_use]
pub fn as_stored(mut organization: Organization) -> Organization {
    let _ = organization.take_events();
    organization
}

/// Password rules no organization starts with: long, and asking for a
/// symbol the default does not. A test that sees these knows the
/// organization's own rules were read rather than the default.
#[must_use]
pub fn strict_password_policy() -> PasswordPolicy {
    let require = CharacterRequirements {
        special: CharacterRule::Required,
        ..PasswordPolicy::default().require().clone()
    };
    PasswordPolicy::new(20, require).expect("a valid password policy")
}

/// The test organization `id`, whose own password rules are
/// [`strict_password_policy`].
#[must_use]
pub fn org_with_strict_password_policy(id: OrganizationId) -> Organization {
    let org = test_org(id, "acme");
    let mut settings = org.auth_config().settings().clone();
    settings.password_policy = strict_password_policy();
    Organization::reconstitute(OrganizationRow {
        auth_config: OrganizationAuthConfig::new(settings).expect("a consistent sign-in config"),
        ..organization_row(&org)
    })
    .expect("a consistent organization row")
}

/// A store holding one organization whose own password rules are
/// [`strict_password_policy`].
#[must_use]
pub fn org_store_with_strict_password_policy(id: OrganizationId) -> Arc<FakeOrganizationStore> {
    org_store_with([org_with_strict_password_policy(id)])
}

/// A store already holding these organizations.
///
/// The one fake every test touching organizations uses, so a use case that
/// saves an organization and a test that reads it back agree.
#[must_use]
pub fn org_store_with(orgs: impl IntoIterator<Item = Organization>) -> Arc<FakeOrganizationStore> {
    let store = FakeOrganizationStore::empty();
    store.orgs.lock().unwrap().extend(orgs);
    Arc::new(store)
}

/// The stored fields of `org`.
fn organization_row(org: &Organization) -> OrganizationRow {
    OrganizationRow {
        id: *org.id(),
        slug: org.slug().clone(),
        name: org.name().clone(),
        contact_email: org.contact_email().clone(),
        display_name: org.display_name().clone(),
        plan: org.plan(),
        terms: org.terms().clone(),
        status: org.status(),
        suspended_by: org.suspended_by(),
        tenant_ids: org.tenant_ids().to_vec(),
        auth_config: org.auth_config().clone(),
        created_at: org.created_at(),
        updated_at: org.updated_at(),
    }
}

/// In-memory organization store that keeps every organization it is
/// handed, and refuses one under a slug another organization holds.
#[derive(Default)]
pub struct FakeOrganizationStore {
    orgs: Mutex<Vec<Organization>>,
    id_reads: AtomicUsize,
}

impl FakeOrganizationStore {
    /// How many reads resolve organization ids, including batched reads.
    #[must_use]
    pub fn id_reads(&self) -> usize {
        self.id_reads.load(Ordering::SeqCst)
    }

    /// A store holding no organization.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many organizations are held.
    #[must_use]
    pub fn count(&self) -> usize {
        self.orgs.lock().unwrap().len()
    }

    /// The organization held under `id`, as it was last saved.
    #[must_use]
    pub fn stored(&self, id: &OrganizationId) -> Option<Organization> {
        self.first(|org| org.id() == id)
    }

    fn first(&self, matches: impl Fn(&Organization) -> bool) -> Option<Organization> {
        self.orgs
            .lock()
            .unwrap()
            .iter()
            .find(|org| matches(org))
            .cloned()
    }
}

#[async_trait]
impl OrganizationStore for FakeOrganizationStore {
    async fn find_by_ids(&self, ids: &[OrganizationId]) -> Result<Vec<Organization>, DomainError> {
        self.id_reads.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .orgs
            .lock()
            .unwrap()
            .iter()
            .filter(|organization| ids.contains(organization.id()))
            .cloned()
            .collect())
    }

    async fn find_by_id(&self, id: &OrganizationId) -> Result<Option<Organization>, DomainError> {
        self.id_reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.stored(id))
    }

    async fn find_by_slug(
        &self,
        slug: &TenantSlug,
    ) -> Result<Option<Arc<Organization>>, DomainError> {
        Ok(self.first(|org| org.slug() == slug).map(Arc::new))
    }

    async fn slug_exists(&self, slug: &TenantSlug) -> Result<bool, DomainError> {
        Ok(self.first(|org| org.slug() == slug).is_some())
    }

    async fn list_all(
        &self,
        status: Option<OrganizationStatus>,
        sort: &SortOrder<OrganizationSortField>,
        request: &PageRequest,
    ) -> Result<Page<Organization>, DomainError> {
        let orgs: Vec<Organization> = self
            .orgs
            .lock()
            .unwrap()
            .iter()
            .filter(|org| status.is_none_or(|wanted| org.status() == wanted))
            .cloned()
            .collect();
        page(orgs, sort, request)
    }

    async fn save(&self, organization: &Organization) -> Result<(), DomainError> {
        let mut orgs = self.orgs.lock().unwrap();
        if orgs
            .iter()
            .any(|held| holds_the_slug_of(held, organization))
        {
            return Err(DomainError::conflict(
                "another organization already has this slug",
            ));
        }
        match orgs.iter_mut().find(|held| held.id() == organization.id()) {
            Some(held) => *held = organization.clone(),
            None => orgs.push(organization.clone()),
        }
        Ok(())
    }
}

#[async_trait]
impl OrganizationStore for ReadBeforeWrite<FakeOrganizationStore> {
    async fn find_by_ids(&self, ids: &[OrganizationId]) -> Result<Vec<Organization>, DomainError> {
        self.seen.find_by_ids(ids).await
    }

    async fn find_by_id(&self, id: &OrganizationId) -> Result<Option<Organization>, DomainError> {
        self.seen.find_by_id(id).await
    }

    async fn find_by_slug(
        &self,
        slug: &TenantSlug,
    ) -> Result<Option<Arc<Organization>>, DomainError> {
        self.seen.find_by_slug(slug).await
    }

    async fn slug_exists(&self, slug: &TenantSlug) -> Result<bool, DomainError> {
        self.seen.slug_exists(slug).await
    }

    async fn list_all(
        &self,
        status: Option<OrganizationStatus>,
        sort: &SortOrder<OrganizationSortField>,
        request: &PageRequest,
    ) -> Result<Page<Organization>, DomainError> {
        self.seen.list_all(status, sort, request).await
    }

    async fn save(&self, organization: &Organization) -> Result<(), DomainError> {
        self.live.save(organization).await
    }
}

/// Whether `held` is another organization under `candidate`'s slug: one the
/// store refuses to keep beside it, as the real store's unique slug does.
fn holds_the_slug_of(held: &Organization, candidate: &Organization) -> bool {
    held.id() != candidate.id() && held.slug() == candidate.slug()
}

/// Organization metrics reader for an organization where nothing happened:
/// every count is zero and every figure is missing.
pub struct NoopOrgMetricsReader;

#[async_trait]
impl OrganizationMetricsReader for NoopOrgMetricsReader {
    async fn login_outcomes(
        &self,
        _organization_id: &OrganizationId,
        _window: &MetricsWindow,
    ) -> Result<LoginOutcomeCounts, DomainError> {
        Ok(LoginOutcomeCounts::new(0, 0))
    }

    async fn login_outcome_series(
        &self,
        _organization_id: &OrganizationId,
        _window: &MetricsWindow,
    ) -> Result<Vec<TimeSeriesPoint>, DomainError> {
        Ok(Vec::new())
    }

    async fn average_auth_duration_ms(
        &self,
        _organization_id: &OrganizationId,
        _window: &MetricsWindow,
    ) -> Result<Option<LatencyMs>, DomainError> {
        Ok(None)
    }

    async fn count_users_as_of(
        &self,
        _organization_id: &OrganizationId,
        _at: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        Ok(0)
    }

    async fn count_tenants_as_of(
        &self,
        _organization_id: &OrganizationId,
        _at: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        Ok(0)
    }

    async fn count_active_sessions_as_of(
        &self,
        _organization_id: &OrganizationId,
        _at: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        Ok(0)
    }

    async fn request_metrics(
        &self,
        _organization_id: &OrganizationId,
        _window: &MetricsWindow,
    ) -> Result<RequestMetrics, DomainError> {
        Ok(no_requests())
    }

    async fn last_login(
        &self,
        _organization_id: &OrganizationId,
    ) -> Result<Option<OffsetDateTime>, DomainError> {
        Ok(None)
    }
}

impl Fake for Arc<dyn OrganizationMetricsReader> {
    fn fake() -> Self {
        Arc::new(NoopOrgMetricsReader)
    }
}

impl Fake for Arc<dyn OrganizationStore> {
    fn fake() -> Self {
        Arc::new(FakeOrganizationStore::empty())
    }
}

/// The organization members a tenant knows, as they stand: an empty one
/// knows nobody, so an agent acting for a member is unknown there.
#[derive(Default)]
pub struct FakeMemberStandings {
    standings: Vec<MemberStanding>,
}

impl FakeMemberStandings {
    /// One that knows `standing`'s member, as it stands.
    #[must_use]
    pub fn knowing(standing: MemberStanding) -> Self {
        Self {
            standings: vec![standing],
        }
    }
}

#[async_trait]
impl MemberStandings for FakeMemberStandings {
    async fn member_in(
        &self,
        _tenant: &ScopedTenant,
        member: &OrgUserId,
    ) -> Result<Option<MemberStanding>, DomainError> {
        Ok(self
            .standings
            .iter()
            .find(|standing| standing.member.id() == member)
            .cloned())
    }
}

impl Fake for Arc<dyn MemberStandings> {
    fn fake() -> Self {
        Arc::new(FakeMemberStandings::default())
    }
}
