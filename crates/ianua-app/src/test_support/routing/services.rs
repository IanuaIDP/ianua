//! An in-memory store of the services routes forward to.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::routing::backend::health_check::HealthCheckPolicy;
use ianua_domain::domains::routing::backend::upstream::Upstream;
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::domains::routing::service::{Service, ServiceRow};
use ianua_domain::domains::routing::sign_in::accepted::AcceptedSignIn;
use ianua_domain::domains::routing::sign_in::app::AppSignIn;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainName, Label, ServiceId, Setting, TenantId};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::routing::{ServiceSortField, ServiceStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::listing::page;
use crate::test_support::routing::held::remove_where;
use crate::test_support::{Fake, rivals};

/// In-memory service store for tests, keeping each service under the
/// tenant it was saved for. No route points at any of them: the store
/// answers every route count with zero. A second service with a name, or a
/// sign-in host, already taken in the tenant is refused, as the unique
/// indexes refuse it.
#[derive(Default)]
pub struct FakeServiceStore {
    services: Mutex<Vec<(TenantId, Service<ResolvedTenant>)>>,
}

impl TenantScoped for FakeServiceStore {}

impl FakeServiceStore {
    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding one active service named `backend` with `upstream`
    /// in `tenant`, with that service's id.
    ///
    /// # Panics
    ///
    /// Panics if the service row is refused, which it never is.
    #[must_use]
    pub fn with_one(tenant: TenantId, upstream: Upstream) -> (Arc<Self>, ServiceId) {
        let now = clock::now();
        let service = Service::reconstitute(ServiceRow {
            id: ServiceId::new(),
            name: Label::new("name", "backend").expect("the test name is a label"),
            upstream,
            health_check: HealthCheckPolicy::default(),
            app_sign_in: Setting::Unset,
            accepted_sign_in: Setting::Unset,
            status: RouteStatus::Active,
            created_at: now,
            updated_at: now,
        })
        .expect("a fresh service row holds");
        let id = *service.id();
        let store = Self {
            services: Mutex::new(vec![(tenant, service)]),
        };
        (Arc::new(store), id)
    }

    /// Number of stored services, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.services.lock().unwrap().len()
    }

    fn in_tenant(
        &self,
        tenant: &ScopedTenant,
        wanted: impl Fn(&Service<ResolvedTenant>) -> bool,
    ) -> Vec<Service<ResolvedTenant>> {
        self.services
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, service)| owner == &**tenant && wanted(service))
            .map(|(_, service)| service.clone())
            .collect()
    }
}

fn is(entry: &(TenantId, Service<ResolvedTenant>), tenant: &ScopedTenant, id: &ServiceId) -> bool {
    entry.0 == **tenant && entry.1.id() == id
}

/// The hosts `service` answers sign-in on or sets its own cookie on.
fn sign_in_hosts(service: &Service<ResolvedTenant>) -> Vec<&DomainName> {
    let own = service.app_sign_in().map_or(&[][..], AppSignIn::hosts);
    let cookie = service
        .accepted_sign_in()
        .map_or(&[][..], AcceptedSignIn::cookie_hosts);
    own.iter().chain(cookie).collect()
}

/// Whether `entry` is another service of `tenant` than `service` holding
/// one of its sign-in hosts.
fn shares_a_sign_in_host(
    entry: &(TenantId, Service<ResolvedTenant>),
    tenant: &ScopedTenant,
    service: &Service<ResolvedTenant>,
) -> bool {
    let held = sign_in_hosts(&entry.1);
    entry.0 == **tenant
        && entry.1.id() != service.id()
        && sign_in_hosts(service)
            .iter()
            .any(|host| held.contains(host))
}

#[async_trait]
impl ServiceStore for FakeServiceStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ServiceId,
    ) -> Result<Option<Service<ResolvedTenant>>, DomainError> {
        Ok(self
            .in_tenant(tenant_id, |service| service.id() == id)
            .into_iter()
            .next())
    }

    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[ServiceId],
    ) -> Result<Vec<Service<ResolvedTenant>>, DomainError> {
        Ok(self.in_tenant(tenant_id, |service| ids.contains(service.id())))
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<ServiceSortField>,
        request: &PageRequest,
    ) -> Result<Page<Service<ResolvedTenant>>, DomainError> {
        let all = self.in_tenant(tenant_id, |_| true);
        page(all, sort, request)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        service: &Service<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut services = self.services.lock().unwrap();
        let by_name = |kept: &Service<ResolvedTenant>| (kept.name().clone(), *kept.id());
        if services
            .iter()
            .any(|entry| rivals(entry, tenant_id, service, by_name))
        {
            return Err(DomainError::conflict(
                "another service of the tenant has the name",
            ));
        }
        if services
            .iter()
            .any(|entry| shares_a_sign_in_host(entry, tenant_id, service))
        {
            return Err(DomainError::conflict(
                "another service of the tenant answers sign-in on one of the hosts",
            ));
        }
        services.retain(|entry| !is(entry, tenant_id, service.id()));
        services.push((**tenant_id, service.clone()));
        Ok(())
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &ServiceId) -> Result<(), DomainError> {
        remove_where(&self.services, |entry| is(entry, tenant_id, id));
        Ok(())
    }

    async fn route_count(
        &self,
        _tenant_id: &ScopedTenant,
        _id: &ServiceId,
    ) -> Result<u64, DomainError> {
        Ok(0)
    }
}

impl Fake for Arc<dyn ServiceStore> {
    fn fake() -> Self {
        Arc::new(FakeServiceStore::empty())
    }
}
