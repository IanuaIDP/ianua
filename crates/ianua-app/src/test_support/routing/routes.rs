//! An in-memory store of HTTP routes.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::routing::route::{Route, RouteRow, WorkflowUse};
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PipelineId, RouteId, TenantId};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::routing::{RouteSortField, RouteStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::listing::page;
use crate::test_support::routing::held::remove_where;
use crate::test_support::{Fake, rivals};

fn route_copy(route: &Route<ResolvedTenant>) -> Route<ResolvedTenant> {
    Route::reconstitute(RouteRow {
        id: *route.id(),
        name: route.name().clone(),
        path_pattern: route.path_pattern().clone(),
        methods: route.methods().to_vec(),
        service_id: *route.service_id(),
        policy: route.policy().clone(),
        hosts: route.hosts().clone(),
        conditions: route.conditions().clone(),
        pipeline_id: *route.pipeline_id(),
        path_rewrite: route.path_rewrite().clone(),
        status: route.status(),
        priority: route.priority(),
        data_class: route.data_class(),
        action_class: route.declared_action_class(),
        reach: route.reach(),
        parameter_rules: route.parameter_rules().to_vec(),
        workflow_use: route.workflow_use(),
        attack_mode: route.attack_mode(),
        created_at: route.created_at(),
        updated_at: route.updated_at(),
    })
    .expect("a route reads back as itself")
}

/// In-memory route store for tests, keeping each route under the tenant it
/// was saved for. A second route with a name already taken in the tenant is
/// refused, as the unique index refuses it.
#[derive(Default)]
pub struct FakeRouteStore {
    routes: Mutex<Vec<(TenantId, Route<ResolvedTenant>)>>,
}

impl TenantScoped for FakeRouteStore {}

impl FakeRouteStore {
    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns the number of stored routes, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.routes.lock().unwrap().len()
    }

    /// How many of `tenant`'s routes run through `pipeline`.
    #[must_use]
    pub fn running_through(&self, tenant: &TenantId, pipeline: &PipelineId) -> u64 {
        self.routes
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, route)| owner == tenant && route.pipeline_id() == pipeline)
            .count() as u64
    }
}

fn is(entry: &(TenantId, Route<ResolvedTenant>), tenant: &ScopedTenant, id: &RouteId) -> bool {
    entry.0 == **tenant && entry.1.id() == id
}

#[async_trait]
impl RouteStore for FakeRouteStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &RouteId,
    ) -> Result<Option<Route<ResolvedTenant>>, DomainError> {
        Ok(self
            .routes
            .lock()
            .unwrap()
            .iter()
            .find(|entry| is(entry, tenant_id, id))
            .map(|(_, route)| route_copy(route)))
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<RouteStatus>,
        sort: &SortOrder<RouteSortField>,
        request: &PageRequest,
    ) -> Result<Page<Route<ResolvedTenant>>, DomainError> {
        let all: Vec<_> = self
            .routes
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, _)| owner == &**tenant_id)
            .filter(|(_, route)| status.is_none_or(|wanted| route.status() == wanted))
            .map(|(_, route)| route_copy(route))
            .collect();
        page(all, sort, request)
    }

    async fn list_by_pipeline(
        &self,
        tenant_id: &ScopedTenant,
        pipeline_id: &PipelineId,
    ) -> Result<Vec<Route<ResolvedTenant>>, DomainError> {
        let mut on_pipeline: Vec<_> = self
            .routes
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, route)| owner == &**tenant_id && route.pipeline_id() == pipeline_id)
            .map(|(_, route)| route_copy(route))
            .collect();
        on_pipeline.sort_by_key(|route| (route.priority(), *route.id().as_uuid()));
        Ok(on_pipeline)
    }

    async fn list_open_to_workflows(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<Route<ResolvedTenant>>, DomainError> {
        let mut open: Vec<_> = self
            .routes
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, route)| {
                owner == &**tenant_id
                    && route.is_active()
                    && route.workflow_use() == WorkflowUse::Open
            })
            .map(|(_, route)| route_copy(route))
            .collect();
        open.sort_by_key(|route| (route.priority(), *route.id().as_uuid()));
        Ok(open)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        route: &Route<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut routes = self.routes.lock().unwrap();
        let by_name = |kept: &Route<ResolvedTenant>| (kept.name().clone(), *kept.id());
        if routes
            .iter()
            .any(|entry| rivals(entry, tenant_id, route, by_name))
        {
            return Err(DomainError::conflict(
                "another route of the tenant has the name",
            ));
        }
        routes.retain(|entry| !is(entry, tenant_id, route.id()));
        routes.push((**tenant_id, route_copy(route)));
        Ok(())
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &RouteId) -> Result<(), DomainError> {
        remove_where(&self.routes, |entry| is(entry, tenant_id, id));
        Ok(())
    }
}

impl Fake for Arc<dyn RouteStore> {
    fn fake() -> Self {
        Arc::new(FakeRouteStore::empty())
    }
}

impl Fake for Arc<crate::use_cases::proxy::DecideAccessUseCase> {
    fn fake() -> Self {
        Arc::new(crate::use_cases::proxy::DecideAccessUseCase::new(
            crate::use_cases::proxy::DecideAccessPorts::fakes(),
        ))
    }
}
