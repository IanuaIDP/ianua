//! An in-memory store of stream routes, and a policy decision point for
//! the people let into them and the callers the gateway asks about.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::proxy::access::question::Standing;
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::stream::{StreamRoute, StreamWorkflowUse, WorkflowLogin};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PrincipalRef, StreamRouteId, TenantId, UserId};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::routing::{
    PolicyDecision, PolicyDecisionPoint, StreamRouteLogins, StreamRouteSortField, StreamRouteStore,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::listing::page;
use crate::test_support::routing::held::remove_where;
use crate::test_support::{Fake, rivals};

/// In-memory stream route store for tests, keeping each route under the
/// tenant it was saved for.
///
/// A listening port belongs to the whole deployment, so a save that claims
/// a port another route holds is refused, whichever tenant holds it, the
/// way the unique index refuses it. So is a second stream route with a name
/// already taken in the tenant.
#[derive(Default)]
pub struct FakeStreamRouteStore {
    routes: Mutex<Vec<(TenantId, StreamRoute<ResolvedTenant>)>>,
}

impl TenantScoped for FakeStreamRouteStore {}

impl FakeStreamRouteStore {
    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Number of stored stream routes, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.routes.lock().unwrap().len()
    }
}

fn is(
    entry: &(TenantId, StreamRoute<ResolvedTenant>),
    tenant: &ScopedTenant,
    id: &StreamRouteId,
) -> bool {
    entry.0 == **tenant && entry.1.id() == id
}

fn claims_port_of(held: &StreamRoute<ResolvedTenant>, route: &StreamRoute<ResolvedTenant>) -> bool {
    held.listen_port() == route.listen_port() && held.id() != route.id()
}

#[async_trait]
impl StreamRouteStore for FakeStreamRouteStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &StreamRouteId,
    ) -> Result<Option<StreamRoute<ResolvedTenant>>, DomainError> {
        Ok(self
            .routes
            .lock()
            .unwrap()
            .iter()
            .find(|entry| is(entry, tenant_id, id))
            .map(|(_, route)| route.clone()))
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<StreamRouteSortField>,
        request: &PageRequest,
    ) -> Result<Page<StreamRoute<ResolvedTenant>>, DomainError> {
        let all: Vec<_> = self
            .routes
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, _)| owner == &**tenant_id)
            .map(|(_, route)| route.clone())
            .collect();
        page(all, sort, request)
    }

    async fn list_open_to_workflows(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<StreamRoute<ResolvedTenant>>, DomainError> {
        let mut open: Vec<_> = self
            .routes
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, route)| {
                owner == &**tenant_id
                    && route.is_active()
                    && route.workflow_use() == StreamWorkflowUse::Open
            })
            .map(|(_, route)| route.clone())
            .collect();
        open.sort_by(|a, b| a.name().as_str().cmp(b.name().as_str()));
        Ok(open)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        route: &StreamRoute<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut routes = self.routes.lock().unwrap();
        if routes.iter().any(|(_, held)| claims_port_of(held, route)) {
            return Err(DomainError::conflict(format!(
                "port {} is already claimed",
                route.listen_port().get()
            )));
        }
        let by_name = |kept: &StreamRoute<ResolvedTenant>| (kept.name().clone(), *kept.id());
        if routes
            .iter()
            .any(|entry| rivals(entry, tenant_id, route, by_name))
        {
            return Err(DomainError::conflict(
                "another stream route of the tenant has the name",
            ));
        }
        routes.retain(|entry| !is(entry, tenant_id, route.id()));
        routes.push((**tenant_id, route.clone()));
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &StreamRouteId,
    ) -> Result<(), DomainError> {
        remove_where(&self.routes, |entry| is(entry, tenant_id, id));
        Ok(())
    }
}

impl Fake for Arc<dyn StreamRouteStore> {
    fn fake() -> Self {
        Arc::new(FakeStreamRouteStore::empty())
    }
}

/// Keeps stream routes' workflow logins in memory, by tenant and route.
#[derive(Default)]
pub struct FakeStreamRouteLogins {
    logins: Mutex<Vec<(TenantId, StreamRouteId, WorkflowLogin)>>,
}

impl FakeStreamRouteLogins {
    /// The logins kept, holding `login` for stream route `id` of the test
    /// tenant.
    #[must_use]
    pub fn holding(tenant: &ScopedTenant, id: StreamRouteId, login: WorkflowLogin) -> Self {
        Self {
            logins: Mutex::new(vec![(**tenant, id, login)]),
        }
    }
}

impl TenantScoped for FakeStreamRouteLogins {}

#[async_trait]
impl StreamRouteLogins for FakeStreamRouteLogins {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        id: &StreamRouteId,
    ) -> Result<Option<WorkflowLogin>, DomainError> {
        Ok(self
            .logins
            .lock()
            .unwrap()
            .iter()
            .find(|(tenant, route, _)| tenant == &**tenant_id && route == id)
            .map(|(_, _, login)| login.clone()))
    }

    async fn keep(
        &self,
        tenant_id: &ScopedTenant,
        id: &StreamRouteId,
        login: &WorkflowLogin,
    ) -> Result<(), DomainError> {
        let mut logins = self.logins.lock().unwrap();
        logins.retain(|(tenant, route, _)| !(tenant == &**tenant_id && route == id));
        logins.push((**tenant_id, *id, login.clone()));
        Ok(())
    }

    async fn forget(
        &self,
        tenant_id: &ScopedTenant,
        id: &StreamRouteId,
    ) -> Result<(), DomainError> {
        self.logins
            .lock()
            .unwrap()
            .retain(|(tenant, route, _)| !(tenant == &**tenant_id && route == id));
        Ok(())
    }
}

impl Fake for Arc<dyn StreamRouteLogins> {
    fn fake() -> Self {
        Arc::new(FakeStreamRouteLogins::default())
    }
}

/// What a [`FakePolicyDecisionPoint`] answers.
#[derive(Clone, Copy)]
enum Answer {
    /// Every person gets this decision, and every caller this standing.
    Gives {
        decision: PolicyDecision,
        standing: Standing,
    },
    /// Every question fails, as an unreachable policy store does.
    Unreachable,
}

/// A policy decision point answering every question the same way, counting
/// how often it was asked.
pub struct FakePolicyDecisionPoint {
    answer: Answer,
    asked: Mutex<u32>,
}

impl TenantScoped for FakePolicyDecisionPoint {}

impl FakePolicyDecisionPoint {
    /// One that answers `decision` to every person, and knows no caller.
    #[must_use]
    pub fn deciding(decision: PolicyDecision) -> Self {
        Self {
            answer: Answer::Gives {
                decision,
                standing: Standing::Unknown,
            },
            asked: Mutex::new(0),
        }
    }

    /// One that says every caller stands as `standing`, and decides nothing
    /// for a person.
    #[must_use]
    pub fn in_standing(standing: Standing) -> Self {
        Self {
            answer: Answer::Gives {
                decision: PolicyDecision::Undecided,
                standing,
            },
            asked: Mutex::new(0),
        }
    }

    /// One whose policy store cannot be reached.
    #[must_use]
    pub fn unreachable() -> Self {
        Self {
            answer: Answer::Unreachable,
            asked: Mutex::new(0),
        }
    }

    /// How many questions it was asked.
    #[must_use]
    pub fn times_asked(&self) -> u32 {
        *self.asked.lock().unwrap()
    }
}

#[async_trait]
impl PolicyDecisionPoint for FakePolicyDecisionPoint {
    async fn decide(
        &self,
        _tenant_id: &ScopedTenant,
        _person: &UserId,
        _policy: &RoutePolicy,
    ) -> Result<PolicyDecision, DomainError> {
        *self.asked.lock().unwrap() += 1;
        match self.answer {
            Answer::Gives { decision, .. } => Ok(decision),
            Answer::Unreachable => Err(DomainError::infra_msg("the policy store is unreachable")),
        }
    }

    async fn standing(
        &self,
        _tenant_id: &ScopedTenant,
        _principal: &PrincipalRef,
    ) -> Result<Standing, DomainError> {
        *self.asked.lock().unwrap() += 1;
        match self.answer {
            Answer::Gives { standing, .. } => Ok(standing),
            Answer::Unreachable => Err(DomainError::infra_msg("the records are unreachable")),
        }
    }
}

impl Fake for Arc<dyn PolicyDecisionPoint> {
    fn fake() -> Self {
        Arc::new(FakePolicyDecisionPoint::deciding(PolicyDecision::Deny))
    }
}
