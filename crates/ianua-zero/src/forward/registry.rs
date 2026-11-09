//! One pool per service, kept as the configuration changes.
//!
//! The route table is compiled per tenant, and each time it is, the
//! tenant's pools are reconciled first: a service whose upstream and probe
//! settings are unchanged keeps its pool, and with it what is known about
//! each backend; a changed one gets a new pool, a gone one loses it. The
//! health probes and the name lookups follow the pools.
//!
//! A service reached through a tenant's connector gets a pool like any
//! other, whose connections are opened down that connector's links. A
//! service whose pool cannot be built, such as one whose client
//! certificate key was not handed in, has no pool, and its routes are
//! refused as not served.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use ianua_domain::domains::routing::backend::health_check::HealthCheckPolicy;
use ianua_domain::domains::routing::backend::upstream::Upstream;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::isolation::scope::TenantScope;
use ianua_domain::types::{ServiceId, TenantId};

use super::client::Clients;
use super::discovery::DiscoveryWatch;
use super::error::ForwardError;
use super::health::HealthChecks;
use super::pool::ServicePool;
use super::tls::ClientKeys;

/// What a pool is built from: a service's id, upstream and probe settings.
pub(super) struct ServiceSpec<'a> {
    /// The service.
    pub(super) id: ServiceId,
    /// Where it forwards to.
    pub(super) upstream: &'a Upstream,
    /// How its backends are probed.
    pub(super) health: &'a HealthCheckPolicy,
}

/// The pools of one tenant's services, by service.
#[derive(Clone, Default)]
pub(crate) struct TenantPools {
    pools: HashMap<ServiceId, Arc<ServicePool>>,
}

impl TenantPools {
    /// The pool of `service_id`.
    ///
    /// # Errors
    ///
    /// - [`ForwardError::NoPool`] when the service is not active, not the
    ///   tenant's, or its pool could not be built.
    pub(crate) fn pool(&self, service_id: &ServiceId) -> Result<&Arc<ServicePool>, ForwardError> {
        self.pools.get(service_id).ok_or(ForwardError::NoPool)
    }
}

/// Every tenant's pools, and the probes and lookups that keep them current.
pub(crate) struct ServicePools {
    clients: Clients,
    health: HealthChecks,
    discovery: Arc<DiscoveryWatch>,
    tenants: RwLock<HashMap<TenantId, TenantPools>>,
}

/// The held pools and client keys used while reconciling one tenant.
struct TenantServices<'a> {
    tenant_id: TenantId,
    previous: &'a TenantPools,
    keys: &'a ClientKeys,
}

impl ServicePools {
    /// Pools built with `clients`, probed by `health` and looked up by
    /// `discovery`.
    #[must_use]
    pub(crate) fn new(
        clients: Clients,
        health: HealthChecks,
        discovery: Arc<DiscoveryWatch>,
    ) -> Self {
        Self {
            clients,
            health,
            discovery,
            tenants: RwLock::new(HashMap::new()),
        }
    }

    /// Brings a tenant's pools in line with its `services`, and answers
    /// with them for the route table.
    ///
    /// Only active services get a pool. `keys` holds the opened client
    /// keys of the services that present a certificate. Probes start for
    /// new pools, so this is called inside the runtime.
    pub(crate) fn reconcile_tenant<T: TenantScope>(
        &self,
        tenant_id: TenantId,
        services: &[Service<T>],
        keys: &ClientKeys,
    ) -> TenantPools {
        let specs: Vec<ServiceSpec<'_>> = services
            .iter()
            .filter(|service| service.is_active())
            .map(|service| ServiceSpec {
                id: *service.id(),
                upstream: service.upstream(),
                health: service.health_check(),
            })
            .collect();
        self.reconcile_specs(tenant_id, &specs, keys)
    }

    /// The pool of `service_id` in `tenant_id`, as the last reconcile of
    /// the tenant left it.
    ///
    /// # Errors
    ///
    /// - [`ForwardError::NoPool`] for a service with no pool: one whose pool
    ///   could not be built, or a tenant or service not reconciled.
    pub(crate) fn pool(
        &self,
        tenant_id: TenantId,
        service_id: &ServiceId,
    ) -> Result<Arc<ServicePool>, ForwardError> {
        let tenants = self.read();
        let Some(pools) = tenants.get(&tenant_id) else {
            return Err(ForwardError::NoPool);
        };
        pools.pool(service_id).map(Arc::clone)
    }

    /// Drops a tenant's pools, probes and lookups.
    pub(crate) fn drop_tenant(&self, tenant_id: TenantId) {
        self.health.drop_tenant(tenant_id);
        self.discovery.drop_tenant(tenant_id);
        self.write().remove(&tenant_id);
    }

    /// Brings a tenant's pools in line with `specs`.
    pub(super) fn reconcile_specs(
        &self,
        tenant_id: TenantId,
        specs: &[ServiceSpec<'_>],
        keys: &ClientKeys,
    ) -> TenantPools {
        let previous = self.tenant(tenant_id);
        let services = TenantServices {
            tenant_id,
            previous: &previous,
            keys,
        };
        let mut current = TenantPools::default();
        for spec in specs {
            let Some(pool) = self.pool_for(spec, &services) else {
                continue;
            };
            current.pools.insert(spec.id, pool);
        }
        let listed: Vec<(ServiceId, Arc<ServicePool>)> = current
            .pools
            .iter()
            .map(|(id, pool)| (*id, Arc::clone(pool)))
            .collect();
        self.health.reconcile_tenant(tenant_id, &listed);
        self.discovery.watch_tenant(tenant_id, &listed);
        self.write().insert(tenant_id, current.clone());
        current
    }

    /// The pool for `tenant_id`'s `spec`: the previous one when it still
    /// fits, a new one otherwise, or none when one cannot be built.
    fn pool_for(
        &self,
        spec: &ServiceSpec<'_>,
        services: &TenantServices<'_>,
    ) -> Option<Arc<ServicePool>> {
        let previous = services.previous.pools.get(&spec.id);
        if let Some(kept) = previous.filter(|pool| pool.serves(spec)) {
            return Some(Arc::clone(kept));
        }
        match self.clients.for_upstream(
            services.tenant_id,
            spec.upstream,
            services.keys.get(&spec.id),
        ) {
            Ok(client) => {
                let pool = ServicePool::new(spec, client, self.clients.networks());
                Some(Arc::new(carried_over(pool, spec, previous)))
            }
            Err(error) => {
                tracing::warn!(
                    service_id = %spec.id,
                    error = %error,
                    "a service's pool could not be built; its routes are refused"
                );
                None
            }
        }
    }

    /// The tenant's current pools.
    fn tenant(&self, tenant_id: TenantId) -> TenantPools {
        self.read().get(&tenant_id).cloned().unwrap_or_default()
    }

    /// Every tenant's pools, for reading.
    fn read(&self) -> RwLockReadGuard<'_, HashMap<TenantId, TenantPools>> {
        self.tenants.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every tenant's pools, for writing.
    fn write(&self) -> RwLockWriteGuard<'_, HashMap<TenantId, TenantPools>> {
        self.tenants.write().unwrap_or_else(PoisonError::into_inner)
    }
}

/// `pool`, starting from the backends `previous` had last resolved to when
/// both find their backends by the same name, so a rebuilt pool does not
/// fall back to the written addresses until the next lookup.
fn carried_over(
    pool: ServicePool,
    spec: &ServiceSpec<'_>,
    previous: Option<&Arc<ServicePool>>,
) -> ServicePool {
    let same_name = previous.filter(|old| {
        spec.upstream.discovery().is_some()
            && old.upstream().discovery() == spec.upstream.discovery()
    });
    let Some(old) = same_name else {
        return pool;
    };
    pool.replace_backends(old.backends());
    pool
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::ConnectorId;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::forward::tests::support::{
        NoResolver, clients, discovery_settings, probe_settings, upstream_over,
    };

    fn pools() -> ServicePools {
        let health = HealthChecks::new(
            CancellationToken::new(),
            probe_settings(),
            Arc::new(ianua_app::test_support::routing::FakeBackendHealth::default()),
        );
        let resolver = Arc::new(NoResolver);
        let discovery = Arc::new(DiscoveryWatch::new(resolver, discovery_settings()));
        ServicePools::new(clients(), health, discovery)
    }

    fn reconcile(
        pools: &ServicePools,
        tenant: TenantId,
        services: &[(ServiceId, &Upstream, &HealthCheckPolicy)],
    ) -> TenantPools {
        let specs: Vec<ServiceSpec<'_>> = services
            .iter()
            .map(|(id, upstream, health)| ServiceSpec {
                id: *id,
                upstream,
                health,
            })
            .collect();
        pools.reconcile_specs(tenant, &specs, &ClientKeys::none())
    }

    fn same(a: &TenantPools, b: &TenantPools, id: &ServiceId) -> bool {
        Arc::ptr_eq(a.pool(id).unwrap(), b.pool(id).unwrap())
    }

    #[tokio::test]
    async fn an_unchanged_service_keeps_its_pool_and_probe() {
        let pools = pools();
        let (tenant, id) = (TenantId::new(), ServiceId::new());
        let upstream = upstream_over(&["http://10.0.0.1:80"]);
        let health = HealthCheckPolicy::default();

        let first = reconcile(&pools, tenant, &[(id, &upstream, &health)]);
        let again = reconcile(&pools, tenant, &[(id, &upstream, &health)]);

        assert!(same(&first, &again, &id));
        assert_eq!(pools.health.running_count(), 1);
    }

    #[tokio::test]
    async fn a_changed_service_gets_a_new_pool() {
        let pools = pools();
        let (tenant, id) = (TenantId::new(), ServiceId::new());
        let before = upstream_over(&["http://10.0.0.1:80"]);
        let after = upstream_over(&["http://10.0.0.2:80"]);
        let health = HealthCheckPolicy::default();

        let first = reconcile(&pools, tenant, &[(id, &before, &health)]);
        let again = reconcile(&pools, tenant, &[(id, &after, &health)]);

        assert!(!same(&first, &again, &id));
        assert_eq!(pools.health.running_count(), 1);
    }

    #[tokio::test]
    async fn a_service_that_is_gone_loses_its_pool_and_probe() {
        let pools = pools();
        let (tenant, id) = (TenantId::new(), ServiceId::new());
        let upstream = upstream_over(&["http://10.0.0.1:80"]);
        let health = HealthCheckPolicy::default();
        reconcile(&pools, tenant, &[(id, &upstream, &health)]);

        let now = reconcile(&pools, tenant, &[]);

        assert!(matches!(now.pool(&id), Err(ForwardError::NoPool)));
        assert_eq!(pools.health.running_count(), 0);
    }

    #[tokio::test]
    async fn a_service_with_probing_off_runs_no_probe() {
        let pools = pools();
        let upstream = upstream_over(&["http://10.0.0.1:80"]);
        let health = HealthCheckPolicy::Disabled;

        reconcile(
            &pools,
            TenantId::new(),
            &[(ServiceId::new(), &upstream, &health)],
        );

        assert_eq!(pools.health.running_count(), 0);
    }

    /// Acme's billing service sits behind its connector at 10.0.0.1. It
    /// gets a pool, whose connections go down the connector's links; with
    /// no link here, a request is answered `503`, never dialled from the
    /// gateway into whatever 10.0.0.1 is on its own network.
    #[tokio::test]
    async fn a_service_behind_a_connector_is_pooled_through_its_links() {
        let pools = pools();
        let id = ServiceId::new();
        let upstream = upstream_over(&["http://10.0.0.1:80"]).through_connector(ConnectorId::new());
        let health = HealthCheckPolicy::Disabled;

        let tenant = reconcile(&pools, TenantId::new(), &[(id, &upstream, &health)]);

        assert!(tenant.pool(&id).is_ok());
        assert_eq!(pools.health.running_count(), 0);
    }

    /// A service the tenant does not have is not served.
    #[tokio::test]
    async fn a_service_never_reconciled_is_not_served() {
        let pools = pools();

        let tenant = reconcile(&pools, TenantId::new(), &[]);

        assert!(matches!(
            tenant.pool(&ServiceId::new()),
            Err(ForwardError::NoPool)
        ));
    }

    #[tokio::test]
    async fn dropping_a_tenant_stops_its_probes() {
        let pools = pools();
        let tenant = TenantId::new();
        let upstream = upstream_over(&["http://10.0.0.1:80"]);
        let health = HealthCheckPolicy::default();
        reconcile(&pools, tenant, &[(ServiceId::new(), &upstream, &health)]);

        pools.drop_tenant(tenant);

        assert_eq!(pools.health.running_count(), 0);
    }
}
