//! Every node's routes kept to the registry: the word that one tenant's
//! route changed, broadcast on the bus by the node that changed it, and a
//! reload of every route now and then, for a word that never arrived.
//!
//! The word carries only the tenant's id. Whoever can broadcast on the bus
//! can make a node read the registry again, nothing more: the route itself
//! is always read from the platform's database.

use std::sync::Arc;
use std::time::Duration;

use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;
use uuid::Uuid;

use crate::bus::{Bus, BusError};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::tenant::databases::registry::{load_tenant_databases, refresh};

/// The subject a tenant's route change is broadcast on, under the
/// deployment's namespace.
const ROUTE_CHANGED: &str = "tenant_databases.changed";

/// Tells every node that `tenant`'s route changed.
///
/// # Errors
///
/// Returns [`BusError`] when the bus did not take the word.
pub(crate) async fn announce(bus: &dyn Bus, tenant: &TenantId) -> Result<(), BusError> {
    bus.broadcast(ROUTE_CHANGED, tenant.as_uuid().as_bytes())
        .await
}

/// Keeps one node's routes to the registry, for as long as it runs.
pub struct TenantDatabaseFollower {
    databases: Arc<Databases>,
    bus: Arc<dyn Bus>,
    reload_every: Duration,
}

impl TenantDatabaseFollower {
    /// A follower routing `databases` as the registry records it, hearing
    /// changes on `bus` and reloading every route each `reload_every`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, bus: Arc<dyn Bus>, reload_every: Duration) -> Self {
        Self {
            databases,
            bus,
            reload_every,
        }
    }

    /// Follows the registry until the bus closes the subscription. A route
    /// that cannot be read this time is logged and read again at the next
    /// word or reload.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the bus cannot be
    /// listened on, or closes the subscription.
    pub async fn follow(&self) -> Result<(), DomainError> {
        let mut listener = self.bus.listen(ROUTE_CHANGED).await?;
        let mut reloads = tokio::time::interval(self.reload_every);
        loop {
            tokio::select! {
                word = listener.next() => {
                    let Some(word) = word else {
                        return Err(DomainError::infra_msg("the bus closed the route changes"));
                    };
                    self.heard(&word).await;
                }
                _ = reloads.tick() => self.reload().await,
            }
        }
    }

    /// Routes again the tenant `word` names. A word that names no tenant
    /// is dropped.
    async fn heard(&self, word: &[u8]) {
        let Ok(id) = Uuid::from_slice(word) else {
            return;
        };
        let tenant = TenantId::from_uuid(id);
        if let Err(error) = refresh(&self.databases, &tenant).await {
            tracing::warn!(tenant_id = %tenant, %error, "a tenant's route was not refreshed");
        }
    }

    /// Routes every tenant again.
    async fn reload(&self) {
        if let Err(error) = load_tenant_databases(&self.databases).await {
            tracing::warn!(%error, "the tenants' routes were not reloaded");
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::tenant::{ProvisionDatabaseRequest, TenantDatabaseProvisioner as _};
    use ianua_domain::domains::tenant::provisioning::infrastructure::{
        DeploymentRegion, IsolationLevel, Placement, TenantResidency,
    };
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::bus::MemoryBus;
    use crate::postgres::tenant::PgTenantDatabaseProvisioner;
    use crate::test_support::TestDb;
    use crate::test_support::rows::audit::{saved_organization, saved_tenant_of};

    /// Gives a new tenant a schema of its own through `bus`, and answers
    /// the tenant.
    async fn moved_apart(db: &TestDb, bus: Arc<dyn Bus>) -> TenantId {
        let organization = saved_organization(&db.databases).await;
        let tenant = *saved_tenant_of(&db.databases, organization).await;
        let residency = TenantResidency::new(
            Placement::Platform {
                region: DeploymentRegion::EuCentral1,
            },
            IsolationLevel::DedicatedSchema,
        )
        .unwrap();
        PgTenantDatabaseProvisioner::new(
            Arc::clone(&db.databases),
            Arc::clone(&db.audit_purge),
            db.schema_access(),
            bus,
        )
        .provision(
            &tenant,
            &OrganizationId::new(),
            &ProvisionDatabaseRequest::for_residency(residency),
        )
        .await
        .unwrap();
        tenant
    }

    /// Another node hears that a tenant moved to its schema, and routes it
    /// there too.
    #[tokio::test]
    async fn another_node_routes_a_tenant_once_it_hears_of_the_move() {
        let db = TestDb::fresh().await;
        let bus: Arc<dyn Bus> = Arc::new(MemoryBus::new(16));
        let other = db.another_node();
        let follower = TenantDatabaseFollower::new(
            Arc::clone(&other),
            Arc::clone(&bus),
            Duration::from_secs(3600),
        );
        let following = tokio::spawn(async move { follower.follow().await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        let tenant = moved_apart(&db, bus).await;
        let heard = tokio::time::timeout(Duration::from_secs(5), async {
            while !other.lives_apart(&tenant) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        following.abort();

        assert!(heard.is_ok());
    }

    /// A node starting up routes every tenant that lives apart.
    #[tokio::test]
    async fn a_node_starting_up_routes_every_tenant_apart() {
        let db = TestDb::fresh().await;
        let tenant = moved_apart(&db, Arc::new(MemoryBus::new(16))).await;
        let other = db.another_node();

        load_tenant_databases(&other).await.unwrap();

        assert!(other.lives_apart(&tenant));
    }
}
