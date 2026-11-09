//! A tenant's own database: made when its setup asks for it, and removed
//! when its teardown does.
//!
//! What the platform can build on its own hardware is a schema of its own
//! database, for a tenant whose residency asks for a dedicated schema. The
//! schema is made and migrated by the database's owner, the tenant's trail
//! so far is copied in and the schema registered, in one transaction under
//! the tenant's purge and chain locks, and then every node is told to
//! route the tenant there. A tenant that asked for an instance or a cluster
//! of its own needs hardware this deployment does not make yet, so its
//! database step fails and the failure is on record; nothing is built half
//! way.
//!
//! Removing the schema first takes every write in it away from the app's
//! role, so a node that has not heard of the move yet fails its writes
//! there instead of losing them with the schema. Then it removes, as the
//! audit purge's role, what the schema's retention purged from the
//! platform's older copy of the trail, brings the rest of the trail back
//! and forgets the schema in one transaction, tells every node, and drops
//! the schema. A record written before the close is copied back: the copy
//! waits on the chain lock any append in flight holds. Every step can run
//! again; one that fails after the close leaves the tenant's schema read
//! only until the teardown is tried again.

mod follower;
mod registry;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::tenant::{
    ProvisionDatabaseRequest, ProvisionedEndpoint, TenantDatabaseProvisioner,
};
use ianua_domain::domains::tenant::provisioning::infrastructure::IsolationLevel;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrganizationId, TenantId};

pub use self::follower::TenantDatabaseFollower;
use self::follower::announce;
pub use self::registry::{load_tenant_databases, migrate_tenant_schemas};
pub(crate) use self::registry::{refresh, schema_of};
use crate::bus::Bus;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
pub use crate::postgres::foundation::tenant_databases::schemas::TenantSchemaAccess;
use crate::postgres::foundation::tenant_databases::schemas::{self, TenantSchema};
use crate::postgres::foundation::tenant_databases::trail;
use crate::postgres::foundation::unit::scoped;

/// Why a database of hardware of its own is not built.
const NO_HOST: &str =
    "a database on hardware of its own needs a host this deployment does not make yet";

/// Makes and removes tenants' own databases.
pub struct PgTenantDatabaseProvisioner {
    databases: Arc<Databases>,
    audit_purge: Arc<Databases>,
    access: TenantSchemaAccess,
    bus: Arc<dyn Bus>,
}

impl PgTenantDatabaseProvisioner {
    /// A provisioner making schemas in the platform's database with
    /// `access`, routing tenants in `databases`, removing what a schema's
    /// purge removed through `audit_purge` (the audit purge's role's
    /// databases), and telling every node on `bus`.
    #[must_use]
    pub fn new(
        databases: Arc<Databases>,
        audit_purge: Arc<Databases>,
        access: TenantSchemaAccess,
        bus: Arc<dyn Bus>,
    ) -> Self {
        Self {
            databases,
            audit_purge,
            access,
            bus,
        }
    }

    /// Makes `tenant`'s schema, hands it its trail, registers it and
    /// routes the tenant there.
    async fn adopted(&self, tenant: &TenantId) -> Result<ProvisionedEndpoint, DomainError> {
        let schema = TenantSchema::of(tenant);
        schemas::make(&self.access, &schema).await?;
        let id = *tenant.as_uuid();
        let name = schema.name().to_owned();
        let now = clock::now();
        scoped(&self.databases, RowScope::Platform, async |connection| {
            trail::adopt(&mut *connection, id, &schema).await?;
            sqlx::query_file!("queries/tenant_databases/save.sql", id, name.as_str(), now)
                .execute(connection)
                .await?;
            Ok(())
        })
        .await?;
        let routed = self.databases.schema_of_platform(schema.name())?;
        self.databases.register(*tenant, routed);
        self.tell(tenant).await;
        Ok(ProvisionedEndpoint::Schema {
            schema_name: schema.name().to_owned(),
        })
    }

    /// Closes `tenant`'s schema to the app's writes, brings its trail back,
    /// forgets the schema, routes the tenant to the platform's tables
    /// again, and drops the schema.
    async fn release_schema(&self, tenant: &TenantId) -> Result<(), DomainError> {
        let schema = TenantSchema::of(tenant);
        let id = *tenant.as_uuid();
        schemas::close_to_writes(&self.access, &schema).await?;
        scoped(
            &self.audit_purge,
            RowScope::Tenant(*tenant),
            async |connection| trail::follow_anchor(connection, id, &schema).await,
        )
        .await?;
        scoped(&self.databases, RowScope::Platform, async |connection| {
            trail::merge(&mut *connection, id, &schema).await?;
            sqlx::query_file!("queries/tenant_databases/remove.sql", id)
                .execute(connection)
                .await?;
            Ok(())
        })
        .await?;
        self.databases.deregister(tenant);
        self.audit_purge.deregister(tenant);
        self.tell(tenant).await;
        schemas::remove(&self.access.owner, &schema).await
    }

    /// Tells every node `tenant`'s route changed. A bus that does not take
    /// the word is logged: each node reloads its routes on its own, and the
    /// trail refuses to write where a tenant no longer lives.
    async fn tell(&self, tenant: &TenantId) {
        if let Err(error) = announce(self.bus.as_ref(), tenant).await {
            tracing::warn!(tenant_id = %tenant, %error, "a route change was not broadcast");
        }
    }
}

#[async_trait]
impl TenantDatabaseProvisioner for PgTenantDatabaseProvisioner {
    async fn provision(
        &self,
        tenant_id: &TenantId,
        _organization_id: &OrganizationId,
        request: &ProvisionDatabaseRequest,
    ) -> Result<ProvisionedEndpoint, DomainError> {
        match request.isolation() {
            IsolationLevel::Shared => Ok(ProvisionedEndpoint::Shared),
            IsolationLevel::DedicatedSchema => self.adopted(tenant_id).await,
            IsolationLevel::DedicatedInstance | IsolationLevel::DedicatedCluster => {
                Err(DomainError::infra_msg(NO_HOST))
            }
        }
    }

    async fn migrate_isolation(
        &self,
        tenant_id: &TenantId,
        organization_id: &OrganizationId,
        from: IsolationLevel,
        to: &ProvisionDatabaseRequest,
    ) -> Result<ProvisionedEndpoint, DomainError> {
        if from == to.isolation() {
            return Err(DomainError::invalid(message!(
                "infra-a-tenant-is-moved-only-to",
                "a tenant is moved only to another isolation"
            )));
        }
        self.provision(tenant_id, organization_id, to).await
    }

    async fn teardown(
        &self,
        tenant_id: &TenantId,
        _organization_id: &OrganizationId,
        isolation: IsolationLevel,
    ) -> Result<(), DomainError> {
        match isolation {
            IsolationLevel::Shared => Ok(()),
            IsolationLevel::DedicatedSchema => self.release_schema(tenant_id).await,
            IsolationLevel::DedicatedInstance | IsolationLevel::DedicatedCluster => {
                Err(DomainError::infra_msg(NO_HOST))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::auditor::RequestAuditor;
    use ianua_app::listing::{Limit, PageRequest, SortOrder};
    use ianua_app::ports::audit::{
        AuditLogFilter, AuditRetentionStore as _, TenantAuditLogStore as _,
    };
    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::domains::tenant::provisioning::infrastructure::{
        DeploymentRegion, Placement, TenantResidency,
    };
    use ianua_domain::shared::config::DomainLimits;

    use super::*;
    use crate::bus::MemoryBus;
    use crate::postgres::audit::{PgAuditRetentionStore, PgEventDispatcher, PgTenantAuditLogStore};
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::{
        chain_heads, failed_sign_in, recorded, saved_organization, saved_tenant_of,
    };

    struct Fixture {
        db: TestDb,
        tenant: ScopedTenant,
        provisioner: PgTenantDatabaseProvisioner,
    }

    /// A tenant with one record kept before it has a schema, and the
    /// provisioner on its database.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        recorded(&db.databases, vec![failed_sign_in(*tenant, 1)]).await;
        let provisioner = PgTenantDatabaseProvisioner::new(
            Arc::clone(&db.databases),
            Arc::clone(&db.audit_purge),
            db.schema_access(),
            Arc::new(MemoryBus::new(16)),
        );
        Fixture {
            db,
            tenant,
            provisioner,
        }
    }

    fn asking_for(isolation: IsolationLevel) -> ProvisionDatabaseRequest {
        let placement = Placement::Platform {
            region: DeploymentRegion::EuCentral1,
        };
        ProvisionDatabaseRequest::for_residency(TenantResidency::new(placement, isolation).unwrap())
    }

    impl Fixture {
        async fn provisioned(
            &self,
            isolation: IsolationLevel,
        ) -> Result<ProvisionedEndpoint, DomainError> {
            self.provisioner
                .provision(&self.tenant, &OrganizationId::new(), &asking_for(isolation))
                .await
        }

        async fn torn_down(&self) -> Result<(), DomainError> {
            self.provisioner
                .teardown(
                    &self.tenant,
                    &OrganizationId::new(),
                    IsolationLevel::DedicatedSchema,
                )
                .await
        }

        /// How many records the tenant's log reads, wherever it lives.
        async fn records(&self) -> usize {
            PgTenantAuditLogStore::new(Arc::clone(&self.db.databases), DomainLimits::default())
                .query(
                    &self.tenant,
                    &AuditLogFilter::default(),
                    &SortOrder::default(),
                    &PageRequest::first(Limit::new(50).unwrap()),
                )
                .await
                .unwrap()
                .items
                .len()
        }
    }

    /// A tenant that asked for a schema of its own gets one: it is routed
    /// there, its record from before is there, and its trail goes on there.
    #[tokio::test]
    async fn a_tenant_gets_its_schema_and_its_trail_goes_on_there() {
        let fx = fixture().await;

        let made = fx
            .provisioned(IsolationLevel::DedicatedSchema)
            .await
            .unwrap();
        recorded(&fx.db.databases, vec![failed_sign_in(*fx.tenant, 2)]).await;

        assert!(matches!(made, ProvisionedEndpoint::Schema { .. }));
        assert!(fx.db.databases.lives_apart(&fx.tenant));
        assert_eq!(fx.records().await, 2);
    }

    /// A setup that runs its database step again makes nothing twice.
    #[tokio::test]
    async fn a_schema_made_again_changes_nothing() {
        let fx = fixture().await;
        fx.provisioned(IsolationLevel::DedicatedSchema)
            .await
            .unwrap();

        let again = fx.provisioned(IsolationLevel::DedicatedSchema).await;

        assert!(again.is_ok());
        assert_eq!(fx.records().await, 1);
    }

    /// Leaving its schema brings the tenant's whole trail back to the
    /// platform's tables and routes it there, and a teardown run again
    /// finds nothing left to do.
    #[tokio::test]
    async fn leaving_its_schema_brings_its_trail_back() {
        let fx = fixture().await;
        fx.provisioned(IsolationLevel::DedicatedSchema)
            .await
            .unwrap();
        recorded(&fx.db.databases, vec![failed_sign_in(*fx.tenant, 2)]).await;

        fx.torn_down().await.unwrap();
        let again = fx.torn_down().await;

        assert!(again.is_ok());
        assert!(!fx.db.databases.lives_apart(&fx.tenant));
        assert_eq!(fx.records().await, 2);
    }

    /// After retention purges two of four records in a tenant's schema,
    /// tearing the schema down leaves two records in its platform log.
    #[tokio::test]
    async fn leaving_its_schema_keeps_what_its_retention_purged_there_gone() {
        let fx = fixture().await;
        fx.provisioned(IsolationLevel::DedicatedSchema)
            .await
            .unwrap();
        let later = (2..=4).map(|s| failed_sign_in(*fx.tenant, s)).collect();
        recorded(&fx.db.databases, later).await;
        PgAuditRetentionStore::new(Arc::clone(&fx.db.audit_purge), chain_heads())
            .purge_before(&fx.tenant, at(3))
            .await
            .unwrap();

        fx.torn_down().await.unwrap();

        assert_eq!(fx.records().await, 2);
    }

    /// After a tenant moves to its own schema, an audit append through a
    /// node still using the platform tables fails and the log keeps one record.
    #[tokio::test]
    async fn a_node_that_has_not_heard_of_the_move_is_refused() {
        let fx = fixture().await;
        fx.provisioned(IsolationLevel::DedicatedSchema)
            .await
            .unwrap();
        let lagging = Arc::new(PgEventDispatcher::new(fx.db.another_node(), chain_heads()));

        let kept = RequestAuditor::new(lagging, AuditContext::system())
            .dispatch(&[failed_sign_in(*fx.tenant, 2)])
            .await;

        assert!(kept.is_err());
        assert_eq!(fx.records().await, 1);
    }

    /// Closing a tenant schema to writes rejects an audit append from a
    /// node still routing there; teardown succeeds and the log keeps one record.
    #[tokio::test]
    async fn a_node_still_routing_to_a_schema_being_left_is_refused() {
        let fx = fixture().await;
        fx.provisioned(IsolationLevel::DedicatedSchema)
            .await
            .unwrap();
        let schema = TenantSchema::of(&fx.tenant);
        let lagging = fx.db.another_node();
        let routed = lagging.schema_of_platform(schema.name()).unwrap();
        lagging.register(*fx.tenant, routed);
        schemas::close_to_writes(&fx.provisioner.access, &schema)
            .await
            .unwrap();

        let kept = RequestAuditor::new(
            Arc::new(PgEventDispatcher::new(lagging, chain_heads())),
            AuditContext::system(),
        )
        .dispatch(&[failed_sign_in(*fx.tenant, 2)])
        .await;
        let left = fx.torn_down().await;

        assert!(kept.is_err());
        assert!(left.is_ok());
        assert_eq!(fx.records().await, 1);
    }

    /// Provisioning an existing schema again after retention purges two of
    /// four records succeeds and leaves two records in the tenant's log.
    #[tokio::test]
    async fn a_schema_made_again_after_a_purge_keeps_the_purged_records_out() {
        let fx = fixture().await;
        fx.provisioned(IsolationLevel::DedicatedSchema)
            .await
            .unwrap();
        let later = (2..=4).map(|s| failed_sign_in(*fx.tenant, s)).collect();
        recorded(&fx.db.databases, later).await;
        PgAuditRetentionStore::new(Arc::clone(&fx.db.audit_purge), chain_heads())
            .purge_before(&fx.tenant, at(3))
            .await
            .unwrap();

        let again = fx.provisioned(IsolationLevel::DedicatedSchema).await;

        assert!(again.is_ok());
        assert_eq!(fx.records().await, 2);
    }

    /// Requesting a dedicated database instance returns an infrastructure
    /// error and leaves the tenant routed to the platform database.
    #[tokio::test]
    async fn hardware_of_its_own_is_refused() {
        let fx = fixture().await;

        let made = fx.provisioned(IsolationLevel::DedicatedInstance).await;

        assert!(matches!(made, Err(DomainError::Infrastructure(_))));
        assert!(!fx.db.databases.lives_apart(&fx.tenant));
    }
}
