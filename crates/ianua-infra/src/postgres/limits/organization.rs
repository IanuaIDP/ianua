//! What an organization holds against its plan itself: its tenants and the
//! channels it posts notifications to, each one indexed count in the
//! platform's tables.
//!
//! Every other kind is held by a tenant and counted inside it by
//! [`PgResourceCounter`](crate::postgres::limits::PgResourceCounter), so it
//! is refused here rather than answered with a number that means nothing.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::limits::{OrgResourceCounter, ResourceKind};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::OrganizationId;
use sqlx::PgConnection;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped_holding;

/// The Postgres counter of an organization's own resources.
pub struct PgOrgResourceCounter {
    databases: Arc<Databases>,
}

impl PgOrgResourceCounter {
    /// A counter reading `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The tenants `organization` holds, every one not deleted, counted
    /// under its count lock.
    async fn tenants(&self, organization: &OrganizationId) -> Result<i64, DomainError> {
        scoped_holding(&self.databases, RowScope::Unscoped, async |connection| {
            hold_count(&mut *connection, organization).await?;
            sqlx::query_file_scalar!(
                "queries/tenants/count_of_organization.sql",
                organization.as_uuid()
            )
            .fetch_one(connection)
            .await
        })
        .await
    }

    /// The channels `organization` posts notifications to, counted under
    /// its count lock.
    async fn destinations(&self, organization: &OrganizationId) -> Result<i64, DomainError> {
        scoped_holding(&self.databases, RowScope::Unscoped, async |connection| {
            hold_count(&mut *connection, organization).await?;
            sqlx::query_file_scalar!(
                "queries/org_notification_destinations/count_of_organization.sql",
                organization.as_uuid()
            )
            .fetch_one(connection)
            .await
        })
        .await
    }
}

/// Takes `organization`'s count lock for the running transaction, waiting
/// while another count of it holds it. Inside a unit of work it holds until
/// the unit settles, with the creation the count allowed.
async fn hold_count(
    connection: &mut PgConnection,
    organization: &OrganizationId,
) -> Result<(), sqlx::Error> {
    sqlx::query_file_scalar!(
        "queries/tenants/hold_organization_count.sql",
        organization.as_uuid()
    )
    .fetch_one(connection)
    .await
    .map(|_| ())
}

#[async_trait]
impl OrgResourceCounter for PgOrgResourceCounter {
    /// The exhaustive rejection list keeps every tenant-only kind outside organization counts.
    #[allow(clippy::too_many_lines)]
    async fn count_for_org(
        &self,
        organization_id: &OrganizationId,
        kind: ResourceKind,
    ) -> Result<u64, DomainError> {
        let count = match kind {
            ResourceKind::Tenants => self.tenants(organization_id).await?,
            ResourceKind::NotificationDestinations => self.destinations(organization_id).await?,
            ResourceKind::Users
            | ResourceKind::Routes
            | ResourceKind::DnsRecordSets
            | ResourceKind::Domains
            | ResourceKind::ApiKeys
            | ResourceKind::OAuthClients
            | ResourceKind::Roles
            | ResourceKind::Groups
            | ResourceKind::Webhooks
            | ResourceKind::FederationConnections
            | ResourceKind::SamlServiceProviders
            | ResourceKind::DirectoryServiceAccounts
            | ResourceKind::MessageSubscriptions
            | ResourceKind::Connectors
            | ResourceKind::LogTargets
            | ResourceKind::AuditStreams
            | ResourceKind::Consumers
            | ResourceKind::Services
            | ResourceKind::StreamRoutes
            | ResourceKind::EgressPolicies
            | ResourceKind::ResourceTypes
            | ResourceKind::UserAttributes
            | ResourceKind::Agents
            | ResourceKind::AgentTools
            | ResourceKind::ModelProviders
            | ResourceKind::Workflows
            | ResourceKind::Sandboxes
            | ResourceKind::RunningTrials
            | ResourceKind::RunningEvaluations
            | ResourceKind::OwnImages
            | ResourceKind::Memories
            | ResourceKind::ActiveAgentRuns
            | ResourceKind::PendingApprovals => {
                return Err(DomainError::invalid(message!(
                    "infra-this-resource-belongs-to-a-tenant",
                    "this resource belongs to a tenant; count it there"
                )));
            }
        };
        u64::try_from(count).map_err(DomainError::infra)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::tenant::TenantStore;
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::shared::config::DomainLimits;

    use super::*;
    use crate::postgres::tenant::PgTenantStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::audit::{saved_organization, saved_tenant_of};
    use crate::test_support::rows::tenant::deleted_tenant_row;

    /// The tenants an organization holds are counted, a deleted one left
    /// out, since it holds nothing any more.
    #[tokio::test]
    async fn an_organizations_tenants_are_counted_without_the_deleted() {
        let db = TestDb::fresh().await;
        let acme = saved_organization(&db.databases).await;
        saved_tenant_of(&db.databases, acme).await;
        saved_tenant_of(&db.databases, acme).await;
        let deleted = Tenant::reconstitute(deleted_tenant_row(acme, "gone")).unwrap();
        PgTenantStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&deleted)
            .await
            .unwrap();
        let counter = PgOrgResourceCounter::new(Arc::clone(&db.databases));

        let tenants = counter
            .count_for_org(&acme, ResourceKind::Tenants)
            .await
            .unwrap();

        assert_eq!(tenants, 2);
    }

    /// Acme's tenant count stays zero when only Globex owns a tenant.
    #[tokio::test]
    async fn another_organizations_tenants_are_not_counted() {
        let db = TestDb::fresh().await;
        let acme = saved_organization(&db.databases).await;
        let globex = saved_organization(&db.databases).await;
        saved_tenant_of(&db.databases, globex).await;
        let counter = PgOrgResourceCounter::new(Arc::clone(&db.databases));

        let tenants = counter
            .count_for_org(&acme, ResourceKind::Tenants)
            .await
            .unwrap();

        assert_eq!(tenants, 0);
    }

    /// An organization with no channels yet holds none.
    #[tokio::test]
    async fn an_organization_without_channels_holds_none() {
        let db = TestDb::fresh().await;
        let acme = saved_organization(&db.databases).await;
        let counter = PgOrgResourceCounter::new(Arc::clone(&db.databases));

        let destinations = counter
            .count_for_org(&acme, ResourceKind::NotificationDestinations)
            .await
            .unwrap();

        assert_eq!(destinations, 0);
    }

    /// Asking the organization counter for tenant routes returns a
    /// validation error.
    #[tokio::test]
    async fn a_tenants_resource_is_refused() {
        let db = TestDb::fresh().await;
        let acme = saved_organization(&db.databases).await;
        let counter = PgOrgResourceCounter::new(Arc::clone(&db.databases));

        let refused = counter.count_for_org(&acme, ResourceKind::Routes).await;

        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }
}
