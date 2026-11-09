//! What a tenant holds against its plan: one count per kind of resource,
//! each a single indexed query on the table that keeps it.
//!
//! A count reads the tenant's own database when it has one, under the
//! tenant's row-level security, and the platform's tables (the zones a
//! tenant delegated) under platform scope with the tenant named. A
//! resource that never ends counts whatever its standing, since a disabled
//! one comes back without a check; one that ends for good, such as a
//! revoked client, does not. Tenants and notification destinations belong
//! to the organization, so they are refused here and counted by
//! [`PgOrgResourceCounter`](crate::postgres::limits::PgOrgResourceCounter).
//!
//! Each count first takes the tenant's count lock, a transaction-level
//! advisory lock in the database the count reads. Inside a request's unit
//! of work it holds until the unit settles, with the creation the count
//! allowed, so two creations at the plan's ceiling at once count one after
//! the other and the second is refused. Outside a unit the lock ends with
//! the count, and guards nothing.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::limits::{ResourceCounter, ResourceKind};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use sqlx::postgres::PgArguments;
use sqlx::query::QueryScalar;
use sqlx::{PgConnection, Postgres};
use uuid::Uuid;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped_holding;

/// The Postgres counter of a tenant's resources.
pub struct PgResourceCounter {
    databases: Arc<Databases>,
}

impl PgResourceCounter {
    /// A counter reading `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgResourceCounter {}

/// Where the count of a kind of resource is read.
#[derive(Debug, Clone, Copy)]
enum Counted {
    /// A table of the tenant's own, in whichever database it lives.
    Kept(Kept),
    /// The record sets of the tenant's zones, in the platform's tables.
    ZoneRecords,
    /// A resource of the organization, not of one tenant.
    Organization,
}

/// A table of the tenant's own a count reads, grouped by what it serves.
#[derive(Debug, Clone, Copy)]
enum Kept {
    /// Accounts and what they hold.
    Access(Access),
    /// What the gateway serves.
    Gateway(Gateway),
    /// The tenant's links to other systems.
    Links(Links),
    /// Agents and workflows.
    Automation(Automation),
    /// Sandboxes and what runs in them.
    Sandboxing(Sandboxing),
}

/// The counted tables of accounts and what they hold.
#[derive(Debug, Clone, Copy)]
enum Access {
    Users,
    Roles,
    Groups,
    ResourceTypes,
    UserAttributes,
    ApiKeys,
    OAuthClients,
}

/// The counted tables of what the gateway serves.
#[derive(Debug, Clone, Copy)]
enum Gateway {
    Routes,
    Services,
    StreamRoutes,
    EgressPolicies,
    Consumers,
    Connectors,
    Domains,
}

/// The counted tables of the tenant's links to other systems.
#[derive(Debug, Clone, Copy)]
enum Links {
    Webhooks,
    FederationConnections,
    SamlServiceProviders,
    DirectoryServiceAccounts,
    MessageSubscriptions,
    LogTargets,
    AuditStreams,
}

/// The counted tables of sandboxes and what runs in them.
#[derive(Debug, Clone, Copy)]
enum Sandboxing {
    Sandboxes,
    RunningTrials,
    RunningEvaluations,
    OwnImages,
}

/// The counted tables of agents, workflows and sandboxes.
#[derive(Debug, Clone, Copy)]
enum Automation {
    Agents,
    AgentTools,
    ModelProviders,
    Workflows,
    Memories,
    ActiveAgentRuns,
    PendingApprovals,
}

/// Where the count of `kind` is read.
/// Every resource kind is named here so adding one requires an explicit storage choice.
#[allow(clippy::too_many_lines)]
fn counted(kind: ResourceKind) -> Counted {
    match kind {
        ResourceKind::Users => Counted::Kept(Kept::Access(Access::Users)),
        ResourceKind::Roles => Counted::Kept(Kept::Access(Access::Roles)),
        ResourceKind::Groups => Counted::Kept(Kept::Access(Access::Groups)),
        ResourceKind::ResourceTypes => Counted::Kept(Kept::Access(Access::ResourceTypes)),
        ResourceKind::UserAttributes => Counted::Kept(Kept::Access(Access::UserAttributes)),
        ResourceKind::ApiKeys => Counted::Kept(Kept::Access(Access::ApiKeys)),
        ResourceKind::OAuthClients => Counted::Kept(Kept::Access(Access::OAuthClients)),
        ResourceKind::Routes => Counted::Kept(Kept::Gateway(Gateway::Routes)),
        ResourceKind::Services => Counted::Kept(Kept::Gateway(Gateway::Services)),
        ResourceKind::StreamRoutes => Counted::Kept(Kept::Gateway(Gateway::StreamRoutes)),
        ResourceKind::EgressPolicies => Counted::Kept(Kept::Gateway(Gateway::EgressPolicies)),
        ResourceKind::Consumers => Counted::Kept(Kept::Gateway(Gateway::Consumers)),
        ResourceKind::Connectors => Counted::Kept(Kept::Gateway(Gateway::Connectors)),
        ResourceKind::Domains => Counted::Kept(Kept::Gateway(Gateway::Domains)),
        ResourceKind::Webhooks => Counted::Kept(Kept::Links(Links::Webhooks)),
        ResourceKind::FederationConnections => {
            Counted::Kept(Kept::Links(Links::FederationConnections))
        }
        ResourceKind::SamlServiceProviders => {
            Counted::Kept(Kept::Links(Links::SamlServiceProviders))
        }
        ResourceKind::DirectoryServiceAccounts => {
            Counted::Kept(Kept::Links(Links::DirectoryServiceAccounts))
        }
        ResourceKind::MessageSubscriptions => {
            Counted::Kept(Kept::Links(Links::MessageSubscriptions))
        }
        ResourceKind::LogTargets => Counted::Kept(Kept::Links(Links::LogTargets)),
        ResourceKind::AuditStreams => Counted::Kept(Kept::Links(Links::AuditStreams)),
        ResourceKind::Agents => Counted::Kept(Kept::Automation(Automation::Agents)),
        ResourceKind::AgentTools => Counted::Kept(Kept::Automation(Automation::AgentTools)),
        ResourceKind::ModelProviders => Counted::Kept(Kept::Automation(Automation::ModelProviders)),
        ResourceKind::Workflows => Counted::Kept(Kept::Automation(Automation::Workflows)),
        ResourceKind::Sandboxes => Counted::Kept(Kept::Sandboxing(Sandboxing::Sandboxes)),
        ResourceKind::RunningTrials => Counted::Kept(Kept::Sandboxing(Sandboxing::RunningTrials)),
        ResourceKind::RunningEvaluations => {
            Counted::Kept(Kept::Sandboxing(Sandboxing::RunningEvaluations))
        }
        ResourceKind::OwnImages => Counted::Kept(Kept::Sandboxing(Sandboxing::OwnImages)),
        ResourceKind::Memories => Counted::Kept(Kept::Automation(Automation::Memories)),
        ResourceKind::ActiveAgentRuns => {
            Counted::Kept(Kept::Automation(Automation::ActiveAgentRuns))
        }
        ResourceKind::PendingApprovals => {
            Counted::Kept(Kept::Automation(Automation::PendingApprovals))
        }
        ResourceKind::DnsRecordSets => Counted::ZoneRecords,
        ResourceKind::Tenants | ResourceKind::NotificationDestinations => Counted::Organization,
    }
}

impl Kept {
    /// How many rows of `tenant` the table holds against the plan.
    async fn count(self, connection: &mut PgConnection, tenant: &Uuid) -> Result<i64, sqlx::Error> {
        match self {
            Self::Access(table) => access(connection, tenant, table).await,
            Self::Gateway(table) => gateway(connection, tenant, table).await,
            Self::Links(table) => links(connection, tenant, table).await,
            Self::Automation(table) => automation(connection, tenant, table).await,
            Self::Sandboxing(table) => sandboxing(connection, tenant, table).await,
        }
    }
}

/// How many accounts, or what they hold, `tenant` has of `table`.
async fn access(
    connection: &mut PgConnection,
    tenant: &Uuid,
    table: Access,
) -> Result<i64, sqlx::Error> {
    let query = match table {
        Access::Users => {
            sqlx::query_file_scalar!("queries/users/count_of_tenant.sql", tenant)
        }
        Access::Roles => {
            sqlx::query_file_scalar!("queries/roles/count_of_tenant.sql", tenant)
        }
        Access::Groups => {
            sqlx::query_file_scalar!("queries/groups/count_of_tenant.sql", tenant)
        }
        Access::ResourceTypes => {
            sqlx::query_file_scalar!("queries/resource_types/count_of_tenant.sql", tenant)
        }
        Access::UserAttributes => {
            sqlx::query_file_scalar!("queries/user_attribute_definitions/count.sql", tenant)
        }
        Access::ApiKeys => {
            sqlx::query_file_scalar!("queries/api_keys/count_of_tenant.sql", tenant)
        }
        Access::OAuthClients => {
            sqlx::query_file_scalar!("queries/oauth_clients/count_of_tenant.sql", tenant)
        }
    };
    query.fetch_one(connection).await
}

/// How many of what the gateway serves `tenant` has of `table`.
async fn gateway(
    connection: &mut PgConnection,
    tenant: &Uuid,
    table: Gateway,
) -> Result<i64, sqlx::Error> {
    let query = match table {
        Gateway::Routes => {
            sqlx::query_file_scalar!("queries/routes/count_of_tenant.sql", tenant)
        }
        Gateway::Services => {
            sqlx::query_file_scalar!("queries/services/count_of_tenant.sql", tenant)
        }
        Gateway::StreamRoutes => {
            sqlx::query_file_scalar!("queries/stream_routes/count_of_tenant.sql", tenant)
        }
        Gateway::EgressPolicies => {
            sqlx::query_file_scalar!("queries/egress_policies/count_of_tenant.sql", tenant)
        }
        Gateway::Consumers => {
            sqlx::query_file_scalar!("queries/consumers/count_of_tenant.sql", tenant)
        }
        Gateway::Connectors => {
            sqlx::query_file_scalar!("queries/connectors/count_of_tenant.sql", tenant)
        }
        Gateway::Domains => {
            sqlx::query_file_scalar!("queries/registered_domains/count_of_tenant.sql", tenant)
        }
    };
    query.fetch_one(connection).await
}

/// How many links to other systems `tenant` has of `table`.
async fn links(
    connection: &mut PgConnection,
    tenant: &Uuid,
    table: Links,
) -> Result<i64, sqlx::Error> {
    let query = match table {
        Links::Webhooks => {
            sqlx::query_file_scalar!("queries/webhook_subscriptions/count_of_tenant.sql", tenant)
        }
        Links::FederationConnections => {
            sqlx::query_file_scalar!("queries/federation_connections/count_of_tenant.sql", tenant)
        }
        Links::SamlServiceProviders => {
            sqlx::query_file_scalar!("queries/saml_service_providers/count_of_tenant.sql", tenant)
        }
        Links::DirectoryServiceAccounts => {
            sqlx::query_file_scalar!(
                "queries/directory_service_accounts/count_of_tenant.sql",
                tenant
            )
        }
        Links::MessageSubscriptions => {
            sqlx::query_file_scalar!("queries/topic_subscriptions/count_of_tenant.sql", tenant)
        }
        Links::LogTargets => {
            sqlx::query_file_scalar!("queries/log_shipping_targets/count_of_tenant.sql", tenant)
        }
        Links::AuditStreams => {
            sqlx::query_file_scalar!("queries/audit_streams/count_of_tenant.sql", tenant)
        }
    };
    query.fetch_one(connection).await
}

/// How many sandboxes, or runs in them, `tenant` has of `table`.
async fn sandboxing(
    connection: &mut PgConnection,
    tenant: &Uuid,
    table: Sandboxing,
) -> Result<i64, sqlx::Error> {
    let query = match table {
        Sandboxing::Sandboxes => {
            sqlx::query_file_scalar!("queries/sandboxes/count_of_tenant.sql", tenant)
        }
        Sandboxing::RunningTrials => {
            sqlx::query_file_scalar!("queries/sandbox_trials/running_of_tenant.sql", tenant)
        }
        Sandboxing::RunningEvaluations => {
            sqlx::query_file_scalar!("queries/evaluations/running_of_tenant.sql", tenant)
        }
        Sandboxing::OwnImages => {
            sqlx::query_file_scalar!("queries/sandboxes/own_images_of_tenant.sql", tenant)
        }
    };
    query.fetch_one(connection).await
}

/// How many agents, or what they run on, `tenant` has of `table`.
async fn automation(
    connection: &mut PgConnection,
    tenant: &Uuid,
    table: Automation,
) -> Result<i64, sqlx::Error> {
    let query = match table {
        Automation::Agents => {
            sqlx::query_file_scalar!("queries/agents/count_of_tenant.sql", tenant)
        }
        Automation::AgentTools => {
            sqlx::query_file_scalar!("queries/agent_tools/count_of_tenant.sql", tenant)
        }
        Automation::ModelProviders => {
            sqlx::query_file_scalar!("queries/agent_model_providers/count_of_tenant.sql", tenant)
        }
        Automation::Workflows => {
            sqlx::query_file_scalar!("queries/workflows/count_of_tenant.sql", tenant)
        }
        Automation::Memories => {
            sqlx::query_file_scalar!("queries/memories/count_of_tenant.sql", tenant)
        }
        Automation::ActiveAgentRuns => {
            sqlx::query_file_scalar!("queries/agent_runs/count_of_tenant.sql", tenant)
        }
        Automation::PendingApprovals => approval_query(tenant),
    };
    query.fetch_one(connection).await
}

/// Binds the current instant so expired undecided requests do not count as pending.
fn approval_query(tenant: &Uuid) -> QueryScalar<'static, Postgres, i64, PgArguments> {
    sqlx::query_file_scalar!(
        "queries/agent_approvals/count_of_tenant.sql",
        tenant,
        clock::now()
    )
}

/// How many record sets `tenant` holds across the zones it delegated.
async fn zone_records(connection: &mut PgConnection, tenant: &Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_file_scalar!("queries/dns_records/count_of_tenant.sql", tenant)
        .fetch_one(connection)
        .await
}

impl PgResourceCounter {
    /// How many rows of `table` the tenant holds, in its own database,
    /// counted under the tenant's count lock there.
    async fn kept(&self, tenant_id: &ScopedTenant, table: Kept) -> Result<i64, DomainError> {
        let tenant = *tenant_id.as_uuid();
        scoped_holding(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                hold_count(&mut *connection, &tenant).await?;
                table.count(connection, &tenant).await
            },
        )
        .await
    }

    /// How many record sets the tenant holds, in the platform's tables,
    /// counted under the tenant's count lock there.
    async fn zone_records(&self, tenant_id: &ScopedTenant) -> Result<i64, DomainError> {
        let tenant = *tenant_id.as_uuid();
        scoped_holding(&self.databases, RowScope::Platform, async |connection| {
            hold_count(&mut *connection, &tenant).await?;
            zone_records(connection, &tenant).await
        })
        .await
    }
}

/// Takes `tenant`'s count lock for the running transaction, waiting while
/// another count of the tenant holds it.
async fn hold_count(connection: &mut PgConnection, tenant: &Uuid) -> Result<(), sqlx::Error> {
    sqlx::query_file_scalar!("queries/tenants/hold_count.sql", tenant)
        .fetch_one(connection)
        .await
        .map(|_| ())
}

#[async_trait]
impl ResourceCounter for PgResourceCounter {
    async fn count_for_tenant(
        &self,
        tenant_id: &ScopedTenant,
        kind: ResourceKind,
    ) -> Result<u64, DomainError> {
        let count = match counted(kind) {
            Counted::Kept(table) => self.kept(tenant_id, table).await?,
            Counted::ZoneRecords => self.zone_records(tenant_id).await?,
            Counted::Organization => {
                return Err(DomainError::invalid(message!(
                    "infra-this-resource-belongs-to-the-organization",
                    "this resource belongs to the organization; count it there"
                )));
            }
        };
        u64::try_from(count).map_err(DomainError::infra)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::agents::{ApprovalStore, RunStore};
    use ianua_app::ports::authorization::RoleStore;
    use ianua_app::ports::identity::UserStore;
    use ianua_app::ports::runtime::{Settlement, atomically};
    use ianua_domain::domains::agents::execution::run::{
        AgentRun, AgentRunRow, NextCall, RunState,
    };
    use ianua_domain::domains::agents::oversight::approval::{ApprovalRequest, ApprovalRequestRow};
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClientRow};
    use ianua_domain::domains::oauth::clients::status::OAuthClientStatus;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::UserId;

    use super::*;
    use crate::postgres::agents::{PgApprovalStore, PgRunStore};
    use crate::postgres::authorization::PgRoleStore;
    use crate::postgres::foundation::unit::PgUnitOfWork;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::run::{another_agent, opened_approval_row, run_row};
    use crate::test_support::rows::authorization::{human, role, tenant};
    use crate::test_support::rows::identity::user_row;
    use crate::test_support::rows::oauth::{a_client, oauth_client_row};

    /// The grants of an ordinary sign-in client.
    const CODE: &[GrantType] = &[GrantType::AuthorizationCode, GrantType::RefreshToken];

    /// Every kind a tenant holds, the ones counted in it.
    const TENANT_KINDS: [ResourceKind; 33] = [
        ResourceKind::Users,
        ResourceKind::Roles,
        ResourceKind::Groups,
        ResourceKind::ResourceTypes,
        ResourceKind::UserAttributes,
        ResourceKind::ApiKeys,
        ResourceKind::OAuthClients,
        ResourceKind::Routes,
        ResourceKind::Services,
        ResourceKind::StreamRoutes,
        ResourceKind::EgressPolicies,
        ResourceKind::Consumers,
        ResourceKind::Connectors,
        ResourceKind::Domains,
        ResourceKind::Webhooks,
        ResourceKind::FederationConnections,
        ResourceKind::SamlServiceProviders,
        ResourceKind::DirectoryServiceAccounts,
        ResourceKind::MessageSubscriptions,
        ResourceKind::LogTargets,
        ResourceKind::AuditStreams,
        ResourceKind::Agents,
        ResourceKind::AgentTools,
        ResourceKind::ModelProviders,
        ResourceKind::Workflows,
        ResourceKind::Sandboxes,
        ResourceKind::Memories,
        ResourceKind::RunningTrials,
        ResourceKind::RunningEvaluations,
        ResourceKind::OwnImages,
        ResourceKind::ActiveAgentRuns,
        ResourceKind::PendingApprovals,
        ResourceKind::DnsRecordSets,
    ];

    async fn saved_users(db: &TestDb, tenant: &ScopedTenant, addresses: &[&str]) {
        let store = PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default());
        for address in addresses {
            let user = User::reconstitute(user_row(address)).unwrap();
            store.save(tenant, &user).await.unwrap();
        }
    }

    /// A tenant with nothing yet holds none of any kind, and every kind's
    /// count runs.
    #[tokio::test]
    async fn an_empty_tenant_holds_none_of_any_kind() {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let counter = PgResourceCounter::new(Arc::clone(&db.databases));

        for kind in TENANT_KINDS {
            assert_eq!(
                counter.count_for_tenant(&acme, kind).await.unwrap(),
                0,
                "{kind:?}"
            );
        }
    }

    /// The accounts a tenant holds are counted.
    #[tokio::test]
    async fn a_tenants_accounts_are_counted() {
        let db = TestDb::fresh().await;
        let acme = tenant();
        saved_users(&db, &acme, &["ada@acme.example", "bob@acme.example"]).await;
        let counter = PgResourceCounter::new(Arc::clone(&db.databases));

        let users = counter
            .count_for_tenant(&acme, ResourceKind::Users)
            .await
            .unwrap();

        assert_eq!(users, 2);
    }

    /// Concurrent units count roles in sequence: the first sees zero and
    /// saves a role, and the second sees that role after the first commits.
    #[tokio::test]
    async fn a_count_waits_for_the_creation_a_count_at_the_same_moment_allowed() {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let counter = PgResourceCounter::new(Arc::clone(&db.databases));
        let roles = PgRoleStore::new(Arc::clone(&db.databases));
        let (counter, roles, acme) = (&counter, &roles, &acme);
        let (counted, first_counted) = tokio::sync::oneshot::channel();
        let first = atomically(
            &PgUnitOfWork,
            async {
                let seen = counter.count_for_tenant(acme, ResourceKind::Roles).await;
                counted.send(()).unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                roles.save(acme, &role("auditor")).await.unwrap();
                seen
            },
            |_| Settlement::Commit,
        );
        let second = atomically(
            &PgUnitOfWork,
            async {
                first_counted.await.unwrap();
                counter.count_for_tenant(acme, ResourceKind::Roles).await
            },
            |_| Settlement::Commit,
        );

        let (first, second) = tokio::join!(first, second);

        assert_eq!(first.unwrap().unwrap(), 0);
        assert_eq!(second.unwrap().unwrap(), 1);
    }

    /// Acme counts no roles while Globex counts its one saved role.
    #[tokio::test]
    async fn another_tenants_resources_are_not_counted() {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let globex = tenant();
        PgRoleStore::new(Arc::clone(&db.databases))
            .save(&globex, &role("auditor"))
            .await
            .unwrap();
        let counter = PgResourceCounter::new(Arc::clone(&db.databases));

        let ours = counter
            .count_for_tenant(&acme, ResourceKind::Roles)
            .await
            .unwrap();
        let theirs = counter
            .count_for_tenant(&globex, ResourceKind::Roles)
            .await
            .unwrap();

        assert_eq!((ours, theirs), (0, 1));
    }

    /// A revoked OAuth client never works again, so it no longer takes up
    /// the plan's room; one in force does.
    #[tokio::test]
    async fn a_revoked_client_is_not_counted() {
        let db = TestDb::fresh().await;
        let acme = tenant();
        a_client(&db, &acme, oauth_client_row("kept", CODE)).await;
        let revoked = OAuthClientRow {
            status: OAuthClientStatus::Revoked,
            ..oauth_client_row("gone", CODE)
        };
        a_client(&db, &acme, revoked).await;
        let counter = PgResourceCounter::new(Arc::clone(&db.databases));

        let clients = counter
            .count_for_tenant(&acme, ResourceKind::OAuthClients)
            .await
            .unwrap();

        assert_eq!(clients, 1);
    }

    /// With one paused run and one completed run, the active run count is
    /// one, retaining the paused run against the tenant's allowance.
    #[tokio::test]
    async fn a_paused_run_is_counted_as_in_flight() {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let runs = PgRunStore::new(Arc::clone(&db.databases));
        for state in [RunState::Paused(NextCall::Model), RunState::Completed] {
            let agent = another_agent(&db.databases, &acme).await;
            let run = AgentRun::reconstitute(AgentRunRow {
                state,
                ..run_row(agent)
            })
            .unwrap();
            runs.save(&acme, &run).await.unwrap();
        }
        let counter = PgResourceCounter::new(Arc::clone(&db.databases));

        let in_flight = counter
            .count_for_tenant(&acme, ResourceKind::ActiveAgentRuns)
            .await
            .unwrap();

        assert_eq!(in_flight, 1);
    }

    /// Of two undecided approval requests, only the one still within its
    /// lifetime counts as pending.
    #[tokio::test]
    async fn a_request_past_its_time_is_not_counted_as_pending() {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let agent = another_agent(&db.databases, &acme).await;
        let approvals = PgApprovalStore::new(Arc::clone(&db.databases));
        let owner = human(UserId::new(), "owner@acme.example");
        let open =
            ApprovalRequest::reconstitute(opened_approval_row(agent, owner.clone())).unwrap();
        let lapsed = ApprovalRequest::reconstitute(ApprovalRequestRow {
            expires_at: clock::now() - time::Duration::seconds(1),
            created_at: clock::now() - time::Duration::minutes(10),
            updated_at: clock::now() - time::Duration::minutes(10),
            ..opened_approval_row(agent, owner)
        })
        .unwrap();
        approvals.save(&acme, &open).await.unwrap();
        approvals.save(&acme, &lapsed).await.unwrap();
        let counter = PgResourceCounter::new(Arc::clone(&db.databases));

        let waiting = counter
            .count_for_tenant(&acme, ResourceKind::PendingApprovals)
            .await
            .unwrap();

        assert_eq!(waiting, 1);
    }

    /// The tenant counter rejects counts of tenants and notification
    /// destinations with validation errors because they belong to the
    /// organization.
    #[tokio::test]
    async fn an_organizations_resource_is_refused() {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let counter = PgResourceCounter::new(Arc::clone(&db.databases));

        for kind in [
            ResourceKind::Tenants,
            ResourceKind::NotificationDestinations,
        ] {
            let refused = counter.count_for_tenant(&acme, kind).await;

            assert!(
                matches!(refused, Err(DomainError::Validation(_))),
                "{kind:?}"
            );
        }
    }

    /// A tenant with a database of its own is counted there.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_is_counted_there() {
        let platform = TestDb::fresh().await;
        let own = TestDb::fresh().await;
        let acme = tenant();
        platform.databases.register(*acme, own.as_dedicated());
        saved_users(&platform, &acme, &["ada@acme.example"]).await;
        let counter = PgResourceCounter::new(Arc::clone(&platform.databases));

        let users = counter
            .count_for_tenant(&acme, ResourceKind::Users)
            .await
            .unwrap();
        let in_own = PgResourceCounter::new(Arc::clone(&own.databases))
            .count_for_tenant(&acme, ResourceKind::Users)
            .await
            .unwrap();

        assert_eq!((users, in_own), (1, 1));
    }
}
