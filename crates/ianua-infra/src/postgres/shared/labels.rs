//! The names the audit trail records for the things an entry points at,
//! read when the entry is written: the two stores of
//! `ports/shared/audit_labels.rs`.
//!
//! Each kind is read with one query on its own table, by id among ids, so
//! the same query names one record or a whole page of them. A tenant's
//! records are read under its row-level security in the database it lives
//! in; a tenant's own name, an organization's members and notifications,
//! and operators and theirs are the platform's records, read from the
//! platform database. A record that is gone answers `None`, and the caller
//! names it by its id. An agent credential has no name of its own, so it
//! answers `None` without a read, as the domain names it by its id too.

mod control_plane;
mod record;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::shared::AuditLabelResolver;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    AgentCredentialId, AgentId, ApprovalId, ConnectionId, ConsumerId, DelegationId, EventLabel,
    GroupId, ModelProviderId, NotificationId, OAuthClientId, PrincipalRef, RoleId, UserId,
};
use sqlx::PgConnection;
use uuid::Uuid;

pub use self::control_plane::PgControlPlaneLabelResolver;
use self::record::{MaybeNamedRecord, NamedRecord, PersonRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The kinds of a tenant's records known by one name, each on its own
/// table.
#[derive(Debug, Clone, Copy)]
enum Named {
    Role,
    Group,
    Agent,
    Approval,
    ModelProvider,
    OAuthClient,
    Connection,
    Notification,
    Consumer,
}

/// The names of the records of `kind` in `tenant` that `ids` names.
/// One exhaustive dispatch keeps each record kind paired with its checked query.
#[allow(clippy::too_many_lines)]
async fn named_in(
    connection: &mut PgConnection,
    tenant: &Uuid,
    kind: Named,
    ids: &[Uuid],
) -> Result<Vec<NamedRecord>, sqlx::Error> {
    match kind {
        Named::Role => {
            sqlx::query_file_as!(NamedRecord, "queries/roles/labels.sql", tenant, ids)
                .fetch_all(connection)
                .await
        }
        Named::Group => {
            sqlx::query_file_as!(NamedRecord, "queries/groups/labels.sql", tenant, ids)
                .fetch_all(connection)
                .await
        }
        Named::Agent => {
            sqlx::query_file_as!(NamedRecord, "queries/agents/labels.sql", tenant, ids)
                .fetch_all(connection)
                .await
        }
        Named::Approval => {
            sqlx::query_file_as!(
                NamedRecord,
                "queries/agent_approvals/labels.sql",
                tenant,
                ids
            )
            .fetch_all(connection)
            .await
        }
        Named::ModelProvider => {
            sqlx::query_file_as!(
                NamedRecord,
                "queries/agent_model_providers/labels.sql",
                tenant,
                ids
            )
            .fetch_all(connection)
            .await
        }
        Named::OAuthClient => {
            sqlx::query_file_as!(NamedRecord, "queries/oauth_clients/labels.sql", tenant, ids)
                .fetch_all(connection)
                .await
        }
        Named::Connection => {
            sqlx::query_file_as!(
                NamedRecord,
                "queries/federation_connections/labels.sql",
                tenant,
                ids
            )
            .fetch_all(connection)
            .await
        }
        Named::Notification => {
            sqlx::query_file_as!(
                NamedRecord,
                "queries/tenant_notifications/labels.sql",
                tenant,
                ids
            )
            .fetch_all(connection)
            .await
        }
        Named::Consumer => {
            sqlx::query_file_as!(NamedRecord, "queries/consumers/labels.sql", tenant, ids)
                .fetch_all(connection)
                .await
        }
    }
}

/// The names of the users of `tenant` that `ids` names.
async fn people_in(
    connection: &mut PgConnection,
    tenant: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<PersonRecord>, sqlx::Error> {
    sqlx::query_file_as!(PersonRecord, "queries/users/labels.sql", tenant, ids)
        .fetch_all(connection)
        .await
}

/// The label of the one record a read by a single id found, if any.
fn only<I: IntoIterator<Item = (Uuid, EventLabel)>>(found: I) -> Option<EventLabel> {
    found.into_iter().next().map(|(_, label)| label)
}

/// The ids of `principals` of the kind `pick` takes.
fn ids_of(principals: &[PrincipalRef], pick: impl Fn(&PrincipalRef) -> Option<Uuid>) -> Vec<Uuid> {
    principals.iter().filter_map(pick).collect()
}

/// The names of a tenant's people, agents and consumers, read in one
/// transaction, one query a kind.
struct PrincipalNames {
    users: Vec<PersonRecord>,
    agents: Vec<NamedRecord>,
    consumers: Vec<NamedRecord>,
}

impl PrincipalNames {
    /// Every name found, keyed by the principal it names.
    fn into_labels(self) -> HashMap<PrincipalRef, EventLabel> {
        let users = self
            .users
            .into_iter()
            .map(PersonRecord::into_label)
            .map(|(id, label)| (PrincipalRef::User(UserId::from_uuid(id)), label));
        let agents = self
            .agents
            .into_iter()
            .map(NamedRecord::into_label)
            .map(|(id, label)| (PrincipalRef::Agent(AgentId::from_uuid(id)), label));
        let consumers = self
            .consumers
            .into_iter()
            .map(NamedRecord::into_label)
            .map(|(id, label)| (PrincipalRef::Consumer(ConsumerId::from_uuid(id)), label));
        users.chain(agents).chain(consumers).collect()
    }
}

/// The Postgres names of a tenant's records, for the audit trail.
pub struct PgAuditLabelResolver {
    databases: Arc<Databases>,
}

impl TenantScoped for PgAuditLabelResolver {}

impl PgAuditLabelResolver {
    /// A resolver reading names from `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The label of the record `id` of `kind` in `tenant`, or `None` when
    /// it is gone.
    async fn named(
        &self,
        tenant: &ScopedTenant,
        kind: Named,
        id: Uuid,
    ) -> Result<Option<EventLabel>, DomainError> {
        let ids = [id];
        let found = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| named_in(connection, tenant.as_uuid(), kind, &ids).await,
        )
        .await?;
        Ok(only(found.into_iter().map(NamedRecord::into_label)))
    }
}

#[async_trait]
impl AuditLabelResolver for PgAuditLabelResolver {
    async fn user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<EventLabel>, DomainError> {
        let ids = [*user_id.as_uuid()];
        let found = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| people_in(connection, tenant_id.as_uuid(), &ids).await,
        )
        .await?;
        Ok(only(found.into_iter().map(PersonRecord::into_label)))
    }

    async fn role(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
    ) -> Result<Option<EventLabel>, DomainError> {
        self.named(tenant_id, Named::Role, *role_id.as_uuid()).await
    }

    async fn group(
        &self,
        tenant_id: &ScopedTenant,
        group_id: &GroupId,
    ) -> Result<Option<EventLabel>, DomainError> {
        self.named(tenant_id, Named::Group, *group_id.as_uuid())
            .await
    }

    async fn agent(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
    ) -> Result<Option<EventLabel>, DomainError> {
        self.named(tenant_id, Named::Agent, *agent_id.as_uuid())
            .await
    }

    async fn delegation(
        &self,
        tenant_id: &ScopedTenant,
        delegation_id: &DelegationId,
    ) -> Result<Option<EventLabel>, DomainError> {
        let ids = [*delegation_id.as_uuid()];
        let found = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    MaybeNamedRecord,
                    "queries/agent_delegations/labels.sql",
                    tenant_id.as_uuid(),
                    ids.as_slice()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        Ok(only(
            found.into_iter().filter_map(MaybeNamedRecord::into_label),
        ))
    }

    async fn credential(
        &self,
        _tenant_id: &ScopedTenant,
        _credential_id: &AgentCredentialId,
    ) -> Result<Option<EventLabel>, DomainError> {
        Ok(None)
    }

    async fn approval(
        &self,
        tenant_id: &ScopedTenant,
        approval_id: &ApprovalId,
    ) -> Result<Option<EventLabel>, DomainError> {
        self.named(tenant_id, Named::Approval, *approval_id.as_uuid())
            .await
    }

    async fn model_provider(
        &self,
        tenant_id: &ScopedTenant,
        provider_id: &ModelProviderId,
    ) -> Result<Option<EventLabel>, DomainError> {
        self.named(tenant_id, Named::ModelProvider, *provider_id.as_uuid())
            .await
    }

    async fn oauth_client(
        &self,
        tenant_id: &ScopedTenant,
        client_id: &OAuthClientId,
    ) -> Result<Option<EventLabel>, DomainError> {
        self.named(tenant_id, Named::OAuthClient, *client_id.as_uuid())
            .await
    }

    async fn connection(
        &self,
        tenant_id: &ScopedTenant,
        connection_id: &ConnectionId,
    ) -> Result<Option<EventLabel>, DomainError> {
        self.named(tenant_id, Named::Connection, *connection_id.as_uuid())
            .await
    }

    async fn notification(
        &self,
        tenant_id: &ScopedTenant,
        notification_id: &NotificationId,
    ) -> Result<Option<EventLabel>, DomainError> {
        self.named(tenant_id, Named::Notification, *notification_id.as_uuid())
            .await
    }

    async fn consumer(
        &self,
        tenant_id: &ScopedTenant,
        consumer_id: &ConsumerId,
    ) -> Result<Option<EventLabel>, DomainError> {
        self.named(tenant_id, Named::Consumer, *consumer_id.as_uuid())
            .await
    }

    async fn tenant(&self, tenant_id: &ScopedTenant) -> Result<Option<EventLabel>, DomainError> {
        let ids = [*tenant_id.as_uuid()];
        let found = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(NamedRecord, "queries/tenants/labels.sql", ids.as_slice())
                .fetch_all(connection)
                .await
        })
        .await?;
        Ok(only(found.into_iter().map(NamedRecord::into_label)))
    }

    async fn principals(
        &self,
        tenant_id: &ScopedTenant,
        principals: &[PrincipalRef],
    ) -> Result<HashMap<PrincipalRef, EventLabel>, DomainError> {
        let users = ids_of(principals, |principal| match principal {
            PrincipalRef::User(id) => Some(*id.as_uuid()),
            PrincipalRef::OrgUser(_) | PrincipalRef::Agent(_) | PrincipalRef::Consumer(_) => None,
        });
        let agents = ids_of(principals, |principal| match principal {
            PrincipalRef::Agent(id) => Some(*id.as_uuid()),
            PrincipalRef::OrgUser(_) | PrincipalRef::User(_) | PrincipalRef::Consumer(_) => None,
        });
        let consumers = ids_of(principals, |principal| match principal {
            PrincipalRef::Consumer(id) => Some(*id.as_uuid()),
            PrincipalRef::OrgUser(_) | PrincipalRef::User(_) | PrincipalRef::Agent(_) => None,
        });
        let tenant = tenant_id.as_uuid();
        let names = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                Ok(PrincipalNames {
                    users: people_in(&mut *connection, tenant, &users).await?,
                    agents: named_in(&mut *connection, tenant, Named::Agent, &agents).await?,
                    consumers: named_in(connection, tenant, Named::Consumer, &consumers).await?,
                })
            },
        )
        .await?;
        Ok(names.into_labels())
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::agents::{ApprovalStore, ModelProviderStore};
    use ianua_app::ports::authorization::{GroupStore, RoleStore};
    use ianua_app::ports::federation::ConnectionStore;
    use ianua_app::ports::notifications::TenantNotificationStore;
    use ianua_app::ports::organization::OrgUserStore;
    use ianua_app::ports::tenant::TenantStore;
    use ianua_domain::domains::agents::execution::model_provider::ModelProvider;
    use ianua_domain::domains::agents::oversight::approval::ApprovalRequest;
    use ianua_domain::domains::federation::connection::FederatedIdpConnection;
    use ianua_domain::domains::oauth::clients::client::GrantType;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{OrgUserId, OrganizationId, TenantId};

    use super::*;
    use crate::postgres::agents::{PgApprovalStore, PgModelProviderStore};
    use crate::postgres::authorization::{PgGroupStore, PgRoleStore};
    use crate::postgres::federation::PgConnectionStore;
    use crate::postgres::notifications::PgTenantNotificationStore;
    use crate::postgres::organization::PgOrgUserStore;
    use crate::postgres::tenant::PgTenantStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::run::{opened_approval_row, provider_row, saved_person};
    use crate::test_support::rows::agents::{saved_agent, saved_delegation};
    use crate::test_support::rows::audit::{saved_organization, saved_tenant_of};
    use crate::test_support::rows::authorization::{group, role};
    use crate::test_support::rows::federation::{connection_row, oidc_config};
    use crate::test_support::rows::messaging::a_consumer;
    use crate::test_support::rows::notifications::{notice, user_registered};
    use crate::test_support::rows::oauth::{a_client, a_person, oauth_client_row};
    use crate::test_support::rows::organization::org_user_row;

    struct Fixture {
        db: TestDb,
        organization: OrganizationId,
        acme: ScopedTenant,
        other: ScopedTenant,
        labels: PgAuditLabelResolver,
    }

    /// A fresh database holding an organization with two tenants, and the
    /// resolver on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let acme = saved_tenant_of(&db.databases, organization).await;
        let other = saved_tenant_of(&db.databases, organization).await;
        Fixture {
            labels: PgAuditLabelResolver::new(Arc::clone(&db.databases)),
            organization,
            acme,
            other,
            db,
        }
    }

    impl Fixture {
        /// A member of the organization at `email`, saved through the
        /// member store.
        async fn member(&self, email: &str) -> OrgUserId {
            let member = OrgUser::reconstitute(org_user_row(self.organization, email)).unwrap();
            PgOrgUserStore::new(Arc::clone(&self.db.databases), DomainLimits::default())
                .save(&member)
                .await
                .unwrap();
            *member.id()
        }
    }

    /// A user is named by their name with their address in brackets.
    #[tokio::test]
    async fn a_user_is_named_by_name_and_address() {
        let fx = fixture().await;
        let ann = a_person(&fx.db, &fx.acme, "ann@acme.example").await;

        let found = fx.labels.user(&fx.acme, &ann).await.unwrap();

        assert_eq!(
            found,
            Some(EventLabel::of("ann@acme.example (ann@acme.example)"))
        );
    }

    /// A role, a group, an agent, a consumer and an OAuth client are named
    /// by their own names.
    #[tokio::test]
    async fn named_records_are_named_by_their_names() {
        let fx = fixture().await;
        let records = named_records(&fx).await;

        let labels = &fx.labels;
        assert_eq!(
            labels.role(&fx.acme, &records.role).await.unwrap(),
            Some(EventLabel::of("Auditor"))
        );
        assert_eq!(
            labels.group(&fx.acme, &records.group).await.unwrap(),
            Some(EventLabel::of("Ops"))
        );
        assert_eq!(
            labels.agent(&fx.acme, &records.agent).await.unwrap(),
            Some(EventLabel::of("ledger"))
        );
        assert_eq!(
            labels.consumer(&fx.acme, &records.consumer).await.unwrap(),
            Some(EventLabel::of("billing"))
        );
        assert_eq!(
            labels
                .oauth_client(&fx.acme, &records.client)
                .await
                .unwrap(),
            Some(EventLabel::of("portal"))
        );
    }

    /// Identities of the five independently named records in the label fixture.
    struct NamedRecords {
        role: RoleId,
        group: GroupId,
        agent: AgentId,
        consumer: ConsumerId,
        client: OAuthClientId,
    }

    /// Saves each independently named record through its owning store.
    async fn named_records(fx: &Fixture) -> NamedRecords {
        let auditor = role("Auditor");
        PgRoleStore::new(Arc::clone(&fx.db.databases))
            .save(&fx.acme, &auditor)
            .await
            .unwrap();
        let ops = group("Ops", Vec::new());
        PgGroupStore::new(Arc::clone(&fx.db.databases))
            .save(&fx.acme, &ops)
            .await
            .unwrap();
        let agent = saved_agent(&fx.db.databases, &fx.acme, "ledger").await;
        let consumer = a_consumer(&fx.db, &fx.acme, "billing").await;
        let client = a_client(
            &fx.db,
            &fx.acme,
            oauth_client_row("portal", &[GrantType::AuthorizationCode]),
        )
        .await;

        NamedRecords {
            role: *auditor.id(),
            group: *ops.id(),
            agent,
            consumer,
            client: *client.id(),
        }
    }

    /// A model provider and a federation connection are named by their
    /// names, and an approval request by the action it waits on.
    #[tokio::test]
    async fn agent_and_federation_records_are_named() {
        let fx = fixture().await;
        let provider = saved_model_provider(&fx).await;
        let okta =
            FederatedIdpConnection::reconstitute(connection_row("Okta", oidc_config())).unwrap();
        PgConnectionStore::new(Arc::clone(&fx.db.databases))
            .save(&fx.acme, &okta)
            .await
            .unwrap();
        let approval = saved_approval(&fx).await;

        let labels = &fx.labels;
        assert_eq!(
            labels.model_provider(&fx.acme, &provider).await.unwrap(),
            Some(EventLabel::of("Gateway"))
        );
        assert_eq!(
            labels.connection(&fx.acme, okta.id()).await.unwrap(),
            Some(EventLabel::of("Okta"))
        );
        assert_eq!(
            labels.approval(&fx.acme, &approval).await.unwrap(),
            Some(EventLabel::of("GET /orders/1"))
        );
    }

    /// Saves the agent, owner and pending approval whose action becomes its label.
    async fn saved_approval(fx: &Fixture) -> ApprovalId {
        let agent = saved_agent(&fx.db.databases, &fx.acme, "ledger").await;
        let owner = saved_person(&fx.db.databases, &fx.acme).await;
        let approval = ApprovalRequest::reconstitute(opened_approval_row(agent, owner)).unwrap();
        PgApprovalStore::new(Arc::clone(&fx.db.databases))
            .save(&fx.acme, &approval)
            .await
            .unwrap();
        *approval.id()
    }

    /// Saves the named gateway provider used by the audit label assertion.
    async fn saved_model_provider(fx: &Fixture) -> ModelProviderId {
        let provider = ModelProvider::reconstitute(provider_row("Gateway")).unwrap();
        PgModelProviderStore::new(Arc::clone(&fx.db.databases))
            .save(&fx.acme, &provider)
            .await
            .unwrap();
        *provider.id()
    }

    /// A delegation never given a name has no label, so the caller names
    /// it by its id; so has an agent credential.
    #[tokio::test]
    async fn unnamed_records_have_no_label() {
        let fx = fixture().await;
        let agent = saved_agent(&fx.db.databases, &fx.acme, "ledger").await;
        let delegation = saved_delegation(&fx.db.databases, &fx.acme, agent).await;

        let labels = &fx.labels;
        assert_eq!(
            labels.delegation(&fx.acme, &delegation).await.unwrap(),
            None
        );
        assert_eq!(
            labels
                .credential(&fx.acme, &AgentCredentialId::new())
                .await
                .unwrap(),
            None
        );
    }

    /// A user's notification is named by its title, and the tenant by its
    /// display name.
    #[tokio::test]
    async fn a_notification_and_the_tenant_are_named() {
        let fx = fixture().await;
        let ann = a_person(&fx.db, &fx.acme, "ann@acme.example").await;
        let registered = notice(user_registered(), 0);
        PgTenantNotificationStore::new(Arc::clone(&fx.db.databases))
            .save(&fx.acme, &ann, &registered)
            .await
            .unwrap();
        let tenant = PgTenantStore::new(Arc::clone(&fx.db.databases), DomainLimits::default())
            .find_by_id(&fx.acme)
            .await
            .unwrap()
            .unwrap();

        let labels = &fx.labels;
        assert_eq!(
            labels
                .notification(&fx.acme, &registered.id())
                .await
                .unwrap(),
            Some(EventLabel::of(registered.title().as_str()))
        );
        assert_eq!(
            labels.tenant(&fx.acme).await.unwrap(),
            Some(EventLabel::of(tenant.display_name().as_str()))
        );
    }

    /// A record that is gone, or a tenant that is gone, answers `None`.
    #[tokio::test]
    async fn a_gone_record_answers_none() {
        let fx = fixture().await;
        let gone = ScopedTenant::for_background(TenantId::new());

        let labels = &fx.labels;
        assert_eq!(labels.user(&fx.acme, &UserId::new()).await.unwrap(), None);
        assert_eq!(labels.role(&fx.acme, &RoleId::new()).await.unwrap(), None);
        assert_eq!(labels.agent(&fx.acme, &AgentId::new()).await.unwrap(), None);
        assert_eq!(labels.tenant(&gone).await.unwrap(), None);
    }

    /// Another tenant cannot resolve labels for Acme's user or agent,
    /// including the user's label through a batch principal lookup.
    #[tokio::test]
    async fn another_tenants_record_is_not_named() {
        let fx = fixture().await;
        let ann = a_person(&fx.db, &fx.acme, "ann@acme.example").await;
        let agent = saved_agent(&fx.db.databases, &fx.acme, "ledger").await;

        let labels = &fx.labels;
        assert_eq!(labels.user(&fx.other, &ann).await.unwrap(), None);
        assert_eq!(labels.agent(&fx.other, &agent).await.unwrap(), None);
        assert!(
            labels
                .principals(&fx.other, &[PrincipalRef::User(ann)])
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Many principals are named together; a gone one and every
    /// organization member are left out.
    #[tokio::test]
    async fn principals_are_named_together_leaving_out_members_and_gone_ones() {
        let fx = fixture().await;
        let ann = a_person(&fx.db, &fx.acme, "ann@acme.example").await;
        let agent = saved_agent(&fx.db.databases, &fx.acme, "ledger").await;
        let consumer = a_consumer(&fx.db, &fx.acme, "billing").await;
        let member = fx.member("bob@acme.example").await;
        let asked = [
            PrincipalRef::User(ann),
            PrincipalRef::Agent(agent),
            PrincipalRef::Consumer(consumer),
            PrincipalRef::OrgUser(member),
            PrincipalRef::User(UserId::new()),
        ];

        let found = fx.labels.principals(&fx.acme, &asked).await.unwrap();

        let expected = HashMap::from([
            (
                PrincipalRef::User(ann),
                EventLabel::of("ann@acme.example (ann@acme.example)"),
            ),
            (PrincipalRef::Agent(agent), EventLabel::of("ledger")),
            (PrincipalRef::Consumer(consumer), EventLabel::of("billing")),
        ]);
        assert_eq!(found, expected);
    }
}
