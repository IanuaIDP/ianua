//! A tenant's recorded event read back by the id of its audit record, for a
//! job planned from it that runs later, under row-level security.
//!
//! The record is read from the trail in the database the tenant lives in,
//! whole: who acted, an agent's delegation chain included, through whom,
//! and what the event said. A record its retention removed is gone.

mod record;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::shared::RecordedEvents;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::audit::record::AuditRecord;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::AuditRecordId;

use self::record::RecordedRecord;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The longest the read may take before it is given up.
const READ_AT_MOST: Duration = Duration::from_secs(5);

/// The Postgres read of recorded events.
pub struct PgRecordedEvents {
    databases: Arc<Databases>,
}

impl TenantScoped for PgRecordedEvents {}

impl PgRecordedEvents {
    /// A read of the records kept in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The record `find` answers, without its time limit.
    async fn read(
        &self,
        tenant_id: &ScopedTenant,
        id: &AuditRecordId,
    ) -> Result<Option<AuditRecord>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RecordedRecord,
                    "queries/audit_records/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record
            .map(|record| record.into_record(**tenant_id))
            .transpose()
    }
}

#[async_trait]
impl RecordedEvents for PgRecordedEvents {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        id: &AuditRecordId,
    ) -> Result<Option<AuditRecord>, DomainError> {
        tokio::time::timeout(READ_AT_MOST, self.read(tenant_id, id))
            .await
            .map_err(DomainError::infra)?
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, PageRequest, SortOrder};
    use ianua_app::ports::audit::{AuditLogFilter, TenantAuditLogStore};
    use ianua_domain::domains::audit::builder::{ActedThrough, AuditContext};
    use ianua_domain::domains::audit::record::AuditScope;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::shared::events::event::DomainEvent;
    use ianua_domain::types::{
        ActingFor, ActorRef, AgentId, Fact, IpAddress, OperatorId, OrganizationId, TenantId,
        UserAgent, UserId, WorkflowExecutionId,
    };

    use super::*;
    use crate::postgres::audit::PgTenantAuditLogStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::audit::{
        failed_sign_in, recorded, recorded_as, saved_organization, saved_tenant_of,
    };

    struct Fixture {
        db: TestDb,
        organization: OrganizationId,
        tenant: ScopedTenant,
        read: PgRecordedEvents,
    }

    /// A fresh database holding Acme and one of its tenants, and the read
    /// on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        Fixture {
            read: PgRecordedEvents::new(Arc::clone(&db.databases)),
            organization,
            tenant,
            db,
        }
    }

    impl Fixture {
        /// The ids of the records the tenant's log holds, newest first.
        async fn ids(&self) -> Vec<AuditRecordId> {
            let log =
                PgTenantAuditLogStore::new(Arc::clone(&self.db.databases), DomainLimits::default());
            let page = log
                .query(
                    &self.tenant,
                    &AuditLogFilter::default(),
                    &SortOrder::default(),
                    &PageRequest::first(Limit::new(50).unwrap()),
                )
                .await
                .unwrap();
            page.items.iter().map(|entry| entry.id).collect()
        }

        async fn found(&self, id: &AuditRecordId) -> Option<AuditRecord> {
            self.read.find(&self.tenant, id).await.unwrap()
        }
    }

    /// An agent acting for Ann, while an operator acts as her, is recorded
    /// from a known address and client. The record reads back whole: the
    /// agent with its chain, the operator, the address, the client, the
    /// event and its details.
    #[tokio::test]
    async fn a_recorded_event_reads_back_whole() {
        let fx = fixture().await;
        let ann = UserId::new();
        let agent = ActorRef::Agent {
            id: AgentId::new(),
            on_behalf_of: ActingFor::Principal(Box::new(ActorRef::User(ann))),
        };
        let operator = OperatorId::new();
        let context = agent_context(&fx, &agent, operator, ann);
        let event = failed_sign_in(*fx.tenant, 5);
        recorded_as(
            &fx.db.databases,
            vec![failed_sign_in(*fx.tenant, 5)],
            &context,
        )
        .await;
        let id = fx.ids().await[0];

        let found = fx.found(&id).await.unwrap();

        assert_eq!(found.id, id);
        assert_eq!(found.actor.audit_label(), agent.audit_label());
        assert_eq!(
            found.acted_through,
            ActedThrough::Impersonation {
                operator_id: operator,
                as_user: ann
            }
        );
        assert!(matches!(found.scope, AuditScope::Tenant { tenant, .. } if tenant == *fx.tenant));
        assert_event_metadata(&found, &event);
    }

    /// Attributes an agent request to Ann while retaining the impersonating operator.
    fn agent_context(
        fx: &Fixture,
        agent: &ActorRef,
        operator: OperatorId,
        ann: UserId,
    ) -> AuditContext {
        AuditContext::for_caller(fx.organization, agent.clone())
            .with_tenant(*fx.tenant)
            .with_request(
                Fact::Known(IpAddress::new("203.0.113.7").unwrap()),
                Fact::Known(UserAgent::new("ledger/1.0").unwrap()),
            )
            .impersonating(operator, ann)
    }

    /// Checks the event details and request origin survive audit persistence.
    fn assert_event_metadata(found: &AuditRecord, event: &DomainEvent) {
        assert_eq!(found.event_type, event.event_type());
        assert_eq!(found.payload, event.payload());
        assert_eq!(
            found.ip_address.known().map(IpAddress::as_str),
            Some("203.0.113.7")
        );
        assert_eq!(
            found.user_agent.known().map(UserAgent::as_str),
            Some("ledger/1.0")
        );
        assert_eq!(found.occurred_at, event.occurred_at());
    }

    /// A record a workflow run made reads back as made through that run.
    #[tokio::test]
    async fn a_record_made_through_a_run_names_the_run() {
        let fx = fixture().await;
        let execution = WorkflowExecutionId::new();
        let context = AuditContext::for_caller(fx.organization, ActorRef::User(UserId::new()))
            .with_tenant(*fx.tenant)
            .through_run(execution);
        recorded_as(
            &fx.db.databases,
            vec![failed_sign_in(*fx.tenant, 5)],
            &context,
        )
        .await;
        let id = fx.ids().await[0];

        let found = fx.found(&id).await.unwrap();

        assert_eq!(found.acted_through, ActedThrough::WorkflowRun { execution });
    }

    /// A record never written, as one its retention removed, is not found,
    /// rather than failing.
    #[tokio::test]
    async fn a_record_never_kept_is_not_found() {
        let fx = fixture().await;

        let found = fx.found(&AuditRecordId::new()).await;

        assert!(found.is_none());
    }

    /// Looking up Acme's audit record through another tenant returns none.
    #[tokio::test]
    async fn another_tenant_finds_none_of_acmes_records() {
        let fx = fixture().await;
        recorded(&fx.db.databases, vec![failed_sign_in(*fx.tenant, 1)]).await;
        let id = fx.ids().await[0];
        let other = ScopedTenant::for_background(TenantId::new());

        let found = fx.read.find(&other, &id).await.unwrap();

        assert!(found.is_none());
    }

    /// An unknown actor label in a stored audit record makes the event
    /// read fail as corrupt storage.
    #[tokio::test]
    async fn a_record_whose_actor_does_not_read_is_refused() {
        let fx = fixture().await;
        recorded(&fx.db.databases, vec![failed_sign_in(*fx.tenant, 1)]).await;
        let id = fx.ids().await[0];
        fx.db
            .tamper(
                "SET session_replication_role = replica; \
                 UPDATE audit_records SET actor = 'wizard:merlin'; \
                 SET session_replication_role = origin;",
            )
            .await;

        let read = fx.read.find(&fx.tenant, &id).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// An event recorded for a tenant with a dedicated database can be
    /// read directly from that database by its audit-record id.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_is_read_there() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = saved_tenant_of(&fx.db.databases, fx.organization).await;
        fx.db.databases.register(*apart, own.as_dedicated());
        let apart_fx = Fixture {
            read: PgRecordedEvents::new(Arc::clone(&fx.db.databases)),
            organization: fx.organization,
            tenant: apart,
            db: fx.db,
        };
        recorded(&apart_fx.db.databases, vec![failed_sign_in(*apart, 1)]).await;
        let id = apart_fx.ids().await[0];

        let in_own = PgRecordedEvents::new(Arc::clone(&own.databases));
        let found = in_own.find(&apart, &id).await.unwrap();

        assert_eq!(found.map(|record| record.id), Some(id));
    }
}
