//! What an agent did, as its tenant's audit trail keeps it: the records it
//! acted in, whoever it acted for, paged and counted under row-level
//! security.
//!
//! The records are the tenant's own audit log narrowed to the agent, read
//! the way that log is read, so a page here and a page there agree.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::Listing;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::AgentActivityStore;
use ianua_app::ports::audit::{AuditLogFilter, AuditLogPage, AuditLogSortField};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ActingFor, ActorRef, AgentId};

use crate::postgres::audit::logs::filters::Narrowing;
use crate::postgres::audit::logs::sources::{PageSelection, Source, read_page};
use crate::postgres::foundation::paging::PageQuery;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres read of an agent's activity.
pub struct PgAgentActivityStore {
    databases: Arc<Databases>,
    limits: DomainLimits,
}

impl TenantScoped for PgAgentActivityStore {}

impl PgAgentActivityStore {
    /// A read of the audit trail kept in `databases`, the names it shows
    /// checked against `limits`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, limits: DomainLimits) -> Self {
        Self { databases, limits }
    }
}

/// What `filter` keeps of the tenant's log, narrowed to the records
/// `agent` acted in, whatever actor the filter named.
fn of_agent(filter: &AuditLogFilter, agent: &AgentId) -> Narrowing {
    let filter = AuditLogFilter {
        actor: Some(ActorRef::Agent {
            id: *agent,
            on_behalf_of: ActingFor::Itself,
        }),
        ..filter.clone()
    };
    Narrowing::of_log(&filter).without_tenant()
}

#[async_trait]
impl AgentActivityStore for PgAgentActivityStore {
    async fn query(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
        listing: Listing<'_, &AuditLogFilter, AuditLogSortField>,
    ) -> Result<AuditLogPage, DomainError> {
        let keyset = listing.page.keyset(listing.sort)?;
        let narrowing = of_agent(listing.filter, agent_id);
        let sources = vec![Source::Tenant(**tenant_id)];
        read_page(
            &self.databases,
            sources,
            &PageSelection {
                narrowing: &narrowing,
                keyset: &keyset,
            },
            &self.limits,
        )
        .await
    }

    async fn count(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
        filter: &AuditLogFilter,
    ) -> Result<u64, DomainError> {
        let narrowing = of_agent(filter, agent_id);
        let counted =
            PageQuery::counted("audit_records").filter("tenant_id = ?", *tenant_id.as_uuid());
        let query = narrowing.applied(counted);
        let count = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| query.count(connection).await,
        )
        .await?;
        u64::try_from(count).map_err(DomainError::infra)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, PageRequest, SortOrder};
    use ianua_domain::types::{TenantId, UserId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::{
        agent_event, failed_sign_in, recorded, saved_organization, saved_tenant_of,
    };

    struct Fixture {
        db: TestDb,
        tenant: ScopedTenant,
        store: PgAgentActivityStore,
        agent: AgentId,
    }

    /// A fresh database holding Acme, one of its tenants and one agent of
    /// it, and the read on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        Fixture {
            store: PgAgentActivityStore::new(Arc::clone(&db.databases), DomainLimits::default()),
            tenant,
            agent: AgentId::new(),
            db,
        }
    }

    impl Fixture {
        async fn page(&self, filter: &AuditLogFilter, page: &PageRequest) -> AuditLogPage {
            let sort = SortOrder::default();
            let listing = Listing {
                filter,
                sort: &sort,
                page,
            };
            self.store
                .query(&self.tenant, &self.agent, listing)
                .await
                .unwrap()
        }

        async fn counted(&self, filter: &AuditLogFilter) -> u64 {
            self.store
                .count(&self.tenant, &self.agent, filter)
                .await
                .unwrap()
        }
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn times(page: &AuditLogPage) -> Vec<time::OffsetDateTime> {
        page.items.iter().map(|entry| entry.occurred_at).collect()
    }

    /// The agent's three records are paged newest first, two then one; a
    /// record of someone else and one of another agent are left out.
    #[tokio::test]
    async fn an_agents_records_are_paged_newest_first() {
        let fx = fixture().await;
        let mut events: Vec<_> = (1..=3)
            .map(|seconds| agent_event(*fx.tenant, fx.agent, seconds))
            .collect();
        events.push(failed_sign_in(*fx.tenant, 4));
        events.push(agent_event(*fx.tenant, AgentId::new(), 5));
        recorded(&fx.db.databases, events).await;

        let page_one = fx.page(&AuditLogFilter::default(), &first(2)).await;
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = fx.page(&AuditLogFilter::default(), &after).await;

        assert_eq!(times(&page_one), [at(3), at(2)]);
        assert_eq!(times(&page_two), [at(1)]);
        assert!(!page_two.has_next());
    }

    /// The count says how many records the agent acted in that the filter
    /// keeps, one count for the whole log.
    #[tokio::test]
    async fn an_agents_records_are_counted_as_the_filter_keeps() {
        let fx = fixture().await;
        let events = (1..=3)
            .map(|seconds| agent_event(*fx.tenant, fx.agent, seconds))
            .chain([failed_sign_in(*fx.tenant, 4)])
            .collect();
        recorded(&fx.db.databases, events).await;
        let since_two = AuditLogFilter {
            after: Some(at(1)),
            ..AuditLogFilter::default()
        };

        assert_eq!(fx.counted(&AuditLogFilter::default()).await, 3);
        assert_eq!(fx.counted(&since_two).await, 2);
    }

    /// A filter naming another actor still returns and counts the requested
    /// agent's activity record.
    #[tokio::test]
    async fn a_filter_naming_someone_else_still_reads_the_agent() {
        let fx = fixture().await;
        recorded(&fx.db.databases, vec![agent_event(*fx.tenant, fx.agent, 1)]).await;
        let someone_else = AuditLogFilter {
            actor: Some(ActorRef::User(UserId::new())),
            ..AuditLogFilter::default()
        };

        let page = fx.page(&someone_else, &first(10)).await;

        assert_eq!(times(&page), [at(1)]);
        assert_eq!(fx.counted(&someone_else).await, 1);
    }

    /// Another tenant gets an empty page and zero count for Acme's agent's
    /// activity.
    #[tokio::test]
    async fn another_tenant_reads_none_of_the_agents_records() {
        let fx = fixture().await;
        recorded(&fx.db.databases, vec![agent_event(*fx.tenant, fx.agent, 1)]).await;
        let other = ScopedTenant::for_background(TenantId::new());
        let sort = SortOrder::default();
        let page = first(10);
        let listing = Listing {
            filter: &AuditLogFilter::default(),
            sort: &sort,
            page: &page,
        };

        let read = fx.store.query(&other, &fx.agent, listing).await.unwrap();
        let counted = fx
            .store
            .count(&other, &fx.agent, &AuditLogFilter::default())
            .await
            .unwrap();

        assert!(read.items.is_empty());
        assert_eq!(counted, 0);
    }
}
