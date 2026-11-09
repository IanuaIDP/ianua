//! A tenant's agent tools, each row under row-level security.
//!
//! A tool calls through one route of the tenant, which its row links to: a
//! tool for a route the tenant does not have is refused, and a route that
//! goes takes its tools with it. A deleted tool is gone for good; the runs
//! that were given it name it only by name.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::ToolStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::execution::tool::AgentTool;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::AgentToolId;

use self::record::{ToolColumns, ToolRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres agent tool store.
pub struct PgToolStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgToolStore {}

impl PgToolStore {
    /// A store keeping agent tools in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// The tools `records` hold, each rebuilt through the domain's checks.
fn rebuilt_all(records: Vec<ToolRecord>) -> Result<Vec<AgentTool<ResolvedTenant>>, DomainError> {
    records.into_iter().map(ToolRecord::into_tool).collect()
}

#[async_trait]
impl ToolStore for PgToolStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AgentToolId,
    ) -> Result<Option<AgentTool<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ToolRecord,
                    "queries/agent_tools/by_ids.sql",
                    tenant_id.as_uuid(),
                    &ids[..]
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        Ok(rebuilt_all(records)?.into_iter().next())
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<AgentTool<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ToolRecord,
                    "queries/agent_tools/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt_all(records)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        tool: &AgentTool<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = ToolColumns::of(tool);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/agent_tools/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.name,
                    columns.description,
                    columns.input_schema,
                    columns.method,
                    columns.path,
                    columns.route_id,
                    columns.declared_action,
                    columns.action_class,
                    columns.data_class,
                    columns.status,
                    columns.created_at,
                    columns.updated_at,
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &AgentToolId) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/agent_tools/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::execution::tool::{AgentToolRow, ToolStatus};
    use ianua_domain::shared::model::aggregate::Aggregate as _;
    use ianua_domain::types::{RouteId, TenantId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::run::{saved_route, tool_row};
    use crate::test_support::rows::at;

    struct Fixture {
        db: TestDb,
        store: PgToolStore,
        tenant: ScopedTenant,
        route: RouteId,
    }

    /// A fresh database, the store on it, and one tenant with one route
    /// its tools call through.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let route = saved_route(&db.databases, &tenant).await;
        Fixture {
            store: PgToolStore::new(Arc::clone(&db.databases)),
            tenant,
            route,
            db,
        }
    }

    fn tool(row: AgentToolRow) -> AgentTool<ResolvedTenant> {
        AgentTool::reconstitute(row).unwrap()
    }

    impl Fixture {
        async fn saved(&self, row: AgentToolRow) -> AgentTool<ResolvedTenant> {
            let tool = tool(row);
            self.store.save(&self.tenant, &tool).await.unwrap();
            tool
        }

        async fn found_in(
            &self,
            tenant: &ScopedTenant,
            id: &AgentToolId,
        ) -> Option<AgentTool<ResolvedTenant>> {
            self.store.find_by_id(tenant, id).await.unwrap()
        }

        async fn found(&self, id: &AgentToolId) -> Option<AgentTool<ResolvedTenant>> {
            self.found_in(&self.tenant, id).await
        }

        async fn names_in(&self, tenant: &ScopedTenant) -> Vec<String> {
            let listed = self.store.list(tenant).await.unwrap();
            listed
                .iter()
                .map(|tool| tool.name().as_str().to_owned())
                .collect()
        }
    }

    /// Ann's `get_order` tool is found again as it was saved, with the
    /// route it calls through and the classes it takes from it.
    #[tokio::test]
    async fn a_saved_tool_is_found_as_it_was_saved() {
        let fx = fixture().await;
        let saved = fx.saved(tool_row(fx.route, "get_order")).await;

        let found = fx.found(saved.id()).await.unwrap();

        assert_eq!(found.name(), saved.name());
        assert_eq!(found.description(), saved.description());
        assert_eq!(found.schema(), saved.schema());
        assert_eq!(found.method(), saved.method());
        assert_eq!(found.path(), saved.path());
        assert_eq!(found.route_id(), &fx.route);
        assert_eq!(found.declared_action(), saved.declared_action());
        assert_eq!(found.action_class(), saved.action_class());
        assert_eq!(found.classification(), saved.classification());
        assert_eq!(found.created_at(), saved.created_at());
    }

    /// An id the tenant has no tool for finds nothing, rather than failing.
    #[tokio::test]
    async fn an_unknown_tool_is_not_found() {
        let fx = fixture().await;

        assert!(fx.found(&AgentToolId::new()).await.is_none());
    }

    /// The tenant's tools are listed oldest first.
    #[tokio::test]
    async fn the_tools_are_listed_oldest_first() {
        let fx = fixture().await;
        fx.saved(AgentToolRow {
            created_at: at(3),
            updated_at: at(3),
            ..tool_row(fx.route, "list_orders")
        })
        .await;
        fx.saved(tool_row(fx.route, "get_order")).await;

        assert_eq!(fx.names_in(&fx.tenant).await, ["get_order", "list_orders"]);
    }

    /// Ann disables a tool: saving it again keeps it disabled, as one tool.
    #[tokio::test]
    async fn saving_again_keeps_the_new_standing() {
        let fx = fixture().await;
        let saved = fx.saved(tool_row(fx.route, "get_order")).await;
        fx.saved(AgentToolRow {
            id: *saved.id(),
            status: ToolStatus::Disabled,
            updated_at: at(4),
            ..tool_row(fx.route, "get_order")
        })
        .await;

        let found = fx.found(saved.id()).await.unwrap();

        assert_eq!(found.status(), ToolStatus::Disabled);
        assert_eq!(found.updated_at(), at(4));
        assert_eq!(fx.names_in(&fx.tenant).await, ["get_order"]);
    }

    /// A deleted tool is gone, and the tenant's other tools stay.
    #[tokio::test]
    async fn a_deleted_tool_is_gone() {
        let fx = fixture().await;
        let kept = fx.saved(tool_row(fx.route, "get_order")).await;
        let gone = fx.saved(tool_row(fx.route, "delete_order")).await;

        fx.store.delete(&fx.tenant, gone.id()).await.unwrap();

        assert!(fx.found(gone.id()).await.is_none());
        assert!(fx.found(kept.id()).await.is_some());
    }

    /// Saving a tool for an unknown route returns an infrastructure error
    /// and leaves the tool absent.
    #[tokio::test]
    async fn a_tool_for_an_unknown_route_is_refused() {
        let fx = fixture().await;
        let stray = tool(tool_row(RouteId::new(), "get_order"));

        let saved = fx.store.save(&fx.tenant, &stray).await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
        assert!(fx.found(stray.id()).await.is_none());
    }

    /// Another tenant sees none of Acme's tools, by id or in its list, and
    /// cannot delete them.
    #[tokio::test]
    async fn another_tenants_tools_are_invisible() {
        let fx = fixture().await;
        let saved = fx.saved(tool_row(fx.route, "get_order")).await;
        let other = ScopedTenant::for_background(TenantId::new());

        fx.store.delete(&other, saved.id()).await.unwrap();

        assert!(fx.found_in(&other, saved.id()).await.is_none());
        assert!(fx.names_in(&other).await.is_empty());
        assert!(fx.found(saved.id()).await.is_some());
    }

    /// A dedicated tenant's tool is readable directly from its database and
    /// through tenant routing.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_keeps_its_tools_there() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());
        let route = saved_route(&fx.db.databases, &apart).await;
        let saved = tool(tool_row(route, "get_order"));

        fx.store.save(&apart, &saved).await.unwrap();

        let in_own = PgToolStore::new(Arc::clone(&own.databases));
        let found = in_own.find_by_id(&apart, saved.id()).await.unwrap();
        assert!(found.is_some());
        assert!(fx.found_in(&apart, saved.id()).await.is_some());
    }

    /// A stored tool name containing spaces and punctuation is rejected as
    /// corrupt.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_tool_is_refused() {
        let fx = fixture().await;
        let saved = fx.saved(tool_row(fx.route, "get_order")).await;
        fx.db
            .tamper("UPDATE agent_tools SET name = 'get order!'")
            .await;

        let read = fx.store.find_by_id(&fx.tenant, saved.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
