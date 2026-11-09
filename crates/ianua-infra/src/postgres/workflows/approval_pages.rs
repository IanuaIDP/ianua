//! The pages of a loop's items each person opened while the loop asked one
//! approval for every item, each table row under row-level security and
//! going with its run.
//!
//! A page is keyed by the approval's opening, its first item and how many
//! it held, so opening it again keeps the first time, and pages of a list
//! since replaced stay apart from the new one's.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::workflows::{ApprovalPages, ItemsViewer};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::execution::{ItemsSeen, SeenPage};
use ianua_domain::shared::errors::DomainError;

use self::record::{PageColumns, PageRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of the pages approvers opened.
pub struct PgApprovalPages {
    databases: Arc<Databases>,
}

impl TenantScoped for PgApprovalPages {}

impl PgApprovalPages {
    /// A store keeping opened pages in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl ApprovalPages for PgApprovalPages {
    async fn record(
        &self,
        tenant_id: &ScopedTenant,
        viewer: &ItemsViewer,
        page: &SeenPage,
    ) -> Result<(), DomainError> {
        let columns = PageColumns::of(page)?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/workflow_approval_pages/record.sql",
                    tenant_id.as_uuid(),
                    viewer.execution_id.as_uuid(),
                    viewer.step.as_str(),
                    viewer.person.as_str(),
                    page.opening,
                    columns.first_item,
                    columns.item_count,
                    page.at,
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(())
    }

    async fn seen_by(
        &self,
        tenant_id: &ScopedTenant,
        viewer: &ItemsViewer,
    ) -> Result<ItemsSeen, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    PageRecord,
                    "queries/workflow_approval_pages/seen_by.sql",
                    tenant_id.as_uuid(),
                    viewer.execution_id.as_uuid(),
                    viewer.step.as_str(),
                    viewer.person.as_str(),
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        let pages = records
            .into_iter()
            .map(PageRecord::into_page)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ItemsSeen::new(pages))
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::workflows::{WorkflowExecutionStore, WorkflowStore};
    use ianua_domain::domains::workflows::design::node::NodeKey;
    use ianua_domain::domains::workflows::design::workflow::Workflow;
    use ianua_domain::domains::workflows::execution::WorkflowExecution;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::{PersonKey, TenantId, WorkflowExecutionId};

    use super::*;
    use crate::postgres::workflows::{PgWorkflowExecutionStore, PgWorkflowStore};
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::run::saved_run;
    use crate::test_support::rows::at;
    use crate::test_support::rows::workflows::{published_row, running_row};

    struct Fixture {
        _db: TestDb,
        store: PgApprovalPages,
        executions: PgWorkflowExecutionStore,
        tenant: ScopedTenant,
        run: WorkflowExecutionId,
    }

    /// A fresh database, one tenant with a run of its report workflow, and
    /// the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let report = Workflow::reconstitute(published_row("report", 0)).unwrap();
        PgWorkflowStore::new(Arc::clone(&db.databases))
            .insert(&tenant, &report)
            .await
            .unwrap();
        let executions = PgWorkflowExecutionStore::new(Arc::clone(&db.databases));
        let agent_run = *saved_run(&db.databases, &tenant).await.id();
        let execution: WorkflowExecution<ResolvedTenant> =
            WorkflowExecution::reconstitute(running_row(&report, agent_run, 0)).unwrap();
        executions.save(&tenant, &execution).await.unwrap();
        Fixture {
            store: PgApprovalPages::new(Arc::clone(&db.databases)),
            executions,
            run: *execution.id(),
            tenant,
            _db: db,
        }
    }

    impl Fixture {
        fn viewer(&self, person: &str) -> ItemsViewer {
            ItemsViewer {
                execution_id: self.run,
                step: NodeKey::new("each").unwrap(),
                person: PersonKey::new(person).unwrap(),
            }
        }
    }

    fn page(first: u32, count: u32, opened: i64) -> SeenPage {
        SeenPage {
            opening: at(0),
            first,
            count,
            at: at(opened),
        }
    }

    /// Bob opens two pages, the first one twice. Both are read back, the
    /// first with the time he first opened it; Cid has opened none.
    #[tokio::test]
    async fn opened_pages_are_kept_once_per_person() {
        let fx = fixture().await;
        let bob = fx.viewer("bob@corp.test");
        fx.store
            .record(&fx.tenant, &bob, &page(0, 2, 10))
            .await
            .unwrap();
        fx.store
            .record(&fx.tenant, &bob, &page(2, 1, 20))
            .await
            .unwrap();
        fx.store
            .record(&fx.tenant, &bob, &page(0, 2, 30))
            .await
            .unwrap();

        let seen = fx.store.seen_by(&fx.tenant, &bob).await.unwrap();
        let none = fx
            .store
            .seen_by(&fx.tenant, &fx.viewer("cid@corp.test"))
            .await
            .unwrap();

        assert_eq!(seen, ItemsSeen::new(vec![page(0, 2, 10), page(2, 1, 20)]));
        assert_eq!(seen.items_shown(at(0), 3), 3);
        assert_eq!(none, ItemsSeen::default());
    }

    /// Another tenant reads none of Bob's pages.
    #[tokio::test]
    async fn pages_are_read_only_by_their_tenant() {
        let fx = fixture().await;
        let bob = fx.viewer("bob@corp.test");
        fx.store
            .record(&fx.tenant, &bob, &page(0, 2, 10))
            .await
            .unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let seen = fx.store.seen_by(&other, &bob).await.unwrap();

        assert_eq!(seen, ItemsSeen::default());
    }

    /// Deleting a run deletes the pages its approvers opened, so nothing of
    /// it is kept past the run's own retention.
    #[tokio::test]
    async fn pages_go_with_their_run() {
        let fx = fixture().await;
        let bob = fx.viewer("bob@corp.test");
        fx.store
            .record(&fx.tenant, &bob, &page(0, 2, 10))
            .await
            .unwrap();

        fx.executions.delete(&fx.tenant, &fx.run).await.unwrap();

        let seen = fx.store.seen_by(&fx.tenant, &bob).await.unwrap();
        assert_eq!(seen, ItemsSeen::default());
    }
}
