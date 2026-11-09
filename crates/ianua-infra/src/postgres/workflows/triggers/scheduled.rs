//! The versions in service that start on a schedule, read across every
//! tenant for the scheduler that fires them.
//!
//! A tenant's versions live in the database it lives in, so a page is read
//! from every database at once: the tenants in the platform database in one
//! query, as platform work, and each tenant with a database of its own from
//! that database. Each read takes the page past the cursor in the page's
//! order, by tenant and then workflow, and the page is the first of all
//! those rows together, so it holds from one page to the next. The
//! timezone each schedule is read in is the tenant's own, read from the
//! platform's tenants in one query. The whole read is held to ten seconds.

mod record;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::listing::{Keyset, Page, PageRequest, SortOrder};
use ianua_app::ports::workflows::{
    ScheduledVersion, ScheduledVersionSortField, ScheduledWorkflows,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{ScheduleRecord, TimezoneRecord, timezones_of};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The longest the scheduler waits for a page.
const READ_AT_MOST: Duration = Duration::from_secs(10);

/// Keeps the versions in service that start on a schedule.
const SCHEDULED: &str = "status = 'published' AND trigger_kind = 'schedule'";

/// The order scheduled versions are read in.
type ScheduledOrder = SortOrder<ScheduledVersionSortField>;

/// The Postgres read of every tenant's scheduled versions.
pub struct PgScheduledWorkflows {
    databases: Arc<Databases>,
}

impl PgScheduledWorkflows {
    /// A read of the versions kept in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The page past the cursor among the tenants in the platform database.
    async fn shared(
        &self,
        keyset: &Keyset<'_, ScheduledOrder>,
    ) -> Result<Vec<ScheduleRecord>, DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            let ids = PageQuery::ids("workflow_id", "workflow_versions")
                .keep(SCHEDULED)
                .fetch(keyset, &mut *connection)
                .await?;
            schedules_of(connection, &ids).await
        })
        .await
    }

    /// The page past the cursor among `tenant`'s versions, read from its
    /// own database.
    async fn own(
        &self,
        tenant: TenantId,
        keyset: &Keyset<'_, ScheduledOrder>,
    ) -> Result<Vec<ScheduleRecord>, DomainError> {
        scoped(
            &self.databases,
            RowScope::Tenant(tenant),
            async |connection| {
                let ids = PageQuery::ids("workflow_id", "workflow_versions")
                    .filter("tenant_id = ?", *tenant.as_uuid())
                    .keep(SCHEDULED)
                    .fetch(keyset, &mut *connection)
                    .await?;
                schedules_of(connection, &ids).await
            },
        )
        .await
    }

    /// The timezones of the tenants `records` name, by tenant.
    async fn timezones(
        &self,
        records: &[ScheduleRecord],
    ) -> Result<HashMap<Uuid, String>, DomainError> {
        let tenants: Vec<Uuid> = records.iter().map(|record| record.tenant_id).collect();
        let found = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(TimezoneRecord, "queries/tenants/timezones.sql", &tenants)
                .fetch_all(connection)
                .await
        })
        .await?;
        Ok(timezones_of(found))
    }

    /// Every scheduled version of the page `keyset` asks for, from every
    /// database, before they are put in order and cut to the page.
    async fn everywhere(
        &self,
        keyset: &Keyset<'_, ScheduledOrder>,
    ) -> Result<Vec<ScheduledVersion>, DomainError> {
        let own = self.databases.with_own_database();
        let (shared, apart) = futures_util::try_join!(
            self.shared(keyset),
            try_join_all(own.into_iter().map(|tenant| self.own(tenant, keyset)))
        )?;
        let records: Vec<ScheduleRecord> = shared
            .into_iter()
            .chain(apart.into_iter().flatten())
            .collect();
        let timezones = self.timezones(&records).await?;
        records
            .into_iter()
            .map(|record| record.into_scheduled(&timezones))
            .collect()
    }
}

/// The schedules of the versions of the workflows `ids` names, in no
/// order.
async fn schedules_of(
    connection: &mut PgConnection,
    ids: &[Uuid],
) -> Result<Vec<ScheduleRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        ScheduleRecord,
        "queries/workflow_versions/scheduled.sql",
        ids
    )
    .fetch_all(connection)
    .await
}

impl SortColumns for ScheduledVersionSortField {
    fn column(self) -> &'static str {
        match self {
            Self::Tenant => "tenant_id",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl ScheduledWorkflows for PgScheduledWorkflows {
    async fn list_scheduled(
        &self,
        page: &PageRequest,
    ) -> Result<Page<ScheduledVersion>, DomainError> {
        let order = ScheduledOrder::default();
        let keyset = page.keyset(&order)?;
        let versions = tokio::time::timeout(READ_AT_MOST, self.everywhere(&keyset))
            .await
            .map_err(DomainError::infra)??;
        Ok(keyset.cut(versions))
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::Limit;
    use ianua_app::ports::workflows::WorkflowStore;
    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::domains::workflows::design::workflow::{Workflow, WorkflowRow};
    use ianua_domain::domains::workflows::triggers::{CronSchedule, Trigger};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::WorkflowId;

    use super::*;
    use crate::postgres::workflows::PgWorkflowStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::domain::saved_tenant;
    use crate::test_support::rows::workflows::{draft_row, published_row};

    const WEEKDAYS: &str = "0 9 * * 1-5";

    struct Fixture {
        db: TestDb,
        scheduled: PgScheduledWorkflows,
        workflows: PgWorkflowStore,
    }

    /// A fresh database, the read on it, and the store its versions are
    /// kept through.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            scheduled: PgScheduledWorkflows::new(Arc::clone(&db.databases)),
            workflows: PgWorkflowStore::new(Arc::clone(&db.databases)),
            db,
        }
    }

    fn on_schedule(row: WorkflowRow) -> Workflow<ResolvedTenant> {
        Workflow::reconstitute(WorkflowRow {
            trigger: Trigger::Schedule(CronSchedule::parse(WEEKDAYS).unwrap()),
            ..row
        })
        .unwrap()
    }

    impl Fixture {
        /// Keeps a scheduled draft and a published manual version that the scheduler must skip.
        async fn insert_unscheduled(&self, tenant: &ScopedTenant) {
            self.workflows
                .insert(tenant, &on_schedule(draft_row("draft", 0)))
                .await
                .unwrap();
            let by_hand = Workflow::reconstitute(published_row("by hand", 0)).unwrap();
            self.workflows.insert(tenant, &by_hand).await.unwrap();
        }

        /// Keeps a published version on the weekday schedule for `tenant`.
        async fn scheduled_for(&self, tenant: &ScopedTenant) -> WorkflowId {
            let kept = on_schedule(published_row("report", 0));
            self.workflows.insert(tenant, &kept).await.unwrap();
            *kept.id()
        }

        async fn page(&self, request: &PageRequest) -> Page<ScheduledVersion> {
            self.scheduled.list_scheduled(request).await.unwrap()
        }
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    /// Every tenant's scheduled versions are read page by page, by tenant
    /// and then workflow, each with its schedule and its tenant's
    /// timezone; a draft on a schedule and a version started by hand are
    /// left out.
    #[tokio::test]
    async fn every_tenants_scheduled_versions_are_read_page_by_page() {
        let fx = fixture().await;
        let acme = saved_tenant(&fx.db.databases).await;
        let globex = saved_tenant(&fx.db.databases).await;
        let mut expected = vec![
            (*acme, fx.scheduled_for(&acme).await),
            (*acme, fx.scheduled_for(&acme).await),
            (*globex, fx.scheduled_for(&globex).await),
        ];
        expected.sort_by_key(|(tenant, workflow)| (*tenant.as_uuid(), *workflow.as_uuid()));
        fx.insert_unscheduled(&acme).await;

        let page_one = fx.page(&first(2)).await;
        let page_two = fx
            .page(&PageRequest::new(
                page_one.next.clone(),
                Limit::new(2).unwrap(),
            ))
            .await;

        let read: Vec<(TenantId, WorkflowId)> = page_one
            .items
            .iter()
            .chain(&page_two.items)
            .map(|version| (version.tenant_id, version.workflow_id))
            .collect();
        assert_eq!(read, expected);
        assert_eq!(page_one.items[0].schedule.as_str(), WEEKDAYS);
        assert_eq!(page_one.items[0].timezone.as_str(), "UTC");
        assert!(!page_two.has_next());
    }

    /// A schedule page includes a dedicated tenant's workflow alongside
    /// the shared tenant's workflow.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_is_read() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let shared = saved_tenant(&fx.db.databases).await;
        let apart = saved_tenant(&fx.db.databases).await;
        fx.db.databases.register(*apart, own.as_dedicated());
        fx.scheduled_for(&shared).await;
        let theirs = fx.scheduled_for(&apart).await;

        let page = fx.page(&first(10)).await;

        assert_eq!(page.items.len(), 2);
        assert!(
            page.items
                .iter()
                .any(|version| version.tenant_id == *apart && version.workflow_id == theirs)
        );
    }

    /// Reading schedules for a tenant absent from the platform returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_version_of_an_unknown_tenant_is_refused() {
        let fx = fixture().await;
        let unknown = ScopedTenant::for_background(TenantId::new());
        fx.scheduled_for(&unknown).await;

        let read = fx.scheduled.list_scheduled(&first(10)).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Reading an invalid stored schedule returns an infrastructure error.
    #[tokio::test]
    async fn a_schedule_that_does_not_read_is_refused() {
        let fx = fixture().await;
        let acme = saved_tenant(&fx.db.databases).await;
        fx.scheduled_for(&acme).await;
        fx.db
            .tamper("UPDATE workflow_versions SET trigger_schedule = 'every monday'")
            .await;

        let read = fx.scheduled.list_scheduled(&first(10)).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
