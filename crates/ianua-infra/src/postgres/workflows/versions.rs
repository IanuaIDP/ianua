//! A tenant's workflows and every version of them, each table row under
//! row-level security.
//!
//! A workflow's own row keeps where it came from, designed or an agent
//! flow; each version is a row of its own beside it. The primary key keeps
//! a workflow and version pair once, so of two drafts made from the same
//! version the second is refused, and a unique index over the published
//! versions keeps one in service per workflow. A list reads the ids of its
//! page first, the latest version of each workflow by its own columns, then
//! reads those versions through the one query by ids.
//!
//! An agent flow is deleted with its workflow row, and its version, run and
//! webhook secret go with it by their foreign keys. A designed workflow is
//! archived, never deleted, so the delete leaves one as it is.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Keyset, Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::workflows::{NewestFirstField, WorkflowSortField, WorkflowStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::design::workflow::Workflow;
use ianua_domain::domains::workflows::triggers::before::GuardedChange;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{EventType, IntegrationAccountId, WorkflowId};
use sqlx::PgConnection;
use sqlx::postgres::PgQueryResult;
use uuid::Uuid;

use self::record::{WorkflowColumns, WorkflowRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a workflow and version pair once.
const VERSION_KEY: &str = "workflow_versions_pkey";

/// The index that keeps one version of a workflow in service.
const PUBLISHED_KEY: &str = "workflow_versions_published_key";

/// The versions a list reads, beside the workflow each belongs to.
const VERSIONS: &str =
    "workflow_versions v JOIN workflows w ON w.tenant_id = v.tenant_id AND w.id = v.workflow_id";

/// Keeps only the highest-numbered version of each workflow.
const LATEST: &str = "NOT EXISTS (SELECT 1 FROM workflow_versions later \
    WHERE later.tenant_id = v.tenant_id AND later.workflow_id = v.workflow_id \
    AND later.version > v.version)";

/// The Postgres store of workflow versions.
pub struct PgWorkflowStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgWorkflowStore {}

impl PgWorkflowStore {
    /// A store keeping workflows and their versions in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The versions of the page `listed` reads, in the order `keyset` asks
    /// for.
    async fn latest_page(
        &self,
        tenant: &ScopedTenant,
        listed: PageQuery<'static>,
        keyset: &Keyset<'_, SortOrder<impl SortColumns>>,
    ) -> Result<Vec<Workflow<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                let ids = listed.fetch(keyset, &mut *connection).await?;
                let records = latest_of(connection, tenant.as_uuid(), &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.workflow_id))
            },
        )
        .await?;
        rebuilt_all(records)
    }

    /// The one version `read` finds.
    async fn one(
        &self,
        tenant: &ScopedTenant,
        read: impl AsyncFnOnce(&mut PgConnection) -> Result<Option<WorkflowRecord>, sqlx::Error>,
    ) -> Result<Option<Workflow<ResolvedTenant>>, DomainError> {
        let record = scoped(&self.databases, RowScope::from(tenant), read).await?;
        record.map(WorkflowRecord::into_workflow).transpose()
    }
}

/// The latest version of each of the workflows of `tenant` that `ids`
/// names, in no order.
async fn latest_of(
    connection: &mut PgConnection,
    tenant: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<WorkflowRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        WorkflowRecord,
        "queries/workflow_versions/latest_of.sql",
        tenant,
        ids
    )
    .fetch_all(connection)
    .await
}

fn rebuilt_all(records: Vec<WorkflowRecord>) -> Result<Vec<Workflow<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(WorkflowRecord::into_workflow)
        .collect()
}

/// Inserts the version after its workflow row exists, preserving the version-number conflict.
async fn insert_version(
    connection: &mut PgConnection,
    tenant: &Uuid,
    c: &WorkflowColumns<'_>,
) -> Result<Uniqueness, sqlx::Error> {
    let attempt = sqlx::query_file!(
        "queries/workflow_versions/insert.sql",
        tenant,
        c.workflow_id,
        c.version,
        c.name,
        c.graph,
        c.trigger_kind,
        c.trigger_schedule,
        c.trigger_event,
        c.trigger_service,
        c.run_limit_secs,
        c.status,
        c.created_by,
        c.edited_by,
        c.authors,
        c.published_by,
        c.hold,
        c.created_at,
        c.updated_at,
        c.description,
        c.layout,
        c.failure_alert,
        c.trigger_change,
    )
    .execute(connection)
    .await;
    unique_on(attempt, VERSION_KEY)
}

/// Updates one version while reporting both publication conflicts and an absent row.
async fn update_version(
    connection: &mut PgConnection,
    tenant: &Uuid,
    c: &WorkflowColumns<'_>,
) -> Result<(Uniqueness, u64), sqlx::Error> {
    let attempt = sqlx::query_file!(
        "queries/workflow_versions/update.sql",
        tenant,
        c.workflow_id,
        c.version,
        c.name,
        c.graph,
        c.trigger_kind,
        c.trigger_schedule,
        c.trigger_event,
        c.trigger_service,
        c.run_limit_secs,
        c.status,
        c.edited_by,
        c.authors,
        c.published_by,
        c.hold,
        c.updated_at,
        c.description,
        c.layout,
        c.failure_alert,
        c.trigger_change,
    )
    .execute(connection)
    .await;
    let changed = attempt.as_ref().map_or(0, PgQueryResult::rows_affected);
    unique_on(attempt, PUBLISHED_KEY).map(|kept| (kept, changed))
}

impl SortColumns for WorkflowSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "v.created_at",
            Self::UpdatedAt => "v.updated_at",
            Self::Name => "v.name",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

/// Agent flows and workflow runs are both listed newest first, by the
/// creation column of the table each list reads. Neither list's query names
/// another table with one, so the column is named on its own.
impl SortColumns for NewestFirstField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl WorkflowStore for PgWorkflowStore {
    async fn find_version(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowId,
        version: u32,
    ) -> Result<Option<Workflow<ResolvedTenant>>, DomainError> {
        let Ok(version) = i32::try_from(version) else {
            return Ok(None);
        };
        self.one(tenant_id, async |connection| {
            sqlx::query_file_as!(
                WorkflowRecord,
                "queries/workflow_versions/version.sql",
                tenant_id.as_uuid(),
                id.as_uuid(),
                version
            )
            .fetch_optional(connection)
            .await
        })
        .await
    }

    async fn find_latest(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowId,
    ) -> Result<Option<Workflow<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        self.one(tenant_id, async |connection| {
            let records = latest_of(connection, tenant_id.as_uuid(), &ids).await?;
            Ok(records.into_iter().next())
        })
        .await
    }

    async fn find_published(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowId,
    ) -> Result<Option<Workflow<ResolvedTenant>>, DomainError> {
        self.one(tenant_id, async |connection| {
            sqlx::query_file_as!(
                WorkflowRecord,
                "queries/workflow_versions/published.sql",
                tenant_id.as_uuid(),
                id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await
    }

    async fn list_latest(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<WorkflowSortField>,
        page: &PageRequest,
    ) -> Result<Page<Workflow<ResolvedTenant>>, DomainError> {
        let keyset = page.keyset(sort)?;
        let listed = PageQuery::ids("v.workflow_id", VERSIONS)
            .filter("v.tenant_id = ?", *tenant_id.as_uuid())
            .keep(LATEST)
            .keep("w.origin = 'designed'");
        let workflows = self.latest_page(tenant_id, listed, &keyset).await?;
        Ok(keyset.seal(workflows))
    }

    async fn list_flows(
        &self,
        tenant_id: &ScopedTenant,
        page: &PageRequest,
    ) -> Result<Page<Workflow<ResolvedTenant>>, DomainError> {
        let order = SortOrder::<NewestFirstField>::default();
        let keyset = page.keyset(&order)?;
        let listed = PageQuery::ids("v.workflow_id", VERSIONS)
            .filter("v.tenant_id = ?", *tenant_id.as_uuid())
            .keep(LATEST)
            .keep("w.origin = 'flow'");
        let flows = self.latest_page(tenant_id, listed, &keyset).await?;
        Ok(keyset.seal(flows))
    }

    async fn list_published_on(
        &self,
        tenant_id: &ScopedTenant,
        event: EventType,
    ) -> Result<Vec<Workflow<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    WorkflowRecord,
                    "queries/workflow_versions/published_on.sql",
                    tenant_id.as_uuid(),
                    event.as_str()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt_all(records)
    }

    async fn list_published_before(
        &self,
        tenant_id: &ScopedTenant,
        change: GuardedChange,
    ) -> Result<Vec<Workflow<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    WorkflowRecord,
                    "queries/workflow_versions/published_before.sql",
                    tenant_id.as_uuid(),
                    change.as_str()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt_all(records)
    }

    async fn list_published_using(
        &self,
        tenant_id: &ScopedTenant,
        account: &IntegrationAccountId,
    ) -> Result<Vec<Workflow<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    WorkflowRecord,
                    "queries/workflow_versions/published_using.sql",
                    tenant_id.as_uuid(),
                    account.to_string()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        Ok(rebuilt_all(records)?
            .into_iter()
            .filter(|workflow| {
                workflow
                    .accounts_used()
                    .iter()
                    .any(|used| used.account == *account)
            })
            .collect())
    }

    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        workflow: &Workflow<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let c = WorkflowColumns::of(workflow)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/workflows/open.sql",
                    c.workflow_id,
                    tenant_id.as_uuid(),
                    c.origin,
                    c.flow_description
                )
                .execute(&mut *connection)
                .await?;
                insert_version(connection, tenant_id.as_uuid(), &c).await
            },
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-the-workflow-already-has-a-version",
                "the workflow already has a version with this number"
            ))),
        }
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        workflow: &Workflow<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let c = WorkflowColumns::of(workflow)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| update_version(connection, tenant_id.as_uuid(), &c).await,
        )
        .await?;
        match written {
            (Uniqueness::Taken, _) => Err(DomainError::conflict(message!(
                "infra-another-version-of-the-workflow-is",
                "another version of the workflow is published"
            ))),
            (Uniqueness::Kept, 0) => Err(DomainError::infra_msg("no such version is kept")),
            (Uniqueness::Kept, _) => Ok(()),
        }
    }

    async fn delete_flow(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/workflows/delete_flow.sql",
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
    use ianua_app::listing::{Limit, Sort};
    use ianua_domain::domains::workflows::design::workflow::{
        AccountUnusable, AccountUse, Hold, MissingAccount, WorkflowRow,
    };
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
    use ianua_domain::domains::workflows::triggers::{EventTrigger, ServiceTrigger, Trigger};
    use ianua_domain::types::TenantId;
    use ianua_domain::types::event_type::IdentityEvent;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::workflows::{draft_row, flow_row, published_row};

    struct Fixture {
        db: TestDb,
        store: PgWorkflowStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the store on it, and one tenant to keep workflows
    /// in.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: PgWorkflowStore::new(Arc::clone(&db.databases)),
            tenant: ScopedTenant::for_background(TenantId::new()),
            db,
        }
    }

    fn workflow(row: WorkflowRow) -> Workflow<ResolvedTenant> {
        Workflow::reconstitute(row).unwrap()
    }

    /// Version `version` of `of`, a draft drafted `created` seconds in.
    fn next_version(of: &Workflow<ResolvedTenant>, version: u32, created: i64) -> WorkflowRow {
        WorkflowRow {
            id: *of.id(),
            version,
            ..draft_row(of.name().as_str(), created)
        }
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn after<T>(page: &Page<T>, limit: u32) -> PageRequest {
        PageRequest::new(page.next.clone(), Limit::new(limit).unwrap())
    }

    fn names(page: &Page<Workflow<ResolvedTenant>>) -> Vec<&str> {
        page.items.iter().map(|kept| kept.name().as_str()).collect()
    }

    fn by_name() -> SortOrder<WorkflowSortField> {
        SortOrder::single(Sort::ascending(WorkflowSortField::Name))
    }

    impl Fixture {
        async fn inserted(&self, row: WorkflowRow) -> Workflow<ResolvedTenant> {
            let kept = workflow(row);
            self.store.insert(&self.tenant, &kept).await.unwrap();
            kept
        }
    }

    /// A drafted version is found by its number and as the latest, with
    /// everything it was drafted with, and a second version becomes the
    /// latest while the first stays as it was.
    #[tokio::test]
    async fn a_version_is_found_by_its_number_and_as_the_latest() {
        let fx = fixture().await;
        let first_draft = fx.inserted(published_row("report", 0)).await;
        let second = fx.inserted(next_version(&first_draft, 2, 5)).await;

        let one = fx
            .store
            .find_version(&fx.tenant, first_draft.id(), 1)
            .await
            .unwrap()
            .unwrap();
        let latest = fx
            .store
            .find_latest(&fx.tenant, first_draft.id())
            .await
            .unwrap()
            .unwrap();
        let published = fx
            .store
            .find_published(&fx.tenant, first_draft.id())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(one.graph(), first_draft.graph());
        assert_eq!(one.publication(), first_draft.publication());
        assert_eq!(one.authors(), first_draft.authors());
        assert_eq!(latest.version(), 2);
        assert_eq!(latest.status(), second.status());
        assert_eq!(published.version(), 1);
    }

    /// An unknown workflow, an unknown version and a workflow with no
    /// version in service find nothing, rather than failing.
    #[tokio::test]
    async fn an_unknown_version_is_not_found() {
        let fx = fixture().await;
        let draft = fx.inserted(draft_row("report", 0)).await;

        let unknown = fx.store.find_latest(&fx.tenant, &WorkflowId::new()).await;
        let version = fx.store.find_version(&fx.tenant, draft.id(), 7).await;
        let published = fx.store.find_published(&fx.tenant, draft.id()).await;

        assert!(unknown.unwrap().is_none());
        assert!(version.unwrap().is_none());
        assert!(published.unwrap().is_none());
    }

    /// Inserting another draft with the same workflow and version number
    /// returns a conflict.
    #[tokio::test]
    async fn a_second_draft_with_the_same_number_is_refused() {
        let fx = fixture().await;
        let draft = fx.inserted(published_row("report", 0)).await;
        fx.inserted(next_version(&draft, 2, 5)).await;

        let again = fx
            .store
            .insert(&fx.tenant, &workflow(next_version(&draft, 2, 6)))
            .await;

        assert!(matches!(again, Err(DomainError::Conflict(_))));
    }

    /// Saving a second version as published while the first is published
    /// returns a conflict.
    #[tokio::test]
    async fn a_second_version_in_service_is_refused() {
        let fx = fixture().await;
        let draft = fx.inserted(published_row("report", 0)).await;
        fx.inserted(next_version(&draft, 2, 5)).await;
        let published_again = workflow(WorkflowRow {
            id: *draft.id(),
            version: 2,
            ..published_row("report", 5)
        });

        let saved = fx.store.save(&fx.tenant, &published_again).await;

        assert!(matches!(saved, Err(DomainError::Conflict(_))));
    }

    /// A draft published later keeps who published it and its new values,
    /// and the time it was drafted stays.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let fx = fixture().await;
        let draft = fx.inserted(draft_row("report", 0)).await;
        let published = workflow(WorkflowRow {
            id: *draft.id(),
            updated_at: at(9),
            ..published_row("weekly report", 0)
        });

        fx.store.save(&fx.tenant, &published).await.unwrap();

        let found = fx
            .store
            .find_published(&fx.tenant, draft.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.name().as_str(), "weekly report");
        assert_eq!(found.publication(), published.publication());
        assert_eq!(found.graph(), published.graph());
        assert_eq!(found.revision(), published.revision());
    }

    /// Updating a workflow version that was never inserted returns an
    /// infrastructure error.
    #[tokio::test]
    async fn saving_a_version_never_kept_is_refused() {
        let fx = fixture().await;

        let saved = fx
            .store
            .save(&fx.tenant, &workflow(draft_row("report", 0)))
            .await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
    }

    /// The tenant's designed workflows are read page by page by name, each
    /// by its latest version, with the agent flows left out.
    #[tokio::test]
    async fn the_latest_designed_versions_are_listed_page_by_page() {
        let fx = fixture().await;
        let budget = fx.inserted(published_row("budget", 0)).await;
        fx.inserted(next_version(&budget, 2, 5)).await;
        fx.inserted(draft_row("audit", 1)).await;
        fx.inserted(draft_row("report", 2)).await;
        fx.inserted(flow_row("digest", 3)).await;

        let page_one = fx
            .store
            .list_latest(&fx.tenant, &by_name(), &first(2))
            .await
            .unwrap();
        let page_two = fx
            .store
            .list_latest(&fx.tenant, &by_name(), &after(&page_one, 2))
            .await
            .unwrap();

        assert_eq!(names(&page_one), ["audit", "budget"]);
        assert_eq!(page_one.items[1].version(), 2);
        assert_eq!(names(&page_two), ["report"]);
        assert!(!page_two.has_next());
    }

    /// The agent flows are listed newest first, page by page, and no
    /// designed workflow among them.
    #[tokio::test]
    async fn the_agent_flows_are_listed_newest_first() {
        let fx = fixture().await;
        fx.inserted(flow_row("older", 1)).await;
        fx.inserted(flow_row("newer", 2)).await;
        fx.inserted(draft_row("report", 3)).await;

        let page_one = fx.store.list_flows(&fx.tenant, &first(1)).await.unwrap();
        let page_two = fx
            .store
            .list_flows(&fx.tenant, &after(&page_one, 1))
            .await
            .unwrap();

        assert_eq!(names(&page_one), ["newer"]);
        assert_eq!(names(&page_two), ["older"]);
        assert!(!page_two.has_next());
    }

    /// The versions in service that start on an event are found by it, and
    /// a draft on the same event or a version on another is not.
    #[tokio::test]
    async fn the_versions_in_service_on_an_event_are_found() {
        let fx = fixture().await;
        let registered = EventType::Identity(IdentityEvent::UserRegistered);
        let on = |event: EventType| Trigger::Event(EventTrigger::new(event).unwrap());
        fx.inserted(WorkflowRow {
            trigger: on(registered),
            ..published_row("welcome", 0)
        })
        .await;
        fx.inserted(WorkflowRow {
            trigger: on(registered),
            ..draft_row("draft", 1)
        })
        .await;
        fx.inserted(WorkflowRow {
            trigger: on(EventType::Identity(IdentityEvent::UserDeleted)),
            ..published_row("farewell", 2)
        })
        .await;

        let found = fx
            .store
            .list_published_on(&fx.tenant, registered)
            .await
            .unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name().as_str(), "welcome");
        assert_eq!(found[0].trigger(), &on(registered));
    }

    /// Deleting an agent flow removes it, and deleting a designed workflow
    /// the same way leaves it, since a designed workflow is only archived.
    #[tokio::test]
    async fn only_an_agent_flow_is_deleted() {
        let fx = fixture().await;
        let flow = fx.inserted(flow_row("digest", 0)).await;
        let designed = fx.inserted(draft_row("report", 1)).await;

        fx.store.delete_flow(&fx.tenant, flow.id()).await.unwrap();
        fx.store
            .delete_flow(&fx.tenant, designed.id())
            .await
            .unwrap();

        assert!(
            fx.store
                .find_latest(&fx.tenant, flow.id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            fx.store
                .find_latest(&fx.tenant, designed.id())
                .await
                .unwrap()
                .is_some()
        );
    }

    /// Another tenant sees none of Acme's workflows, by id or in a list,
    /// and a tenant with a database of its own keeps its workflows there.
    #[tokio::test]
    async fn another_tenants_workflows_are_invisible() {
        let fx = fixture().await;
        let report = fx.inserted(draft_row("report", 0)).await;
        let other = ScopedTenant::for_background(TenantId::new());
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());
        let theirs = workflow(draft_row("theirs", 0));
        fx.store.insert(&apart, &theirs).await.unwrap();

        let by_id = fx.store.find_latest(&other, report.id()).await.unwrap();
        let listed = fx
            .store
            .list_latest(&other, &by_name(), &first(10))
            .await
            .unwrap();
        let in_own = PgWorkflowStore::new(Arc::clone(&own.databases))
            .find_latest(&apart, theirs.id())
            .await
            .unwrap();

        assert!(by_id.is_none());
        assert!(listed.items.is_empty());
        assert!(in_own.is_some());
    }

    /// Reading a workflow version whose stored graph has no steps returns
    /// an infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_version_is_refused() {
        let fx = fixture().await;
        let draft = fx.inserted(published_row("report", 0)).await;
        fx.db
            .tamper(
                "UPDATE workflow_versions \
                 SET graph = '{\"v\": 1, \"value\": {\"nodes\": [], \"edges\": []}}'",
            )
            .await;

        let read = fx.store.find_latest(&fx.tenant, draft.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// A version started by new sheet rows through `account`, in service.
    fn watching(account: IntegrationAccountId) -> WorkflowRow {
        WorkflowRow {
            trigger: Trigger::Service(
                ServiceTrigger::from_stored(
                    IntegrationKey::new("google-sheets").unwrap(),
                    ServiceEventKey::new("row-added").unwrap(),
                    account,
                    Vec::new(),
                )
                .unwrap(),
            ),
            ..published_row("watch", 0)
        }
    }

    /// Pat's sheets account is switched off, so Ann's watching version is
    /// held: it is found by the account it registers through, and reads
    /// back held for that account, at its trigger, because it is switched
    /// off. Another version is not found.
    #[tokio::test]
    async fn a_held_version_is_found_by_its_account_and_reads_back_held() {
        let fx = fixture().await;
        let account = IntegrationAccountId::new();
        let missing = MissingAccount {
            account,
            at: AccountUse::Trigger,
            why: AccountUnusable::Disabled,
        };
        let held = fx
            .inserted(WorkflowRow {
                hold: Hold::NeedsAccount(missing.clone()),
                ..watching(account)
            })
            .await;
        fx.inserted(watching(IntegrationAccountId::new())).await;

        let found = fx
            .store
            .list_published_using(&fx.tenant, &account)
            .await
            .unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id(), held.id());
        assert_eq!(found[0].hold(), &Hold::NeedsAccount(missing));
    }
}
