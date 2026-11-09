//! The task templates of a tenant, each table row under row-level
//! security: proposed by one person, approved by a second, and kept after
//! they are retired.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::TaskTemplateStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::authority::task_template::TaskTemplate;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TaskTemplateId;
use sqlx::PgConnection;

use self::record::{TemplateColumns, TemplateRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of task templates.
pub struct PgTaskTemplateStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgTaskTemplateStore {}

impl PgTaskTemplateStore {
    /// A store keeping task templates in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

fn rebuilt(records: Vec<TemplateRecord>) -> Result<Vec<TaskTemplate<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(TemplateRecord::into_template)
        .collect()
}

/// Writes the template's limits and approval together on the scoped connection.
async fn write_template(
    connection: &mut PgConnection,
    tenant_id: &ScopedTenant,
    columns: &TemplateColumns<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/agent_task_templates/save.sql",
        columns.id,
        tenant_id.as_uuid(),
        columns.name,
        columns.purpose,
        columns.purpose_digest,
        columns.ceiling,
        columns.action_classes,
        columns.max_ttl_seconds,
        columns.max_depth,
        columns.max_data_class,
        columns.resource_scope,
        columns.budget,
        columns.approval,
        columns.proposed_by.kind,
        columns.proposed_by.id,
        columns.proposed_by.person,
        columns.proposed_at,
        columns.approved_by_kind(),
        columns.approved_by_id(),
        columns.approved_by_person(),
        columns.approved_at,
        columns.retired_at,
    )
    .execute(connection)
    .await?;
    Ok(())
}

#[async_trait]
impl TaskTemplateStore for PgTaskTemplateStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        template: &TaskTemplate<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = TemplateColumns::of(template)?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| write_template(connection, tenant_id, &columns).await,
        )
        .await
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &TaskTemplateId,
    ) -> Result<Option<TaskTemplate<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    TemplateRecord,
                    "queries/agent_task_templates/by_ids.sql",
                    tenant_id.as_uuid(),
                    &ids
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        Ok(rebuilt(records)?.pop())
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<TaskTemplate<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    TemplateRecord,
                    "queries/agent_task_templates/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt(records)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::task_template::{
        TaskTemplateRow, TemplateState, TemplateStatus,
    };
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::{human, template_row};
    use crate::test_support::rows::at;

    fn template(row: TaskTemplateRow) -> TaskTemplate<ResolvedTenant> {
        TaskTemplate::reconstitute(row).unwrap()
    }

    /// A fresh database, the store on it, and one tenant to keep templates
    /// in.
    async fn fixture() -> (TestDb, PgTaskTemplateStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgTaskTemplateStore::new(Arc::clone(&db.databases));
        (db, store, ScopedTenant::for_background(TenantId::new()))
    }

    /// Ann proposes a template and Bob approves it: it is found by its id
    /// with everything it allows and his approval; an id nobody has finds
    /// nothing.
    #[tokio::test]
    async fn a_saved_template_is_found_with_its_approval() {
        let (_db, store, tenant) = fixture().await;
        let proposed = template(template_row("reconcile", at(0)));
        store.save(&tenant, &proposed).await.unwrap();
        let bob = human("bob@acme.example");
        let approved = template(TaskTemplateRow {
            id: *proposed.id(),
            state: TemplateState::from_stored(Some(bob.clone()), Some(at(20)), None).unwrap(),
            ..template_row("reconcile", at(0))
        });

        store.save(&tenant, &approved).await.unwrap();

        let found = store
            .find_by_id(&tenant, proposed.id())
            .await
            .unwrap()
            .unwrap();
        let unknown = store
            .find_by_id(&tenant, &TaskTemplateId::new())
            .await
            .unwrap();
        assert_eq!(found.name(), proposed.name());
        assert_eq!(found.purpose(), proposed.purpose());
        assert_eq!(found.digest(), proposed.digest());
        assert_eq!(found.ceiling(), proposed.ceiling());
        assert_eq!(found.classes(), proposed.classes());
        assert_eq!(found.limits(), proposed.limits());
        assert_eq!(found.proposed_by(), proposed.proposed_by());
        assert_eq!(found.status(), TemplateStatus::Approved);
        assert_eq!(found.approved_by(), Some(&bob));
        assert!(unknown.is_none());
    }

    /// The tenant's templates are listed newest first, a retired one among
    /// them, and another tenant sees none.
    #[tokio::test]
    async fn templates_are_listed_newest_first() {
        let (_db, store, tenant) = fixture().await;
        let older = template(TaskTemplateRow {
            state: TemplateState::from_stored(None, None, Some(at(5))).unwrap(),
            ..template_row("older", at(0))
        });
        let newer = template(template_row("newer", at(10)));
        store.save(&tenant, &older).await.unwrap();
        store.save(&tenant, &newer).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let listed = store.list(&tenant).await.unwrap();
        let elsewhere = store.list(&other).await.unwrap();

        let names: Vec<&str> = listed
            .iter()
            .map(|template| template.name().as_str())
            .collect();
        assert_eq!(names, ["newer", "older"]);
        assert_eq!(listed[1].status(), TemplateStatus::Retired);
        assert!(elsewhere.is_empty());
    }

    /// A template of a tenant with a database of its own is kept there, and
    /// not in the platform database.
    #[tokio::test]
    async fn a_template_of_a_tenant_with_its_own_database_is_kept_there() {
        let (db, store, _) = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        db.databases.register(*apart, own.as_dedicated());
        let proposed = template(template_row("reconcile", at(0)));
        store.save(&apart, &proposed).await.unwrap();

        let in_its_own = store.find_by_id(&apart, proposed.id()).await.unwrap();
        db.databases.deregister(&apart);
        let in_the_platform = store.find_by_id(&apart, proposed.id()).await.unwrap();

        assert!(in_its_own.is_some());
        assert!(in_the_platform.is_none());
    }

    /// A stored template approved by its proposer is rejected as corrupt.
    #[tokio::test]
    async fn a_template_approved_by_its_proposer_is_refused() {
        let (db, store, tenant) = fixture().await;
        let proposed = template(template_row("reconcile", at(0)));
        store.save(&tenant, &proposed).await.unwrap();
        db.tamper(
            "UPDATE agent_task_templates SET approved_by_kind = proposed_by_kind, \
             approved_by_id = proposed_by_id, approved_by_person = proposed_by_person, \
             approved_at = proposed_at",
        )
        .await;

        let read = store.find_by_id(&tenant, proposed.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
