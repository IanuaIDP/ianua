//! A tenant's proxy pipelines, kept as tenant rows under row-level
//! security, each with its stages as one checked JSON list.
//!
//! A pipeline a route still runs is never deleted: the delete keeps it
//! when any route of the tenant names it, in the same statement, and the
//! store reports the routes that hold it.

mod record;
mod words;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::proxy::PipelineStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::PipelineId;

use self::record::{PipelineColumns, PipelineRecord, RouteCountRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a name to one pipeline of a tenant.
const NAME_KEY: &str = "pipelines_name_key";

/// The Postgres store of pipelines.
pub struct PgPipelineStore {
    databases: Arc<Databases>,
}

impl PgPipelineStore {
    /// A store keeping pipelines in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgPipelineStore {}

#[async_trait]
impl PipelineStore for PgPipelineStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        pipeline_id: &PipelineId,
    ) -> Result<Option<Pipeline<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    PipelineRecord,
                    "queries/pipelines/by_id.sql",
                    tenant_id.as_uuid(),
                    pipeline_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(PipelineRecord::into_pipeline).transpose()
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<Pipeline<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    PipelineRecord,
                    "queries/pipelines/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(PipelineRecord::into_pipeline)
            .collect()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        pipeline: &Pipeline<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = PipelineColumns::of(pipeline)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/pipelines/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.name,
                    columns.status,
                    columns.stages,
                    columns.created_at,
                    columns.updated_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, NAME_KEY)
            },
        )
        .await?;
        ensure_unique_name(written, pipeline.name().as_str())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        pipeline_id: &PipelineId,
    ) -> Result<(), DomainError> {
        let deleted = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/pipelines/delete_unused.sql",
                    tenant_id.as_uuid(),
                    pipeline_id.as_uuid()
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        if deleted.rows_affected() > 0 {
            return Ok(());
        }
        let in_use = self.route_count(tenant_id, pipeline_id).await?;
        if in_use > 0 {
            return Err(DomainError::conflict(message!(
                "infra-route-s-still-run-this-pipeline",
                format!(
                    "{in_use} route(s) still run this pipeline; move them to another one first"
                )
            )));
        }
        Ok(())
    }

    async fn route_counts(
        &self,
        tenant_id: &ScopedTenant,
        pipeline_ids: &[PipelineId],
    ) -> Result<HashMap<PipelineId, u64>, DomainError> {
        if pipeline_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let ids: Vec<_> = pipeline_ids.iter().map(|id| *id.as_uuid()).collect();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RouteCountRecord,
                    "queries/routes/running_pipelines.sql",
                    tenant_id.as_uuid(),
                    &ids
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(RouteCountRecord::into_count)
            .collect()
    }

    async fn route_count(
        &self,
        tenant_id: &ScopedTenant,
        pipeline_id: &PipelineId,
    ) -> Result<u64, DomainError> {
        let count = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/routes/running_pipeline.sql",
                    tenant_id.as_uuid(),
                    pipeline_id.as_uuid()
                )
                .fetch_one(connection)
                .await
            },
        )
        .await?;
        Ok(u64::try_from(count).unwrap_or_default())
    }
}

/// Reports the conflicting pipeline name after the scoped write completes.
fn ensure_unique_name(written: Uniqueness, name: &str) -> Result<(), DomainError> {
    match written {
        Uniqueness::Kept => Ok(()),
        Uniqueness::Taken => Err(DomainError::conflict(message!(
            "infra-a-pipeline-named-already-exists-in",
            format!("a pipeline named '{name}' already exists in this tenant")
        ))),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::proxy::pipeline::PipelineRow;
    use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::proxy::{pipeline_row, saved_route_on};

    struct Fixture {
        db: TestDb,
        tenant: ScopedTenant,
        store: PgPipelineStore,
    }

    /// A fresh database, a tenant, and the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let store = PgPipelineStore::new(Arc::clone(&db.databases));
        Fixture {
            db,
            tenant: ScopedTenant::for_background(TenantId::new()),
            store,
        }
    }

    fn pipeline(row: PipelineRow) -> Pipeline<ResolvedTenant> {
        Pipeline::reconstitute(row).unwrap()
    }

    fn names(pipelines: &[Pipeline<ResolvedTenant>]) -> Vec<&str> {
        pipelines.iter().map(|p| p.name().as_str()).collect()
    }

    /// A saved pipeline is found by its id with its stages, and saving it
    /// again keeps the new status.
    #[tokio::test]
    async fn a_saved_pipeline_is_found_with_its_stages() {
        let db = fixture().await;
        let edge = pipeline(pipeline_row("edge", 0));
        db.store.save(&db.tenant, &edge).await.unwrap();
        let disabled = pipeline(PipelineRow {
            id: *edge.id(),
            status: PipelineStatus::Disabled,
            updated_at: at(5),
            ..pipeline_row("edge", 0)
        });

        db.store.save(&db.tenant, &disabled).await.unwrap();

        let found = db.store.find(&db.tenant, edge.id()).await.unwrap().unwrap();
        assert_eq!(found.status(), PipelineStatus::Disabled);
        assert_eq!(found.stages().len(), 2);
        assert_eq!(found.updated_at(), at(5));
    }

    /// A tenant's pipelines are listed oldest first; another tenant finds
    /// none of them.
    #[tokio::test]
    async fn a_tenants_pipelines_are_listed_oldest_first() {
        let db = fixture().await;
        let other = ScopedTenant::for_background(TenantId::new());
        let newer = pipeline(pipeline_row("newer", 5));
        let older = pipeline(pipeline_row("older", 1));
        db.store.save(&db.tenant, &newer).await.unwrap();
        db.store.save(&db.tenant, &older).await.unwrap();

        assert_eq!(
            names(&db.store.list(&db.tenant).await.unwrap()),
            ["older", "newer"]
        );
        assert!(db.store.find(&other, newer.id()).await.unwrap().is_none());
    }

    /// Batch counts include only the requested tenant's pipelines, preserve
    /// exact counts with duplicate ids, and leave unused pipelines at zero.
    #[tokio::test]
    async fn route_counts_are_scoped_to_the_requested_pipelines() {
        let db = fixture().await;
        let edge = pipeline(pipeline_row("edge", 0));
        let unused = pipeline(pipeline_row("unused", 1));
        let omitted = pipeline(pipeline_row("omitted", 2));
        let foreign = save_counted_routes(&db, [&edge, &unused, &omitted]).await;
        let ids = [*edge.id(), *edge.id(), *unused.id(), PipelineId::new()];

        let counts = db.store.route_counts(&db.tenant, &ids).await.unwrap();

        assert_eq!(counts.get(edge.id()), Some(&2));
        assert_eq!(counts.get(unused.id()).copied().unwrap_or(0), 0);
        assert!(!counts.contains_key(omitted.id()));
        assert_eq!(
            db.store
                .route_counts(&foreign, &ids)
                .await
                .unwrap()
                .get(edge.id()),
            Some(&1)
        );
        assert!(
            db.store
                .route_counts(&db.tenant, &[])
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Saves routes on the counted and omitted pipelines, plus one foreign route.
    async fn save_counted_routes(
        db: &Fixture,
        pipelines: [&Pipeline<ResolvedTenant>; 3],
    ) -> ScopedTenant {
        let [edge, _, omitted] = pipelines;
        for pipeline in pipelines {
            db.store.save(&db.tenant, pipeline).await.unwrap();
        }
        saved_route_on(&db.db.databases, &db.tenant, *edge.id(), "checkout").await;
        saved_route_on(&db.db.databases, &db.tenant, *edge.id(), "account").await;
        saved_route_on(&db.db.databases, &db.tenant, *omitted.id(), "other").await;
        let foreign = ScopedTenant::for_background(TenantId::new());
        db.store.save(&foreign, edge).await.unwrap();
        saved_route_on(&db.db.databases, &foreign, *edge.id(), "foreign").await;
        foreign
    }

    /// Saving a second pipeline named `edge` in the same tenant returns a
    /// conflict.
    #[tokio::test]
    async fn a_name_another_pipeline_has_is_refused() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &pipeline(pipeline_row("edge", 0)))
            .await
            .unwrap();

        let saved = db
            .store
            .save(&db.tenant, &pipeline(pipeline_row("edge", 1)))
            .await;

        assert!(matches!(saved, Err(DomainError::Conflict(_))));
    }

    /// Deleting a pipeline used by a route returns a conflict and leaves
    /// its route count at one; a separate unused pipeline can be deleted.
    #[tokio::test]
    async fn a_pipeline_a_route_runs_is_kept() {
        let db = fixture().await;
        let edge = pipeline(pipeline_row("edge", 0));
        db.store.save(&db.tenant, &edge).await.unwrap();
        saved_route_on(&db.db.databases, &db.tenant, *edge.id(), "checkout").await;

        let refused = db.store.delete(&db.tenant, edge.id()).await;
        let unused = pipeline(pipeline_row("unused", 0));
        db.store.save(&db.tenant, &unused).await.unwrap();
        db.store.delete(&db.tenant, unused.id()).await.unwrap();

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
        assert_eq!(
            db.store.route_count(&db.tenant, edge.id()).await.unwrap(),
            1
        );
        assert!(
            db.store
                .find(&db.tenant, unused.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A stored pipeline missing its Identity stage fails to load as
    /// corrupt storage.
    #[tokio::test]
    async fn a_pipeline_without_its_identity_stage_is_refused() {
        let db = fixture().await;
        let edge = pipeline(pipeline_row("edge", 0));
        db.store.save(&db.tenant, &edge).await.unwrap();
        db.db
            .tamper(
                "UPDATE pipelines SET stages = jsonb_set(stages, '{value}', \
                 (SELECT jsonb_agg(s) FROM jsonb_array_elements(stages->'value') s \
                  WHERE s->>'kind' <> 'Identity'))",
            )
            .await;

        let read = db.store.find(&db.tenant, edge.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
