//! A tenant's HTTP routes, under row-level security.
//!
//! Every read of a route goes through one checked query by ids, or by
//! pipeline, and one mapping into the aggregate. A list first reads the ids
//! of its page, then reads those rows the same way. The gateway compiles a
//! tenant's routes from one page or one pipeline read, never one query per
//! route.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::routing::{RouteSortField, RouteStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::routing::route::Route;
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PipelineId, RouteId};
use sqlx::PgConnection;
use sqlx::postgres::PgQueryResult;
use uuid::Uuid;

use self::record::{RouteColumns, RouteRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a name to one route of a tenant.
const NAME_KEY: &str = "routes_name_key";

/// The Postgres route store.
pub struct PgRouteStore {
    databases: Arc<Databases>,
}

impl PgRouteStore {
    /// A store keeping routes in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgRouteStore {}

/// The routes `records` hold, rebuilt through the domain's checks.
fn rebuilt(records: Vec<RouteRecord>) -> Result<Vec<Route<ResolvedTenant>>, DomainError> {
    records.into_iter().map(RouteRecord::into_route).collect()
}

/// Writes the route's matching, policy and forwarding columns in one checked statement.
async fn write_columns(
    connection: &mut PgConnection,
    tenant: &ScopedTenant,
    columns: &RouteColumns<'_>,
) -> Result<PgQueryResult, sqlx::Error> {
    sqlx::query_file!(
        "queries/routes/save.sql",
        columns.id,
        tenant.as_uuid(),
        columns.name,
        columns.path_pattern,
        &columns.methods as &[String],
        columns.service_id,
        columns.policy,
        columns.hosts.as_deref(),
        columns.conditions,
        columns.pipeline_id,
        columns.path_rewrite,
        columns.status,
        columns.priority,
        columns.data_class,
        columns.action_class,
        columns.reach,
        columns.parameter_rules,
        columns.workflow_use,
        columns.attack_mode_until,
        columns.created_at,
        columns.updated_at,
    )
    .execute(connection)
    .await
}

/// The records of the routes of `tenant` that `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<RouteRecord>, sqlx::Error> {
    sqlx::query_file_as!(RouteRecord, "queries/routes/by_ids.sql", tenant, ids)
        .fetch_all(connection)
        .await
}

impl SortColumns for RouteSortField {
    fn column(self) -> &'static str {
        match self {
            Self::Priority => "priority",
            Self::CreatedAt => "created_at",
            Self::UpdatedAt => "updated_at",
            Self::Name => "name",
            Self::Status => "status",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

/// The ids of `tenant`'s routes in `status`, or of every one.
fn listed(tenant: Uuid, status: Option<RouteStatus>) -> PageQuery<'static> {
    let every = PageQuery::ids("id", "routes").filter("tenant_id = ?", tenant);
    let Some(status) = status else {
        return every;
    };
    every.filter("status = ?", status.word())
}

#[async_trait]
impl RouteStore for PgRouteStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &RouteId,
    ) -> Result<Option<Route<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id.as_uuid(), &ids).await,
        )
        .await?;
        records
            .into_iter()
            .next()
            .map(RouteRecord::into_route)
            .transpose()
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<RouteStatus>,
        sort: &SortOrder<RouteSortField>,
        page: &PageRequest,
    ) -> Result<Page<Route<ResolvedTenant>>, DomainError> {
        let keyset = page.keyset(sort)?;
        let tenant = *tenant_id.as_uuid();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed(tenant, status)
                    .fetch(&keyset, &mut *connection)
                    .await?;
                let records = records_of(connection, &tenant, &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(rebuilt(records)?))
    }

    async fn list_by_pipeline(
        &self,
        tenant_id: &ScopedTenant,
        pipeline_id: &PipelineId,
    ) -> Result<Vec<Route<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RouteRecord,
                    "queries/routes/on_pipeline.sql",
                    tenant_id.as_uuid(),
                    pipeline_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt(records)
    }

    async fn list_open_to_workflows(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<Route<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RouteRecord,
                    "queries/routes/open_to_workflows.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt(records)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        route: &Route<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = RouteColumns::of(route)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = write_columns(connection, tenant_id, &columns).await;
                unique_on(attempt, NAME_KEY)
            },
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-another-route-of-the-tenant-has",
                "another route of the tenant has the name"
            ))),
        }
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &RouteId) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/routes/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_app::ports::routing::ServiceStore;
    use ianua_domain::domains::routing::route::{RouteRow, WorkflowUse};
    use ianua_domain::domains::routing::service::Service;
    use ianua_domain::types::{Label, ServiceId, TenantId};

    use super::*;
    use crate::postgres::routing::PgServiceStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::routing::{route_row, service_row};

    struct Fixture {
        database: TestDb,
        store: PgRouteStore,
        tenant: ScopedTenant,
        service: ServiceId,
    }

    /// A fresh database holding one service of one tenant, and the store
    /// on it.
    async fn fixture() -> Fixture {
        let database = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let service = a_service(&database, &tenant).await;
        let store = PgRouteStore::new(Arc::clone(&database.databases));
        Fixture {
            database,
            store,
            tenant,
            service,
        }
    }

    /// Saves a service of `tenant` through its store.
    async fn a_service(database: &TestDb, tenant: &ScopedTenant) -> ServiceId {
        let service: Service<ResolvedTenant> =
            Service::reconstitute(service_row("projects-api")).unwrap();
        PgServiceStore::new(Arc::clone(&database.databases))
            .save(tenant, &service)
            .await
            .unwrap();
        *service.id()
    }

    fn route(row: RouteRow) -> Route<ResolvedTenant> {
        Route::reconstitute(row).unwrap()
    }

    fn named(service: ServiceId, name: &str) -> Route<ResolvedTenant> {
        route(route_row(service, name))
    }

    fn at_priority(service: ServiceId, name: &str, priority: u16) -> Route<ResolvedTenant> {
        route(RouteRow {
            priority,
            ..route_row(service, name)
        })
    }

    async fn save_all(db: &Fixture, routes: &[&Route<ResolvedTenant>]) {
        for route in routes {
            db.store.save(&db.tenant, route).await.unwrap();
        }
    }

    fn by(field: RouteSortField) -> SortOrder<RouteSortField> {
        SortOrder::single(Sort::ascending(field))
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn names(routes: &[Route<ResolvedTenant>]) -> Vec<&str> {
        routes.iter().map(|route| route.name().as_str()).collect()
    }

    /// A saved route is found by its id, with every setting it was saved
    /// with.
    #[tokio::test]
    async fn a_saved_route_is_found_by_its_id() {
        let db = fixture().await;
        let projects = named(db.service, "projects");

        db.store.save(&db.tenant, &projects).await.unwrap();

        let found = db
            .store
            .find_by_id(&db.tenant, projects.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.name(), projects.name());
        assert_eq!(found.path_pattern(), projects.path_pattern());
        assert_eq!(found.methods(), projects.methods());
        assert_eq!(found.policy(), projects.policy());
        assert_eq!(found.hosts(), projects.hosts());
        assert_eq!(found.conditions(), projects.conditions());
        assert_eq!(found.path_rewrite(), projects.path_rewrite());
        assert_eq!(found.parameter_rules(), projects.parameter_rules());
        assert_eq!(
            found.declared_action_class(),
            projects.declared_action_class()
        );
        assert_eq!(found.created_at(), projects.created_at());
    }

    /// An id nobody has finds nothing, rather than failing.
    #[tokio::test]
    async fn an_unknown_route_is_not_found() {
        let db = fixture().await;

        let found = db.store.find_by_id(&db.tenant, &RouteId::new()).await;

        assert!(found.unwrap().is_none());
    }

    /// Another tenant cannot find Acme's route by ID and has an empty route
    /// list.
    #[tokio::test]
    async fn a_route_is_invisible_to_another_tenant() {
        let db = fixture().await;
        let projects = named(db.service, "projects");
        db.store.save(&db.tenant, &projects).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let found = db.store.find_by_id(&other, projects.id()).await.unwrap();
        let listed = db
            .store
            .list_all(&other, None, &SortOrder::default(), &first(10))
            .await
            .unwrap();

        assert!(found.is_none());
        assert!(listed.items.is_empty());
    }

    /// Saving a second route named `projects` in the same tenant returns a
    /// conflict.
    #[tokio::test]
    async fn a_name_another_route_has_is_refused() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &named(db.service, "projects"))
            .await
            .unwrap();

        let second = db
            .store
            .save(&db.tenant, &named(db.service, "projects"))
            .await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// Saving a route naming an unknown service returns an infrastructure
    /// error.
    #[tokio::test]
    async fn a_route_to_an_unknown_service_is_refused() {
        let db = fixture().await;

        let saved = db
            .store
            .save(&db.tenant, &named(ServiceId::new(), "projects"))
            .await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
    }

    /// The tenant's routes list in priority order, page by page, and the
    /// last page says nothing follows.
    #[tokio::test]
    async fn routes_are_listed_page_by_page_in_priority_order() {
        let db = fixture().await;
        save_all(
            &db,
            &[
                &at_priority(db.service, "third", 30),
                &at_priority(db.service, "first", 10),
                &at_priority(db.service, "second", 20),
            ],
        )
        .await;
        let order = by(RouteSortField::Priority);

        let page_one = db
            .store
            .list_all(&db.tenant, None, &order, &first(2))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = db
            .store
            .list_all(&db.tenant, None, &order, &after)
            .await
            .unwrap();

        assert_eq!(names(&page_one.items), ["first", "second"]);
        assert_eq!(names(&page_two.items), ["third"]);
        assert!(!page_two.has_next());
    }

    /// A list narrowed to disabled routes shows only those.
    #[tokio::test]
    async fn a_list_narrowed_to_a_status_shows_only_that_status() {
        let db = fixture().await;
        let off = route(RouteRow {
            status: RouteStatus::Disabled,
            ..route_row(db.service, "off")
        });
        save_all(&db, &[&named(db.service, "on"), &off]).await;

        let page = db
            .store
            .list_all(
                &db.tenant,
                Some(RouteStatus::Disabled),
                &by(RouteSortField::Name),
                &first(10),
            )
            .await
            .unwrap();

        assert_eq!(names(&page.items), ["off"]);
    }

    /// Paging by status returns the active route first and the disabled
    /// route second, without repeats or omissions.
    #[tokio::test]
    async fn a_list_sorted_by_status_pages_by_the_stored_word() {
        let db = fixture().await;
        let off = route(RouteRow {
            status: RouteStatus::Disabled,
            ..route_row(db.service, "off")
        });
        save_all(&db, &[&off, &named(db.service, "on")]).await;
        let order = by(RouteSortField::Status);

        let page_one = db
            .store
            .list_all(&db.tenant, None, &order, &first(1))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(1).unwrap());
        let rest = db
            .store
            .list_all(&db.tenant, None, &order, &after)
            .await
            .unwrap();

        assert_eq!(names(&page_one.items), ["on"]);
        assert_eq!(names(&rest.items), ["off"]);
    }

    /// Every route on one pipeline is read at once, in priority order, and
    /// a route on another pipeline is left out.
    #[tokio::test]
    async fn the_routes_on_a_pipeline_are_read_in_priority_order() {
        let db = fixture().await;
        let pipeline = PipelineId::new();
        let on = |name: &str, priority| {
            route(RouteRow {
                pipeline_id: pipeline,
                priority,
                ..route_row(db.service, name)
            })
        };
        save_all(
            &db,
            &[
                &on("late", 50),
                &on("early", 5),
                &named(db.service, "elsewhere"),
            ],
        )
        .await;

        let found = db
            .store
            .list_by_pipeline(&db.tenant, &pipeline)
            .await
            .unwrap();

        assert_eq!(names(&found), ["early", "late"]);
    }

    /// Saving again keeps the new values: a renamed, disabled route reads
    /// back renamed and disabled.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let db = fixture().await;
        let projects = named(db.service, "projects");
        db.store.save(&db.tenant, &projects).await.unwrap();
        let changed = route(RouteRow {
            id: *projects.id(),
            name: Label::new("name", "renamed").unwrap(),
            status: RouteStatus::Disabled,
            updated_at: at(5),
            ..route_row(db.service, "projects")
        });

        db.store.save(&db.tenant, &changed).await.unwrap();

        let found = db
            .store
            .find_by_id(&db.tenant, projects.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.name().as_str(), "renamed");
        assert_eq!(found.status(), RouteStatus::Disabled);
        assert_eq!(found.updated_at(), at(5));
    }

    /// A deleted route is gone, and deleting it again does nothing.
    #[tokio::test]
    async fn a_deleted_route_is_gone() {
        let db = fixture().await;
        let projects = named(db.service, "projects");
        db.store.save(&db.tenant, &projects).await.unwrap();

        db.store.delete(&db.tenant, projects.id()).await.unwrap();
        db.store.delete(&db.tenant, projects.id()).await.unwrap();

        let found = db.store.find_by_id(&db.tenant, projects.id()).await;
        assert!(found.unwrap().is_none());
    }

    /// A route with a percent-encoded stored path pattern fails to load as
    /// corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_route_is_refused() {
        let db = fixture().await;
        let projects = named(db.service, "projects");
        db.store.save(&db.tenant, &projects).await.unwrap();
        db.database
            .tamper("UPDATE routes SET path_pattern = '/caf%C3%A9'")
            .await;

        let read = db.store.find_by_id(&db.tenant, projects.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Acme opened its orders app to workflows, left reports closed, and
    /// disabled the open billing app. Only orders is listed, and it reads
    /// back open.
    #[tokio::test]
    async fn only_active_routes_open_to_workflows_are_listed_for_them() {
        let db = fixture().await;
        let orders = route(RouteRow {
            workflow_use: WorkflowUse::Open,
            ..route_row(db.service, "orders")
        });
        let billing = route(RouteRow {
            workflow_use: WorkflowUse::Open,
            status: RouteStatus::Disabled,
            ..route_row(db.service, "billing")
        });
        save_all(&db, &[&orders, &named(db.service, "reports"), &billing]).await;

        let open = db.store.list_open_to_workflows(&db.tenant).await.unwrap();

        assert_eq!(names(&open), ["orders"]);
        assert_eq!(open[0].workflow_use(), WorkflowUse::Open);
    }

    /// A route with an unknown stored workflow-use value fails to load as
    /// corrupt storage.
    #[tokio::test]
    async fn an_unknown_workflow_use_is_refused() {
        let db = fixture().await;
        let projects = named(db.service, "projects");
        db.store.save(&db.tenant, &projects).await.unwrap();
        db.database
            .tamper(
                "ALTER TABLE routes DROP CONSTRAINT routes_workflow_use_known; \
                 UPDATE routes SET workflow_use = 'always'",
            )
            .await;

        let read = db.store.find_by_id(&db.tenant, projects.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
