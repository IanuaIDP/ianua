//! Stream routes, and the directory the gateway binds their ports from:
//! the two stores of `ports/routing/stream_routes.rs`, sharing one mapping.
//!
//! A tenant's stream routes are tenant rows, under row-level security, in
//! the database the tenant lives in. The port a route listens on belongs to
//! the whole deployment, so it is claimed apart from the route, in
//! `stream_route_ports`, always in the platform database: its primary key
//! keeps a port to one route across every tenant, whichever database the
//! routes live in. A unique index on the routes themselves could not, since
//! a tenant with a database of its own keeps its routes there.
//!
//! The claim and the route are written by two store calls, which a unit of
//! work keeps or drops together; the port is claimed first, so a taken port
//! is refused before anything of the route is written.
//!
//! The directory reads every tenant's active routes: those of the tenants
//! in the platform database in one query, as platform work, and those of
//! each tenant with a database of its own from that database, all at once.
//! No one query reaches across databases, so one per database is the least
//! there can be.

mod logins;
mod record;

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::routing::{StreamRouteDirectory, StreamRouteSortField, StreamRouteStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::routing::stream::StreamRoute;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{StreamRouteId, TenantId};
use sqlx::PgConnection;
use sqlx::postgres::PgQueryResult;
use uuid::Uuid;

pub use self::logins::PgStreamRouteLogins;
use self::record::{StreamRouteColumns, StreamRouteRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a listening port to one stream route.
const PORT_KEY: &str = "stream_route_ports_pkey";

/// The constraint that keeps a name to one stream route of a tenant.
const NAME_KEY: &str = "stream_routes_name_key";

/// The Postgres stream route store.
pub struct PgStreamRouteStore {
    databases: Arc<Databases>,
}

impl PgStreamRouteStore {
    /// A store keeping stream routes, and the ports they claim, in
    /// `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Claims the port `route` listens on for it, in the platform database.
    async fn claim_port(
        &self,
        tenant: &ScopedTenant,
        route: &StreamRoute<ResolvedTenant>,
    ) -> Result<Uniqueness, DomainError> {
        let port = i32::from(route.listen_port().get());
        scoped(&self.databases, RowScope::Platform, async |connection| {
            let attempt = sqlx::query_file!(
                "queries/stream_route_ports/claim.sql",
                port,
                tenant.as_uuid(),
                route.id().as_uuid()
            )
            .execute(connection)
            .await;
            unique_on(attempt, PORT_KEY)
        })
        .await
    }

    /// Writes `route` itself, in the tenant's database.
    async fn write(
        &self,
        tenant: &ScopedTenant,
        route: &StreamRoute<ResolvedTenant>,
    ) -> Result<Uniqueness, DomainError> {
        let columns = StreamRouteColumns::of(route)?;
        scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                let attempt = write_columns(connection, tenant, &columns).await;
                unique_on(attempt, NAME_KEY)
            },
        )
        .await
    }
}

impl TenantScoped for PgStreamRouteStore {}

/// Writes the stream route's listener, policy and backend settings together.
async fn write_columns(
    connection: &mut PgConnection,
    tenant: &ScopedTenant,
    columns: &StreamRouteColumns<'_>,
) -> Result<PgQueryResult, sqlx::Error> {
    sqlx::query_file!(
        "queries/stream_routes/save.sql",
        columns.id,
        tenant.as_uuid(),
        columns.name,
        columns.protocol,
        columns.listen_port,
        columns.sni.as_deref(),
        columns.policy,
        columns.access,
        columns.backends,
        columns.connect_timeout_secs,
        columns.idle_timeout_secs,
        columns.status,
        columns.workflow_use,
        columns.created_at,
        columns.updated_at,
    )
    .execute(connection)
    .await
}

/// The records of the stream routes of `tenant` that `ids` names, in no
/// order.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<StreamRouteRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        StreamRouteRecord,
        "queries/stream_routes/by_ids.sql",
        tenant,
        ids
    )
    .fetch_all(connection)
    .await
}

impl SortColumns for StreamRouteSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::UpdatedAt => "updated_at",
            Self::Name => "name",
            Self::ListenPort => "listen_port",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl StreamRouteStore for PgStreamRouteStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &StreamRouteId,
    ) -> Result<Option<StreamRoute<ResolvedTenant>>, DomainError> {
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
            .map(StreamRouteRecord::into_stream_route)
            .transpose()
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<StreamRouteSortField>,
        page: &PageRequest,
    ) -> Result<Page<StreamRoute<ResolvedTenant>>, DomainError> {
        let keyset = page.keyset(sort)?;
        let tenant = *tenant_id.as_uuid();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = PageQuery::ids("id", "stream_routes")
                    .filter("tenant_id = ?", tenant)
                    .fetch(&keyset, &mut *connection)
                    .await?;
                let records = records_of(connection, &tenant, &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        let routes = records
            .into_iter()
            .map(StreamRouteRecord::into_stream_route)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(keyset.seal(routes))
    }

    async fn list_open_to_workflows(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<StreamRoute<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    StreamRouteRecord,
                    "queries/stream_routes/open_to_workflows.sql",
                    tenant_id.as_uuid(),
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(StreamRouteRecord::into_stream_route)
            .collect()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        route: &StreamRoute<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        if self.claim_port(tenant_id, route).await? == Uniqueness::Taken {
            return Err(DomainError::conflict(message!(
                "infra-port-is-already-claimed",
                format!("port {} is already claimed", route.listen_port().get())
            )));
        }
        match self.write(tenant_id, route).await? {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-another-stream-route-of-the-tenant",
                "another stream route of the tenant has the name"
            ))),
        }
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &StreamRouteId,
    ) -> Result<(), DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/stream_route_ports/release.sql",
                tenant_id.as_uuid(),
                id.as_uuid()
            )
            .execute(connection)
            .await?;
            Ok(())
        })
        .await?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/stream_routes/delete.sql",
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

/// The Postgres directory of every tenant's active stream routes.
pub struct PgStreamRouteDirectory {
    databases: Arc<Databases>,
}

impl PgStreamRouteDirectory {
    /// A directory reading stream routes from `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl PgStreamRouteDirectory {
    /// The active stream routes of every tenant in the platform database.
    async fn shared(&self) -> Result<Vec<StreamRouteRecord>, DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(StreamRouteRecord, "queries/stream_routes/active.sql")
                .fetch_all(connection)
                .await
        })
        .await
    }

    /// The active stream routes of `tenant`, read from its own database.
    async fn own(&self, tenant: TenantId) -> Result<Vec<StreamRouteRecord>, DomainError> {
        scoped(
            &self.databases,
            RowScope::Tenant(tenant),
            async |connection| {
                sqlx::query_file_as!(
                    StreamRouteRecord,
                    "queries/stream_routes/active_of_tenant.sql",
                    tenant.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await
    }
}

#[async_trait]
impl StreamRouteDirectory for PgStreamRouteDirectory {
    async fn active_routes(
        &self,
    ) -> Result<Vec<(TenantId, StreamRoute<ResolvedTenant>)>, DomainError> {
        let own_databases = self.databases.with_own_database();
        let (shared, own) = futures_util::try_join!(
            self.shared(),
            try_join_all(own_databases.into_iter().map(|tenant| self.own(tenant)))
        )?;
        shared
            .into_iter()
            .chain(own.into_iter().flatten())
            .map(StreamRouteRecord::into_listed)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_app::ports::organization::OrganizationStore;
    use ianua_app::ports::tenant::TenantStore;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::routing::route_status::RouteStatus;
    use ianua_domain::domains::routing::stream::{ListenPort, StreamRouteRow, StreamWorkflowUse};
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::Label;

    use super::*;
    use crate::postgres::organization::PgOrganizationStore;
    use crate::postgres::tenant::PgTenantStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::organization::organization_row;
    use crate::test_support::rows::routing::stream_route_row;
    use crate::test_support::rows::tenant::tenant_row;

    struct Fixture {
        database: TestDb,
        store: PgStreamRouteStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, one tenant, and the store on it.
    async fn fixture() -> Fixture {
        let database = TestDb::fresh().await;
        let store = PgStreamRouteStore::new(Arc::clone(&database.databases));
        let tenant = a_tenant(&database).await;
        Fixture {
            database,
            store,
            tenant,
        }
    }

    /// A tenant saved with an organization of its own, as a port claim
    /// names a tenant the platform keeps.
    async fn a_tenant(database: &TestDb) -> ScopedTenant {
        let key = TenantId::new().as_uuid().simple().to_string();
        let organization =
            Organization::reconstitute(organization_row(&format!("o{key}"), "Acme")).unwrap();
        PgOrganizationStore::new(Arc::clone(&database.databases), DomainLimits::default())
            .save(&organization)
            .await
            .unwrap();
        let tenant =
            Tenant::reconstitute(tenant_row(*organization.id(), &format!("t{key}"))).unwrap();
        PgTenantStore::new(Arc::clone(&database.databases), DomainLimits::default())
            .save(&tenant)
            .await
            .unwrap();
        ScopedTenant::for_background(*tenant.id())
    }

    fn stream_route(row: StreamRouteRow) -> StreamRoute<ResolvedTenant> {
        StreamRoute::reconstitute(row).unwrap()
    }

    fn on(name: &str, port: u16) -> StreamRoute<ResolvedTenant> {
        stream_route(stream_route_row(name, port))
    }

    fn names(routes: &[StreamRoute<ResolvedTenant>]) -> Vec<&str> {
        routes.iter().map(|route| route.name().as_str()).collect()
    }

    /// A saved stream route is found by its id, with every setting it was
    /// saved with.
    #[tokio::test]
    async fn a_saved_stream_route_is_found_by_its_id() {
        let db = fixture().await;
        let postgres = on("postgres", 15432);

        db.store.save(&db.tenant, &postgres).await.unwrap();

        let found = db
            .store
            .find_by_id(&db.tenant, postgres.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.name(), postgres.name());
        assert_eq!(found.listen_port(), postgres.listen_port());
        assert_eq!(found.sni(), postgres.sni());
        assert_eq!(found.access(), postgres.access());
        assert_eq!(found.backends(), postgres.backends());
        assert_eq!(found.timeouts(), postgres.timeouts());
    }

    /// An id nobody has finds nothing, and another tenant does not find
    /// this tenant's route.
    #[tokio::test]
    async fn a_stream_route_is_found_only_by_its_tenant() {
        let db = fixture().await;
        let postgres = on("postgres", 15432);
        db.store.save(&db.tenant, &postgres).await.unwrap();
        let other = a_tenant(&db.database).await;

        let unknown = db
            .store
            .find_by_id(&db.tenant, &StreamRouteId::new())
            .await
            .unwrap();
        let theirs = db.store.find_by_id(&other, postgres.id()).await.unwrap();

        assert!(unknown.is_none());
        assert!(theirs.is_none());
    }

    /// Saving a stream route on another tenant's claimed port returns a
    /// conflict.
    #[tokio::test]
    async fn a_port_another_tenant_claims_is_refused() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &on("postgres", 15432))
            .await
            .unwrap();
        let other = a_tenant(&db.database).await;

        let second = db.store.save(&other, &on("theirs", 15432)).await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// Saving a second stream route with the same tenant and name returns
    /// a conflict even when its port differs.
    #[tokio::test]
    async fn a_name_another_stream_route_has_is_refused() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &on("postgres", 15432))
            .await
            .unwrap();

        let second = db.store.save(&db.tenant, &on("postgres", 15433)).await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// A route moved to another port frees its old one, and saving it again
    /// on its own port is no clash with itself.
    #[tokio::test]
    async fn a_moved_route_frees_its_old_port() {
        let db = fixture().await;
        let postgres = on("postgres", 15432);
        db.store.save(&db.tenant, &postgres).await.unwrap();
        db.store.save(&db.tenant, &postgres).await.unwrap();
        let moved = stream_route(StreamRouteRow {
            id: *postgres.id(),
            listen_port: ListenPort::new(15500).unwrap(),
            updated_at: at(5),
            ..stream_route_row("postgres", 15432)
        });

        db.store.save(&db.tenant, &moved).await.unwrap();
        let next = db.store.save(&db.tenant, &on("next", 15432)).await;

        assert!(next.is_ok());
    }

    /// A deleted stream route is gone, and its port is free again.
    #[tokio::test]
    async fn a_deleted_stream_route_releases_its_port() {
        let db = fixture().await;
        let postgres = on("postgres", 15432);
        db.store.save(&db.tenant, &postgres).await.unwrap();

        db.store.delete(&db.tenant, postgres.id()).await.unwrap();

        let found = db.store.find_by_id(&db.tenant, postgres.id()).await;
        let other = a_tenant(&db.database).await;
        assert!(found.unwrap().is_none());
        assert!(db.store.save(&other, &on("theirs", 15432)).await.is_ok());
    }

    /// The tenant's stream routes list by port, page by page.
    #[tokio::test]
    async fn stream_routes_are_listed_page_by_page_by_port() {
        let db = fixture().await;
        for (name, port) in [("c", 3000), ("a", 1100), ("b", 2000)] {
            db.store.save(&db.tenant, &on(name, port)).await.unwrap();
        }
        let order = SortOrder::single(Sort::ascending(StreamRouteSortField::ListenPort));

        let page_one = db
            .store
            .list_all(
                &db.tenant,
                &order,
                &PageRequest::first(Limit::new(2).unwrap()),
            )
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = db.store.list_all(&db.tenant, &order, &after).await.unwrap();

        assert_eq!(names(&page_one.items), ["a", "b"]);
        assert_eq!(names(&page_two.items), ["c"]);
        assert!(!page_two.has_next());
    }

    /// The directory holds every tenant's active stream routes, each with
    /// its tenant, and leaves a disabled one out.
    #[tokio::test]
    async fn the_directory_holds_every_tenants_active_routes() {
        let db = fixture().await;
        let other = a_tenant(&db.database).await;
        let off = stream_route(StreamRouteRow {
            status: RouteStatus::Disabled,
            ..stream_route_row("off", 15434)
        });
        db.store
            .save(&db.tenant, &on("postgres", 15432))
            .await
            .unwrap();
        db.store.save(&db.tenant, &off).await.unwrap();
        db.store.save(&other, &on("theirs", 15433)).await.unwrap();
        let directory = PgStreamRouteDirectory::new(Arc::clone(&db.database.databases));

        let mut active: Vec<(TenantId, String)> = directory
            .active_routes()
            .await
            .unwrap()
            .into_iter()
            .map(|(tenant, route)| (tenant, route.name().as_str().to_owned()))
            .collect();
        active.sort_by(|a, b| a.1.cmp(&b.1));

        assert_eq!(
            active,
            [
                (*db.tenant, "postgres".to_owned()),
                (*other, "theirs".to_owned())
            ]
        );
    }

    /// The directory includes routes from both shared and dedicated tenant
    /// databases; another route cannot claim the dedicated tenant's port.
    #[tokio::test]
    async fn the_directory_holds_the_routes_of_a_tenant_with_its_own_database() {
        let db = fixture().await;
        let own = TestDb::fresh().await;
        let apart = a_tenant(&db.database).await;
        db.database.databases.register(*apart, own.as_dedicated());
        db.store
            .save(&db.tenant, &on("postgres", 15432))
            .await
            .unwrap();
        db.store.save(&apart, &on("apart", 15433)).await.unwrap();
        let directory = PgStreamRouteDirectory::new(Arc::clone(&db.database.databases));

        let mut active: Vec<(TenantId, String)> = directory
            .active_routes()
            .await
            .unwrap()
            .into_iter()
            .map(|(tenant, route)| (tenant, route.name().as_str().to_owned()))
            .collect();
        active.sort_by(|a, b| a.1.cmp(&b.1));
        let clash = db.store.save(&db.tenant, &on("clash", 15433)).await;

        assert_eq!(
            active,
            [
                (*apart, "apart".to_owned()),
                (*db.tenant, "postgres".to_owned())
            ]
        );
        assert!(matches!(clash, Err(DomainError::Conflict(_))));
    }

    /// Saving again keeps the new values: a renamed route reads back
    /// renamed.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let db = fixture().await;
        let postgres = on("postgres", 15432);
        db.store.save(&db.tenant, &postgres).await.unwrap();
        let renamed = stream_route(StreamRouteRow {
            id: *postgres.id(),
            name: Label::new("name", "database").unwrap(),
            updated_at: at(5),
            ..stream_route_row("postgres", 15432)
        });

        db.store.save(&db.tenant, &renamed).await.unwrap();

        let found = db
            .store
            .find_by_id(&db.tenant, postgres.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.name().as_str(), "database");
    }

    /// A stored stream route without a backend fails to load as corrupt
    /// storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_stream_route_is_refused() {
        let db = fixture().await;
        let postgres = on("postgres", 15432);
        db.store.save(&db.tenant, &postgres).await.unwrap();
        db.database
            .tamper("UPDATE stream_routes SET backends = '{\"v\": 1, \"value\": []}'")
            .await;

        let read = db.store.find_by_id(&db.tenant, postgres.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Acme opened its orders database to workflows and left billing
    /// closed. Only orders is listed for Protected data steps, and it reads
    /// back open.
    #[tokio::test]
    async fn only_the_stream_routes_open_to_workflows_are_listed_for_them() {
        let db = fixture().await;
        let orders = stream_route(StreamRouteRow {
            workflow_use: StreamWorkflowUse::Open,
            ..stream_route_row("orders-db", 15432)
        });
        db.store.save(&db.tenant, &orders).await.unwrap();
        db.store
            .save(&db.tenant, &on("billing-db", 15433))
            .await
            .unwrap();

        let open = db.store.list_open_to_workflows(&db.tenant).await.unwrap();
        let read = db.store.find_by_id(&db.tenant, orders.id()).await.unwrap();

        assert_eq!(names(&open), ["orders-db"]);
        assert_eq!(read.unwrap().workflow_use(), StreamWorkflowUse::Open);
    }
}
