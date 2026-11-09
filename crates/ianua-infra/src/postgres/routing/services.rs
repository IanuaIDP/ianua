//! A tenant's services, the backends its routes forward to, under row-level
//! security.
//!
//! Every read goes through one checked query by ids and one mapping into
//! the aggregate; the gateway reads every service a route table names in
//! that one query. A save writes the service and the hosts its sign-in
//! holds in one statement, so a host another service holds refuses the
//! whole write and nothing is half kept. A delete is refused by the
//! foreign keys of the routes forwarding to the service and of the
//! services accepting its sign-in, never taking them with it.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::routing::{ServiceSortField, ServiceStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::ServiceId;
use sqlx::PgConnection;
use sqlx::postgres::PgQueryResult;
use uuid::Uuid;

use self::record::{ServiceColumns, ServiceRecord};
use crate::postgres::foundation::errors::{Reference, Uniqueness, referenced_on, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a name to one service of a tenant.
const NAME_KEY: &str = "services_name_key";

/// The constraint that keeps a sign-in host to one service of a tenant.
const SIGN_IN_HOST_KEY: &str = "service_sign_in_hosts_pkey";

/// The foreign key of a route forwarding to a service.
const ROUTE_REFERENCE: &str = "routes_service_fkey";

/// The foreign key of a service accepting another's sign-in.
const ACCEPTANCE_REFERENCE: &str = "services_accepted_sign_in_fkey";

/// The Postgres service store.
pub struct PgServiceStore {
    databases: Arc<Databases>,
}

impl PgServiceStore {
    /// A store keeping services in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The services of `tenant` that `ids` names, in no order.
    async fn read(
        &self,
        tenant: &ScopedTenant,
        ids: &[Uuid],
    ) -> Result<Vec<Service<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| records_of(connection, tenant.as_uuid(), ids).await,
        )
        .await?;
        rebuilt(records)
    }
}

impl TenantScoped for PgServiceStore {}

/// What a save came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Saved {
    /// The service and its sign-in hosts were written.
    Kept,
    /// Another service of the tenant has the name.
    NameTaken,
    /// Another service of the tenant holds one of the sign-in hosts.
    HostTaken,
}

/// Reports whether the name or sign-in hostname prevented the service save.
fn ensure_saved(written: Saved) -> Result<(), DomainError> {
    match written {
        Saved::Kept => Ok(()),
        Saved::NameTaken => Err(DomainError::conflict(message!(
            "infra-another-service-of-the-tenant-has",
            "another service of the tenant has the name"
        ))),
        Saved::HostTaken => Err(DomainError::conflict(message!(
            "infra-another-service-of-the-tenant-answers",
            "another service of the tenant answers sign-in or sets its cookie on one of the hosts"
        ))),
    }
}

/// What `attempt` to save a service came to, read by the constraint it
/// broke, if any.
fn saved(attempt: Result<PgQueryResult, sqlx::Error>) -> Result<Saved, sqlx::Error> {
    match unique_on(attempt, NAME_KEY) {
        Ok(Uniqueness::Kept) => Ok(Saved::Kept),
        Ok(Uniqueness::Taken) => Ok(Saved::NameTaken),
        Err(error) => unique_on(Err::<(), _>(error), SIGN_IN_HOST_KEY).map(|host| match host {
            Uniqueness::Kept => Saved::Kept,
            Uniqueness::Taken => Saved::HostTaken,
        }),
    }
}

/// What `attempt` to delete a service came to: done, or refused because a
/// route or another service still points at it.
fn deleted(attempt: Result<PgQueryResult, sqlx::Error>) -> Result<Reference, sqlx::Error> {
    match referenced_on(attempt, ROUTE_REFERENCE) {
        Ok(reference) => Ok(reference),
        Err(error) => referenced_on(Err::<(), _>(error), ACCEPTANCE_REFERENCE),
    }
}

/// The services `records` hold, rebuilt through the domain's checks.
fn rebuilt(records: Vec<ServiceRecord>) -> Result<Vec<Service<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(ServiceRecord::into_service)
        .collect()
}

/// The records of the services of `tenant` that `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<ServiceRecord>, sqlx::Error> {
    sqlx::query_file_as!(ServiceRecord, "queries/services/by_ids.sql", tenant, ids)
        .fetch_all(connection)
        .await
}

impl SortColumns for ServiceSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::UpdatedAt => "updated_at",
            Self::Name => "name",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl ServiceStore for PgServiceStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ServiceId,
    ) -> Result<Option<Service<ResolvedTenant>>, DomainError> {
        let found = self.read(tenant_id, &[*id.as_uuid()]).await?;
        Ok(found.into_iter().next())
    }

    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[ServiceId],
    ) -> Result<Vec<Service<ResolvedTenant>>, DomainError> {
        let ids: Vec<Uuid> = ids.iter().map(|id| *id.as_uuid()).collect();
        self.read(tenant_id, &ids).await
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<ServiceSortField>,
        page: &PageRequest,
    ) -> Result<Page<Service<ResolvedTenant>>, DomainError> {
        let keyset = page.keyset(sort)?;
        let tenant = *tenant_id.as_uuid();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = PageQuery::ids("id", "services")
                    .filter("tenant_id = ?", tenant)
                    .fetch(&keyset, &mut *connection)
                    .await?;
                let records = records_of(connection, &tenant, &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(rebuilt(records)?))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        service: &Service<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = ServiceColumns::of(service)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/services/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.name,
                    columns.upstream,
                    columns.health_check,
                    columns.app_sign_in,
                    columns.accepts_sign_in_of,
                    columns.sign_in_delivery,
                    columns.status,
                    columns.created_at,
                    columns.updated_at,
                    &columns.sign_in_hosts as &[String],
                )
                .execute(connection)
                .await;
                saved(attempt)
            },
        )
        .await?;
        ensure_saved(written)
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &ServiceId) -> Result<(), DomainError> {
        let removed = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/services/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await;
                deleted(attempt)
            },
        )
        .await?;
        match removed {
            Reference::Free => Ok(()),
            Reference::Held => Err(DomainError::conflict(message!(
                "infra-a-route-still-forwards-to-the",
                "a route still forwards to the service, or another service accepts its sign-in"
            ))),
        }
    }

    async fn route_count(
        &self,
        tenant_id: &ScopedTenant,
        id: &ServiceId,
    ) -> Result<u64, DomainError> {
        let count = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/routes/to_service.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_one(connection)
                .await
            },
        )
        .await?;
        u64::try_from(count).map_err(DomainError::infra)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ianua_app::listing::{Limit, Sort};
    use ianua_app::ports::routing::RouteStore;
    use ianua_domain::domains::routing::route::Route;
    use ianua_domain::domains::routing::route_status::RouteStatus;
    use ianua_domain::domains::routing::service::ServiceRow;
    use ianua_domain::domains::routing::sign_in::accepted::{
        AcceptedSignIn, CookieHosts, SignInDelivery,
    };
    use ianua_domain::domains::routing::sign_in::app::{
        AppSignIn, AppSignInParams, SignedOutBrowsers,
    };
    use ianua_domain::types::{DomainName, Setting, TenantId};

    use super::*;
    use crate::postgres::routing::PgRouteStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::routing::{route_row, service_row};

    struct Fixture {
        database: TestDb,
        store: PgServiceStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, one tenant, and the store on it.
    async fn fixture() -> Fixture {
        let database = TestDb::fresh().await;
        let store = PgServiceStore::new(Arc::clone(&database.databases));
        Fixture {
            database,
            store,
            tenant: ScopedTenant::for_background(TenantId::new()),
        }
    }

    fn service(row: ServiceRow) -> Service<ResolvedTenant> {
        Service::reconstitute(row).unwrap()
    }

    fn named(name: &str) -> Service<ResolvedTenant> {
        service(service_row(name))
    }

    fn host(name: &str) -> DomainName {
        DomainName::new(name).unwrap()
    }

    /// A service signing people in on `hosts`.
    fn signing_in_on(name: &str, hosts: &[&str]) -> Service<ResolvedTenant> {
        let sign_in = AppSignIn::new(AppSignInParams {
            hosts: hosts.iter().map(|name| host(name)).collect(),
            prefix: Setting::Unset,
            moved: BTreeMap::new(),
            after_sign_in: Setting::Unset,
            signed_out_browsers: SignedOutBrowsers::Refuse,
        })
        .unwrap();
        service(ServiceRow {
            app_sign_in: Setting::Set(sign_in),
            ..service_row(name)
        })
    }

    /// A service accepting `owner`'s sign-in by a cookie of its own on
    /// `hosts`.
    fn accepting(name: &str, owner: &ServiceId, hosts: &[&str]) -> Service<ResolvedTenant> {
        let cookie = CookieHosts::new(hosts.iter().map(|name| host(name)).collect()).unwrap();
        service(ServiceRow {
            accepted_sign_in: Setting::Set(AcceptedSignIn::new(
                *owner,
                SignInDelivery::OwnCookie(cookie),
            )),
            ..service_row(name)
        })
    }

    fn names(services: &[Service<ResolvedTenant>]) -> Vec<&str> {
        services
            .iter()
            .map(|service| service.name().as_str())
            .collect()
    }

    /// A saved service is found by its id, with every setting it was saved
    /// with.
    #[tokio::test]
    async fn a_saved_service_is_found_by_its_id() {
        let db = fixture().await;
        let shop = signing_in_on("shop", &["shop.example.com"]);

        db.store.save(&db.tenant, &shop).await.unwrap();

        let found = db
            .store
            .find_by_id(&db.tenant, shop.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.name(), shop.name());
        assert_eq!(found.upstream(), shop.upstream());
        assert_eq!(found.health_check(), shop.health_check());
        assert_eq!(found.app_sign_in(), shop.app_sign_in());
        assert_eq!(found.created_at(), shop.created_at());
    }

    /// An id nobody has finds nothing, rather than failing.
    #[tokio::test]
    async fn an_unknown_service_is_not_found() {
        let db = fixture().await;

        let found = db.store.find_by_id(&db.tenant, &ServiceId::new()).await;

        assert!(found.unwrap().is_none());
    }

    /// The services a route table names are read in one go, and an id of
    /// another tenant's service is not among them.
    #[tokio::test]
    async fn several_services_are_found_at_once_within_the_tenant() {
        let db = fixture().await;
        let (api, web) = (named("api"), named("web"));
        db.store.save(&db.tenant, &api).await.unwrap();
        db.store.save(&db.tenant, &web).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());
        let theirs = named("theirs");
        db.store.save(&other, &theirs).await.unwrap();

        let mut found = db
            .store
            .find_by_ids(&db.tenant, &[*api.id(), *web.id(), *theirs.id()])
            .await
            .unwrap();
        found.sort_by(|a, b| a.name().as_str().cmp(b.name().as_str()));

        assert_eq!(names(&found), ["api", "web"]);
    }

    /// The tenant's services list by name, page by page, and another
    /// tenant's are left out.
    #[tokio::test]
    async fn services_are_listed_page_by_page_by_name() {
        let db = fixture().await;
        for name in ["carol", "alice", "bob"] {
            db.store.save(&db.tenant, &named(name)).await.unwrap();
        }
        let other = ScopedTenant::for_background(TenantId::new());
        db.store.save(&other, &named("aaron")).await.unwrap();
        let order = SortOrder::single(Sort::ascending(ServiceSortField::Name));

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

        assert_eq!(names(&page_one.items), ["alice", "bob"]);
        assert_eq!(names(&page_two.items), ["carol"]);
        assert!(!page_two.has_next());
    }

    /// A second service named `api` conflicts in the same tenant, while
    /// another tenant can save that name.
    #[tokio::test]
    async fn a_name_another_service_has_is_refused() {
        let db = fixture().await;
        db.store.save(&db.tenant, &named("api")).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let second = db.store.save(&db.tenant, &named("api")).await;
        let elsewhere = db.store.save(&other, &named("api")).await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
        assert!(elsewhere.is_ok());
    }

    /// Saving a rival service on an existing sign-in host returns a
    /// conflict and leaves no rival service to read.
    #[tokio::test]
    async fn a_sign_in_host_another_service_holds_is_refused() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &signing_in_on("shop", &["shop.example.com"]))
            .await
            .unwrap();
        let rival = signing_in_on("rival", &["shop.example.com"]);

        let second = db.store.save(&db.tenant, &rival).await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
        let kept = db.store.find_by_id(&db.tenant, rival.id()).await.unwrap();
        assert!(kept.is_none());
    }

    /// A service keeps its own sign-in hosts when saved again, and a host
    /// it gives up is free for another service.
    #[tokio::test]
    async fn a_sign_in_host_given_up_is_free_again() {
        let db = fixture().await;
        let shop = signing_in_on("shop", &["shop.example.com", "store.example.com"]);
        db.store.save(&db.tenant, &shop).await.unwrap();
        db.store.save(&db.tenant, &shop).await.unwrap();
        let narrowed = signing_in_on("shop", &["shop.example.com"]);
        let narrowed = service(ServiceRow {
            id: *shop.id(),
            app_sign_in: Setting::from_stored(narrowed.app_sign_in().cloned()),
            ..service_row("shop")
        });

        db.store.save(&db.tenant, &narrowed).await.unwrap();
        let store = signing_in_on("store", &["store.example.com"]);

        assert!(db.store.save(&db.tenant, &store).await.is_ok());
    }

    /// Saving a service with its own cookie on another service's sign-in
    /// host returns a conflict.
    #[tokio::test]
    async fn a_cookie_host_another_service_signs_in_on_is_refused() {
        let db = fixture().await;
        let shop = signing_in_on("shop", &["shop.example.com"]);
        db.store.save(&db.tenant, &shop).await.unwrap();

        let saved = db
            .store
            .save(
                &db.tenant,
                &accepting("api", shop.id(), &["shop.example.com"]),
            )
            .await;

        assert!(matches!(saved, Err(DomainError::Conflict(_))));
    }

    /// A service accepting another's sign-in reads back whose it accepts
    /// and how it reaches it.
    #[tokio::test]
    async fn an_accepted_sign_in_is_kept() {
        let db = fixture().await;
        let shop = signing_in_on("shop", &["shop.example.com"]);
        db.store.save(&db.tenant, &shop).await.unwrap();
        let api = accepting("api", shop.id(), &["api.example.com"]);

        db.store.save(&db.tenant, &api).await.unwrap();

        let found = db
            .store
            .find_by_id(&db.tenant, api.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.accepted_sign_in(), api.accepted_sign_in());
    }

    /// Deleting a service whose sign-in another service accepts returns a
    /// conflict.
    #[tokio::test]
    async fn a_service_whose_sign_in_is_accepted_is_not_deleted() {
        let db = fixture().await;
        let shop = signing_in_on("shop", &["shop.example.com"]);
        db.store.save(&db.tenant, &shop).await.unwrap();
        db.store
            .save(
                &db.tenant,
                &accepting("api", shop.id(), &["api.example.com"]),
            )
            .await
            .unwrap();

        let deleted = db.store.delete(&db.tenant, shop.id()).await;

        assert!(matches!(deleted, Err(DomainError::Conflict(_))));
    }

    /// Routes forwarding to a service are counted, and while one does, the
    /// service is not deleted.
    #[tokio::test]
    async fn a_service_with_routes_counts_them_and_is_not_deleted() {
        let db = fixture().await;
        let api = named("api");
        db.store.save(&db.tenant, &api).await.unwrap();
        let routes = PgRouteStore::new(Arc::clone(&db.database.databases));
        for name in ["one", "two"] {
            let route: Route<ResolvedTenant> =
                Route::reconstitute(route_row(*api.id(), name)).unwrap();
            routes.save(&db.tenant, &route).await.unwrap();
        }

        let count = db.store.route_count(&db.tenant, api.id()).await.unwrap();
        let deleted = db.store.delete(&db.tenant, api.id()).await;

        assert_eq!(count, 2);
        assert!(matches!(deleted, Err(DomainError::Conflict(_))));
    }

    /// A service nothing points at is deleted, and its sign-in hosts are
    /// free for another.
    #[tokio::test]
    async fn an_unused_service_is_deleted_with_its_hosts() {
        let db = fixture().await;
        let shop = signing_in_on("shop", &["shop.example.com"]);
        db.store.save(&db.tenant, &shop).await.unwrap();

        db.store.delete(&db.tenant, shop.id()).await.unwrap();

        let found = db.store.find_by_id(&db.tenant, shop.id()).await.unwrap();
        let next = signing_in_on("next", &["shop.example.com"]);
        assert!(found.is_none());
        assert!(db.store.save(&db.tenant, &next).await.is_ok());
    }

    /// Saving again keeps the new values: a disabled, renamed service reads
    /// back that way.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let db = fixture().await;
        let api = named("api");
        db.store.save(&db.tenant, &api).await.unwrap();
        let changed = service(ServiceRow {
            id: *api.id(),
            status: RouteStatus::Disabled,
            updated_at: at(5),
            ..service_row("renamed")
        });

        db.store.save(&db.tenant, &changed).await.unwrap();

        let found = db
            .store
            .find_by_id(&db.tenant, api.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.name().as_str(), "renamed");
        assert_eq!(found.status(), RouteStatus::Disabled);
    }

    /// A service with an unsupported version-two upstream envelope fails
    /// to load as corrupt storage.
    #[tokio::test]
    async fn a_row_in_a_shape_the_store_does_not_read_is_refused() {
        let db = fixture().await;
        let api = named("api");
        db.store.save(&db.tenant, &api).await.unwrap();
        db.database
            .tamper("UPDATE services SET upstream = jsonb_set(upstream, '{v}', '2')")
            .await;

        let read = db.store.find_by_id(&db.tenant, api.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// A service with a blank stored name fails to load as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_service_is_refused() {
        let db = fixture().await;
        let api = named("api");
        db.store.save(&db.tenant, &api).await.unwrap();
        db.database.tamper("UPDATE services SET name = ' '").await;

        let read = db.store.find_by_id(&db.tenant, api.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
