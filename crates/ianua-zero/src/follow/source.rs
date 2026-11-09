//! Where the follower reads the tables from: the stores, through the app's
//! ports, under the gateway's own database role.

use std::future::Future;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Limit, Page, PageRequest, SortOrder};
use ianua_app::ports::branding::BrandingStore;
use ianua_app::ports::pages::ErrorBranding;
use ianua_app::ports::proxy::{
    CrossTenantHosts, CrossTenantServedCertificates, PipelineStore, ServedCertificate,
};
use ianua_app::ports::routing::{
    ConnectorTunnelStore, RouteSortField, RouteStore, ServiceSortField, ServiceStore,
    StreamRouteSortField, StreamRouteStore,
};
use ianua_app::ports::tenant::TenantStore;
use ianua_app::services::issuers::TenantIssuers;
use ianua_app::tenancy::ScopedTenant;
use ianua_app::use_case::Query as _;
use ianua_app::use_cases::routing::services::{OpenClientKeyRequest, OpenClientKeyUseCase};
use ianua_domain::domains::branding::config::TenantBranding;
use ianua_domain::domains::routing::route::Route;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::domains::routing::stream::StreamRoute;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Issuer, SealedSecret, ServiceId, TenantId};

use super::snapshot::{OpenedClientKey, TenantSnapshot};

/// The rows one page of a tenant's list holds.
const PAGE_ROWS: u32 = 500;

/// The most pages one list of a snapshot reads. A tenant's lists are
/// bounded by its plan far below this; a list longer than it is refused
/// rather than served cut short.
const MOST_PAGES: usize = 200;

/// What the follower reads the tables from.
#[async_trait]
pub(crate) trait SnapshotSource: Send + Sync {
    /// Every tenant served now.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the tenants cannot be read.
    async fn served(&self) -> Result<Vec<TenantId>, DomainError>;

    /// The snapshot of `tenant`, or `None` when it is not served now: gone,
    /// or closed to requests.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when any part of it cannot be read.
    async fn snapshot(&self, tenant: TenantId) -> Result<Option<TenantSnapshot>, DomainError>;

    /// The current certificate of every name served.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the certificates cannot be read.
    async fn certificates(&self) -> Result<Vec<ServedCertificate>, DomainError>;
}

/// The stores a [`StoreSnapshotSource`] reads, each under the gateway's
/// database role.
pub(crate) struct SnapshotStores {
    /// The tenants served and the names they are served on.
    pub hosts: Arc<dyn CrossTenantHosts>,
    /// The tenants, for whom each trusts with client certificates.
    pub tenants: Arc<dyn TenantStore>,
    /// Each tenant's routes.
    pub routes: Arc<dyn RouteStore>,
    /// Each tenant's services.
    pub services: Arc<dyn ServiceStore>,
    /// Each tenant's pipelines.
    pub pipelines: Arc<dyn PipelineStore>,
    /// Each tenant's stream routes.
    pub stream_routes: Arc<dyn StreamRouteStore>,
    /// The issuer each tenant's tokens name.
    pub issuers: TenantIssuers,
    /// Each tenant's look, for its error pages.
    pub branding: Arc<dyn BrandingStore>,
    /// The certificate every served name is answered with.
    pub certificates: Arc<dyn CrossTenantServedCertificates>,
    /// Opens the private key a service presents to its backends.
    pub client_keys: Arc<OpenClientKeyUseCase>,
    /// Each tenant's enrolled connectors, as the gateway judges their links.
    pub connector_tunnels: Arc<dyn ConnectorTunnelStore>,
}

/// The tables read from the stores.
pub(crate) struct StoreSnapshotSource {
    stores: SnapshotStores,
}

impl std::fmt::Debug for StoreSnapshotSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreSnapshotSource")
            .finish_non_exhaustive()
    }
}

impl StoreSnapshotSource {
    /// A source reading `stores`.
    #[must_use]
    pub(crate) fn new(stores: SnapshotStores) -> Self {
        Self { stores }
    }

    async fn routes_of(
        &self,
        tenant: ScopedTenant,
    ) -> Result<Vec<Route<ResolvedTenant>>, DomainError> {
        let store = &self.stores.routes;
        let sort = &SortOrder::<RouteSortField>::default();
        every_row(|page| async move { store.list_all(&tenant, None, sort, &page).await }).await
    }

    async fn services_of(
        &self,
        tenant: ScopedTenant,
    ) -> Result<Vec<Service<ResolvedTenant>>, DomainError> {
        let store = &self.stores.services;
        let sort = &SortOrder::<ServiceSortField>::default();
        every_row(|page| async move { store.list_all(&tenant, sort, &page).await }).await
    }

    async fn issuer_of(&self, tenant_id: &TenantId) -> Result<Issuer, DomainError> {
        self.stores
            .issuers
            .of(tenant_id)
            .await
            .map_err(DomainError::infra)
    }

    /// The opened keys of `services` that present a client certificate. A
    /// key that does not open is left out and the service named in the
    /// log, so that service alone is refused, never called without it.
    async fn client_keys_of(
        &self,
        tenant: &ScopedTenant,
        services: &[Service<ResolvedTenant>],
    ) -> Vec<OpenedClientKey> {
        let mut opened = Vec::new();
        for (service_id, sealed) in services.iter().filter_map(sealed_client_key) {
            let request = OpenClientKeyRequest { service_id, sealed };
            match self.stores.client_keys.execute(tenant, request).await {
                Ok(pem) => opened.push(OpenedClientKey { service_id, pem }),
                Err(error) => tracing::warn!(
                    %service_id,
                    %error,
                    "a service's client key does not open; its routes are refused"
                ),
            }
        }
        opened
    }

    async fn stream_routes_of(
        &self,
        tenant: ScopedTenant,
    ) -> Result<Vec<StreamRoute<ResolvedTenant>>, DomainError> {
        let store = &self.stores.stream_routes;
        let sort = &SortOrder::<StreamRouteSortField>::default();
        every_row(|page| async move { store.list_all(&tenant, sort, &page).await }).await
    }
}

#[async_trait]
impl SnapshotSource for StoreSnapshotSource {
    async fn served(&self) -> Result<Vec<TenantId>, DomainError> {
        let hosted = self.stores.hosts.all().await?;
        Ok(hosted.into_iter().map(|tenant| tenant.tenant_id).collect())
    }

    async fn snapshot(&self, tenant_id: TenantId) -> Result<Option<TenantSnapshot>, DomainError> {
        let Some(hosted) = self.stores.hosts.find(&tenant_id).await? else {
            return Ok(None);
        };
        let Some(tenant) = self.stores.tenants.find_by_id(&tenant_id).await? else {
            return Ok(None);
        };
        let scoped = ScopedTenant::for_background(tenant_id);
        let (routes, services, pipelines, _, issuer, look, connectors) = futures_util::try_join!(
            self.routes_of(scoped),
            self.services_of(scoped),
            self.stores.pipelines.list(&scoped),
            self.stream_routes_of(scoped),
            self.issuer_of(&tenant_id),
            self.stores.branding.find(&scoped),
            self.stores.connector_tunnels.enrolled(&scoped),
        )?;
        let client_keys = self.client_keys_of(&scoped, &services).await;
        Ok(Some(TenantSnapshot {
            hosted,
            organization: *tenant.organization_id(),
            issuer,
            branding: branding_of(&tenant, look.as_ref()),
            mtls: tenant.mtls().clone(),
            routes,
            services,
            pipelines,
            client_keys,
            connectors,
        }))
    }

    async fn certificates(&self) -> Result<Vec<ServedCertificate>, DomainError> {
        self.stores.certificates.current().await
    }
}

/// The sealed key `service` presents with its client certificate, when it
/// is active and presents one.
fn sealed_client_key(service: &Service<ResolvedTenant>) -> Option<(ServiceId, SealedSecret)> {
    if !service.is_active() {
        return None;
    }
    let certificate = service.upstream().tls()?.client_certificate()?;
    Some((*service.id(), certificate.private_key().clone()))
}

/// The look `tenant`'s error pages wear: its name, with its logo and
/// colours where it set them.
fn branding_of(tenant: &Tenant, look: Option<&TenantBranding<ResolvedTenant>>) -> ErrorBranding {
    let name = tenant.display_name().clone();
    match look {
        Some(look) => ErrorBranding::of(name, look),
        None => ErrorBranding {
            name,
            logo_url: None,
            primary_color: None,
            background_color: None,
        },
    }
}

/// Every row of a list `read` answers page by page.
///
/// # Errors
///
/// Returns the first page's failure, or `DomainError::Infrastructure` when
/// the list runs past [`MOST_PAGES`].
async fn every_row<T, F, Fut>(mut read: F) -> Result<Vec<T>, DomainError>
where
    F: FnMut(PageRequest) -> Fut,
    Fut: Future<Output = Result<Page<T>, DomainError>>,
{
    let mut request = PageRequest::first(Limit::internal(PAGE_ROWS));
    let mut rows = Vec::new();
    for _ in 0..MOST_PAGES {
        let page = read(request.clone()).await?;
        let following = request.following(&page);
        rows.extend(page.items);
        let Some(next) = following else {
            return Ok(rows);
        };
        request = next;
    }
    Err(DomainError::infra_msg(
        "a tenant's list runs past what one snapshot reads",
    ))
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::Cursor;

    use super::*;

    fn a_cursor() -> Cursor {
        Cursor::at(&SortOrder::<RouteSortField>::default(), Vec::new())
    }

    /// Following a two-page list's cursor returns the rows from both pages
    /// in their original order.
    #[tokio::test]
    async fn every_page_of_a_list_is_read() {
        let pages = [vec![1, 2], vec![3]];
        let mut asked = 0;

        let rows = every_row(|_| {
            let page = pages[asked].clone();
            asked += 1;
            let next = (asked < pages.len()).then(a_cursor);
            async move {
                Ok(Page {
                    items: page,
                    next,
                    limit: Limit::internal(2),
                })
            }
        })
        .await
        .unwrap();

        assert_eq!(rows, vec![1, 2, 3]);
    }

    /// A list that never ends is refused, never served cut short.
    #[tokio::test]
    async fn a_list_without_end_is_refused() {
        let read = every_row(|_| async {
            Ok(Page {
                items: vec![0],
                next: Some(a_cursor()),
                limit: Limit::internal(1),
            })
        })
        .await;

        assert!(read.is_err());
    }
}
