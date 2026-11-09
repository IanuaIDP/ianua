//! Loading the connector a caller names, the services reached through one,
//! and the check that a service's upstream may be reached the way it says.

use ianua_domain::domains::routing::backend::upstream::Upstream;
use ianua_domain::domains::routing::connector::scope::{ConnectorScope, UpstreamReach};
use ianua_domain::domains::routing::connector::{ConnectorStatus, PrivateConnector};
use ianua_domain::domains::routing::service::Service;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::ConnectorId;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::listing::{Limit, PageRequest, SortOrder};
use crate::ports::routing::{ConnectorStore, ServiceStore};
use crate::tenancy::ScopedTenant;
use crate::use_cases::routing::destinations::{Destination, ensure_reachable};

/// How many of a tenant's services are examined when a check needs all of
/// them. Far above what any tenant defines; being wrong here refuses a
/// legitimate change rather than allowing an unsafe one.
const MAX_TENANT_SERVICES: u32 = 10_000;

/// The tenant's connector with `connector_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such connector.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn existing_connector(
    store: &dyn ConnectorStore,
    tenant: &ScopedTenant,
    connector_id: &ConnectorId,
) -> Result<PrivateConnector<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, connector_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "routing-connector-not-found",
            "connector not found"
        ))
}

/// Every service of the tenant whose upstream is reached through
/// `connector`.
///
/// # Errors
///
/// Returns `AppError::Internal` on storage failure.
pub(crate) async fn services_through(
    store: &dyn ServiceStore,
    tenant: &ScopedTenant,
    connector: &ConnectorId,
) -> Result<Vec<Service<ResolvedTenant>>, AppError> {
    let services = store
        .list_all(
            tenant,
            &SortOrder::default(),
            &PageRequest::first(Limit::internal(MAX_TENANT_SERVICES)),
        )
        .await
        .or_internal()?
        .items;
    Ok(services
        .into_iter()
        .filter(|service| service.upstream().reach() == UpstreamReach::Connector(*connector))
        .collect())
}

/// Refuses `upstream` unless it may be reached the way it says.
///
/// Reached directly, the gateway dials it, so no target may be an internal
/// address `networks` does not allow. Reached through a connector, the
/// connector dials it from inside the tenant's own network. Then the
/// operator's networks are out of reach, and the connector's scope is the
/// bound instead: it must be the tenant's, not revoked, and allowed to dial
/// every target.
///
/// # Errors
///
/// - `AppError::Domain` when a direct target is a refused internal address,
///   the connector is revoked, or a target is outside its scope.
/// - `AppError::NotFound` when the tenant has no such connector.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn ensure_upstream_reachable(
    connectors: &dyn ConnectorStore,
    tenant: &ScopedTenant,
    upstream: &Upstream,
    networks: &UpstreamNetworks,
) -> Result<(), AppError> {
    let UpstreamReach::Connector(connector_id) = upstream.reach() else {
        return ensure_reachable(Some(Destination::Upstream(upstream)), networks);
    };
    let connector = existing_connector(connectors, tenant, &connector_id).await?;
    ensure_carries_traffic(&connector)?;
    ensure_scope_permits(connector.scope(), upstream)
}

/// Refuses an upstream outside `scope`.
///
/// # Errors
///
/// `AppError::Domain` naming the first target outside it.
pub(crate) fn ensure_scope_permits(
    scope: &ConnectorScope,
    upstream: &Upstream,
) -> Result<(), AppError> {
    scope
        .ensure_permits(upstream.all_target_urls())
        .map_err(AppError::from_domain)
}

/// Refuses a revoked connector: it carries nothing again, so a service
/// pointed at it would be unreachable from the start.
///
/// # Errors
///
/// `AppError::Domain` when it is revoked.
fn ensure_carries_traffic(connector: &PrivateConnector<ResolvedTenant>) -> Result<(), AppError> {
    if connector.status() == ConnectorStatus::Revoked {
        return Err(AppError::from_domain(DomainError::invalid(message!(
            "routing-the-connector-is-revoked-so-nothing",
            "the connector is revoked, so nothing is reached through it"
        ))));
    }
    Ok(())
}
