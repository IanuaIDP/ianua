//! Loading the route, service, stream route, egress policy or pipeline a
//! caller names, checking they may view routing at all, and refusing a
//! route that points at domains or permissions the tenant does not have.

use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::domains::routing::egress::EgressPolicy;
use ianua_domain::domains::routing::matching::host::RouteHosts;
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::route::Route;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::domains::routing::stream::StreamRoute;
use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use ianua_domain::domains::tenant::custom_domains::verification_status::VerificationStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{EgressPolicyId, PipelineId, RouteId, ServiceId, StreamRouteId};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::listing::{Limit, PageRequest, SortOrder};
use crate::ports::authorization::ResourceTypeStore;
use crate::ports::domain::RegisteredDomainStore;
use crate::ports::proxy::PipelineStore;
use crate::ports::routing::{EgressPolicyStore, RouteStore, ServiceStore, StreamRouteStore};
use crate::services::authorization::catalogue_check::ensure_declared;
use crate::services::hosts::PlatformAddresses;
use crate::tenancy::ScopedTenant;
use crate::use_cases::routing::tenant_domains::registered_domains;

/// How many of a tenant's routes are examined when a check needs all of them.
///
/// Far above what any tenant defines; being wrong here refuses a legitimate
/// edit rather than allowing an unsafe one.
const MAX_TENANT_ROUTES: u32 = 100_000;

/// How many of a tenant's services are examined when a check needs all of
/// them, for the same reason.
const MAX_TENANT_SERVICES: u32 = 10_000;

/// Refuses `caller` unless the domain agrees they may view the tenant's
/// routing.
///
/// # Errors
///
/// - `AppError::Unauthenticated` when their session or key no longer counts.
/// - `AppError::Forbidden` when they may not view routing.
/// - `AppError::Internal` when what they hold cannot be worked out.
pub(crate) async fn ensure_may_view_routing(
    authorities: &dyn TenantAuthorities,
    caller: &CallerContext,
) -> Result<(), AppError> {
    authorities
        .authority(caller)
        .await?
        .ensure_holds(SystemPermission::Routing(RoutingAction::View))
        .map_err(AppError::from_domain)
}

/// Every route of the tenant, for checks that span all of them.
///
/// # Errors
///
/// Returns `AppError::Internal` on storage failure.
pub(crate) async fn all_routes(
    store: &dyn RouteStore,
    tenant: &ScopedTenant,
) -> Result<Vec<Route<ResolvedTenant>>, AppError> {
    let routes = store
        .list_all(
            tenant,
            None,
            &SortOrder::default(),
            &PageRequest::first(Limit::internal(MAX_TENANT_ROUTES)),
        )
        .await
        .or_internal()?
        .items;
    Ok(routes)
}

/// Every route of the tenant that forwards to `service`.
///
/// # Errors
///
/// Returns `AppError::Internal` on storage failure.
pub(crate) async fn routes_to(
    store: &dyn RouteStore,
    tenant: &ScopedTenant,
    service: &ServiceId,
) -> Result<Vec<Route<ResolvedTenant>>, AppError> {
    let routes = all_routes(store, tenant).await?;
    Ok(routes
        .into_iter()
        .filter(|route| route.service_id() == service)
        .collect())
}

/// Every route of the tenant that runs `pipeline`, as stored.
///
/// The domain checks a pipeline against all of them, so none may be left
/// out.
///
/// # Errors
///
/// Returns `AppError::Internal` on storage failure.
pub(crate) async fn routes_on(
    store: &dyn RouteStore,
    tenant: &ScopedTenant,
    pipeline: &PipelineId,
) -> Result<Vec<Route<ResolvedTenant>>, AppError> {
    store.list_by_pipeline(tenant, pipeline).await.or_internal()
}

/// Every service of the tenant that accepts the app sign-in of `owner`.
///
/// # Errors
///
/// Returns `AppError::Internal` on storage failure.
pub(crate) async fn services_accepting(
    store: &dyn ServiceStore,
    tenant: &ScopedTenant,
    owner: &ServiceId,
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
        .filter(|service| service.accepts_app_sign_in_of() == Some(owner))
        .collect())
}

/// The tenant's route with `route_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such route.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn existing_route(
    store: &dyn RouteStore,
    tenant: &ScopedTenant,
    route_id: &RouteId,
) -> Result<Route<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, route_id)
        .await
        .or_internal()?
        .or_not_found(message!("routing-route-not-found", "route not found"))
}

/// The tenant's service with `service_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such service.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn existing_service(
    store: &dyn ServiceStore,
    tenant: &ScopedTenant,
    service_id: &ServiceId,
) -> Result<Service<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, service_id)
        .await
        .or_internal()?
        .or_not_found(message!("routing-service-not-found", "service not found"))
}

/// The tenant's stream route with `stream_route_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such stream route.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn existing_stream_route(
    store: &dyn StreamRouteStore,
    tenant: &ScopedTenant,
    stream_route_id: &StreamRouteId,
) -> Result<StreamRoute<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, stream_route_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "routing-stream-route-not-found",
            "stream route not found"
        ))
}

/// The tenant's egress policy with `policy_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such policy.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn existing_egress_policy(
    store: &dyn EgressPolicyStore,
    tenant: &ScopedTenant,
    policy_id: &EgressPolicyId,
) -> Result<EgressPolicy<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, policy_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "routing-egress-policy-not-found",
            "egress policy not found"
        ))
}

/// The tenant's pipeline a route names.
///
/// A route without a live pipeline behind it refuses every request, and
/// the database would only report the miss as a foreign-key violation. The
/// caller named the pipeline, so the answer belongs where they named it.
///
/// # Errors
///
/// - `AppError::Domain(Validation)` if the tenant holds no such pipeline.
/// - `AppError::Internal` if the lookup fails.
pub(crate) async fn named_pipeline(
    store: &dyn PipelineStore,
    tenant: &ScopedTenant,
    pipeline_id: &PipelineId,
) -> Result<Pipeline<ResolvedTenant>, AppError> {
    let found = store.find(tenant, pipeline_id).await.or_internal()?;
    found.ok_or_else(|| {
        AppError::Domain(DomainError::invalid(message!(
            "routing-pipeline-does-not-exist-in-this",
            format!("pipeline {pipeline_id} does not exist in this tenant")
        )))
    })
}

/// Refuses a route restricted to a domain the tenant cannot answer on.
///
/// The proxy only resolves verified domains, so naming anything else makes
/// a route that is saved, listed and never matched. Nothing reports that,
/// so the write is the one place the answer is still obvious.
///
/// # Errors
///
/// - `AppError::Domain(Validation)` naming the first host that is not served
///   by a verified domain of this tenant.
/// - `AppError::Internal` if the domain listing fails.
pub(crate) async fn ensure_hosts_belong_to_tenant(
    domain_store: &dyn RegisteredDomainStore,
    tenant: &ScopedTenant,
    hosts: &RouteHosts,
    platform: Option<&PlatformAddresses>,
) -> Result<(), AppError> {
    let Some(requested) = hosts.as_stored() else {
        return Ok(());
    };
    let owned = registered_domains(domain_store, tenant).await?;
    let platform = match platform {
        Some(platform) => Some(platform.owned(tenant).await?),
        None => None,
    };
    let unusable = requested.iter().find(|host| {
        !platform
            .as_ref()
            .and_then(|platform| platform.owns(host))
            .unwrap_or_else(|| owned.iter().any(|d| is_usable(d, host.as_str())))
    });
    let Some(host) = unusable else {
        return Ok(());
    };
    Err(AppError::Domain(DomainError::invalid(message!(
        "routing-is-not-a-verified-domain-of",
        format!(
            "{host} is not a verified domain of this tenant; register and verify it before routing \
         to it"
        )
    ))))
}

/// Refuses a route whose required custom permissions the tenant's catalogue
/// does not declare.
///
/// A route requiring `projects:write` while roles grant `project:write`
/// matches nobody, so the proxy denies every caller and nothing reports
/// that the two spellings were meant to be one.
///
/// # Errors
///
/// - `AppError::Domain` naming each undeclared permission.
/// - `AppError::Internal` if the catalogue lookup fails.
pub(crate) async fn ensure_policy_permissions_declared(
    resource_type_store: &dyn ResourceTypeStore,
    tenant: &ScopedTenant,
    policy: &RoutePolicy,
) -> Result<(), AppError> {
    let RoutePolicy::RequireCustomPermission(permissions) = policy else {
        return Ok(());
    };
    ensure_declared(resource_type_store, tenant, permissions).await
}

/// Whether `domain` lets a route answer on `host`: it serves the host and
/// the tenant proved they own it.
fn is_usable(domain: &RegisteredDomain<ResolvedTenant>, host: &str) -> bool {
    domain.domain().serves(host) && domain.verification_status() == VerificationStatus::Verified
}
