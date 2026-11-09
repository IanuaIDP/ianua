//! Domain registration handlers: a tenant's custom domains, registered,
//! listed, read and removed.

use axum::extract::{Path, State};
use ianua_app::ports::domain::DomainSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::domain::registration::ListDomainsRequest;
use ianua_assembly::domain::DomainState;

use crate::dto::domain::registration::{
    AddDomainBody, DnsSetup, DomainDetailResponse, DomainResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::domain::DomainPath;
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/domains",
    tag = "Domains",
    params(SortQuery<DomainSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<DomainResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// List a tenant's registered domains
///
/// Returns the domains this tenant has registered, paginated and sortable
/// (see the `sort` parameter for allowed fields). Each entry carries its
/// `connection`, DNS `verification_status`, `tls_status`, the challenge
/// record to publish, `verified_at`, and the records that bring its
/// traffic here. Read-only.
///
/// Requires `Domains(View)`.
pub(crate) async fn list_domains(
    State(domains): State<DomainState>,
    tenant: TenantCaller,
    SortQuery(sort): SortQuery<DomainSortField>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<DomainResponse>>, ApiError> {
    let dns = DnsSetup::new(&tenant.platform_label, domains.dns.clone())?;
    let page = domains
        .registration
        .list
        .execute(
            &tenant.caller,
            ListDomainsRequest {
                sort,
                page: pagination,
            },
        )
        .await?;
    Ok(Json(PageResponse::from_page(page, |domain| {
        DomainResponse::new(&domain, &dns)
    })))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/domains",
    tag = "Domains",
    request_body = AddDomainBody,
    responses(
        (status = 201, description = "Created", body = DomainResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Register a domain
///
/// Defaults to `SelfManaged`: the tenant keeps DNS and receives TXT proof
/// (`dns_record_name` / `dns_record_value`) and `traffic_records.subdomain`
/// or `.bare_domain`. Publish these, then verify; traffic follows the records.
/// `Delegated` hands over the hostname using registration-specific NS records
/// in `traffic_records.delegation`, with automatic DNS-01 certificate renewal.
/// Without deployment nameservers and an answer address, it uses `SelfManaged`.
/// Starts `Pending`, except under an operator-vouched parent or for a wildcard.
/// Wildcards must be under this tenant's verified, delegated domain and are
/// always delegated (`422` otherwise). Conflicting names, ancestors, descendants
/// or externally held zones return `409`; exhausted domain capacity returns
/// `403`; invalid names or unknown connections return `422`.
/// Requires `Domains(Create)`; records `tenant.domain_registered`.
pub(crate) async fn add_domain(
    State(domains): State<DomainState>,
    tenant: TenantCaller,
    Json(body): Json<AddDomainBody>,
) -> Result<Created<DomainResponse>, ApiError> {
    let dns = DnsSetup::new(&tenant.platform_label, domains.dns.clone())?;
    let domain = domains
        .registration
        .add
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(DomainResponse::new(&domain, &dns)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/domains/{id}",
    tag = "Domains",
    responses(
        (status = 200, description = "Success", body = DomainDetailResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get a registered domain
///
/// Returns one of this tenant's domains, in the shape the list answers,
/// with the `certificate` it serves: where it came from (`Acme` or
/// `Uploaded`), who renews it, its issuer and names when uploaded, and when
/// it was issued and runs out. `certificate` is `null` when the domain was
/// never given one or the tenant removed it. The private key is never
/// answered. `404` if the domain does not exist under this tenant.
/// Read-only.
///
/// Requires `Domains(View)`.
pub(crate) async fn get_domain(
    State(domains): State<DomainState>,
    tenant: TenantCaller,
    Path(path): Path<DomainPath>,
) -> Result<Json<DomainDetailResponse>, ApiError> {
    let dns = DnsSetup::new(&tenant.platform_label, domains.dns.clone())?;
    let detail = domains
        .registration
        .get
        .execute(&tenant.caller, path.domain())
        .await?;
    Ok(Json(DomainDetailResponse::new(detail, &dns)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/domains/{id}",
    tag = "Domains",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Remove a registered domain
///
/// Deletes a domain registration, and the zone we held for it when it was
/// delegated. Returns `404` if the domain does not exist under this tenant.
/// Removing the domain frees it for another tenant to claim and stops it
/// being used for routing or email federation; when it was the tenant's
/// primary domain, the tenant lets go of it too. Records
/// `tenant.domain_removed`, and `tenant.primary_domain_changed` when it was
/// primary.
///
/// Requires `Domains(Delete)`.
pub(crate) async fn remove_domain(
    State(domains): State<DomainState>,
    tenant: TenantCaller,
    Path(path): Path<DomainPath>,
) -> Result<NoContent, ApiError> {
    domains
        .registration
        .remove
        .execute(&tenant.caller, &tenant.auditor, path.domain())
        .await?;
    Ok(NoContent)
}
