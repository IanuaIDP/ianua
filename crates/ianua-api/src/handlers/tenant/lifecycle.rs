//! Tenant lifecycle handlers: provisioning, listing and reading tenants,
//! moving them through their life, and a tenant's metrics overview.

use axum::extract::{Path, State};
use ianua_app::ports::tenant::TenantSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::tenant::TenantState;

use crate::dto::tenant::lifecycle::{
    EarlyDeletionBody, ProvisionTenantBody, ProvisionTenantResponse, TenantFilterParams,
    TenantMetricsResponse, TenantResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::{Operator, TenantCaller};
use crate::extractors::json::Json;
use crate::extractors::listing::ListingQuery;
use crate::extractors::metrics_window::MetricsWindowQuery;
use crate::extractors::pagination::PaginationParams;
use crate::extractors::paths::tenant::OrgSlugPath;
use crate::extractors::sort::SortQuery;
use crate::extractors::tenant::{Lister, Steward, TenantInPath, Viewer};
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants",
    tag = "Tenants",
    request_body = ProvisionTenantBody,
    responses(
        (status = 201, description = "Created", body = ProvisionTenantResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Provision a tenant
///
/// Creates a new tenant within this organization in `Provisioning` status:
/// its default roles, sign-in settings and signing keys are set up before
/// it goes `Active`. Provide a `slug`, `display_name`, `contact_email`,
/// `timezone`, `locale` and optionally a `residency`. A tenant starts with
/// no primary domain: it registers and proves one afterwards. The plan on
/// record decides whether there is room for another tenant and whether it
/// covers the residency (`403` otherwise). Returns the new tenant's `id`.
///
/// Returns `409` if another tenant of the organization has the slug (another
/// organization's tenant may), `404` if the organization does not exist, or
/// `422` for an invalid slug, name, address, timezone, locale or residency.
/// Records `tenant.provisioned` and `organization.tenant_created`.
///
/// Requires a member who may create the organization's tenants, or an
/// operator.
pub(crate) async fn provision_tenant(
    State(tenant): State<TenantState>,
    steward: Steward,
    Json(body): Json<ProvisionTenantBody>,
) -> Result<Created<ProvisionTenantResponse>, ApiError> {
    let request = body.into_request(
        steward.organization,
        &tenant.domain_limits,
        tenant.default_region,
    )?;
    let id = tenant
        .lifecycle
        .provision
        .execute(&steward.caller, &steward.auditor, request)
        .await?;
    Ok(Created(ProvisionTenantResponse { id }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants",
    tag = "Tenants",
    params(TenantFilterParams, SortQuery<TenantSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<TenantResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// List tenants
///
/// Returns the tenants in this organization, optionally filtered by
/// `status` (`Provisioning`, `Active`, `Suspended`, `Archived` or
/// `Deleted`), sortable and paginated. Read-only.
///
/// A member who may view the organization's tenants sees every one of
/// them; any other member sees only the tenants they hold a grant in, the
/// same set the tenant routes admit them to. An operator sees every tenant
/// of the organization.
pub(crate) async fn list_tenants(
    State(tenant): State<TenantState>,
    Lister(lister): Lister,
    Path(path): Path<OrgSlugPath>,
    ListingQuery {
        query: filter,
        sort,
        page: pagination,
    }: ListingQuery<TenantFilterParams, TenantSortField>,
) -> Result<Json<PageResponse<TenantResponse>>, ApiError> {
    let page = tenant
        .lifecycle
        .list
        .execute(&lister, filter.listing(sort, pagination))
        .await?;
    Ok(Json(PageResponse::from_page(page, |listed| {
        TenantResponse::new(&listed, &tenant.app_base_url, path.organization())
    })))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}",
    tag = "Tenants",
    responses(
        (status = 200, description = "Success", body = TenantResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Get a tenant
///
/// Returns this tenant: name, primary domain, contact address,
/// timezone and locale, lifecycle `status`, where its data lives and where
/// its users sign in. Read-only.
///
/// Requires `TenantSettings(View)` for someone acting in the tenant, the
/// right to view the organization's tenants for a member, or an operator.
pub(crate) async fn get_tenant(
    State(tenant): State<TenantState>,
    Viewer(viewer): Viewer,
    Path(path): Path<OrgSlugPath>,
) -> Result<Json<TenantResponse>, ApiError> {
    let found = tenant.lifecycle.get.execute(&viewer, ()).await?;
    Ok(Json(TenantResponse::new(
        &found,
        &tenant.app_base_url,
        path.organization(),
    )))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/activate",
    tag = "Tenants",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Activate a tenant
///
/// Promotes a `Provisioning` tenant to `Active`, enabling sign-in and API
/// access.
///
/// **State.** `Provisioning → Active`. Returns `404` if the tenant does not
/// exist, or `422` if it is not `Provisioning`. Records
/// `tenant.status_changed`.
///
/// Requires an operator: provisioning activates a tenant itself once its
/// infrastructure exists, and this is the override for when it cannot.
pub(crate) async fn activate_tenant(
    State(tenant): State<TenantState>,
    operator: Operator,
    TenantInPath(tenant_id): TenantInPath,
) -> Result<NoContent, ApiError> {
    tenant
        .lifecycle
        .activate
        .execute(&operator.caller, &operator.auditor, tenant_id)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/suspend",
    tag = "Tenants",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Suspend a tenant
///
/// Freezes an `Active` tenant: every session is signed out and new
/// sign-ins are refused, but its data is kept for reactivation. When an
/// operator suspends it, the platform holds it, and only the platform
/// brings it back.
///
/// **State.** `Active → Suspended`. Returns `404` if the tenant does not
/// exist, or `422` if it is not `Active`. Records `tenant.status_changed`.
///
/// Requires a member who may change the organization's tenants, or an
/// operator.
pub(crate) async fn suspend_tenant(
    State(tenant): State<TenantState>,
    steward: Steward,
    TenantInPath(tenant_id): TenantInPath,
) -> Result<NoContent, ApiError> {
    tenant
        .lifecycle
        .suspend
        .execute(&steward.caller, &steward.auditor, tenant_id)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/reactivate",
    tag = "Tenants",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Reactivate a tenant
///
/// Lifts a suspension: a `Suspended` tenant returns to `Active` and
/// sign-ins resume. A tenant the platform holds comes back only through an
/// operator (`403` for a member).
///
/// **State.** `Suspended → Active`. Returns `404` if the tenant does not
/// exist, or `422` if it is not `Suspended`. Records
/// `tenant.status_changed`.
///
/// Requires a member who may change the organization's tenants, or an
/// operator.
pub(crate) async fn reactivate_tenant(
    State(tenant): State<TenantState>,
    steward: Steward,
    TenantInPath(tenant_id): TenantInPath,
) -> Result<NoContent, ApiError> {
    tenant
        .lifecycle
        .reactivate
        .execute(&steward.caller, &steward.auditor, tenant_id)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/archive",
    tag = "Tenants",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Archive a tenant
///
/// Soft-deletes an `Active` or `Suspended` tenant: every session is signed
/// out and its data is kept through a grace period. Until the grace has
/// run it can be restored; after it, deleted.
///
/// **State.** `Active | Suspended → Archived`. Returns `404` if the tenant
/// does not exist, or `422` from any other status. Records
/// `tenant.status_changed`.
///
/// Requires a member who may delete the organization's tenants, or an
/// operator.
pub(crate) async fn archive_tenant(
    State(tenant): State<TenantState>,
    steward: Steward,
    TenantInPath(tenant_id): TenantInPath,
) -> Result<NoContent, ApiError> {
    tenant
        .lifecycle
        .archive
        .execute(&steward.caller, &steward.auditor, tenant_id)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/restore",
    tag = "Tenants",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Restore an archived tenant
///
/// Brings an `Archived` tenant back to `Active` before it is deleted, and
/// ends its wait for deletion. A tenant the platform archived comes back
/// only through an operator (`403` for a member).
///
/// **State.** `Archived → Active`. Returns `404` if the tenant does not
/// exist, or `422` if it is not `Archived`. Records
/// `tenant.status_changed`.
///
/// Requires a member who may restore the organization's tenants, or an
/// operator.
pub(crate) async fn restore_tenant(
    State(tenant): State<TenantState>,
    steward: Steward,
    TenantInPath(tenant_id): TenantInPath,
) -> Result<NoContent, ApiError> {
    tenant
        .lifecycle
        .restore
        .execute(&steward.caller, &steward.auditor, tenant_id)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}",
    tag = "Tenants",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Grace not yet run", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Delete a tenant
///
/// Permanently deletes a tenant and takes it off its organization, so it
/// no longer counts against the plan. Irreversible. It must be `Archived`
/// first (`422` otherwise), and its grace must have run since (`409`
/// otherwise); the platform can cut the grace short with an early
/// deletion.
///
/// **State.** `Archived → Deleted` (terminal). Returns `404` if the tenant
/// does not exist. Records `tenant.status_changed` and `tenant.deleted`.
///
/// Requires a member who may delete the organization's tenants, or an
/// operator.
pub(crate) async fn delete_tenant(
    State(tenant): State<TenantState>,
    steward: Steward,
    TenantInPath(tenant_id): TenantInPath,
) -> Result<NoContent, ApiError> {
    tenant
        .lifecycle
        .delete
        .execute(&steward.caller, &steward.auditor, tenant_id)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/early-deletion",
    tag = "Tenants",
    request_body = EarlyDeletionBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Delete an archived tenant early
///
/// Deletes an `Archived` tenant at once, before its grace has run, for
/// abuse or a legal order, and says why on the record: `reason` is `abuse`
/// or `legal_order`, `note` what happened or which order it was. This
/// cannot be undone.
///
/// **State.** `Archived → Deleted` (terminal). Returns `404` if the tenant
/// does not exist, or `422` if it is not `Archived`. Records
/// `tenant.status_changed`, `tenant.deleted` and `tenant.deleted_early`.
///
/// Requires an operator.
pub(crate) async fn delete_tenant_early(
    State(tenant): State<TenantState>,
    operator: Operator,
    TenantInPath(tenant_id): TenantInPath,
    Json(body): Json<EarlyDeletionBody>,
) -> Result<NoContent, ApiError> {
    tenant
        .lifecycle
        .delete_early
        .execute(
            &operator.caller,
            &operator.auditor,
            body.into_request(tenant_id)?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/metrics",
    tag = "Tenants",
    params(MetricsWindowQuery),
    responses(
        (status = 200, description = "Tenant metrics overview", body = TenantMetricsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Tenant metrics overview
///
/// Returns aggregate metrics for this tenant over an adjustable window
/// (`since`/`until`, RFC 3339; the last 30 days by default, 90 at most),
/// headed by what the dashboard shows of the tenant itself: its slug and
/// name, primary domain, contact address, timezone, locale, status and
/// when it was made. Read-only.
///
/// Requires `Metrics(View)` in this tenant: the overview is the tenant's
/// own dashboard, and its own users are who read it.
pub(crate) async fn get_tenant_metrics(
    State(tenant): State<TenantState>,
    caller: TenantCaller,
    MetricsWindowQuery(window): MetricsWindowQuery,
) -> Result<Json<TenantMetricsResponse>, ApiError> {
    let label = tenant.lifecycle.label.execute(&caller.caller, ()).await?;
    let metrics = tenant
        .lifecycle
        .metrics
        .execute(&caller.caller, window)
        .await?;
    Ok(Json(TenantMetricsResponse::from_parts(&label, metrics)))
}
