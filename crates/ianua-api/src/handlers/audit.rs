//! Audit handlers: the audit log of an organization, of a tenant and of the
//! whole platform, read a page at a time or exported in the background,
//! and the last verdict on a tenant's audit chain.

use axum::extract::{Path, State};
use ianua_app::ports::audit::AuditLogSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::audit::AuditState;

use crate::dto::audit::{
    AuditChainVerificationResponse, AuditExportAcceptedResponse, AuditExportBody,
    AuditExportResponse, AuditLogEntryResponse, AuditLogQueryParams,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::{Operator, OrgMember, TenantCaller};
use crate::extractors::json::Json;
use crate::extractors::listing::PageQuery;
use crate::extractors::pagination::PaginationParams;
use crate::extractors::paths::audit::AuditExportPath;
use crate::extractors::sort::SortQuery;
use crate::response::{Accepted, PageResponse};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/audit-log",
    tag = "Organizations",
    params(AuditLogQueryParams, SortQuery<AuditLogSortField>, PaginationParams),
    responses(
        (status = 200, description = "Audit log entries", body = PageResponse<AuditLogEntryResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// List audit-log entries
///
/// Returns this organization's audit-log entries, filtered by `event_type`
/// (a prefix), a time window (`since` / `before`, RFC 3339), the `actor`,
/// a `tenant_id`, the `target` entity and the client's `ip_address`,
/// sortable and paged by cursor (`after` / `limit`, 20 by default, at most 100). Each entry
/// records the event type, actor, tenant, target, address, details and
/// time. The log holds the organization's own records and those of the
/// tenants the caller reaches: every tenant for an owner or admin, the
/// tenants granted to a member, none for a viewer. A `tenant_id` they do
/// not reach reads as a tenant with no records. Read-only.
///
/// Requires a member who may read the organization's audit log.
pub(crate) async fn list_audit_log(
    State(audit): State<AuditState>,
    member: OrgMember,
    SortQuery(sort): SortQuery<AuditLogSortField>,
    PageQuery {
        query: params,
        page,
    }: PageQuery<AuditLogQueryParams>,
) -> Result<Json<PageResponse<AuditLogEntryResponse>>, ApiError> {
    let log = audit
        .list
        .execute(&member.caller, params.listing(sort, page)?)
        .await?;
    Ok(Json(PageResponse::from_page(
        log,
        AuditLogEntryResponse::from,
    )))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/audit-log/exports",
    tag = "Organizations",
    request_body = AuditExportBody,
    responses(
        (status = 202, description = "The export is being written", body = AuditExportAcceptedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "As many exports are waiting as the organization may have", body = ErrorBody)
    )
)]
/// Export the audit log
///
/// Starts an export of the organization's audit-log entries, with the same
/// filters as the list, as `csv` (the default, columns
/// `id,event_type,actor,tenant,target_id,ip_address,occurred_at,acted_through,through_id`) or
/// `json`. The worker writes every matching entry, newest first, as the log
/// stood when the export was asked for; nothing is cut off. Poll
/// `GET .../audit-log/exports/{id}` for the file. Only a few exports may
/// wait at once. The file holds what the caller reaches when they ask, as
/// the list does. Records `organization.audit_log_export_requested`.
///
/// Requires a member who may export the organization's audit log
/// (`org:audit_log:export`); viewing it is not enough.
pub(crate) async fn request_audit_log_export(
    State(audit): State<AuditState>,
    member: OrgMember,
    body: Option<Json<AuditExportBody>>,
) -> Result<Accepted<AuditExportAcceptedResponse>, ApiError> {
    let request = AuditExportBody::request(body.map(|Json(body)| body))?;
    let id = audit
        .exports
        .request_for_org
        .execute(&member.caller, &member.auditor, request)
        .await?;
    Ok(Accepted(id.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/audit-log/exports/{id}",
    tag = "Organizations",
    responses(
        (status = 200, description = "The export, with a download link once written", body = AuditExportResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get an audit log export
///
/// Where the export stands: `pending`, `ready`, `failed` or `expired`. Once
/// ready it says how many entries the file holds and until when it may be
/// downloaded, with a signed `download_url` that works once, for a few
/// minutes. Each answer while it is ready hands out a fresh link and
/// records `organization.audit_log_export_downloaded`. An export holding
/// records of a tenant the caller does not reach now answers `404`.
///
/// Requires a member who may export the organization's audit log
/// (`org:audit_log:export`); viewing it is not enough.
pub(crate) async fn get_audit_log_export(
    State(audit): State<AuditState>,
    member: OrgMember,
    Path(path): Path<AuditExportPath>,
) -> Result<Json<AuditExportResponse>, ApiError> {
    let answer = audit
        .exports
        .get_for_org
        .execute(&member.caller, &member.auditor, path.export())
        .await?;
    Ok(Json(answer.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/audit-log",
    tag = "Tenants",
    params(AuditLogQueryParams, SortQuery<AuditLogSortField>, PaginationParams),
    responses(
        (status = 200, description = "Audit log entries", body = PageResponse<AuditLogEntryResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// List the tenant's audit-log entries
///
/// Returns this tenant's own audit-log entries, with the same filters,
/// sorting and paging as the organization's log. The log read is always
/// this tenant's: a `tenant_id` naming another is ignored. Read-only.
///
/// Requires `ViewAuditLog`.
pub(crate) async fn list_tenant_audit_log(
    State(audit): State<AuditState>,
    tenant: TenantCaller,
    SortQuery(sort): SortQuery<AuditLogSortField>,
    PageQuery {
        query: params,
        page,
    }: PageQuery<AuditLogQueryParams>,
) -> Result<Json<PageResponse<AuditLogEntryResponse>>, ApiError> {
    let log = audit
        .list_for_tenant
        .execute(&tenant.caller, params.listing(sort, page)?)
        .await?;
    Ok(Json(PageResponse::from_page(
        log,
        AuditLogEntryResponse::from,
    )))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/audit-log/exports",
    tag = "Tenants",
    request_body = AuditExportBody,
    responses(
        (status = 202, description = "The export is being written", body = AuditExportAcceptedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "As many exports are waiting as the tenant may have", body = ErrorBody)
    )
)]
/// Export the tenant's audit log
///
/// Starts an export of this tenant's own audit-log entries, with the same
/// filters and formats as the organization's export, written by the worker
/// in full. Poll `GET .../audit-log/exports/{id}` for the file. Records
/// `tenant.audit_log_export_requested`.
///
/// Requires `ExportAuditLog` (`idp:audit_log:export`); viewing the log is
/// not enough.
pub(crate) async fn request_tenant_audit_log_export(
    State(audit): State<AuditState>,
    tenant: TenantCaller,
    body: Option<Json<AuditExportBody>>,
) -> Result<Accepted<AuditExportAcceptedResponse>, ApiError> {
    let request = AuditExportBody::request(body.map(|Json(body)| body))?;
    let id = audit
        .exports
        .request_for_tenant
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Accepted(id.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/audit-log/exports/{id}",
    tag = "Tenants",
    responses(
        (status = 200, description = "The export, with a download link once written", body = AuditExportResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get an export of the tenant's audit log
///
/// Where the export stands, and once ready a signed `download_url` that
/// works once, for a few minutes, as for the organization's exports.
/// Records `tenant.audit_log_export_downloaded` for each link handed out.
///
/// Requires `ExportAuditLog` (`idp:audit_log:export`); viewing the log is
/// not enough.
pub(crate) async fn get_tenant_audit_log_export(
    State(audit): State<AuditState>,
    tenant: TenantCaller,
    Path(path): Path<AuditExportPath>,
) -> Result<Json<AuditExportResponse>, ApiError> {
    let answer = audit
        .exports
        .get_for_tenant
        .execute(&tenant.caller, &tenant.auditor, path.export())
        .await?;
    Ok(Json(answer.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/audit-log",
    tag = "Operators",
    params(AuditLogQueryParams, SortQuery<AuditLogSortField>, PaginationParams),
    responses(
        (status = 200, description = "Audit log entries", body = PageResponse<AuditLogEntryResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// List the platform's audit-log entries (operator)
///
/// Returns audit-log entries across the whole platform: platform,
/// organization and tenant records alike, with the same filters, sorting
/// and paging as the organization's log; `tenant_id` narrows to one
/// tenant. Read-only.
///
/// Requires an operator's own key.
pub(crate) async fn list_platform_audit_log(
    State(audit): State<AuditState>,
    operator: Operator,
    SortQuery(sort): SortQuery<AuditLogSortField>,
    PageQuery {
        query: params,
        page,
    }: PageQuery<AuditLogQueryParams>,
) -> Result<Json<PageResponse<AuditLogEntryResponse>>, ApiError> {
    let log = audit
        .list_for_platform
        .execute(&operator.caller, params.listing(sort, page)?)
        .await?;
    Ok(Json(PageResponse::from_page(
        log,
        AuditLogEntryResponse::from,
    )))
}

#[utoipa::path(
    post,
    path = "/api/v1/audit-log/exports",
    tag = "Operators",
    request_body = AuditExportBody,
    responses(
        (status = 202, description = "The export is being written", body = AuditExportAcceptedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "As many platform exports are waiting as may", body = ErrorBody)
    )
)]
/// Export the platform's audit log (operator)
///
/// Starts an export of audit-log entries across the whole platform, with
/// the same filters and formats as the organization's export, written by
/// the worker in full. Poll `GET /api/v1/audit-log/exports/{id}` for the
/// file. Records `operator.audit_log_export_requested`.
///
/// Requires an operator's own key.
pub(crate) async fn request_platform_audit_log_export(
    State(audit): State<AuditState>,
    operator: Operator,
    body: Option<Json<AuditExportBody>>,
) -> Result<Accepted<AuditExportAcceptedResponse>, ApiError> {
    let request = AuditExportBody::request(body.map(|Json(body)| body))?;
    let id = audit
        .exports
        .request_for_platform
        .execute(&operator.caller, &operator.auditor, request)
        .await?;
    Ok(Accepted(id.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/audit-log/exports/{id}",
    tag = "Operators",
    responses(
        (status = 200, description = "The export, with a download link once written", body = AuditExportResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get an export of the platform's audit log (operator)
///
/// Where the export stands, and once ready a signed `download_url` that
/// works once, for a few minutes. Records
/// `operator.audit_log_export_downloaded` for each link handed out.
///
/// Requires an operator's own key.
pub(crate) async fn get_platform_audit_log_export(
    State(audit): State<AuditState>,
    operator: Operator,
    Path(path): Path<AuditExportPath>,
) -> Result<Json<AuditExportResponse>, ApiError> {
    let answer = audit
        .exports
        .get_for_platform
        .execute(&operator.caller, &operator.auditor, path.export())
        .await?;
    Ok(Json(answer.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/audit/verify",
    tag = "Agents",
    responses(
        (status = 200, description = "The last verdict on the chain", body = AuditChainVerificationResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Verify the tamper-evident audit chain
///
/// The last verdict of the scheduled sweep that walks the tenant's
/// hash-linked audit records, proving no record was removed, reordered or
/// edited after the fact. Answers `status` (`intact`, `intact_so_far` while
/// a long chain is still being walked, `broken`, or `not_verified_yet`
/// before the first sweep), `verified_at`, the last record verified
/// (`checked_through_seq`), and the first tampered record when it is
/// broken. The chain is not walked in the request. This is the evidence
/// that an agent stayed in purpose. Read-only.
///
/// Requires `AuditLog(View)`.
pub(crate) async fn verify_audit_chain(
    State(audit): State<AuditState>,
    tenant: TenantCaller,
) -> Result<Json<AuditChainVerificationResponse>, ApiError> {
    let verdict = audit.verify_chain.execute(&tenant.caller, ()).await?;
    Ok(Json(AuditChainVerificationResponse::from(verdict)))
}
