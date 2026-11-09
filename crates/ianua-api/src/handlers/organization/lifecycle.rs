//! Organization handlers: the organization itself, its status, its metrics
//! overview and its sign-in settings.

use axum::extract::State;
use ianua_app::ports::organization::OrganizationSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::organization::lifecycle::{
    StatusChange, UpdateOrganizationAuthConfigRequest,
};
use ianua_assembly::organization::OrganizationState;
use ianua_domain::domains::organization::status::OrganizationStatus;
use ianua_domain::shared::config::DomainLimits;

use crate::dto::organization::lifecycle::{
    OrgAuthConfigBody, OrgMetricsResponse, OrganizationFilterParams, OrganizationResponse,
    UpdateOrgAuthConfigBody, UpdateOrganizationBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::{Operator, OrgMember};
use crate::extractors::json::Json;
use crate::extractors::listing::ListingQuery;
use crate::extractors::metrics_window::MetricsWindowQuery;
use crate::extractors::organization::OrgSteward;
use crate::extractors::pagination::PaginationParams;
use crate::extractors::sort::SortQuery;
use crate::response::{NoContent, PageResponse};

#[utoipa::path(
    get,
    path = "/api/v1/organizations",
    tag = "Organizations",
    params(OrganizationFilterParams, SortQuery<OrganizationSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<OrganizationResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List organizations
///
/// Every organization on the platform, optionally filtered by `status`
/// (`Active` / `Suspended` / `Closed`), sortable and paginated. Each entry
/// carries the slug, display name, plan, and lifecycle status. Read-only.
/// Requires an operator's own key.
pub(crate) async fn list_organizations(
    State(organization): State<OrganizationState>,
    operator: Operator,
    ListingQuery {
        query: filter,
        sort,
        page: pagination,
    }: ListingQuery<OrganizationFilterParams, OrganizationSortField>,
) -> Result<Json<PageResponse<OrganizationResponse>>, ApiError> {
    let page = organization
        .lifecycle
        .list
        .execute(&operator.caller, filter.listing(sort, pagination))
        .await?;
    Ok(Json(PageResponse::from_page(
        page,
        OrganizationResponse::from,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}",
    tag = "Organizations",
    responses(
        (status = 200, description = "Success", body = OrganizationResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get an organization
///
/// The caller's own organization (named by `{org_slug}`) with its slug,
/// display name, contact email, plan, and lifecycle `status`. Read-only.
/// Requires a member's own session or organization API key.
pub(crate) async fn get_organization(
    State(organization): State<OrganizationState>,
    member: OrgMember,
) -> Result<Json<OrganizationResponse>, ApiError> {
    let found = organization
        .lifecycle
        .get
        .execute(&member.caller, ())
        .await?;
    Ok(Json(OrganizationResponse::from(found)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}",
    tag = "Organizations",
    request_body = UpdateOrganizationBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Update organization details
///
/// Partial update: send `name`, `contact_email`, and/or `display_name` to
/// change just those; omit any to leave it. A field sent with its current
/// value records nothing and notifies nobody. This edits profile fields
/// only: the status has its suspend, reactivate and close endpoints, and
/// the plan its own. Returns `422` for an invalid value. The app decides
/// whether the caller may update the organization.
pub(crate) async fn update_organization(
    State(organization): State<OrganizationState>,
    State(limits): State<DomainLimits>,
    member: OrgMember,
    Json(body): Json<UpdateOrganizationBody>,
) -> Result<NoContent, ApiError> {
    let request = body.into_request(&limits)?;
    organization
        .lifecycle
        .update
        .execute(&member.caller, &member.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/suspend",
    tag = "Organizations",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Not active", body = ErrorBody)
    )
)]
/// Suspend an organization
///
/// Freezes an `Active` organization: its sessions all end at once and its
/// tenants stop accepting traffic (deny-by-default) until it is
/// reactivated. An owner may pause their own organization; an operator may
/// suspend any, for billing or policy issues.
///
/// **State.** `Active -> Suspended`. Returns `404` if the organization does
/// not exist, or `422` if it is not `Active`. Records
/// `organization.status_changed`.
pub(crate) async fn suspend_organization(
    State(organization): State<OrganizationState>,
    steward: OrgSteward,
) -> Result<NoContent, ApiError> {
    let change = StatusChange {
        organization_id: steward.organization,
        to: OrganizationStatus::Suspended,
    };
    organization
        .lifecycle
        .change_status
        .execute(&steward.caller, &steward.auditor, change)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/reactivate",
    tag = "Organizations",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Not suspended", body = ErrorBody)
    )
)]
/// Reactivate an organization
///
/// Lifts a suspension: a `Suspended` organization returns to `Active` and
/// its tenants can serve traffic again. Only the platform lifts a
/// suspension the platform made.
///
/// **State.** `Suspended -> Active`. Returns `404` if the organization does
/// not exist, or `422` if it is not `Suspended`. Records
/// `organization.status_changed`.
pub(crate) async fn reactivate_organization(
    State(organization): State<OrganizationState>,
    steward: OrgSteward,
) -> Result<NoContent, ApiError> {
    let change = StatusChange {
        organization_id: steward.organization,
        to: OrganizationStatus::Active,
    };
    organization
        .lifecycle
        .change_status
        .execute(&steward.caller, &steward.auditor, change)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/close",
    tag = "Organizations",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Already closed", body = ErrorBody)
    )
)]
/// Close an organization
///
/// Permanently closes the organization: its sessions end and the
/// organization and its data are scheduled for deletion. This is the
/// terminal state and cannot be undone.
///
/// **State.** `Active | Suspended -> Closed` (terminal). Returns `404` if
/// the organization does not exist, or `422` if it is already `Closed`.
/// Records `organization.status_changed`.
pub(crate) async fn close_organization(
    State(organization): State<OrganizationState>,
    steward: OrgSteward,
) -> Result<NoContent, ApiError> {
    let change = StatusChange {
        organization_id: steward.organization,
        to: OrganizationStatus::Closed,
    };
    organization
        .lifecycle
        .change_status
        .execute(&steward.caller, &steward.auditor, change)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/metrics",
    tag = "Organizations",
    params(MetricsWindowQuery),
    responses(
        (status = 200, description = "Organization metrics overview", body = OrgMetricsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Organization metrics overview
///
/// Aggregate figures for this organization over an adjustable window
/// (`since` / `until`, RFC 3339, at most 90 days): sign-in timing and
/// success, users, tenants, active sessions and proxied API usage, each
/// trended against the window before. Read-only. The app decides whether
/// the caller may view metrics.
pub(crate) async fn get_org_metrics(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    MetricsWindowQuery(window): MetricsWindowQuery,
) -> Result<Json<OrgMetricsResponse>, ApiError> {
    let metrics = organization
        .lifecycle
        .metrics
        .execute(&member.caller, window)
        .await?;
    Ok(Json(OrgMetricsResponse::from(metrics)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/auth-config",
    tag = "Organizations",
    responses(
        (status = 200, description = "Success", body = OrgAuthConfigBody),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get the organization's sign-in settings
///
/// Everything about how this organization's administrators reach the
/// management plane: the methods allowed, the password rules, the MFA
/// policy, session and idle lifetimes, the lockout threshold and duration,
/// the IP allowlist, and the step-up policy.
///
/// Distinct from a tenant's `auth-config`, which governs that tenant's own
/// users. An organization that never changed it gets the defaults. Read
/// from the organization record, so whoever may view the organization may
/// read it.
pub(crate) async fn get_auth_config(
    State(organization): State<OrganizationState>,
    member: OrgMember,
) -> Result<Json<OrgAuthConfigBody>, ApiError> {
    let found = organization
        .lifecycle
        .get
        .execute(&member.caller, ())
        .await?;
    Ok(Json(OrgAuthConfigBody::from(found)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/auth-config",
    tag = "Organizations",
    request_body = UpdateOrgAuthConfigBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the proof is wrong", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Replace the organization's sign-in settings
///
/// Full replace, not a partial update: send every field, plus `proof`, the
/// caller's password typed again (with a code from their second factor
/// when they have one), so a stolen session alone never weakens how the
/// organization is protected. A rejected config changes nothing.
///
/// **These settings govern the accounts with the most reach in the
/// system.** `ip_allowlist` refuses every address outside it, including
/// your own; removing `Password` from `enabled_methods` stops password
/// sign-in for every administrator; `max_login_attempts` applies from the
/// next failure. Turning on `require_mfa_new_device` is what gives "trust
/// this device" its meaning.
///
/// Returns `422` when the config contradicts itself: no method enabled, a
/// method org sign-in does not implement, a password floor below 8, an
/// idle timeout outlasting its session, a lockout threshold under 2, or a
/// sensitive assurance level below the ordinary one. Records
/// `organization.auth_config_updated`.
pub(crate) async fn update_auth_config(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Json(body): Json<UpdateOrgAuthConfigBody>,
) -> Result<NoContent, ApiError> {
    organization
        .lifecycle
        .update_auth_config
        .execute(
            &member.caller,
            &member.auditor,
            UpdateOrganizationAuthConfigRequest::try_from(body)?,
        )
        .await?;
    Ok(NoContent)
}
