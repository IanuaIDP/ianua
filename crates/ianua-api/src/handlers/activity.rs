//! Activity handlers: the contribution heatmap of an organization and of
//! one tenant.

use axum::extract::State;
use ianua_app::use_case::Query as _;
use ianua_app::use_cases::activity::ActivityViewer;
use ianua_assembly::activity::ActivityState;

use crate::dto::activity::ActivityCalendarResponse;
use crate::error::{ApiError, ErrorBody};
use crate::extractors::calendar::CalendarQuery;
use crate::extractors::callers::{OrgMember, TenantCaller};
use crate::extractors::json::Json;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/activity",
    tag = "Organizations",
    params(CalendarQuery),
    responses(
        (status = 200, description = "Organization activity calendar", body = ActivityCalendarResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Organization contribution calendar
///
/// Counts audit events of the organization and the tenants the caller
/// reaches by UTC day: every tenant for an owner or admin, the tenants
/// granted to a member, none for a viewer.
/// Inclusive `from` and `to` dates use `YYYY-MM-DD`; defaults span the year
/// ending today. Reversed or oversized windows return `422`.
/// Returns `total`, `max_count`, occurring `categories` and oldest-first
/// `days`, including quiet days, with `count`, `level` (0 to 4) and `by_category`.
/// Categories group authentication, access, administration, identity,
/// provisioning and other events. Requires organization audit-read rights;
/// this read changes nothing. Use the tenant calendar for one tenant.
pub(crate) async fn org_activity(
    State(activity): State<ActivityState>,
    member: OrgMember,
    CalendarQuery(range): CalendarQuery,
) -> Result<Json<ActivityCalendarResponse>, ApiError> {
    let viewer = ActivityViewer::Organization(member.caller);
    let calendar = activity.calendar.execute(&viewer, range).await?;
    Ok(Json(ActivityCalendarResponse::from(calendar)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/activity",
    tag = "Tenants",
    params(CalendarQuery),
    responses(
        (status = 200, description = "Tenant activity calendar", body = ActivityCalendarResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Tenant contribution calendar
///
/// The same heatmap as the organization calendar, counting only this
/// tenant's events. Same window (`?from=&to=`), same response shape and
/// the same categories; use it for a tenant's own dashboard and the
/// organization calendar for the roll-up across all tenants. Read-only.
///
/// Requires `AuditLog(View)` in the tenant.
pub(crate) async fn tenant_activity(
    State(activity): State<ActivityState>,
    tenant: TenantCaller,
    CalendarQuery(range): CalendarQuery,
) -> Result<Json<ActivityCalendarResponse>, ApiError> {
    let viewer = ActivityViewer::Tenant(tenant.caller);
    let calendar = activity.calendar.execute(&viewer, range).await?;
    Ok(Json(ActivityCalendarResponse::from(calendar)))
}
