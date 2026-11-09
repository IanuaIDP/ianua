//! Notification handlers: the operator's, an organization member's and a
//! tenant user's inbox, and a tenant user's delivery preferences. A
//! member's and an operator's own preferences are in `personal`, an
//! organization's destinations outside the app in `destinations`.

pub mod destinations;
pub mod personal;

use axum::extract::{Path, State};
use ianua_app::ports::notifications::NotificationSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::notifications::NotificationReader;
use ianua_assembly::notifications::NotificationState;

use crate::dto::notifications::{
    MarkAllReadResponse, NotificationFilterParams, NotificationResponse, PreferenceResponse,
    UnreadCountResponse, UpdatePreferencesBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::{Operator, OrgMember, TenantCaller};
use crate::extractors::json::Json;
use crate::extractors::listing::ListingQuery;
use crate::extractors::pagination::PaginationParams;
use crate::extractors::paths::notifications::NotificationPath;
use crate::extractors::sort::SortQuery;
use crate::response::{NoContent, PageResponse};

#[utoipa::path(
    get,
    path = "/api/v1/notifications",
    tag = "Notifications",
    params(NotificationFilterParams, SortQuery<NotificationSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<NotificationResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List my notifications (operator)
///
/// Returns the calling operator's notifications, the platform inbox.
/// Sortable (for example by `severity`) and paginated; `unread_only=true`
/// returns only unread ones. Each entry carries the `event_type` that
/// produced it, its `category` and `severity`, a `title` with an optional
/// `body`, an optional `resource_id` naming what it is about, the `read`
/// flag and `created_at`. Requires an operator's own key.
pub(crate) async fn platform_list(
    State(notifications): State<NotificationState>,
    operator: Operator,
    ListingQuery {
        query: filter,
        sort,
        page: pagination,
    }: ListingQuery<NotificationFilterParams, NotificationSortField>,
) -> Result<Json<PageResponse<NotificationResponse>>, ApiError> {
    let reader = NotificationReader::Operator(operator.caller);
    let page = notifications
        .list
        .execute(&reader, filter.listing(sort, pagination))
        .await?;
    Ok(Json(PageResponse::from_page(
        page,
        NotificationResponse::from,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/notifications/unread-count",
    tag = "Notifications",
    responses(
        (status = 200, description = "Success", body = UnreadCountResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// Unread notification count (operator)
///
/// How many of the calling operator's notifications are unread: a cheap
/// badge poll instead of fetching the list. Requires an operator's own key.
pub(crate) async fn platform_unread_count(
    State(notifications): State<NotificationState>,
    operator: Operator,
) -> Result<Json<UnreadCountResponse>, ApiError> {
    let reader = NotificationReader::Operator(operator.caller);
    let count = notifications.unread_count.execute(&reader, ()).await?;
    Ok(Json(UnreadCountResponse { count }))
}

#[utoipa::path(
    post,
    path = "/api/v1/notifications/{id}/read",
    tag = "Notifications",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not in this inbox", body = ErrorBody)
    )
)]
/// Mark a notification read (operator)
///
/// Marks one of the calling operator's notifications read. There is no
/// mark-unread. `404` when the notification is not in their inbox. Records
/// `notifications.notification_read` in the platform's trail, so the
/// operator's other devices follow. Requires an operator's own key.
pub(crate) async fn platform_mark_read(
    State(notifications): State<NotificationState>,
    operator: Operator,
    Path(path): Path<NotificationPath>,
) -> Result<NoContent, ApiError> {
    let reader = NotificationReader::Operator(operator.caller);
    notifications
        .mark_read
        .execute(&reader, &operator.auditor, path.notification())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/notifications/read-all",
    tag = "Notifications",
    responses(
        (status = 200, description = "Success", body = MarkAllReadResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// Mark all notifications read (operator)
///
/// Marks every one of the calling operator's notifications read and says
/// how many changed (`marked`). Records
/// `notifications.all_notifications_read` in the platform's trail.
/// Requires an operator's own key.
pub(crate) async fn platform_mark_all_read(
    State(notifications): State<NotificationState>,
    operator: Operator,
) -> Result<Json<MarkAllReadResponse>, ApiError> {
    let reader = NotificationReader::Operator(operator.caller);
    let marked = notifications
        .mark_all_read
        .execute(&reader, &operator.auditor, ())
        .await?;
    Ok(Json(MarkAllReadResponse { marked }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/notifications",
    tag = "Notifications",
    params(NotificationFilterParams, SortQuery<NotificationSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<NotificationResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such organization", body = ErrorBody)
    )
)]
/// List my notifications (organization member)
///
/// Returns the calling member's notifications in their organization's
/// inbox. Sortable and paginated; `unread_only=true` returns only unread
/// ones. Same entry shape as the other inboxes. Requires a member's own
/// session or organization API key.
pub(crate) async fn org_list(
    State(notifications): State<NotificationState>,
    member: OrgMember,
    ListingQuery {
        query: filter,
        sort,
        page: pagination,
    }: ListingQuery<NotificationFilterParams, NotificationSortField>,
) -> Result<Json<PageResponse<NotificationResponse>>, ApiError> {
    let reader = NotificationReader::Member(member.caller);
    let page = notifications
        .list
        .execute(&reader, filter.listing(sort, pagination))
        .await?;
    Ok(Json(PageResponse::from_page(
        page,
        NotificationResponse::from,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/notifications/unread-count",
    tag = "Notifications",
    responses(
        (status = 200, description = "Success", body = UnreadCountResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such organization", body = ErrorBody)
    )
)]
/// Unread notification count (organization member)
///
/// How many of the calling member's notifications are unread. Requires a
/// member's own session or organization API key.
pub(crate) async fn org_unread_count(
    State(notifications): State<NotificationState>,
    member: OrgMember,
) -> Result<Json<UnreadCountResponse>, ApiError> {
    let reader = NotificationReader::Member(member.caller);
    let count = notifications.unread_count.execute(&reader, ()).await?;
    Ok(Json(UnreadCountResponse { count }))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/notifications/{id}/read",
    tag = "Notifications",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not in this inbox", body = ErrorBody)
    )
)]
/// Mark a notification read (organization member)
///
/// Marks one of the calling member's notifications read. `404` when the
/// notification is not in their inbox. Records
/// `notifications.notification_read` in the organization's trail. Requires
/// a member's own session or organization API key.
pub(crate) async fn org_mark_read(
    State(notifications): State<NotificationState>,
    member: OrgMember,
    Path(path): Path<NotificationPath>,
) -> Result<NoContent, ApiError> {
    let reader = NotificationReader::Member(member.caller);
    notifications
        .mark_read
        .execute(&reader, &member.auditor, path.notification())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/notifications/read-all",
    tag = "Notifications",
    responses(
        (status = 200, description = "Success", body = MarkAllReadResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such organization", body = ErrorBody)
    )
)]
/// Mark all notifications read (organization member)
///
/// Marks every one of the calling member's notifications read and says how
/// many changed (`marked`). Records `notifications.all_notifications_read`
/// in the organization's trail. Requires a member's own session or
/// organization API key.
pub(crate) async fn org_mark_all_read(
    State(notifications): State<NotificationState>,
    member: OrgMember,
) -> Result<Json<MarkAllReadResponse>, ApiError> {
    let reader = NotificationReader::Member(member.caller);
    let marked = notifications
        .mark_all_read
        .execute(&reader, &member.auditor, ())
        .await?;
    Ok(Json(MarkAllReadResponse { marked }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/notifications",
    tag = "Notifications",
    params(NotificationFilterParams, SortQuery<NotificationSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<NotificationResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List my notifications (tenant user)
///
/// Returns the calling user's notifications in the tenant's inbox. Sortable
/// and paginated; `unread_only=true` returns only unread ones. Only
/// notifications whose category the user may see are listed, so nobody
/// learns of an area they cannot reach. Same entry shape as the other
/// inboxes. Requires a tenant user's session or key.
pub(crate) async fn tenant_list(
    State(notifications): State<NotificationState>,
    tenant: TenantCaller,
    ListingQuery {
        query: filter,
        sort,
        page: pagination,
    }: ListingQuery<NotificationFilterParams, NotificationSortField>,
) -> Result<Json<PageResponse<NotificationResponse>>, ApiError> {
    let reader = NotificationReader::Tenant(tenant.caller);
    let page = notifications
        .list
        .execute(&reader, filter.listing(sort, pagination))
        .await?;
    Ok(Json(PageResponse::from_page(
        page,
        NotificationResponse::from,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/notifications/unread-count",
    tag = "Notifications",
    responses(
        (status = 200, description = "Success", body = UnreadCountResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// Unread notification count (tenant user)
///
/// How many of the calling user's notifications are unread, counting only
/// the categories they may see, so the badge matches the list. Requires a
/// tenant user's session or key.
pub(crate) async fn tenant_unread_count(
    State(notifications): State<NotificationState>,
    tenant: TenantCaller,
) -> Result<Json<UnreadCountResponse>, ApiError> {
    let reader = NotificationReader::Tenant(tenant.caller);
    let count = notifications.unread_count.execute(&reader, ()).await?;
    Ok(Json(UnreadCountResponse { count }))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/notifications/{id}/read",
    tag = "Notifications",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not in this inbox", body = ErrorBody)
    )
)]
/// Mark a notification read (tenant user)
///
/// Marks one of the calling user's notifications read. `404` when the
/// notification is not in their inbox. Records
/// `notifications.notification_read` in the tenant's trail. Requires a
/// tenant user's session or key.
pub(crate) async fn tenant_mark_read(
    State(notifications): State<NotificationState>,
    tenant: TenantCaller,
    Path(path): Path<NotificationPath>,
) -> Result<NoContent, ApiError> {
    let reader = NotificationReader::Tenant(tenant.caller);
    notifications
        .mark_read
        .execute(&reader, &tenant.auditor, path.notification())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/notifications/read-all",
    tag = "Notifications",
    responses(
        (status = 200, description = "Success", body = MarkAllReadResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// Mark all notifications read (tenant user)
///
/// Marks every one of the calling user's notifications read, including
/// ones in categories they can no longer see, and says how many changed
/// (`marked`). Records `notifications.all_notifications_read` in the
/// tenant's trail. Requires a tenant user's session or key.
pub(crate) async fn tenant_mark_all_read(
    State(notifications): State<NotificationState>,
    tenant: TenantCaller,
) -> Result<Json<MarkAllReadResponse>, ApiError> {
    let reader = NotificationReader::Tenant(tenant.caller);
    let marked = notifications
        .mark_all_read
        .execute(&reader, &tenant.auditor, ())
        .await?;
    Ok(Json(MarkAllReadResponse { marked }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/notifications/preferences",
    tag = "Notifications",
    responses(
        (status = 200, description = "Success", body = Vec<PreferenceResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// Get my notification preferences (tenant user)
///
/// The calling user's delivery channel for each category, as
/// `{ category, channel }` pairs. A channel is `InApp` (the inbox and live
/// dashboard only), `InAppAndEmail` (also emailed) or `Disabled` (not
/// delivered). A category the user never set is `InApp`. Only tenant users
/// have preferences. Requires a tenant user's session.
pub(crate) async fn tenant_get_preferences(
    State(notifications): State<NotificationState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<PreferenceResponse>>, ApiError> {
    let set = notifications
        .get_preferences
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(PreferenceResponse::all_of(&set)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/notifications/preferences",
    tag = "Notifications",
    request_body = UpdatePreferencesBody,
    responses(
        (status = 200, description = "Success", body = Vec<PreferenceResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// Update my notification preferences (tenant user)
///
/// Sets the calling user's delivery channel for the categories listed, as
/// `{ category, channel }` entries; the other categories keep theirs.
/// Answers the whole set after the change. Records one
/// `notifications.preferences_updated` per entry in the tenant's trail.
/// Requires a tenant user's session.
pub(crate) async fn tenant_update_preferences(
    State(notifications): State<NotificationState>,
    tenant: TenantCaller,
    Json(body): Json<UpdatePreferencesBody>,
) -> Result<Json<Vec<PreferenceResponse>>, ApiError> {
    let set = notifications
        .update_preferences
        .execute(&tenant.caller, &tenant.auditor, body.into())
        .await?;
    Ok(Json(PreferenceResponse::all_of(&set)))
}
