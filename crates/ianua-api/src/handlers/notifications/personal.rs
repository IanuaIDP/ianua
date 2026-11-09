//! Personal preference handlers: how notifications reach an organization
//! member or an operator, one channel per category.

use axum::extract::State;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::notifications::NotificationState;

use crate::dto::notifications::{PreferenceResponse, UpdatePreferencesBody};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::{Operator, OrgMember};
use crate::extractors::json::Json;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/notifications/preferences",
    tag = "Notifications",
    responses(
        (status = 200, description = "Success", body = Vec<PreferenceResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such organization", body = ErrorBody)
    )
)]
/// Get my notification preferences (organization member)
///
/// The calling member's delivery channel for each category, as
/// `{ category, channel }` pairs: `InApp`, `InAppAndEmail` or `Disabled`.
/// A category the member never set is `InApp`. Requires a member's own
/// session or organization API key.
pub(crate) async fn member_get_preferences(
    State(notifications): State<NotificationState>,
    member: OrgMember,
) -> Result<Json<Vec<PreferenceResponse>>, ApiError> {
    let chosen = notifications
        .personal
        .member
        .execute(&member.caller, ())
        .await?;
    Ok(Json(PreferenceResponse::listed(chosen.preferences())))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/notifications/preferences",
    tag = "Notifications",
    request_body = UpdatePreferencesBody,
    responses(
        (status = 200, description = "Success", body = Vec<PreferenceResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such organization", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Update my notification preferences (organization member)
///
/// Sets the calling member's delivery channel for the categories listed,
/// as `{ category, channel }` entries; the other categories keep theirs.
/// Answers the whole set after the change, and records
/// `notifications.member_preferences_updated` in the organization's trail.
/// Requires a member's own session or organization API key.
pub(crate) async fn member_update_preferences(
    State(notifications): State<NotificationState>,
    member: OrgMember,
    Json(body): Json<UpdatePreferencesBody>,
) -> Result<Json<Vec<PreferenceResponse>>, ApiError> {
    let chosen = notifications
        .personal
        .update_member
        .execute(&member.caller, &member.auditor, body.updates())
        .await?;
    Ok(Json(PreferenceResponse::listed(chosen.preferences())))
}

#[utoipa::path(
    get,
    path = "/api/v1/notifications/preferences",
    tag = "Notifications",
    responses(
        (status = 200, description = "Success", body = Vec<PreferenceResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// Get my notification preferences (operator)
///
/// The calling operator's delivery channel for each category, as
/// `{ category, channel }` pairs: `InApp`, `InAppAndEmail` or `Disabled`.
/// A category the operator never set is `InApp`. Requires an operator's
/// own key.
pub(crate) async fn operator_get_preferences(
    State(notifications): State<NotificationState>,
    operator: Operator,
) -> Result<Json<Vec<PreferenceResponse>>, ApiError> {
    let chosen = notifications
        .personal
        .operator
        .execute(&operator.caller, ())
        .await?;
    Ok(Json(PreferenceResponse::listed(chosen.preferences())))
}

#[utoipa::path(
    patch,
    path = "/api/v1/notifications/preferences",
    tag = "Notifications",
    request_body = UpdatePreferencesBody,
    responses(
        (status = 200, description = "Success", body = Vec<PreferenceResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Update my notification preferences (operator)
///
/// Sets the calling operator's delivery channel for the categories listed,
/// as `{ category, channel }` entries; the other categories keep theirs.
/// Answers the whole set after the change, and records
/// `notifications.operator_preferences_updated` in the platform's trail.
/// Requires an operator's own key.
pub(crate) async fn operator_update_preferences(
    State(notifications): State<NotificationState>,
    operator: Operator,
    Json(body): Json<UpdatePreferencesBody>,
) -> Result<Json<Vec<PreferenceResponse>>, ApiError> {
    let chosen = notifications
        .personal
        .update_operator
        .execute(&operator.caller, &operator.auditor, body.updates())
        .await?;
    Ok(Json(PreferenceResponse::listed(chosen.preferences())))
}
