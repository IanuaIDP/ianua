//! Destination handlers: posting an organization's notifications to a
//! Slack or Teams channel or a webhook of its own, and changing, pausing,
//! resuming and removing such a destination.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::notifications::NotificationState;

use crate::dto::notifications::destinations::{
    DestinationAddedResponse, DestinationBody, DestinationChangedResponse, DestinationResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::OrgMember;
use crate::extractors::json::Json;
use crate::extractors::paths::notifications::DestinationPath;
use crate::response::{Created, NoContent};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/notifications/destinations",
    tag = "Notifications",
    responses(
        (status = 200, description = "The organization's destinations", body = Vec<DestinationResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such organization", body = ErrorBody)
    )
)]
/// List notification destinations
///
/// Every place outside the app this organization's notifications are
/// posted to: its name, `kind` (`slack`, `teams` or `webhook`), the
/// categories and least severity it receives, and whether it is `active`
/// or `paused`. Addresses and signing secrets are never shown. Read-only.
///
/// Requires a member who may view the organization's notifications.
pub(crate) async fn list_destinations(
    State(notifications): State<NotificationState>,
    member: OrgMember,
) -> Result<Json<Vec<DestinationResponse>>, ApiError> {
    let destinations = notifications
        .destinations
        .list
        .execute(&member.caller, ())
        .await?;
    Ok(Json(
        destinations.iter().map(DestinationResponse::from).collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/notifications/destinations",
    tag = "Notifications",
    request_body = DestinationBody,
    responses(
        (status = 201, description = "Destination added", body = DestinationAddedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such organization", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Add a notification destination
///
/// Posts this organization's notifications of the listed `categories`, at
/// `minimum_severity` or above, to a Slack channel or a Teams channel
/// (through its webhook address on their own hosts) or to a public HTTPS
/// endpoint of the organization's own, active at once. The address is
/// sealed at once and never shown again. A webhook's posts are signed: its
/// `signing_secret` is in this answer and never again. No category, a
/// category twice, or a Slack or Teams address on another host is `422`;
/// the plan's destination limit is `403`. Records
/// `notifications.destination_added`, naming the kind only.
///
/// Requires a member who may manage the organization's notifications.
pub(crate) async fn add_destination(
    State(notifications): State<NotificationState>,
    member: OrgMember,
    Json(body): Json<DestinationBody>,
) -> Result<Created<DestinationAddedResponse>, ApiError> {
    let added = notifications
        .destinations
        .add
        .execute(&member.caller, &member.auditor, body.try_into()?)
        .await?;
    Ok(Created(DestinationAddedResponse::from(added)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/notifications/destinations/{destination_id}",
    tag = "Notifications",
    request_body = DestinationBody,
    responses(
        (status = 200, description = "Destination changed", body = DestinationChangedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Change a notification destination
///
/// Replaces the destination's name, address and filter whole, with the
/// address typed again. A webhook gets a new signing secret, in this
/// answer and never again. Records `notifications.destination_changed`.
///
/// Requires a member who may manage the organization's notifications.
pub(crate) async fn reconfigure_destination(
    State(notifications): State<NotificationState>,
    member: OrgMember,
    Path(path): Path<DestinationPath>,
    Json(body): Json<DestinationBody>,
) -> Result<Json<DestinationChangedResponse>, ApiError> {
    let secret = notifications
        .destinations
        .reconfigure
        .execute(
            &member.caller,
            &member.auditor,
            body.into_reconfigure(path.destination())?,
        )
        .await?;
    Ok(Json(DestinationChangedResponse::from(secret)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/notifications/destinations/{destination_id}/pause",
    tag = "Notifications",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Already paused", body = ErrorBody)
    )
)]
/// Pause a notification destination
///
/// Stops posting to the destination until it is resumed; one already
/// paused is `422`. Records `notifications.destination_paused`.
///
/// Requires a member who may manage the organization's notifications.
pub(crate) async fn pause_destination(
    State(notifications): State<NotificationState>,
    member: OrgMember,
    Path(path): Path<DestinationPath>,
) -> Result<NoContent, ApiError> {
    notifications
        .destinations
        .pause
        .execute(&member.caller, &member.auditor, path.destination())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/notifications/destinations/{destination_id}/resume",
    tag = "Notifications",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Not paused", body = ErrorBody)
    )
)]
/// Resume a notification destination
///
/// Starts posting to a paused destination again; one not paused is
/// `422`. Records `notifications.destination_resumed`.
///
/// Requires a member who may manage the organization's notifications.
pub(crate) async fn resume_destination(
    State(notifications): State<NotificationState>,
    member: OrgMember,
    Path(path): Path<DestinationPath>,
) -> Result<NoContent, ApiError> {
    notifications
        .destinations
        .resume
        .execute(&member.caller, &member.auditor, path.destination())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/notifications/destinations/{destination_id}",
    tag = "Notifications",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Remove a notification destination
///
/// Stops posting to the destination for good and forgets its address and
/// secret. Records `notifications.destination_removed`.
///
/// Requires a member who may manage the organization's notifications.
pub(crate) async fn remove_destination(
    State(notifications): State<NotificationState>,
    member: OrgMember,
    Path(path): Path<DestinationPath>,
) -> Result<NoContent, ApiError> {
    notifications
        .destinations
        .remove
        .execute(&member.caller, &member.auditor, path.destination())
        .await?;
    Ok(NoContent)
}
