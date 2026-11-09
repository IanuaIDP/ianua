//! Notification endpoints: three inboxes, the delivery preferences of
//! tenant users, members and operators, and an organization's destinations
//! outside the app.

use axum::Router;
use utoipa::OpenApi;

use crate::dto::notifications::destinations::{
    DestinationAddedResponse, DestinationBody, DestinationChangedResponse, DestinationResponse,
    DestinationTargetBody,
};
use crate::dto::notifications::{
    MarkAllReadResponse, NotificationResponse, PreferenceResponse, PreferenceUpdateEntry,
    UnreadCountResponse, UpdatePreferencesBody,
};
use crate::handlers::notifications as handlers;
use crate::handlers::notifications::{destinations, personal};
use crate::method::{get, post, put, shared};
use crate::state::ApiState;

/// The notification endpoints.
pub(crate) fn routes() -> Router<ApiState> {
    let tenant = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/notifications";
    let org = "/api/v1/organizations/{org_slug}/notifications";
    platform_routes()
        .merge(organization_routes(org))
        .merge(tenant_routes(tenant))
}

/// Registers the operator inbox and its delivery preferences.
fn platform_routes() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/notifications", get(handlers::platform_list))
        .route(
            "/api/v1/notifications/unread-count",
            get(handlers::platform_unread_count),
        )
        .route(
            "/api/v1/notifications/{id}/read",
            post(handlers::platform_mark_read),
        )
        .route(
            "/api/v1/notifications/read-all",
            post(handlers::platform_mark_all_read),
        )
        .route(
            "/api/v1/notifications/preferences",
            get(personal::operator_get_preferences)
                .patch(shared(personal::operator_update_preferences)),
        )
}

/// Registers the member inbox, preferences and external destinations.
fn organization_routes(org: &str) -> Router<ApiState> {
    Router::new()
        .route(org, get(handlers::org_list))
        .route(
            &format!("{org}/unread-count"),
            get(handlers::org_unread_count),
        )
        .route(&format!("{org}/{{id}}/read"), post(handlers::org_mark_read))
        .route(
            &format!("{org}/read-all"),
            post(handlers::org_mark_all_read),
        )
        .route(
            &format!("{org}/preferences"),
            get(personal::member_get_preferences)
                .patch(shared(personal::member_update_preferences)),
        )
        .merge(destination_routes(org))
}

/// Registers the tenant user's inbox and delivery preferences.
fn tenant_routes(tenant: &str) -> Router<ApiState> {
    Router::new()
        .route(tenant, get(handlers::tenant_list))
        .route(
            &format!("{tenant}/unread-count"),
            get(handlers::tenant_unread_count),
        )
        .route(
            &format!("{tenant}/{{id}}/read"),
            post(handlers::tenant_mark_read),
        )
        .route(
            &format!("{tenant}/read-all"),
            post(handlers::tenant_mark_all_read),
        )
        .route(
            &format!("{tenant}/preferences"),
            get(handlers::tenant_get_preferences)
                .patch(shared(handlers::tenant_update_preferences)),
        )
}

/// The destinations of the organization whose notifications are at `org`.
fn destination_routes(org: &str) -> Router<ApiState> {
    let all = format!("{org}/destinations");
    let one = format!("{all}/{{destination_id}}");
    Router::new()
        .route(
            &all,
            get(destinations::list_destinations).post(shared(destinations::add_destination)),
        )
        .route(
            &one,
            put(destinations::reconfigure_destination)
                .delete(shared(destinations::remove_destination)),
        )
        .route(
            &format!("{one}/pause"),
            post(destinations::pause_destination),
        )
        .route(
            &format!("{one}/resume"),
            post(destinations::resume_destination),
        )
}

/// The notification part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::platform_list,
        handlers::platform_unread_count,
        handlers::platform_mark_read,
        handlers::platform_mark_all_read,
        handlers::org_list,
        handlers::org_unread_count,
        handlers::org_mark_read,
        handlers::org_mark_all_read,
        handlers::tenant_list,
        handlers::tenant_unread_count,
        handlers::tenant_mark_read,
        handlers::tenant_mark_all_read,
        handlers::tenant_get_preferences,
        handlers::tenant_update_preferences,
        personal::member_get_preferences,
        personal::member_update_preferences,
        personal::operator_get_preferences,
        personal::operator_update_preferences,
        destinations::list_destinations,
        destinations::add_destination,
        destinations::reconfigure_destination,
        destinations::pause_destination,
        destinations::resume_destination,
        destinations::remove_destination,
    ),
    components(schemas(
        NotificationResponse,
        UnreadCountResponse,
        MarkAllReadResponse,
        PreferenceResponse,
        UpdatePreferencesBody,
        PreferenceUpdateEntry,
        DestinationBody,
        DestinationTargetBody,
        DestinationAddedResponse,
        DestinationChangedResponse,
        DestinationResponse,
    ))
)]
pub(crate) struct Document;
