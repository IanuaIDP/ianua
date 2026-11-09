//! Subscription handlers: which services receive a topic's messages, and
//! how.

use axum::extract::{Path, State};
use ianua_app::ports::messaging::SubscriptionSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::messaging::subscriptions::{CreateRequest, ListRequest};
use ianua_assembly::messaging::MessagingState;

use crate::dto::messaging::{
    CreateSubscriptionBody, CreateSubscriptionResponse, RotatePushSecretBody,
    RotatePushSecretResponse, SubscriptionFilterParams, SubscriptionResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::listing::ListingQuery;
use crate::extractors::messaging::TenantMessenger;
use crate::extractors::pagination::PaginationParams;
use crate::extractors::paths::messaging::SubscriptionPath;
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/subscriptions",
    tag = "Messaging",
    request_body = CreateSubscriptionBody,
    responses(
        (status = 201, description = "Created", body = CreateSubscriptionResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Create a subscription
///
/// Subscribes `consumer_id` to a topic using `Push` to a signed public-HTTPS
/// `push_endpoint`, or `Pull` with per-message acknowledgement.
/// `ack_deadline_seconds` (5..600, default 30) bounds acknowledgement waits before
/// redelivery; `max_deliveries` (1..100, default 5) bounds attempts before dead-lettering.
/// `consumer_group` shares messages among members; without one each subscriber gets all.
/// An optional `filter` matches message-type prefixes. Returns `id` and, for `Push`,
/// a one-time `signing_secret`. Records `messaging.subscription_created`.
///
/// `404` if the topic or the service does not exist, `409` if the service
/// is already subscribed, `422` when the topic is archived, a push
/// endpoint is missing or not public HTTPS, or a value is invalid. `403`
/// when the service is disabled, the topic carries data it is not cleared
/// for, or the plan's subscription limit is reached. Requires the right to
/// create in messaging.
pub(crate) async fn create_subscription(
    State(messaging): State<MessagingState>,
    messenger: TenantMessenger,
    Json(body): Json<CreateSubscriptionBody>,
) -> Result<Created<CreateSubscriptionResponse>, ApiError> {
    let request = CreateRequest::try_from(body)?;
    let created = messaging
        .create_subscription
        .execute(&messenger.caller, &messenger.auditor, request)
        .await?;
    Ok(Created(CreateSubscriptionResponse::from(created)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/subscriptions/{id}/rotate-push-secret",
    tag = "Messaging",
    request_body(content = Option<RotatePushSecretBody>, description = "How long the old secret keeps signing; send none to stop it at once"),
    responses(
        (status = 200, description = "Success", body = RotatePushSecretResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "A pull subscription signs nothing", body = ErrorBody),
        (status = 422, description = "The overlap is not valid, or over seven days", body = ErrorBody)
    )
)]
/// Rotate a push subscription's signing secret
///
/// Gives a `Push` subscription a new signing secret. With no body, or no
/// `overlap_seconds`, the old one stops at once, as after a leak. With
/// `overlap_seconds` (at most seven days), the old one keeps signing beside
/// the new one until then: each push carries a signature per secret, so a
/// service still checking with the old one accepts it while it moves over.
/// A secret from an earlier rotation stops at once. Returns the new
/// `signing_secret`, shown this once. Records
/// `messaging.subscription_secret_rotated`. `409` for a `Pull`
/// subscription. Requires the right to manage messaging.
pub(crate) async fn rotate_push_secret(
    State(messaging): State<MessagingState>,
    tenant: TenantCaller,
    Path(path): Path<SubscriptionPath>,
    body: Option<Json<RotatePushSecretBody>>,
) -> Result<Json<RotatePushSecretResponse>, ApiError> {
    let request =
        RotatePushSecretBody::rotation_of(path.subscription(), body.map(|Json(body)| body))?;
    let secret = messaging
        .rotate_push_secret
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Json(RotatePushSecretResponse::from(secret)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/subscriptions",
    tag = "Messaging",
    params(SubscriptionFilterParams, SortQuery<SubscriptionSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<SubscriptionResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Neither a topic nor a service named", body = ErrorBody)
    )
)]
/// List subscriptions
///
/// Returns the subscriptions of one topic (`topic_name`) or of one service
/// (`consumer_id`); naming neither is `422`, since the list is always about
/// one topic or one service, never the whole tenant. Sortable and
/// paginated. Each entry carries the `delivery_mode`, an optional
/// `consumer_group` and `filter`, and the lifecycle `status` (`Active` or
/// `Paused`). Read-only. Requires the right to view messaging.
pub(crate) async fn list_subscriptions(
    State(messaging): State<MessagingState>,
    tenant: TenantCaller,
    ListingQuery {
        query: filter,
        sort,
        page: pagination,
    }: ListingQuery<SubscriptionFilterParams, SubscriptionSortField>,
) -> Result<Json<PageResponse<SubscriptionResponse>>, ApiError> {
    let request = ListRequest {
        filter: filter.filter()?,
        sort,
        page: pagination,
    };
    let page = messaging
        .list_subscriptions
        .execute(&tenant.caller, request)
        .await?;
    Ok(Json(PageResponse::from_page(
        page,
        SubscriptionResponse::from,
    )))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/subscriptions/{id}",
    tag = "Messaging",
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Delete a subscription
///
/// Removes a service's subscription to a topic, with the bus consumer it
/// reads through and the messages waiting there, so that service stops
/// receiving the topic. Other subscriptions on the topic are untouched.
/// Subscribing again later starts fresh, with no memory of what was
/// delivered. Records `messaging.subscription_deleted`. `404` if it does
/// not exist. Requires the right to delete in messaging.
pub(crate) async fn delete_subscription(
    State(messaging): State<MessagingState>,
    tenant: TenantCaller,
    Path(path): Path<SubscriptionPath>,
) -> Result<NoContent, ApiError> {
    messaging
        .delete_subscription
        .execute(&tenant.caller, &tenant.auditor, path.subscription())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/subscriptions/{id}/pause",
    tag = "Messaging",
    responses(
        (status = 204, description = "Paused"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Already paused", body = ErrorBody)
    )
)]
/// Pause a subscription
///
/// Pauses an `Active` subscription: its messages wait undelivered, and a
/// pull is refused until it resumes. Records `messaging.subscription_paused`.
/// `404` if it does not exist, `422` if it is already paused. Requires the
/// right to manage messaging.
pub(crate) async fn pause_subscription(
    State(messaging): State<MessagingState>,
    tenant: TenantCaller,
    Path(path): Path<SubscriptionPath>,
) -> Result<NoContent, ApiError> {
    messaging
        .pause_subscription
        .execute(&tenant.caller, &tenant.auditor, path.subscription())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/subscriptions/{id}/resume",
    tag = "Messaging",
    responses(
        (status = 204, description = "Resumed"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Already active", body = ErrorBody)
    )
)]
/// Resume a subscription
///
/// Resumes a `Paused` subscription, so its messages are delivered again.
/// Records `messaging.subscription_resumed`. `404` if it does not exist,
/// `422` if it is already active. Requires the right to manage messaging.
pub(crate) async fn resume_subscription(
    State(messaging): State<MessagingState>,
    tenant: TenantCaller,
    Path(path): Path<SubscriptionPath>,
) -> Result<NoContent, ApiError> {
    messaging
        .resume_subscription
        .execute(&tenant.caller, &tenant.auditor, path.subscription())
        .await?;
    Ok(NoContent)
}
