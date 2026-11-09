//! Webhook subscription handlers: registering a URL for the tenant's
//! events, changing it, its lifecycle, its signing secret, and the events
//! it may receive.

use axum::extract::{Path, State};
use ianua_app::ports::webhooks::WebhookSubscriptionSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::webhooks::subscriptions::{
    CreateRequest, ListRequest, SubscriptionFilter,
};
use ianua_assembly::webhooks::WebhookState;

use crate::dto::webhooks::{
    CreateSubscriptionBody, CreateSubscriptionResponse, EventTypeResponse, RotateSecretBody,
    RotateSecretResponse, SubscriptionFilterParams, SubscriptionResponse, UpdateSubscriptionBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::listing::ListingQuery;
use crate::extractors::pagination::PaginationParams;
use crate::extractors::paths::webhooks::WebhookPath;
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/webhooks",
    tag = "Webhooks",
    request_body = CreateSubscriptionBody,
    responses(
        (status = 201, description = "Created", body = CreateSubscriptionResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Create a webhook subscription
///
/// Registers a webhook: ianua posts matching events to `url` (HTTPS on the
/// public internet), signed as Standard Webhooks lays it out
/// (`webhook-id`, `webhook-timestamp`, `webhook-signature`) with a secret
/// of the subscription's own. Choose the `event_types` to receive (empty
/// means every event the creator may see now), an optional `description`
/// and how hard failed deliveries are retried (`retry`: `Standard` when
/// left out, `Aggressive` or `Patient`). Created in `Active` status.
/// Returns the subscription `id` and the `signing_secret`, shown this once:
/// keep it to verify deliveries. Records `webhooks.subscription_created`.
///
/// `422` for a URL that is not public HTTPS, an invalid description, or the
/// webhook delivery event named. `403` when the caller names an event they
/// may not see, or the plan's webhook limit is reached. Requires the right
/// to update webhooks.
pub(crate) async fn create_subscription(
    State(webhooks): State<WebhookState>,
    tenant: TenantCaller,
    Json(body): Json<CreateSubscriptionBody>,
) -> Result<Created<CreateSubscriptionResponse>, ApiError> {
    let request = CreateRequest::try_from(body)?;
    let created = webhooks
        .create
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Created(CreateSubscriptionResponse::from(created)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/webhooks",
    tag = "Webhooks",
    params(SubscriptionFilterParams, SortQuery<WebhookSubscriptionSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<SubscriptionResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// List webhook subscriptions
///
/// Returns this tenant's webhook subscriptions, optionally only those in one
/// `status` (`Active`, `Paused` or `Disabled`), sortable and paginated. Each
/// entry carries the URL, event types, description and lifecycle status,
/// never the signing secret. Read-only. Requires the right to view webhooks.
pub(crate) async fn list_subscriptions(
    State(webhooks): State<WebhookState>,
    tenant: TenantCaller,
    ListingQuery {
        query: filter,
        sort,
        page: pagination,
    }: ListingQuery<SubscriptionFilterParams, WebhookSubscriptionSortField>,
) -> Result<Json<PageResponse<SubscriptionResponse>>, ApiError> {
    let request = ListRequest {
        filter: SubscriptionFilter {
            status: filter.status,
        },
        sort,
        page: pagination,
    };
    let page = webhooks.list.execute(&tenant.caller, request).await?;
    Ok(Json(PageResponse::from_page(
        page,
        SubscriptionResponse::from,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/webhooks/{id}",
    tag = "Webhooks",
    responses(
        (status = 200, description = "Success", body = SubscriptionResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get a webhook subscription
///
/// Returns a single subscription by `id`, never its signing secret. `404`
/// if it does not exist under this tenant. Read-only. Requires the right to
/// view webhooks.
pub(crate) async fn get_subscription(
    State(webhooks): State<WebhookState>,
    tenant: TenantCaller,
    Path(path): Path<WebhookPath>,
) -> Result<Json<SubscriptionResponse>, ApiError> {
    let subscription = webhooks
        .get
        .execute(&tenant.caller, path.subscription())
        .await?;
    Ok(Json(SubscriptionResponse::from(subscription)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/webhooks/{id}",
    tag = "Webhooks",
    request_body = UpdateSubscriptionBody,
    responses(
        (status = 200, description = "Success", body = SubscriptionResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error, or disabled", body = ErrorBody)
    )
)]
/// Update a webhook subscription
///
/// Partial update: send `url`, `event_types`, `description` (or `null` to
/// clear it) and/or `retry` to change just those; leave any out to keep
/// it. A new URL starts with no failures counted. New event types are held
/// to what the caller may see, like at creation. Returns the subscription
/// as it now stands. Records one `webhooks.subscription_updated` naming
/// what changed; a body that changes nothing records nothing.
///
/// `404` if the subscription does not exist, `422` for a URL that is not
/// public HTTPS, the webhook delivery event named, or a disabled
/// subscription (it is replaced, not changed). `403` when the caller names
/// an event they may not see. Requires the right to update webhooks.
pub(crate) async fn update_subscription(
    State(webhooks): State<WebhookState>,
    tenant: TenantCaller,
    Path(path): Path<WebhookPath>,
    Json(body): Json<UpdateSubscriptionBody>,
) -> Result<Json<SubscriptionResponse>, ApiError> {
    let subscription = webhooks
        .update
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.update_of(path.subscription())?,
        )
        .await?;
    Ok(Json(SubscriptionResponse::from(subscription)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/webhooks/{id}/pause",
    tag = "Webhooks",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Not active", body = ErrorBody)
    )
)]
/// Pause a webhook subscription
///
/// Pauses an `Active` subscription. Events raised while it is paused are
/// not delivered, then or later. Records `webhooks.subscription_paused`.
/// `404` if the subscription does not exist, `422` if it is already paused
/// or disabled. Requires the right to update webhooks.
pub(crate) async fn pause_subscription(
    State(webhooks): State<WebhookState>,
    tenant: TenantCaller,
    Path(path): Path<WebhookPath>,
) -> Result<NoContent, ApiError> {
    webhooks
        .pause
        .execute(&tenant.caller, &tenant.auditor, path.subscription())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/webhooks/{id}/resume",
    tag = "Webhooks",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Not paused", body = ErrorBody)
    )
)]
/// Resume a webhook subscription
///
/// Resumes a `Paused` subscription and clears its failure count. Events
/// raised during the pause are not sent. Records
/// `webhooks.subscription_resumed`. `404` if the subscription does not
/// exist, `422` if it is active or disabled (a disabled subscription is
/// never resumed). Requires the right to update webhooks.
pub(crate) async fn resume_subscription(
    State(webhooks): State<WebhookState>,
    tenant: TenantCaller,
    Path(path): Path<WebhookPath>,
) -> Result<NoContent, ApiError> {
    webhooks
        .resume
        .execute(&tenant.caller, &tenant.auditor, path.subscription())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/webhooks/{id}",
    tag = "Webhooks",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Still active", body = ErrorBody)
    )
)]
/// Delete a webhook subscription
///
/// Removes a subscription and its delivery history for good; nothing more
/// is delivered to its URL. An active subscription is paused or disabled
/// first (`409` otherwise). Records `webhooks.subscription_deleted`. `404`
/// if it does not exist. Requires the right to update webhooks.
pub(crate) async fn delete_subscription(
    State(webhooks): State<WebhookState>,
    tenant: TenantCaller,
    Path(path): Path<WebhookPath>,
) -> Result<NoContent, ApiError> {
    webhooks
        .delete
        .execute(&tenant.caller, &tenant.auditor, path.subscription())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/webhooks/{id}/rotate-secret",
    tag = "Webhooks",
    request_body(content = Option<RotateSecretBody>),
    responses(
        (status = 200, description = "Success", body = RotateSecretResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Overlap not valid, or over seven days", body = ErrorBody)
    )
)]
/// Rotate the webhook signing secret
///
/// Gives the subscription a new signing secret. With no body, or no
/// `overlap_seconds`, the old one stops at once, as after a leak. With
/// `overlap_seconds` (at most seven days), the old one keeps signing beside
/// the new one until then: each delivery carries a signature per secret,
/// so a receiver still on the old secret accepts it while it moves over. A
/// secret from an earlier rotation stops at once. Returns the new
/// `signing_secret`, shown this once. Records `webhooks.secret_rotated`.
/// `404` if the subscription does not exist. Requires the right to manage
/// webhooks.
pub(crate) async fn rotate_secret(
    State(webhooks): State<WebhookState>,
    tenant: TenantCaller,
    Path(path): Path<WebhookPath>,
    body: Option<Json<RotateSecretBody>>,
) -> Result<Json<RotateSecretResponse>, ApiError> {
    let request = RotateSecretBody::rotation_of(path.subscription(), body.map(|Json(body)| body))?;
    let secret = webhooks
        .rotate_secret
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Json(RotateSecretResponse::from(secret)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/webhooks/event-types",
    tag = "Webhooks",
    responses(
        (status = 200, description = "Success", body = Vec<EventTypeResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List the events a webhook may receive
///
/// Returns every event the caller may subscribe a webhook to, each with the
/// `event_type` a subscription lists, its dotted `name` and what it means.
/// Only events the caller's rights let them see are listed, and never the
/// record of a webhook's own delivery. Read-only. Requires the right to
/// view webhooks.
pub(crate) async fn list_event_types(
    State(webhooks): State<WebhookState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<EventTypeResponse>>, ApiError> {
    let entries = webhooks.event_catalog.execute(&tenant.caller, ()).await?;
    Ok(Json(
        entries.into_iter().map(EventTypeResponse::from).collect(),
    ))
}
