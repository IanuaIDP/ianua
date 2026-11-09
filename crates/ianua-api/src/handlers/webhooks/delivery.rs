//! Webhook delivery handlers: what was sent to a subscription's URL, how
//! each try ended, sending a message again, and sending a test event.

use axum::extract::{Path, State};
use ianua_app::ports::webhooks::DeliveryAttemptSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::webhooks::delivery::ListAttemptsRequest;
use ianua_assembly::webhooks::WebhookState;

use crate::dto::webhooks::{DeliveryAttemptResponse, SendTestEventBody, resend_of};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::listing::SortedPage;
use crate::extractors::pagination::PaginationParams;
use crate::extractors::paths::webhooks::{WebhookDeliveryPath, WebhookPath};
use crate::extractors::sort::SortQuery;
use crate::response::PageResponse;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/webhooks/{id}/deliveries",
    tag = "Webhooks",
    params(SortQuery<DeliveryAttemptSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<DeliveryAttemptResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// List webhook delivery attempts
///
/// Returns the subscription's delivery attempts (how each ended, the code
/// the receiver answered with, how long it took, when), sortable and
/// paginated, for working out why events are not getting through. `404` if
/// the subscription does not exist. Read-only. Requires the right to view
/// webhooks.
pub(crate) async fn list_delivery_attempts(
    State(webhooks): State<WebhookState>,
    tenant: TenantCaller,
    Path(path): Path<WebhookPath>,
    SortedPage {
        sort,
        page: pagination,
    }: SortedPage<DeliveryAttemptSortField>,
) -> Result<Json<PageResponse<DeliveryAttemptResponse>>, ApiError> {
    let request = ListAttemptsRequest {
        subscription_id: path.subscription(),
        sort,
        page: pagination,
    };
    let page = webhooks
        .list_deliveries
        .execute(&tenant.caller, request)
        .await?;
    Ok(Json(PageResponse::from_page(
        page,
        DeliveryAttemptResponse::from,
    )))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/webhooks/{id}/deliveries/{delivery_id}/resend",
    tag = "Webhooks",
    responses(
        (status = 200, description = "Sent again; how the new try ended", body = DeliveryAttemptResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the webhook no longer receives the event", body = ErrorBody),
        (status = 404, description = "No such subscription, attempt or message", body = ErrorBody),
        (status = 409, description = "The subscription is disabled", body = ErrorBody),
        (status = 422, description = "The URL resolves to an address deliveries may not reach", body = ErrorBody),
        (status = 429, description = "Sent to a moment ago", body = ErrorBody)
    )
)]
/// Resend a webhook delivery
///
/// Sends the message of an earlier attempt again, under its own message id
/// (`webhook-id`), so a receiver that already handled it drops it, signed
/// with every secret the subscription signs with now. Returns the new
/// attempt, which is kept in the history, counted on the endpoint's
/// failure streak and recorded as `webhooks.delivery_attempted`. It is not
/// retried. Only an event the subscription's creator may still see is
/// sent again (`403` otherwise). Each webhook may be sent to only now and
/// then (`429`). Requires the right to update webhooks.
pub(crate) async fn resend_delivery(
    State(webhooks): State<WebhookState>,
    tenant: TenantCaller,
    Path(path): Path<WebhookDeliveryPath>,
) -> Result<Json<DeliveryAttemptResponse>, ApiError> {
    let attempt = webhooks
        .resend
        .execute(
            &tenant.caller,
            &tenant.auditor,
            resend_of(path.subscription(), path.delivery()),
        )
        .await?;
    Ok(Json(DeliveryAttemptResponse::from(attempt)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/webhooks/{id}/test",
    tag = "Webhooks",
    request_body = SendTestEventBody,
    responses(
        (status = 200, description = "Sent; how the try ended", body = DeliveryAttemptResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "The subscription is disabled", body = ErrorBody),
        (status = 422, description = "The subscription does not list the event, or its URL may not be reached", body = ErrorBody),
        (status = 429, description = "Sent to a moment ago", body = ErrorBody)
    )
)]
/// Send a test event to a webhook
///
/// Sends the subscription a sample of one of the events it lists
/// (`event_type`), marked `"test": true` and holding none of the tenant's
/// data, signed and bounded like any delivery, so its owner can check the
/// endpoint receives and verifies deliveries. Returns the attempt, which
/// is kept in the history and recorded as `webhooks.delivery_attempted`,
/// but never counted on the failure streak, so testing an endpoint that is
/// down never switches it off. It is not retried. Each webhook may be sent
/// to only now and then (`429`). Requires the right to update webhooks.
pub(crate) async fn send_test_event(
    State(webhooks): State<WebhookState>,
    tenant: TenantCaller,
    Path(path): Path<WebhookPath>,
    Json(body): Json<SendTestEventBody>,
) -> Result<Json<DeliveryAttemptResponse>, ApiError> {
    let attempt = webhooks
        .send_test
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.test_of(path.subscription()),
        )
        .await?;
    Ok(Json(DeliveryAttemptResponse::from(attempt)))
}
