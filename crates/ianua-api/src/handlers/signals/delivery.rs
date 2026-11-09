//! Signal delivery handlers: what was sent to a stream's receiver, how
//! each try ended, and a poll stream's receiver reading its events.

use axum::extract::{Path, State};
use ianua_app::ports::signals::StreamDeliverySortField;
use ianua_app::use_case::Query as _;
use ianua_app::use_cases::signals::delivery::ListStreamDeliveriesRequest;
use ianua_assembly::signals::SignalState;

use crate::dto::signals::{PollBody, PollResponse, StreamDeliveryResponse};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::listing::SortedPage;
use crate::extractors::pagination::PaginationParams;
use crate::extractors::paths::signals::StreamPath;
use crate::extractors::signals::StreamCaller;
use crate::extractors::sort::SortQuery;
use crate::response::PageResponse;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/streams/{id}/deliveries",
    tag = "Signals",
    params(SortQuery<StreamDeliverySortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<StreamDeliveryResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// List a stream's delivery history
///
/// Returns the stream's delivery attempts, one per signal pushed (or
/// queued, for a poll stream), sortable and paginated: how each ended, the
/// code the receiver answered with, and how long it took. `404` if the
/// stream does not exist. Read-only. Requires the right to view signal
/// streams.
pub(crate) async fn list_stream_deliveries(
    State(signals): State<SignalState>,
    tenant: TenantCaller,
    Path(path): Path<StreamPath>,
    SortedPage {
        sort,
        page: pagination,
    }: SortedPage<StreamDeliverySortField>,
) -> Result<Json<PageResponse<StreamDeliveryResponse>>, ApiError> {
    let request = ListStreamDeliveriesRequest {
        stream_id: path.stream(),
        sort,
        page: pagination,
    };
    let page = signals
        .list_deliveries
        .execute(&tenant.caller, request)
        .await?;
    Ok(Json(PageResponse::from_page(
        page,
        StreamDeliveryResponse::from,
    )))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/streams/{id}/poll",
    tag = "Signals",
    request_body(content = Option<PollBody>, description = "What to acknowledge and how many to take; send none for the largest batch"),
    responses(
        (status = 200, description = "The events waiting", body = PollResponse),
        (status = 401, description = "Unauthenticated, or not the stream's key", body = ErrorBody),
        (status = 403, description = "Forbidden, or the key is another stream's", body = ErrorBody),
        (status = 404, description = "No such stream", body = ErrorBody),
        (status = 409, description = "The stream is pushed, not polled", body = ErrorBody),
        (status = 422, description = "maxEvents is not from 1 to 100", body = ErrorBody)
    )
)]
/// Poll a signal stream
///
/// RFC 8936 for `Poll` streams: `ack` removes received event `jti`s; `maxEvents`
/// requests 1..100 events, default 100. Returns the oldest unacknowledged signed
/// tokens in `sets`, keyed by `jti`, with `moreAvailable` when more wait.
/// Replies immediately and repeats events until acknowledged, including after lost
/// responses. Records nothing; each event was recorded when raised.
///
/// The stream's receiver polls with the key it was handed at registration
/// as its bearer, and reaches its own stream only; a person needs the
/// right to manage signal streams.
pub(crate) async fn poll_events(
    State(signals): State<SignalState>,
    manager: StreamCaller,
    Path(path): Path<StreamPath>,
    body: Option<Json<PollBody>>,
) -> Result<Json<PollResponse>, ApiError> {
    let request = PollBody::poll_of(path.stream(), body.map(|Json(body)| body))?;
    let polled = signals.poll.execute(&manager.caller, request).await?;
    Ok(Json(PollResponse::from(polled)))
}
