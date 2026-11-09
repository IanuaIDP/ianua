//! Signal verification handlers: a stream asked for a verification event,
//! so its receiver sees the stream works end to end.

use axum::extract::{Path, State};
use ianua_app::use_case::Command as _;
use ianua_assembly::signals::SignalState;

use crate::dto::signals::VerifyStreamBody;
use crate::error::{ApiError, ErrorBody};
use crate::extractors::json::Json;
use crate::extractors::paths::signals::StreamPath;
use crate::extractors::signals::StreamCaller;
use crate::response::NoContent;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/streams/{id}/verify",
    tag = "Signals",
    request_body(content = Option<VerifyStreamBody>, description = "The state the event carries back; send none for no state"),
    responses(
        (status = 204, description = "A verification event was sent down the stream"),
        (status = 401, description = "Unauthenticated, or not the stream's key", body = ErrorBody),
        (status = 403, description = "Forbidden, or the key is another stream's", body = ErrorBody),
        (status = 404, description = "No such stream", body = ErrorBody),
        (status = 409, description = "The stream is not active, or its endpoint is not verified", body = ErrorBody),
        (status = 422, description = "The state is not a short token", body = ErrorBody),
        (status = 429, description = "Asked a moment ago", body = ErrorBody)
    )
)]
/// Ask a signal stream for a verification event
///
/// Sends a verification event down the stream, pushed to its endpoint or
/// held for its receiver to poll, carrying back the `state` given, if any,
/// so the receiver can match it to its request. The answer does not wait
/// on the receiver. Only an active stream with a verified endpoint is sent
/// one (`409` otherwise), and a stream may be asked only now and then
/// (`429`). Records `signals.verification_requested`.
///
/// The stream's receiver calls with the key it was handed at registration
/// as its bearer, and reaches its own stream only; a person needs the
/// right to manage signal streams.
pub(crate) async fn request_verification(
    State(signals): State<SignalState>,
    manager: StreamCaller,
    Path(path): Path<StreamPath>,
    body: Option<Json<VerifyStreamBody>>,
) -> Result<NoContent, ApiError> {
    let request = VerifyStreamBody::verification_of(path.stream(), body.map(|Json(body)| body))?;
    signals
        .request_verification
        .execute(&manager.caller, &manager.auditor, request)
        .await?;
    Ok(NoContent)
}
