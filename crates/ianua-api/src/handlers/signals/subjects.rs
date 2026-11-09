//! Signal subject handlers: whom a stream hears about, changed by the
//! stream's receiver with its key or by a person of the tenant.

use axum::extract::{Path, State};
use ianua_app::use_case::Command as _;
use ianua_assembly::signals::SignalState;

use crate::dto::signals::SubjectBody;
use crate::error::{ApiError, ErrorBody};
use crate::extractors::json::Json;
use crate::extractors::paths::signals::StreamPath;
use crate::extractors::signals::StreamCaller;
use crate::response::NoContent;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/streams/{id}/subjects/add",
    tag = "Signals",
    request_body = SubjectBody,
    responses(
        (status = 204, description = "The stream hears about the subject"),
        (status = 401, description = "Unauthenticated, or not the stream's key", body = ErrorBody),
        (status = 403, description = "Forbidden, or the key is another stream's", body = ErrorBody),
        (status = 404, description = "No such stream, user or agent", body = ErrorBody),
        (status = 422, description = "Not an opaque subject, or the stream lists the most it keeps", body = ErrorBody)
    )
)]
/// Add a subject to a signal stream
///
/// Makes the stream hear about one user or agent: `subject` names it in
/// the opaque format (`{"format": "opaque", "id": "<uuid>"}`) and `kind`
/// says which it is (`User`, the default, or `Agent`). A stream that
/// already hears about it is left as it is. Records
/// `signals.subject_added` when it changed.
///
/// The stream's receiver calls with the key it was handed at registration
/// as its bearer, and reaches its own stream only; a person needs the
/// right to manage signal streams.
pub(crate) async fn add_subject(
    State(signals): State<SignalState>,
    manager: StreamCaller,
    Path(path): Path<StreamPath>,
    Json(body): Json<SubjectBody>,
) -> Result<NoContent, ApiError> {
    signals
        .add_subject
        .execute(
            &manager.caller,
            &manager.auditor,
            body.addition_to(path.stream())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/streams/{id}/subjects/remove",
    tag = "Signals",
    request_body = SubjectBody,
    responses(
        (status = 204, description = "The stream no longer hears about the subject"),
        (status = 401, description = "Unauthenticated, or not the stream's key", body = ErrorBody),
        (status = 403, description = "Forbidden, or the key is another stream's", body = ErrorBody),
        (status = 404, description = "No such stream, user or agent", body = ErrorBody),
        (status = 422, description = "Not an opaque subject, or the stream lists the most it keeps", body = ErrorBody)
    )
)]
/// Remove a subject from a signal stream
///
/// Makes the stream stop hearing about one user or agent, named as for
/// adding one. A stream that already does not hear about it is left as it
/// is. Records `signals.subject_removed` when it changed.
///
/// The stream's receiver calls with its key as its bearer, and reaches its
/// own stream only; a person needs the right to manage signal streams.
pub(crate) async fn remove_subject(
    State(signals): State<SignalState>,
    manager: StreamCaller,
    Path(path): Path<StreamPath>,
    Json(body): Json<SubjectBody>,
) -> Result<NoContent, ApiError> {
    signals
        .remove_subject
        .execute(
            &manager.caller,
            &manager.auditor,
            body.removal_from(path.stream())?,
        )
        .await?;
    Ok(NoContent)
}
