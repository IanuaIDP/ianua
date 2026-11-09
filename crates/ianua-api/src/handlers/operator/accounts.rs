//! Operator account handlers: creating, listing, reading, enabling and
//! disabling operators, and moving another operator's address.

use axum::extract::{Path, State};
use ianua_app::ports::operator::OperatorSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::operator::OperatorState;

use crate::dto::operator::{
    ChangeOperatorEmailBody, CreateOperatorBody, CreateOperatorResponse, OperatorFilterParams,
    OperatorResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::Operator;
use crate::extractors::json::Json;
use crate::extractors::listing::ListingQuery;
use crate::extractors::pagination::PaginationParams;
use crate::extractors::paths::operator::OperatorPath;
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/operators",
    tag = "Operators",
    request_body = CreateOperatorBody,
    responses(
        (status = 201, description = "Created", body = CreateOperatorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Create a platform operator
///
/// Creates a new operator account in `Active` status with the given
/// `email` and `password` (hashed). Operators are platform-level staff who
/// administer the deployment itself, not scoped to any organization or
/// tenant. Returns the new operator's `id`. Returns `409` if the email is
/// already registered, or `422` for an invalid email. Records
/// `operator.operator_created`, naming the operator who made it. Requires
/// an operator's own key.
pub(crate) async fn create_operator(
    State(operators): State<OperatorState>,
    operator: Operator,
    Json(body): Json<CreateOperatorBody>,
) -> Result<Created<CreateOperatorResponse>, ApiError> {
    let request = body.request(&operators.password_hashing.permitted().await?)?;
    let id = operators
        .create
        .execute(&operator.caller, &operator.auditor, request)
        .await?;
    Ok(Created(CreateOperatorResponse { id }))
}

#[utoipa::path(
    get,
    path = "/api/v1/operators",
    tag = "Operators",
    params(OperatorFilterParams, SortQuery<OperatorSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<OperatorResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// List platform operators
///
/// Returns every operator account, optionally filtered by `status`
/// (`Active` / `Disabled`), sortable and paginated. Each entry carries the
/// `email`, lifecycle `status`, and `created_at`. Read-only. Requires an
/// operator's own key.
pub(crate) async fn list_operators(
    State(operators): State<OperatorState>,
    operator: Operator,
    ListingQuery {
        query: filter,
        sort,
        page: pagination,
    }: ListingQuery<OperatorFilterParams, OperatorSortField>,
) -> Result<Json<PageResponse<OperatorResponse>>, ApiError> {
    let page = operators
        .list
        .execute(&operator.caller, filter.listing(sort, pagination))
        .await?;
    Ok(Json(PageResponse::from_page(page, OperatorResponse::from)))
}

#[utoipa::path(
    get,
    path = "/api/v1/operators/{id}",
    tag = "Operators",
    responses(
        (status = 200, description = "Success", body = OperatorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get a platform operator
///
/// Returns a single operator by `id`: `email`, `status`, and `created_at`.
/// Returns `404` if the operator doesn't exist. Read-only. Requires an
/// operator's own key.
pub(crate) async fn get_operator(
    State(operators): State<OperatorState>,
    operator: Operator,
    Path(path): Path<OperatorPath>,
) -> Result<Json<OperatorResponse>, ApiError> {
    let found = operators
        .get
        .execute(&operator.caller, path.operator())
        .await?;
    Ok(Json(OperatorResponse::from(found)))
}

#[utoipa::path(
    post,
    path = "/api/v1/operators/{id}/enable",
    tag = "Operators",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Enable an operator
///
/// Re-enables a `Disabled` operator so they can sign in and act again.
///
/// **State.** `Disabled → Active`. Returns `404` if the operator doesn't
/// exist, `403` for the caller naming themselves, or `422` if they're
/// already `Active`. Records `operator.operator_enabled`. Requires an
/// operator's own key.
pub(crate) async fn enable_operator(
    State(operators): State<OperatorState>,
    operator: Operator,
    Path(path): Path<OperatorPath>,
) -> Result<NoContent, ApiError> {
    operators
        .enable
        .execute(&operator.caller, &operator.auditor, path.operator())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/operators/{id}/disable",
    tag = "Operators",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Disable an operator
///
/// Disables an `Active` operator, so they can no longer sign in, and
/// **revokes all their outstanding impersonation grants**. Their keys stop
/// working at once. Nobody disables themselves, so the platform always
/// keeps someone who can run it.
///
/// **State.** `Active → Disabled`. Returns `404` if the operator doesn't
/// exist, `403` for the caller naming themselves, or `422` if they're
/// already `Disabled`. Records `operator.operator_disabled`. Requires an
/// operator's own key.
pub(crate) async fn disable_operator(
    State(operators): State<OperatorState>,
    operator: Operator,
    Path(path): Path<OperatorPath>,
) -> Result<NoContent, ApiError> {
    operators
        .disable
        .execute(&operator.caller, &operator.auditor, path.operator())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/operators/{id}/email",
    tag = "Operators",
    request_body = ChangeOperatorEmailBody,
    responses(
        (status = 204, description = "Confirmation link sent"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Address taken", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Change another operator's address
///
/// Asks to move the operator `id` to `new_email`. A link to confirm goes to
/// the new address, and the address the account has now is warned with a
/// link that stops the change; the account keeps its old address until the
/// link is followed. Operators sign in with keys, so another operator asks
/// on their behalf: naming yourself is `403`. Returns `404` for an unknown
/// operator, `409` when another operator has the address, and `422` when
/// it is the one they have. Records
/// `identity.management_email_change_requested`. Requires an operator's
/// own key.
pub(crate) async fn change_operator_email(
    State(operators): State<OperatorState>,
    operator: Operator,
    Path(path): Path<OperatorPath>,
    Json(body): Json<ChangeOperatorEmailBody>,
) -> Result<NoContent, ApiError> {
    let request = body.request(path.operator())?;
    operators
        .change_email
        .execute(&operator.caller, &operator.auditor, request)
        .await?;
    Ok(NoContent)
}
