//! Impersonation handlers: an operator taking a time-limited grant to act
//! as one tenant user, and ending it early.

use axum::extract::{Path, State};
use ianua_app::use_case::Command as _;
use ianua_assembly::operator::OperatorState;
use ianua_domain::domains::operator::impersonation::ImpersonationTerms;

use crate::dto::operator::{GrantImpersonationBody, GrantImpersonationResponse};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::Operator;
use crate::extractors::json::Json;
use crate::extractors::operator::OwnOperator;
use crate::extractors::paths::operator::ImpersonationGrantPath;
use crate::response::{Created, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/operators/{id}/grants",
    tag = "Operators",
    request_body = GrantImpersonationBody,
    responses(
        (status = 201, description = "Granted", body = GrantImpersonationResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Grant impersonation rights
///
/// Lets the calling operator (`id` being their own) act as a specific
/// tenant user (`tenant_id` + `user_id`) until `expires_at`, recording the
/// mandatory `reason`. Used for support and break-glass access. Returns
/// `404` if the tenant or the user in it doesn't exist or `id` is another
/// operator, `403` if the tenant forbids impersonation, `409` while the
/// operator already holds an active grant for that user, and `422` if
/// `expires_at` isn't in the future or is more than 24 hours ahead. Answers
/// the grant's id: a request to the user's tenant carrying the operator's
/// own key and the id in the `ianua-operator-impersonation` header acts as
/// the user, checked again on every request. Records
/// `operator.impersonation_granted`. Requires the operator's own key.
pub(crate) async fn grant_impersonation(
    State(operators): State<OperatorState>,
    OwnOperator(operator): OwnOperator,
    Json(body): Json<GrantImpersonationBody>,
) -> Result<Created<GrantImpersonationResponse>, ApiError> {
    let terms = ImpersonationTerms::try_from(body)?;
    let id = operators
        .grant_impersonation
        .execute(&operator.caller, &operator.auditor, terms)
        .await?;
    Ok(Created(GrantImpersonationResponse { id }))
}

#[utoipa::path(
    delete,
    path = "/api/v1/operators/grants/{id}",
    tag = "Operators",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Already revoked", body = ErrorBody)
    )
)]
/// Revoke an impersonation grant
///
/// Ends one of the calling operator's own grants early by its `id`, so they
/// can no longer act as that user. Returns `404` if the grant doesn't exist,
/// `403` if it is another operator's (disabling its holder ends every grant
/// they hold), and `422` if it is already revoked. Records
/// `operator.impersonation_revoked`. Requires an operator's own key.
pub(crate) async fn revoke_impersonation(
    State(operators): State<OperatorState>,
    operator: Operator,
    Path(path): Path<ImpersonationGrantPath>,
) -> Result<NoContent, ApiError> {
    operators
        .revoke_impersonation
        .execute(&operator.caller, &operator.auditor, path.grant())
        .await?;
    Ok(NoContent)
}
