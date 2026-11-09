//! Operator key handlers: an operator signing in for a key, and making and
//! revoking keys of their own.

use axum::extract::{Path, State};
use ianua_app::use_case::Command as _;
use ianua_assembly::operator::OperatorState;

use crate::dto::operator::{
    CreateOperatorKeyBody, CreateOperatorKeyResponse, OperatorSignInBody, RevokeAllKeysResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::Visitor;
use crate::extractors::json::Json;
use crate::extractors::operator::OwnOperator;
use crate::extractors::paths::operator::OperatorKeyPath;
use crate::response::{Created, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/operators/sign-in",
    tag = "Operators",
    request_body = OperatorSignInBody,
    responses(
        (status = 201, description = "Signed in; the key is shown once", body = CreateOperatorKeyResponse),
        (status = 404, description = "Not found: every refusal alike", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Sign in as an operator
///
/// Exchanges an operator's address and password for a short-lived operator
/// key, the way onto the operator plane; every later call carries the key.
/// The **raw key is returned once**. The key ends after the deployment's
/// operator key lifetime. Every refusal answers `404` alike: an address no
/// operator holds, a wrong password, a disabled account, or a network
/// locked out of the address after three wrong passwords in five minutes,
/// for an hour. Records `operator.operator_api_key_created`, or
/// `operator.operator_sign_in_failed` with why. Limited per client
/// address; a `429` with `Retry-After` means slow down.
pub(crate) async fn sign_in_operator(
    State(operators): State<OperatorState>,
    visitor: Visitor,
    Json(body): Json<OperatorSignInBody>,
) -> Result<Created<CreateOperatorKeyResponse>, ApiError> {
    let created = operators
        .sign_in
        .execute(&(), &visitor.auditor, body.into_request(visitor.meta)?)
        .await?;
    Ok(Created(CreateOperatorKeyResponse::from(created)))
}

#[utoipa::path(
    post,
    path = "/api/v1/operators/{id}/keys",
    tag = "Operators",
    request_body(content = Option<CreateOperatorKeyBody>, description = "When the key ends; send none for a key that never ends"),
    responses(
        (status = 201, description = "Created", body = CreateOperatorKeyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Create an operator API key
///
/// Mints a new API key for the calling operator, `id` being their own. The
/// **raw key is returned once** (only its hash is stored) alongside the
/// `key_prefix` used to identify the key later. Send `expires_at` for a key
/// that ends; one acting through a key that ends sooner is `403`, and an
/// instant already passed is `422`. Another operator's `id` is `404`.
/// Records `operator.operator_api_key_created`. Requires the operator's own
/// key.
pub(crate) async fn create_operator_key(
    State(operators): State<OperatorState>,
    OwnOperator(operator): OwnOperator,
    body: Option<Json<CreateOperatorKeyBody>>,
) -> Result<Created<CreateOperatorKeyResponse>, ApiError> {
    let expires_at = CreateOperatorKeyBody::expiry(body.map(|Json(body)| body));
    let created = operators
        .create_key
        .execute(&operator.caller, &operator.auditor, expires_at)
        .await?;
    Ok(Created(CreateOperatorKeyResponse::from(created)))
}

#[utoipa::path(
    post,
    path = "/api/v1/operators/{id}/keys/{key_prefix}/revoke",
    tag = "Operators",
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Already revoked or malformed prefix", body = ErrorBody)
    )
)]
/// Revoke an operator API key
///
/// Revokes one of the calling operator's keys by its `key_prefix`; it stops
/// working at once. Returns `404` if no key has that prefix or `id` is
/// another operator, `403` if the key is another operator's, and `422` if
/// it is already revoked. Records `operator.operator_api_key_revoked`.
/// Requires the operator's own key.
pub(crate) async fn revoke_operator_key(
    State(operators): State<OperatorState>,
    OwnOperator(operator): OwnOperator,
    Path(path): Path<OperatorKeyPath>,
) -> Result<NoContent, ApiError> {
    operators
        .revoke_key
        .execute(&operator.caller, &operator.auditor, path.key()?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/operators/{id}/keys/revoke-all",
    tag = "Operators",
    responses(
        (status = 200, description = "All keys revoked", body = RevokeAllKeysResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Revoke all operator API keys
///
/// Revokes every key the calling operator holds at once, the one this
/// request came with included, and returns how many (`revoked`) went.
/// Another operator's `id` is `404`. Records one
/// `operator.operator_api_key_revoked` when any key went. Requires the
/// operator's own key.
pub(crate) async fn revoke_all_operator_keys(
    State(operators): State<OperatorState>,
    OwnOperator(operator): OwnOperator,
) -> Result<Json<RevokeAllKeysResponse>, ApiError> {
    let revoked = operators
        .revoke_all_keys
        .execute(&operator.caller, &operator.auditor, ())
        .await?;
    Ok(Json(RevokeAllKeysResponse { revoked }))
}
