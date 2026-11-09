//! An operator acting on their own account: their keys and their
//! impersonation grants, under `/api/v1/operators/{id}/...`.
//!
//! An operator's key acts for that operator alone, so a path naming another
//! operator is not found, the way a tenant path naming another tenant is.
//! What the operator may do there is the app's question.

use axum::extract::{FromRequestParts, Path};
use axum::http::HeaderMap;
use axum::http::request::Parts;
use ianua_app::error::AppError;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::ImpersonationGrantId;

use crate::error::ApiError;
use crate::extractors::callers::Operator;
use crate::extractors::paths::operator::OperatorPath;
use crate::state::ApiState;

/// The header an operator names their impersonation grant with, so a
/// request to the user's tenant acts as the user through it.
pub(crate) const OPERATOR_IMPERSONATION_HEADER: &str = "ianua-operator-impersonation";

/// The grant `headers` name, when they name one.
///
/// # Errors
///
/// `422` when the header is there but is not a grant id: a request meant
/// to act as a user is never quietly run some other way.
pub(crate) fn named_grant(headers: &HeaderMap) -> Result<Option<ImpersonationGrantId>, ApiError> {
    let Some(value) = headers.get(OPERATOR_IMPERSONATION_HEADER) else {
        return Ok(None);
    };
    value
        .to_str()
        .ok()
        .and_then(|raw| raw.trim().parse::<uuid::Uuid>().ok())
        .map(|id| Some(ImpersonationGrantId::from_uuid(id)))
        .ok_or_else(|| {
            ApiError(AppError::Domain(DomainError::invalid(message!(
                "api-must-name-a-grant-by-its",
                format!("{OPERATOR_IMPERSONATION_HEADER} must name a grant by its id")
            ))))
        })
}

/// The operator the path names, calling with their own key.
pub(crate) struct OwnOperator(pub Operator);

impl FromRequestParts<ApiState> for OwnOperator {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let operator = Operator::from_request_parts(parts, state).await?;
        let Path(path) = Path::<OperatorPath>::from_request_parts(parts, state)
            .await
            .map_err(ApiError::rejected)?;
        if path.operator() != *operator.caller.operator() {
            return Err(ApiError(AppError::NotFound(message!(
                "api-not-found",
                "not found"
            ))));
        }
        Ok(Self(operator))
    }
}
