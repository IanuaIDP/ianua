//! Errors answered in SCIM's own format (RFC 7644 section 3.12), for the
//! provisioning endpoints a tenant's directory calls.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ianua_app::error::AppError;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::validation::ValidationError;

use crate::dto::scim::{ERROR_SCHEMA, ScimErrorBody};
use crate::error::{ApiError, log_error, public_message, status_and_code};
use crate::extractors::json::BodyRejection;
use crate::extractors::query::QueryRejection;
use crate::response::scim::ScimJson;

/// An error a SCIM endpoint answers, with the SCIM error type that goes
/// with it.
#[derive(Debug)]
pub struct ScimApiError {
    error: AppError,
    scim_type: Option<&'static str>,
}

impl From<AppError> for ScimApiError {
    fn from(error: AppError) -> Self {
        let scim_type = match &error {
            AppError::Domain(refusal) if is_too_many(refusal) => Some("tooMany"),
            AppError::Domain(_) => Some("invalidValue"),
            AppError::Conflict(_) => Some("uniqueness"),
            _ => None,
        };
        Self { error, scim_type }
    }
}

/// Whether `refusal` is a list longer than the service takes, which SCIM
/// calls `tooMany` (RFC 7644 section 3.12).
fn is_too_many(refusal: &DomainError) -> bool {
    matches!(
        refusal,
        DomainError::Validation(ValidationError::Count { max, actual, .. }) if actual > max
    )
}

impl From<ApiError> for ScimApiError {
    fn from(error: ApiError) -> Self {
        Self::from(error.0)
    }
}

impl From<BodyRejection> for ScimApiError {
    fn from(rejection: BodyRejection) -> Self {
        let (_, _, message) = rejection.answer();
        Self::invalid_value(message)
    }
}

impl From<QueryRejection> for ScimApiError {
    fn from(rejection: QueryRejection) -> Self {
        let (_, _, message) = rejection.answer();
        Self::invalid_value(message)
    }
}

impl ScimApiError {
    /// A request value that is malformed or not allowed.
    pub fn invalid_value(detail: impl std::fmt::Display) -> Self {
        Self::from(ApiError::rejected(detail))
    }

    /// A `filter` this service does not support.
    pub fn invalid_filter(detail: impl std::fmt::Display) -> Self {
        Self {
            scim_type: Some("invalidFilter"),
            ..Self::invalid_value(detail)
        }
    }
}

impl IntoResponse for ScimApiError {
    fn into_response(self) -> Response {
        let (status, _) = status_and_code(&self.error);
        let status = match self.error {
            AppError::Domain(_) => StatusCode::BAD_REQUEST,
            _ => status,
        };
        log_error(&self.error, status);
        let body = ScimErrorBody {
            schemas: [ERROR_SCHEMA],
            status: status.as_u16().to_string(),
            scim_type: self.scim_type,
            detail: public_message(&self.error),
        };
        ScimJson::with_status(status, body).into_response()
    }
}
