//! Errors answered in the OAuth protocol's own shape: the token endpoint
//! and the endpoints a client proves itself at the same way (RFC 6749 5.2),
//! the endpoints an access token is presented to (RFC 6750 3), and dynamic
//! client registration (RFC 7591 3.2.2).
//!
//! A refusal says no more than the app said, and never names a token or a
//! secret. A failure of the platform is logged with its chain and told as
//! `server_error`.

use axum::Json;
use axum::http::header::WWW_AUTHENTICATE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use ianua_app::error::AppError;
use ianua_app::use_cases::oauth::token::refusal::{OAuthErrorCode, TokenError};

use crate::dto::oauth::errors::OAuthErrorBody;
use crate::error::{ApiError, log_error, public_message, status_and_code};

/// The challenge a refused client is answered with: it may prove itself
/// with its secret in the `Authorization` header.
const CLIENT_CHALLENGE: &str = "Basic realm=\"ianua\"";

/// An error the token endpoint, or an endpoint a client proves itself at
/// the same way, answers.
pub struct OAuthError(pub TokenError);

impl From<TokenError> for OAuthError {
    fn from(error: TokenError) -> Self {
        Self(error)
    }
}

impl From<AppError> for OAuthError {
    fn from(error: AppError) -> Self {
        Self(TokenError::Failed(error))
    }
}

impl OAuthError {
    /// A refusal with `code`, described by `reason`.
    pub fn refused(code: OAuthErrorCode, reason: impl Into<String>) -> Self {
        Self(TokenError::Refused {
            code,
            reason: reason.into(),
        })
    }

    /// A request missing a parameter, repeating one, or sending one
    /// malformed.
    pub fn invalid_request(reason: impl Into<String>) -> Self {
        Self::refused(OAuthErrorCode::InvalidRequest, reason)
    }

    /// A client that named itself in a way that cannot be read.
    pub fn invalid_client(reason: impl Into<String>) -> Self {
        Self::refused(OAuthErrorCode::InvalidClient, reason)
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        match self.0 {
            TokenError::Refused { code, reason } => refusal(code, reason),
            TokenError::Failed(error) => failure(&error),
        }
    }
}

/// The answer to a refusal: `401` with a challenge for a client that did
/// not prove itself, `400` for everything else.
fn refusal(code: OAuthErrorCode, reason: String) -> Response {
    let body = Json(OAuthErrorBody {
        error: code.as_str(),
        error_description: Some(reason),
    });
    if code != OAuthErrorCode::InvalidClient {
        return (StatusCode::BAD_REQUEST, body).into_response();
    }
    let challenge = [(WWW_AUTHENTICATE, HeaderValue::from_static(CLIENT_CHALLENGE))];
    (StatusCode::UNAUTHORIZED, challenge, body).into_response()
}

/// The answer to a failure: `server_error` when the platform failed, the
/// refusal the app's answer means otherwise.
fn failure(error: &AppError) -> Response {
    let (status, _) = status_and_code(error);
    log_error(error, status);
    if error.is_server_error() {
        let body = OAuthErrorBody {
            error: "server_error",
            error_description: None,
        };
        return (status, Json(body)).into_response();
    }
    let code = match error {
        AppError::Unauthenticated => OAuthErrorCode::InvalidClient,
        _ => OAuthErrorCode::InvalidRequest,
    };
    refusal(code, public_message(error))
}

/// An error an endpoint answers when it is presented an access token or a
/// registration token in the `Authorization` header (RFC 6750 3).
pub(crate) enum BearerError {
    /// No token was presented: the challenge carries no error code.
    Missing,
    /// The app refused the token, or failed.
    Refused(AppError),
}

impl From<AppError> for BearerError {
    fn from(error: AppError) -> Self {
        Self::Refused(error)
    }
}

impl From<ApiError> for BearerError {
    fn from(error: ApiError) -> Self {
        Self::Refused(error.0)
    }
}

impl IntoResponse for BearerError {
    fn into_response(self) -> Response {
        let error = match self {
            Self::Missing => return challenged(StatusCode::UNAUTHORIZED, None),
            Self::Refused(error) => error,
        };
        let (status, _) = status_and_code(&error);
        log_error(&error, status);
        match error {
            AppError::Unauthenticated => {
                challenged(StatusCode::UNAUTHORIZED, Some("invalid_token"))
            }
            AppError::Forbidden(_) => challenged(StatusCode::FORBIDDEN, Some("insufficient_scope")),
            AppError::Domain(_) => challenged(StatusCode::BAD_REQUEST, Some("invalid_request")),
            other => ApiError(other).into_response(),
        }
    }
}

/// `status` with a `Bearer` challenge naming `code`, and the same code in
/// the body.
fn challenged(status: StatusCode, code: Option<&'static str>) -> Response {
    let challenge = match code {
        Some(code) => format!("Bearer realm=\"ianua\", error=\"{code}\""),
        None => "Bearer realm=\"ianua\"".to_owned(),
    };
    let header =
        HeaderValue::from_str(&challenge).unwrap_or_else(|_| HeaderValue::from_static("Bearer"));
    let Some(code) = code else {
        return (status, [(WWW_AUTHENTICATE, header)]).into_response();
    };
    let body = Json(OAuthErrorBody {
        error: code,
        error_description: None,
    });
    (status, [(WWW_AUTHENTICATE, header)], body).into_response()
}

/// An error dynamic client registration answers (RFC 7591 3.2.2, RFC 7592
/// 2).
pub enum RegistrationError {
    /// A redirect URI that is not one a client may register.
    InvalidRedirectUri(String),
    /// Metadata that is malformed or not allowed.
    InvalidMetadata(String),
    /// The app refused the request, or failed.
    Refused(AppError),
}

impl From<AppError> for RegistrationError {
    fn from(error: AppError) -> Self {
        Self::Refused(error)
    }
}

impl IntoResponse for RegistrationError {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidRedirectUri(reason) => metadata_refusal("invalid_redirect_uri", reason),
            Self::InvalidMetadata(reason) => metadata_refusal("invalid_client_metadata", reason),
            Self::Refused(error @ AppError::Domain(_)) => {
                metadata_refusal("invalid_client_metadata", public_message(&error))
            }
            Self::Refused(error @ AppError::Unauthenticated) => {
                BearerError::Refused(error).into_response()
            }
            Self::Refused(error) => ApiError(error).into_response(),
        }
    }
}

/// `400` with the registration error `code`, described by `reason`.
fn metadata_refusal(code: &'static str, reason: String) -> Response {
    let body = OAuthErrorBody {
        error: code,
        error_description: Some(reason),
    };
    (StatusCode::BAD_REQUEST, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A wrong client secret is answered `401` with a Basic challenge, as
    /// every OAuth library expects.
    #[test]
    fn an_unproved_client_is_challenged() {
        let response = OAuthError::refused(
            OAuthErrorCode::InvalidClient,
            "client authentication failed",
        )
        .into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[WWW_AUTHENTICATE], CLIENT_CHALLENGE);
    }

    /// A used code is answered `400` with no challenge.
    #[test]
    fn a_refused_grant_is_a_bad_request() {
        let response =
            OAuthError::refused(OAuthErrorCode::InvalidGrant, "the code was used").into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
    }

    /// A platform failure becomes an HTTP 500 OAuth response.
    #[test]
    fn a_platform_failure_says_nothing_of_its_cause() {
        let response =
            OAuthError::from(AppError::internal_msg("database password rejected")).into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// An access token the app does not know is answered `401` with an
    /// `invalid_token` challenge.
    #[test]
    fn an_unknown_access_token_is_challenged() {
        let response = BearerError::from(AppError::Unauthenticated).into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            response.headers()[WWW_AUTHENTICATE]
                .to_str()
                .unwrap()
                .contains("invalid_token")
        );
    }
}
