//! How the token endpoint, and the endpoints that authenticate clients the
//! same way, say no: the error codes of RFC 6749 5.2 and the extensions
//! that add to them, or a failure of the platform itself.

use ianua_domain::domains::oauth::grants::authorization_code::AuthCodeError;
use ianua_domain::domains::oauth::grants::authorization_request::AuthorizeRefusal;
use ianua_domain::domains::oauth::grants::device_authorization::DeviceAuthError;
use ianua_domain::domains::oauth::grants::refresh_terms::RefreshRefusal;
use ianua_domain::domains::oauth::grants::token_exchange::ExchangeRefusal;

use crate::error::AppError;
use crate::input::validate_token;

/// An error code a client is answered with, by the name its library
/// branches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthErrorCode {
    /// `invalid_request`: a parameter is missing, repeated or malformed.
    InvalidRequest,
    /// `invalid_client`: the client is unknown, revoked, or did not prove
    /// itself the way it registered. Answered with 401.
    InvalidClient,
    /// `invalid_grant`: the code, refresh token, device code or subject
    /// token does not work, or was issued to another client.
    InvalidGrant,
    /// `unauthorized_client`: the client may not use this grant.
    UnauthorizedClient,
    /// `unsupported_grant_type`: the server offers no such grant.
    UnsupportedGrantType,
    /// `unsupported_response_type`: a pushed request asked for something
    /// other than a code.
    UnsupportedResponseType,
    /// `invalid_scope`: a scope is unknown, or wider than allowed.
    InvalidScope,
    /// `authorization_pending`: nobody answered the device request yet
    /// (RFC 8628 3.5).
    AuthorizationPending,
    /// `slow_down`: the device polled too soon (RFC 8628 3.5).
    SlowDown,
    /// `access_denied`: the person refused the device (RFC 8628 3.5).
    AccessDenied,
    /// `expired_token`: the device request ran out (RFC 8628 3.5).
    ExpiredToken,
    /// `invalid_target`: the audience asked for is not one the token can be
    /// exchanged for (RFC 8693 2.2.2).
    InvalidTarget,
    /// `invalid_dpop_proof`: the client must bind its tokens to a `DPoP`
    /// key and proved none (RFC 9449 5).
    InvalidDpopProof,
}

impl OAuthErrorCode {
    /// The code's registered name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::AccessDenied => "access_denied",
            Self::ExpiredToken => "expired_token",
            Self::InvalidTarget => "invalid_target",
            Self::InvalidDpopProof => "invalid_dpop_proof",
        }
    }
}

/// Why a request at the token endpoint got no tokens.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// The request was refused, with the code the client is told and a
    /// description safe to show it. No token or secret is ever in it.
    #[error("{}: {reason}", code.as_str())]
    Refused {
        /// The protocol value returned in the OAuth error field.
        code: OAuthErrorCode,
        /// What was wrong, for `error_description`.
        reason: String,
    },
    /// The platform failed, or a lookup said what [`AppError`] says.
    #[error(transparent)]
    Failed(#[from] AppError),
}

impl TokenError {
    /// A refusal with `code`, described by `reason`.
    pub(crate) fn refused(code: OAuthErrorCode, reason: impl Into<String>) -> Self {
        Self::Refused {
            code,
            reason: reason.into(),
        }
    }

    /// The code a refusal carries, if it is one.
    #[must_use]
    pub fn code(&self) -> Option<OAuthErrorCode> {
        match self {
            Self::Refused { code, .. } => Some(*code),
            Self::Failed(_) => None,
        }
    }

    /// The client did not prove itself.
    pub(crate) fn invalid_client() -> Self {
        Self::refused(
            OAuthErrorCode::InvalidClient,
            "client authentication failed",
        )
    }
}

impl From<AuthCodeError> for TokenError {
    fn from(refusal: AuthCodeError) -> Self {
        Self::refused(OAuthErrorCode::InvalidGrant, refusal.to_string())
    }
}

impl From<RefreshRefusal> for TokenError {
    fn from(refusal: RefreshRefusal) -> Self {
        let code = match refusal {
            RefreshRefusal::ClientRefused => OAuthErrorCode::UnauthorizedClient,
            RefreshRefusal::ScopeWidened => OAuthErrorCode::InvalidScope,
            RefreshRefusal::OtherClient
            | RefreshRefusal::UnprovedKey
            | RefreshRefusal::Reused
            | RefreshRefusal::Revoked
            | RefreshRefusal::Expired => OAuthErrorCode::InvalidGrant,
        };
        Self::refused(code, refusal.to_string())
    }
}

impl From<DeviceAuthError> for TokenError {
    fn from(refusal: DeviceAuthError) -> Self {
        let code = match refusal {
            DeviceAuthError::SlowDown => OAuthErrorCode::SlowDown,
            DeviceAuthError::Expired => OAuthErrorCode::ExpiredToken,
            DeviceAuthError::ClientRefused => OAuthErrorCode::UnauthorizedClient,
            DeviceAuthError::NotTheSignedInPerson | DeviceAuthError::InvalidTransition(_) => {
                OAuthErrorCode::InvalidGrant
            }
        };
        Self::refused(code, refusal.to_string())
    }
}

impl From<ExchangeRefusal> for TokenError {
    fn from(refusal: ExchangeRefusal) -> Self {
        let code = match refusal {
            ExchangeRefusal::UnauthorizedClient => OAuthErrorCode::UnauthorizedClient,
            ExchangeRefusal::InvalidSubjectToken => OAuthErrorCode::InvalidGrant,
            ExchangeRefusal::InvalidActorToken => OAuthErrorCode::InvalidRequest,
            ExchangeRefusal::InvalidTarget => OAuthErrorCode::InvalidTarget,
            ExchangeRefusal::InvalidScope => OAuthErrorCode::InvalidScope,
        };
        Self::refused(code, refusal.to_string())
    }
}

impl From<AuthorizeRefusal> for TokenError {
    fn from(refusal: AuthorizeRefusal) -> Self {
        let (code, reason) = match refusal {
            AuthorizeRefusal::InvalidRequest => (
                OAuthErrorCode::InvalidRequest,
                "the request is malformed or names a redirect the client did not register",
            ),
            AuthorizeRefusal::UnauthorizedClient => (
                OAuthErrorCode::UnauthorizedClient,
                "this client may not use the authorization code flow",
            ),
            AuthorizeRefusal::UnsupportedResponseType => (
                OAuthErrorCode::UnsupportedResponseType,
                "only the authorization code flow is offered",
            ),
            AuthorizeRefusal::InvalidScope => (
                OAuthErrorCode::InvalidScope,
                "a scope is not one this client may ask for",
            ),
            AuthorizeRefusal::LoginRequired | AuthorizeRefusal::ConsentRequired => (
                OAuthErrorCode::InvalidRequest,
                "the person must sign in or consent in the browser",
            ),
        };
        Self::refused(code, reason)
    }
}

/// Refuses `value`, sent as `field`, when it is empty or too long, before
/// anything is hashed. The refusal names it as `what`.
///
/// # Errors
///
/// - `invalid_request` when `value` is malformed.
pub(crate) fn ensure_token_shaped(
    field: &'static str,
    value: &str,
    what: &str,
) -> Result<(), TokenError> {
    validate_token(field, value).map_err(|_| {
        TokenError::refused(
            OAuthErrorCode::InvalidRequest,
            format!("the {what} is malformed"),
        )
    })
}
