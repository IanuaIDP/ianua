//! Tokens an app presents as `Bearer` (RFC 6750 2), or as `DPoP` for a
//! bound access token (RFC 9449 7.1): an access token to `userinfo`, an
//! initial access token to the registration endpoint, and a registration
//! access token to manage what it registered.
//!
//! These are not callers: the auth middleware finds no one behind them,
//! and the use case decides what each one is worth.

use axum::extract::{FromRequest, FromRequestParts, Path, Request};
use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use ianua_app::error::AppError;
use ianua_app::use_cases::oauth::flows::PresentedAccessToken;
use ianua_app::use_cases::oauth::sender::DpopHeader;
use ianua_domain::shared::security::secret::Secret;

use crate::error::oauth::BearerError;
use crate::extractors::oauth::dpop::{SentTo, evidence, sender_evidence};
use crate::extractors::oauth::form::path_issuer;
use crate::extractors::paths::oauth::RegisteredClientPath;
use crate::state::ApiState;

/// The largest form body an access token is read from.
const MOST_BODY_BYTES: usize = 16 * 1024;

/// The `userinfo` endpoint's path under a tenant's issuer.
const USERINFO_PATH: &str = "/oauth/userinfo";

/// The token in an `Authorization: Bearer` header.
pub(crate) struct BearerToken(pub Secret);

impl<S: Send + Sync> FromRequestParts<S> for BearerToken {
    type Rejection = BearerError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        header_token(&parts.headers)
            .map(Self)
            .ok_or(BearerError::Missing)
    }
}

/// The registered client route and its presented management token.
pub(crate) struct RegistrationBearer {
    /// The client named by the route, validated when the request is mapped.
    pub path: RegisteredClientPath,
    /// The bearer token whose ownership the application checks.
    pub token: Secret,
}

impl<S: Send + Sync> FromRequestParts<S> for RegistrationBearer {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Path(path) = Path::<RegisteredClientPath>::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let BearerToken(token) = BearerToken::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        Ok(Self { path, token })
    }
}

/// An access token presented to `userinfo`: in the `Authorization`
/// header, or, on a form `POST`, as `access_token` in the body.
///
/// A `DPoP`-bound token comes as `Authorization: DPoP` beside its `DPoP`
/// proof (RFC 9449 7.1), and only then is the proof handed on. A token
/// presented as `Bearer` or in the body proves nothing, so a bound one is
/// refused by the app.
pub(crate) struct AccessTokenPresented(pub PresentedAccessToken);

impl FromRequest<ApiState> for AccessTokenPresented {
    type Rejection = BearerError;

    async fn from_request(req: Request, state: &ApiState) -> Result<Self, Self::Rejection> {
        let (mut parts, body) = req.into_parts();
        let issuer = path_issuer(&mut parts, state).await?;
        let to = SentTo {
            method: &parts.method,
            issuer: &issuer,
            path: USERINFO_PATH,
        };
        if let Some(token) = scheme_token(&parts.headers, "DPoP ") {
            let sender = sender_evidence(&parts.headers, &to)
                .map_err(|_| BearerError::Refused(AppError::Unauthenticated))?;
            return Ok(Self(PresentedAccessToken {
                token,
                sender,
                issuer,
            }));
        }
        let token = match header_token(&parts.headers) {
            Some(token) => token,
            None => body_token(&parts.headers, body).await?,
        };
        Ok(Self(PresentedAccessToken {
            token,
            sender: evidence(DpopHeader::NotSent, &to),
            issuer,
        }))
    }
}

/// The token in the `Authorization: Bearer` header of `headers`, if any.
fn header_token(headers: &HeaderMap) -> Option<Secret> {
    scheme_token(headers, "Bearer ")
}

/// The token after `scheme` in the `Authorization` header of `headers`, if
/// it carries one.
fn scheme_token(headers: &HeaderMap, scheme: &str) -> Option<Secret> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix(scheme))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(|token| Secret::new(token.to_owned()))
}

/// The `access_token` of a form body, the only other place a token may be
/// sent (RFC 6750 2.2).
async fn body_token(headers: &HeaderMap, body: axum::body::Body) -> Result<Secret, BearerError> {
    let form = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .to_ascii_lowercase()
                .starts_with("application/x-www-form-urlencoded")
        });
    if !form {
        return Err(BearerError::Missing);
    }
    let bytes = axum::body::to_bytes(body, MOST_BODY_BYTES)
        .await
        .map_err(|_| BearerError::Missing)?;
    url::form_urlencoded::parse(&bytes)
        .find(|(name, value)| name == "access_token" && !value.is_empty())
        .map(|(_, value)| Secret::new(value.into_owned()))
        .ok_or(BearerError::Missing)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    /// A bearer token is read from the header, without the scheme.
    #[test]
    fn a_bearer_token_is_read_from_the_header() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer abc"));

        assert_eq!(
            header_token(&headers).map(|token| token.expose().to_owned()),
            Some("abc".to_owned())
        );
    }

    /// A Basic header carries no bearer token.
    #[test]
    fn a_basic_header_carries_no_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic abc"));

        assert!(header_token(&headers).is_none());
    }
}
