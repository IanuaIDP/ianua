//! The requests a client makes about a token it holds: introspection
//! (RFC 7662 2.1) and revocation (RFC 7009 2.1).

use axum::extract::{FromRequest, Request};
use ianua_app::use_cases::oauth::token::{IntrospectRequest, RevokeRequest, TypeHint};
use ianua_domain::shared::security::secret::Secret;

use crate::error::oauth::OAuthError;
use crate::extractors::oauth::client::client_proof;
use crate::extractors::oauth::form::OAuthForm;
use crate::state::ApiState;

/// A resource server asking what an access token says about itself.
pub(crate) struct IntrospectionRequest(pub IntrospectRequest);

impl FromRequest<ApiState> for IntrospectionRequest {
    type Rejection = OAuthError;

    async fn from_request(req: Request, state: &ApiState) -> Result<Self, Self::Rejection> {
        let mut form = OAuthForm::from_request(req, state).await?;
        let token = Secret::new(form.required("token")?);
        Ok(Self(IntrospectRequest {
            client: client_proof(&mut form)?,
            issuer: form.issuer(),
            token,
        }))
    }
}

/// A client asking for a token it holds to be revoked.
pub(crate) struct RevocationRequest(pub RevokeRequest);

impl FromRequest<ApiState> for RevocationRequest {
    type Rejection = OAuthError;

    async fn from_request(req: Request, state: &ApiState) -> Result<Self, Self::Rejection> {
        let mut form = OAuthForm::from_request(req, state).await?;
        let token = Secret::new(form.required("token")?);
        let hint = type_hint(form.take("token_type_hint").as_deref());
        Ok(Self(RevokeRequest {
            client: client_proof(&mut form)?,
            issuer: form.issuer(),
            token,
            hint,
        }))
    }
}

/// The kind of token `hint` says it is. A hint this server does not know
/// is no hint (RFC 7009 2.1): every kind is searched.
fn type_hint(hint: Option<&str>) -> TypeHint {
    match hint {
        Some("access_token") => TypeHint::AccessToken,
        Some("refresh_token") => TypeHint::RefreshToken,
        Some(_) | None => TypeHint::NotGiven,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hint this server does not know searches every kind of token.
    #[test]
    fn an_unknown_hint_is_no_hint() {
        assert_eq!(type_hint(Some("id_token")), TypeHint::NotGiven);
        assert_eq!(type_hint(Some("refresh_token")), TypeHint::RefreshToken);
    }
}
