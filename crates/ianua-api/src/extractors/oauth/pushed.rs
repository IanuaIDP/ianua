//! A pushed authorization request (RFC 9126 2.1): the authorization
//! parameters, sent by the client itself, proved as at the token endpoint.

use axum::extract::{FromRequest, Request};
use ianua_app::use_cases::oauth::flows::PushRequest;

use crate::error::oauth::OAuthError;
use crate::error::public_message;
use crate::extractors::oauth::authorization::AuthorizationParams;
use crate::extractors::oauth::client::client_proof;
use crate::extractors::oauth::form::OAuthForm;
use crate::state::ApiState;

/// An authorization request a client pushes.
pub(crate) struct PushedAuthorization(pub PushRequest);

impl FromRequest<ApiState> for PushedAuthorization {
    type Rejection = OAuthError;

    async fn from_request(req: Request, state: &ApiState) -> Result<Self, Self::Rejection> {
        let mut form = OAuthForm::from_request(req, state).await?;
        let client = client_proof(&mut form)?;
        let params = AuthorizationParams::from_form(&mut form);
        if params.request_uri.is_some() {
            return Err(OAuthError::invalid_request(
                "a pushed request may not name a request_uri",
            ));
        }
        let parameters = params
            .carried()
            .map_err(|refused| OAuthError::invalid_request(public_message(&refused.0)))?;
        Ok(Self(PushRequest {
            client,
            issuer: form.issuer(),
            parameters,
        }))
    }
}
