//! A device asking for its codes (RFC 8628 3.1): its client, proved as at
//! the token endpoint, and the scopes it asks for, separated by spaces.

use axum::extract::{FromRequest, Request};
use ianua_app::use_cases::oauth::flows::RequestDeviceCodeRequest;

use crate::error::oauth::OAuthError;
use crate::extractors::oauth::client::client_proof;
use crate::extractors::oauth::form::OAuthForm;
use crate::extractors::oauth::token::scope_list;
use crate::state::ApiState;

/// A device authorization request.
pub(crate) struct DeviceCodeAsk(pub RequestDeviceCodeRequest);

impl FromRequest<ApiState> for DeviceCodeAsk {
    type Rejection = OAuthError;

    async fn from_request(req: Request, state: &ApiState) -> Result<Self, Self::Rejection> {
        let mut form = OAuthForm::from_request(req, state).await?;
        let scopes = form
            .take("scope")
            .map(|raw| scope_list(&raw))
            .transpose()?
            .unwrap_or_default();
        Ok(Self(RequestDeviceCodeRequest {
            client: client_proof(&mut form)?,
            issuer: form.issuer(),
            scopes,
        }))
    }
}
