//! Signing out through an app (OpenID Connect RP-Initiated Logout 1.0): the
//! request an app sends the browser with, and the browser that brings it,
//! signed in here or not.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use ianua_app::auditor::RequestAuditor;
use ianua_app::ports::shared::ResolvedCaller;
use ianua_app::services::authentication::logout_browser::LogoutBrowser;
use ianua_app::use_cases::oauth::flows::{
    AddressAsked, ClientNamed, EndSessionRequest, HintSent, LogoutConfirmation,
};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ClientId, Issuer, RedirectUri};
use serde::Deserialize;

use crate::error::ApiError;
use crate::extractors::callers::TenantCaller;
use crate::extractors::oauth::form::path_issuer;
use crate::extractors::public_tenant::PublicTenant;
use crate::state::ApiState;

/// A sign-out request, every parameter as the app sent it.
#[derive(Default, Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
#[into_params(parameter_in = Query)]
pub(crate) struct LogoutParams {
    /// An ID token this tenant issued to the app, naming who signs out.
    pub id_token_hint: Option<String>,
    /// Who the app expects to sign out; shown on the page.
    pub logout_hint: Option<String>,
    /// The app asking, by the `client_id` it was issued.
    pub client_id: Option<String>,
    /// Where to send the person afterwards; one the app registered.
    pub post_logout_redirect_uri: Option<String>,
    /// The app's own value, handed back with the person.
    pub state: Option<String>,
    /// The languages the pages should speak, separated by spaces.
    pub ui_locales: Option<String>,
}

impl LogoutParams {
    /// The sign-out the app asks of the tenant `issuer` names, `confirmation`
    /// saying whether the person already agreed to it.
    ///
    /// # Errors
    ///
    /// `422` when the `client_id` or the address is malformed.
    pub(crate) fn request(
        &self,
        issuer: Issuer,
        confirmation: LogoutConfirmation,
    ) -> Result<EndSessionRequest, ApiError> {
        Ok(EndSessionRequest {
            issuer,
            id_token_hint: self
                .id_token_hint
                .clone()
                .map_or(HintSent::NotSent, |hint| HintSent::Sent(Secret::new(hint))),
            client_id: self.client_named()?,
            post_logout_redirect_uri: self.address_asked()?,
            confirmation,
        })
    }

    /// Every parameter that was sent, by its name, to carry the request on.
    pub(crate) fn sent(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("id_token_hint", &self.id_token_hint),
            ("logout_hint", &self.logout_hint),
            ("client_id", &self.client_id),
            ("post_logout_redirect_uri", &self.post_logout_redirect_uri),
            ("state", &self.state),
            ("ui_locales", &self.ui_locales),
        ]
        .into_iter()
        .filter_map(|(name, value)| value.as_deref().map(|value| (name, value)))
    }

    /// The app the request names, if any.
    fn client_named(&self) -> Result<ClientNamed, ApiError> {
        let Some(raw) = self.client_id.as_deref() else {
            return Ok(ClientNamed::NotNamed);
        };
        ClientId::new(raw)
            .map(ClientNamed::Named)
            .map_err(ApiError::validation)
    }

    /// The address the request asks to go to afterwards, if any.
    fn address_asked(&self) -> Result<AddressAsked, ApiError> {
        let Some(raw) = self.post_logout_redirect_uri.as_deref() else {
            return Ok(AddressAsked::NotAsked);
        };
        RedirectUri::new(raw)
            .map(AddressAsked::Asked)
            .map_err(ApiError::validation)
    }
}

/// The browser asking to sign out: signed in to the tenant the path names,
/// or not, with the tenant's issuer.
pub(crate) struct LogoutVisit {
    /// Whether the browser holds a session here, and the tenant.
    pub browser: LogoutBrowser,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
    /// The tenant's issuer, whose ID tokens a hint must be.
    pub issuer: Issuer,
}

impl FromRequestParts<ApiState> for LogoutVisit {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let issuer = path_issuer(parts, state).await?;
        if parts.extensions.get::<ResolvedCaller>().is_none() {
            let visitor = PublicTenant::from_request_parts(parts, state).await?;
            return Ok(Self {
                browser: LogoutBrowser::SignedOut(visitor.tenant),
                auditor: visitor.auditor,
                issuer,
            });
        }
        let signed_in = TenantCaller::from_request_parts(parts, state).await?;
        Ok(Self {
            browser: LogoutBrowser::SignedIn(Box::new(signed_in.caller)),
            auditor: signed_in.auditor,
            issuer,
        })
    }
}
