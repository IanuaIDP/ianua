//! Signing in at an installed integration's service to connect an account,
//! through the app the deployment registered with it.
//!
//! The platform has one callback address every app registers; each
//! integration knows its service's authorize and token addresses, the
//! scopes it needs and the app's client id and secret. The browser is sent
//! the `S256` challenge of the PKCE verifier, never the verifier, and the
//! exchange is held to a time limit, so a hung service fails the sign-in
//! rather than holding the callback.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_app::ports::workflows::{
    Exchanging, PlaceAsked, ServiceSignIn, SignInAddress, SignInFailure, SignInRequest,
};
use ianua_domain::domains::workflows::account::connection::ServicePlace;
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::HttpsUrl;
use ianua_integration::connect::{Exchange, SignIn, SignInLink, Swap};
use sha2::{Digest as _, Sha256};

use crate::http::client::LONGEST_CALL;
use crate::integrations::installed::Installed;

/// The path of the one callback address under the deployment's public base
/// URL.
const CALLBACK_PATH: &str = "api/v1/integrations/callback";

/// Signs people in at the installed integrations' services.
pub struct InstalledServiceSignIn {
    installed: Arc<Installed>,
    redirect: String,
    limit: Duration,
}

impl InstalledServiceSignIn {
    /// Sign-ins through `installed`, every service sending the browser back
    /// to the callback under `app_base_url`, an exchange given up after
    /// `limit`, at most [`LONGEST_CALL`].
    #[must_use]
    pub fn new(installed: Arc<Installed>, app_base_url: &HttpsUrl, limit: Duration) -> Self {
        Self {
            installed,
            redirect: callback_address(app_base_url),
            limit: limit.min(LONGEST_CALL),
        }
    }

    /// The sign-in `integration` offers here, if it does.
    fn of(&self, integration: &IntegrationKey) -> Option<&dyn SignIn> {
        self.installed.find(integration)?.sign_in()
    }
}

#[async_trait]
impl ServiceSignIn for InstalledServiceSignIn {
    fn offers(&self, integration: &IntegrationKey) -> bool {
        self.of(integration).is_some()
    }

    fn asks_for(&self, integration: &IntegrationKey) -> PlaceAsked {
        self.of(integration)
            .and_then(SignIn::asks_for_place)
            .map_or(PlaceAsked::Nothing, PlaceAsked::Named)
    }

    fn authorize_address(
        &self,
        integration: &IntegrationKey,
        request: SignInRequest<'_>,
    ) -> Result<SignInAddress, DomainError> {
        let Some(sign_in) = self.of(integration) else {
            return Err(DomainError::invalid(message!(
                "infra-the-integration-offers-no-sign-in",
                "the integration cannot be connected by signing in here"
            )));
        };
        let challenge = challenge_of(request.verifier);
        Ok(SignInAddress::new(sign_in.authorize_address(SignInLink {
            state: request.state,
            challenge: &challenge,
            redirect: &self.redirect,
        })))
    }

    async fn exchange(&self, exchanging: Exchanging<'_>) -> Result<Secret, SignInFailure> {
        let sign_in = self
            .of(exchanging.integration)
            .ok_or(SignInFailure::Refused)?;
        let swap = Swap {
            code: exchanging.code,
            verifier: exchanging.verifier,
            redirect: &self.redirect,
            place: exchanging.place.map(ServicePlace::as_str),
        };
        let exchanged = tokio::time::timeout(self.limit, sign_in.exchange(swap))
            .await
            .map_err(|_| SignInFailure::Unreachable)?;
        match exchanged {
            Exchange::Issued(credential) => Ok(credential),
            Exchange::Refused => Err(SignInFailure::Refused),
            Exchange::Unreachable => Err(SignInFailure::Unreachable),
        }
    }
}

/// The one callback address under `app_base_url`.
fn callback_address(app_base_url: &HttpsUrl) -> String {
    format!(
        "{}/{CALLBACK_PATH}",
        app_base_url.as_str().trim_end_matches('/')
    )
}

/// The `S256` PKCE challenge of `verifier`: base64url of its SHA-256.
fn challenge_of(verifier: &Secret) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.expose().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The challenge is RFC 7636's own example: the verifier
    /// `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` gives
    /// `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM`.
    #[test]
    fn the_challenge_is_the_rfc_example() {
        let verifier = Secret::new("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_owned());

        assert_eq!(
            challenge_of(&verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    /// Every app registers the callback under the deployment's address,
    /// however its base URL is written.
    #[test]
    fn the_callback_sits_under_the_public_base_url() {
        let base = HttpsUrl::new("https://ianua.example.com/").unwrap();

        assert_eq!(
            callback_address(&base),
            "https://ianua.example.com/api/v1/integrations/callback"
        );
    }
}
