//! Telling an app's server that a person signed out (OpenID Connect
//! Back-Channel Logout).

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::HttpsUrl;

/// Dyn-safe port posting a signed logout token to the back-channel logout
/// address an app registered.
///
/// The adapter posts `logout_token` as a form field, follows no redirect,
/// and times out after a few seconds: an app whose server hangs must not
/// hold up the sign-out of everyone else. It never logs the token.
#[async_trait]
pub trait BackChannelLogoutSender: Send + Sync {
    /// Posts `logout_token` to `uri`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the app cannot be reached
    /// in time or does not answer with success.
    async fn deliver(&self, uri: &HttpsUrl, logout_token: &Secret) -> Result<(), DomainError>;
}
