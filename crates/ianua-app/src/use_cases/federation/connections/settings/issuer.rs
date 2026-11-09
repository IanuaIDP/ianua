//! Checking an OIDC connection's issuer before it is saved.
//!
//! Every sign-in reads the provider's endpoints from the issuer's discovery
//! document, so an issuer that publishes none, or a mistyped one, makes a
//! connection nobody can sign in through. Creating a connection and changing
//! its config both go through here, so the mistake shows where it was made
//! instead of at the first failed sign-in.

use crate::error::AppError;
use crate::ports::federation::OidcValidator;
use crate::use_cases::federation::connections::ProviderConfig;

/// Refuses an OIDC `config` whose issuer publishes no usable discovery
/// document. SAML connections have no issuer to check and pass through.
///
/// # Errors
///
/// Returns `AppError::Domain` if the issuer's discovery document cannot be
/// fetched or does not name it as the issuer.
pub(in crate::use_cases::federation::connections) async fn ensure_published(
    validator: &dyn OidcValidator,
    config: &ProviderConfig,
) -> Result<(), AppError> {
    let ProviderConfig::Oidc(oidc) = config else {
        return Ok(());
    };
    validator
        .confirm_issuer(&oidc.issuer)
        .await
        .map_err(AppError::from_domain)
}
