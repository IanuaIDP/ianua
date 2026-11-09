//! What sending a member to the organization's identity provider and taking
//! its answer share: the provider must be switched on, and the
//! organization must allow its protocol from where the request came.

use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::federation::connection::FederationProtocol;
use ianua_domain::domains::organization::access::identity_provider::OrgIdentityProvider;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::message;

use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgIdentityProviderStore;
use crate::services::authentication::sign_in_gate::ClientOrigin;

/// The organization's provider, provided members may sign in through it
/// now.
///
/// An organization without one answers as one whose provider is switched
/// off, so the answer says nothing more than that single sign-on is not
/// available.
///
/// # Errors
///
/// - `AppError::Forbidden` when the organization has no provider, or it is
///   switched off.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization::sign_in) async fn switched_on_provider(
    store: &dyn OrgIdentityProviderStore,
    organization: &Organization,
) -> Result<OrgIdentityProvider, AppError> {
    store
        .find_for_organization(organization.id())
        .await
        .or_internal()?
        .filter(|provider| provider.status().is_active())
        .ok_or_else(unavailable)
}

/// Refuses a sign-in through `protocol` the organization does not allow,
/// or not from where `origin` came.
///
/// # Errors
///
/// - `AppError::Forbidden` when the organization's settings rule it out.
/// - `AppError::Domain` when they cannot be read.
pub(in crate::use_cases::organization::sign_in) fn ensure_admitted(
    organization: &Organization,
    protocol: FederationProtocol,
    origin: &ClientOrigin,
) -> Result<(), AppError> {
    organization
        .auth_config()
        .admits(sso_method(protocol), origin.ip_address.as_ref())
        .map(|_| ())
        .map_err(AppError::from_domain)
}

/// The refusal for an organization that offers no single sign-on now.
pub(in crate::use_cases::organization::sign_in) fn unavailable() -> AppError {
    AppError::Forbidden(message!(
        "organization-single-sign-on-is-not-available",
        "single sign-on is not available for this organization"
    ))
}

/// The way of signing in a protocol is.
fn sso_method(protocol: FederationProtocol) -> AuthMethod {
    match protocol {
        FederationProtocol::Saml => AuthMethod::Saml,
        FederationProtocol::Oidc => AuthMethod::Oidc,
    }
}
