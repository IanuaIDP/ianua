//! Loading the organization's identity provider, and the check every change
//! to it starts from.

use ianua_domain::domains::organization::access::identity_provider::OrgIdentityProvider;
use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::domains::organization::members::permission::{OrgPermission, OrganizationAction};
use ianua_domain::message;
use ianua_domain::types::OrganizationId;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::organization::OrgIdentityProviderStore;

/// The identity provider of `organization_id`.
///
/// # Errors
///
/// - `AppError::NotFound` when the organization has none.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization) async fn existing_provider(
    store: &dyn OrgIdentityProviderStore,
    organization_id: &OrganizationId,
) -> Result<OrgIdentityProvider, AppError> {
    store
        .find_for_organization(organization_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "organization-identity-provider-not-found",
            "identity provider not found"
        ))
}

/// Refuses a caller who may not read or change the organization's sign-in
/// settings, before anything about its provider is read or fetched.
///
/// # Errors
///
/// - `AppError::Forbidden` when `control` does not hold the right.
pub(in crate::use_cases::organization::identity_providers) fn ensure_manages_sign_in(
    control: &OrgControl<'_>,
    organization_id: &OrganizationId,
) -> Result<(), AppError> {
    control
        .ensure_may(
            organization_id,
            OrgPermission::Organization(OrganizationAction::AuthConfig),
        )
        .map_err(AppError::from_domain)
}
