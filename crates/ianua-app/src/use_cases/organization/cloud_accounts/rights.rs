//! Who may change and read an organization's cloud connections.
//!
//! A connection decides where tenant data is built, so changing it, using
//! it, or reading the customer's infrastructure through it is a change to
//! the organization. Seeing that one exists is a read of the organization.

use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::domains::organization::members::permission::{OrgPermission, OrganizationAction};
use ianua_domain::types::OrganizationId;

use crate::error::AppError;

/// Refuses a member who may not change `organization_id`.
///
/// # Errors
///
/// - `AppError::Forbidden` when `control` does not carry the right.
pub(in crate::use_cases::organization::cloud_accounts) fn ensure_may_connect(
    control: &OrgControl<'_>,
    organization_id: &OrganizationId,
) -> Result<(), AppError> {
    control
        .ensure_may(
            organization_id,
            OrgPermission::Organization(OrganizationAction::Update),
        )
        .map_err(AppError::from_domain)
}

/// Refuses a member who may not read `organization_id`.
///
/// # Errors
///
/// - `AppError::Forbidden` when `control` does not carry the right.
pub(in crate::use_cases::organization::cloud_accounts) fn ensure_may_see_connections(
    control: &OrgControl<'_>,
    organization_id: &OrganizationId,
) -> Result<(), AppError> {
    control
        .ensure_may(
            organization_id,
            OrgPermission::Organization(OrganizationAction::View),
        )
        .map_err(AppError::from_domain)
}
