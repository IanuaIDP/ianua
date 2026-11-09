//! Loading the organization's branding the branding use cases start from.

use ianua_domain::domains::organization::branding::OrgBranding;
use ianua_domain::types::OrganizationId;

use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgBrandingStore;

/// The branding of `organization_id`, or the platform's own look when the
/// organization never changed it.
///
/// # Errors
///
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization::branding) async fn current_org_branding(
    store: &dyn OrgBrandingStore,
    organization_id: &OrganizationId,
) -> Result<OrgBranding, AppError> {
    let stored = store.find(organization_id).await.or_internal()?;
    Ok(stored.unwrap_or_else(|| OrgBranding::platform_default(*organization_id)))
}
