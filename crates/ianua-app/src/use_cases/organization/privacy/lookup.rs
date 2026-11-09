//! Loading the erasure requests the privacy use cases start from, and the
//! check that a member has none under way.

use ianua_domain::domains::organization::members::privacy::erasure::OrgErasureRequest;
use ianua_domain::message;
use ianua_domain::types::{ErasureRequestId, OrgUserId, OrganizationId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::organization::OrgErasureRequestStore;

/// The erasure request `id` of `organization_id`. A request of another
/// organization reads as absent.
///
/// # Errors
///
/// - `AppError::NotFound` if the organization has no such request.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization::privacy) async fn existing_org_erasure(
    store: &dyn OrgErasureRequestStore,
    organization_id: &OrganizationId,
    id: &ErasureRequestId,
) -> Result<OrgErasureRequest, AppError> {
    store
        .find_by_id(organization_id, id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "identity-erasure-request-not-found",
            "erasure request not found"
        ))
}

/// Refuses a second erasure request while one for `member` is under way.
///
/// # Errors
///
/// - `AppError::Conflict` when a request for the member is under way.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization::privacy) async fn ensure_no_erasure_under_way(
    store: &dyn OrgErasureRequestStore,
    organization_id: &OrganizationId,
    member: &OrgUserId,
) -> Result<(), AppError> {
    let existing = store
        .find_active_by_member(organization_id, member)
        .await
        .or_internal()?;
    if existing.is_some() {
        return Err(AppError::Conflict(message!(
            "organization-an-erasure-of-this-member-is",
            "an erasure of this member is already under way"
        )));
    }
    Ok(())
}
