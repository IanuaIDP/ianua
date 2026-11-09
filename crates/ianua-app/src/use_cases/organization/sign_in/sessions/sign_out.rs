//! Ending org sessions in bulk, once the domain has decided they may no
//! longer hold: a member signs in again, changes their password, is locked
//! or removed, or the organization is suspended or closed.
//!
//! The callers a cache keeps for these sessions are dropped by the event
//! each such path records, once its change is committed, never here.

use ianua_domain::types::{OrgUserId, OrganizationId};

use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgSessionStore;

/// Ends every session of `member`.
///
/// # Errors
///
/// Returns `AppError::Internal` if the store fails.
pub(in crate::use_cases::organization) async fn sign_out_member(
    sessions: &dyn OrgSessionStore,
    member: &OrgUserId,
) -> Result<(), AppError> {
    sessions.revoke_all_by_user(member).await.or_internal()?;
    Ok(())
}

/// Ends every session of the organization, so a suspended or closed
/// organization's tokens stop working.
///
/// # Errors
///
/// Returns `AppError::Internal` if the store fails.
pub(in crate::use_cases::organization) async fn sign_out_organization(
    sessions: &dyn OrgSessionStore,
    organization_id: &OrganizationId,
) -> Result<(), AppError> {
    sessions
        .revoke_all_by_org(organization_id)
        .await
        .or_internal()?;
    Ok(())
}
