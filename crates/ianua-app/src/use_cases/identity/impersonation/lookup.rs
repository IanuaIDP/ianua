//! Loading the support impersonation a use case names, failing with
//! not-found when there is none for the caller.

use ianua_domain::domains::identity::impersonation::SupportImpersonation;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{SupportImpersonationId, UserId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::identity::SupportImpersonationStore;
use crate::tenancy::ScopedTenant;

/// The impersonation `id`, when it names `person` as the admin or as the
/// person acted as. One between other people answers the same as a missing
/// one, so its existence is not revealed.
///
/// # Errors
///
/// - `AppError::NotFound` if there is no such impersonation involving
///   `person`.
/// - `AppError::Internal` on storage failure.
pub(super) async fn involving(
    store: &dyn SupportImpersonationStore,
    tenant: &ScopedTenant,
    id: &SupportImpersonationId,
    person: &UserId,
) -> Result<SupportImpersonation<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .filter(|found| found.admin() == person || found.user_id() == person)
        .or_not_found(message!(
            "identity-support-impersonation-not-found",
            "support impersonation not found"
        ))
}
