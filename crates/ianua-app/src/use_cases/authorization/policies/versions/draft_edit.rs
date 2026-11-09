//! Changing the tenant's open policy draft: load it, make one change through
//! the policy's own step, save it, then record what the policy raised. Each
//! step checks the editor's right and that the version is still a draft, so
//! a draft sent to review is not rewritten. The live version is never
//! touched here.

use ianua_domain::domains::authorization::policy::set::PolicySet;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::PolicyStore;
use crate::tenancy::ScopedTenant;
use crate::use_cases::authorization::lookup::existing_draft;

/// The tenant's open draft after `edit`, saved, with what the policy raised
/// recorded as done by `editor` once it is.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no open draft.
/// - The errors of `edit`, after which nothing is saved or recorded.
/// - `AppError::Internal` when the policy cannot be read or written, or the
///   change cannot be recorded.
pub(in crate::use_cases::authorization::policies) async fn saved_edit(
    store: &dyn PolicyStore,
    tenant: &ScopedTenant,
    auditor: &RequestAuditor,
    editor: &ActorRef,
    edit: impl FnOnce(&mut PolicySet) -> Result<(), AppError>,
) -> Result<PolicySet, AppError> {
    let mut draft = existing_draft(store, tenant).await?;
    edit(&mut draft)?;
    store.save(tenant, &draft).await.or_internal()?;
    auditor
        .dispatch_by(editor, draft.take_events(tenant))
        .await
        .or_internal()?;
    Ok(draft)
}
