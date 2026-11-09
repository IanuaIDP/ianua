//! The user or agent a receiver names when it adds a subject to its stream
//! or removes one, which must be the tenant's.

use ianua_domain::domains::signals::signal::SignalSubject;
use ianua_domain::message;
use ianua_domain::types::PrincipalRef;

use crate::error::{AppError, OrInternal};
use crate::ports::shared::PrincipalExistenceChecker;
use crate::tenancy::ScopedTenant;

/// Refuses a subject the tenant has no user or agent for, as the Shared
/// Signals framework answers an unknown subject.
///
/// Without it, a receiver adding made-up ids would fill its stream's list
/// with subjects that never exist, up to the most a stream keeps.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such user or agent.
/// - `AppError::Internal` when the lookup fails.
pub(in crate::use_cases::signals::streams) async fn ensure_subject_exists(
    principals: &dyn PrincipalExistenceChecker,
    tenant: &ScopedTenant,
    subject: &SignalSubject,
) -> Result<(), AppError> {
    let principal = match *subject {
        SignalSubject::User(id) => PrincipalRef::User(id),
        SignalSubject::Agent(id) => PrincipalRef::Agent(id),
    };
    if principals
        .principal_exists(tenant, &principal)
        .await
        .or_internal()?
    {
        return Ok(());
    }
    Err(AppError::NotFound(message!(
        "signals-subject-not-found",
        "subject not found"
    )))
}
