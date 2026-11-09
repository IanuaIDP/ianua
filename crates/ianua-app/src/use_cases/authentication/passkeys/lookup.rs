//! Loading the passkey or passkey ceremony a passkey use case names,
//! failing with not-found when there is none.

use ianua_domain::domains::authentication::credentials::passkey::PasskeyCredential;
use ianua_domain::domains::authentication::credentials::passkey_ceremony::PasskeyCeremony;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{CeremonyId, PasskeyId, UserId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authentication::{PasskeyCeremonyStore, PasskeyStore};
use crate::tenancy::ScopedTenant;

/// One of `user_id`'s passkeys, by id.
///
/// Only the user's own passkeys are searched, so another user's passkey
/// answers the same as one that never existed.
///
/// # Errors
///
/// - `AppError::NotFound` if the user has no passkey with that id.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::authentication::passkeys) async fn owned_passkey(
    store: &dyn PasskeyStore,
    tenant: &ScopedTenant,
    user_id: &UserId,
    passkey_id: &PasskeyId,
) -> Result<PasskeyCredential<ResolvedTenant>, AppError> {
    store
        .list_by_user(tenant, user_id)
        .await
        .or_internal()?
        .into_iter()
        .find(|passkey| passkey.id() == passkey_id)
        .or_not_found(message!(
            "authentication-passkey-not-found",
            "passkey not found"
        ))
}

/// The tenant's passkey ceremony with `ceremony_id`, which was opened for
/// `user_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such ceremony.
/// - `AppError::Forbidden` if it was opened for someone else.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::authentication::passkeys) async fn owned_ceremony(
    store: &dyn PasskeyCeremonyStore,
    tenant: &ScopedTenant,
    ceremony_id: &CeremonyId,
    user_id: &UserId,
) -> Result<PasskeyCeremony, AppError> {
    let ceremony = store
        .find_by_id(tenant, ceremony_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "authentication-passkey-challenge-not-found",
            "passkey challenge not found"
        ))?;
    if ceremony.user_id() != Some(user_id) {
        return Err(AppError::Forbidden(message!(
            "authentication-this-challenge-belongs-to-another-user",
            "this challenge belongs to another user"
        )));
    }
    Ok(ceremony)
}
