//! Loading the operator, impersonation grant or operator key an operator
//! use case names, failing with not-found when it does not exist.

use ianua_domain::domains::operator::api_key::OperatorApiKey;
use ianua_domain::domains::operator::control::OperatorAuthority;
use ianua_domain::domains::operator::identity::Operator;
use ianua_domain::domains::operator::impersonation::ImpersonationGrant;
use ianua_domain::message;
use ianua_domain::types::{ImpersonationGrantId, KeyPrefix, OperatorId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::operator::{ImpersonationGrantStore, OperatorKeyStore, OperatorStore};

/// The operator with `operator_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if no such operator exists.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_operator(
    store: &dyn OperatorStore,
    operator_id: &OperatorId,
) -> Result<Operator, AppError> {
    store
        .find_by_id(operator_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "operator-operator-not-found",
            "operator not found"
        ))
}

/// The impersonation grant with `grant_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if no such grant exists.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_grant(
    store: &dyn ImpersonationGrantStore,
    grant_id: &ImpersonationGrantId,
) -> Result<ImpersonationGrant, AppError> {
    store
        .find_by_id(grant_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "authentication-grant-not-found",
            "grant not found"
        ))
}

/// The impersonation grant with `grant_id`, held by the operator
/// `authority` names. Another operator's grant reads as missing, so an id
/// cannot be used to find out which grants exist.
///
/// # Errors
///
/// - `AppError::NotFound` if no such grant exists, or it is another
///   operator's.
/// - `AppError::Internal` on storage failure.
pub(super) async fn owned_grant(
    store: &dyn ImpersonationGrantStore,
    grant_id: &ImpersonationGrantId,
    authority: &OperatorAuthority,
) -> Result<ImpersonationGrant, AppError> {
    Some(existing_grant(store, grant_id).await?)
        .filter(|grant| grant.operator_id() == authority.operator())
        .or_not_found(message!(
            "authentication-grant-not-found",
            "grant not found"
        ))
}

/// The operator key found by `prefix`.
///
/// # Errors
///
/// - `AppError::NotFound` if no key has that prefix.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_key(
    store: &dyn OperatorKeyStore,
    prefix: &KeyPrefix,
) -> Result<OperatorApiKey, AppError> {
    store
        .find_by_prefix(prefix)
        .await
        .or_internal()?
        .or_not_found(message!("operator-key-not-found", "key not found"))
}

/// The key found by `prefix`, of the operator `authority` names. Another
/// operator's key reads as missing, so a prefix cannot be used to find out
/// which keys exist.
///
/// # Errors
///
/// - `AppError::NotFound` if no key has that prefix, or it is another
///   operator's.
/// - `AppError::Internal` on storage failure.
pub(super) async fn owned_key(
    store: &dyn OperatorKeyStore,
    prefix: &KeyPrefix,
    authority: &OperatorAuthority,
) -> Result<OperatorApiKey, AppError> {
    Some(existing_key(store, prefix).await?)
        .filter(|key| key.operator_id() == authority.operator())
        .or_not_found(message!("operator-key-not-found", "key not found"))
}
