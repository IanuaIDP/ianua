//! Loading the second factor or recovery codes an MFA use case names,
//! failing with not-found when there are none.

use ianua_domain::domains::authentication::mfa::enrollment::MfaEnrollment;
use ianua_domain::domains::authentication::recovery::codes::RecoveryCodeSet;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::UserId;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authentication::{MfaEnrollmentStore, RecoveryCodeStore};
use crate::tenancy::ScopedTenant;

/// The user's MFA enrollment, provided it is in force, held until the unit
/// of work ends: every caller answers a code on it and saves it, and a
/// second answer at once must wait for this one's count.
///
/// A pending or removed enrollment answers the same as none at all: neither
/// is a factor the user can present.
///
/// # Errors
///
/// - `AppError::NotFound` if the user has no active enrollment.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::authentication::mfa) async fn existing_active_enrollment(
    store: &dyn MfaEnrollmentStore,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> Result<MfaEnrollment<ResolvedTenant>, AppError> {
    store
        .hold_by_user(tenant, user_id)
        .await
        .or_internal()?
        .filter(MfaEnrollment::is_active)
        .or_not_found(message!(
            "authentication-no-mfa-enrollment",
            "no MFA enrollment"
        ))
}

/// The user's MFA enrollment, provided it still waits to be confirmed,
/// held until the unit of work ends: its callers change it and save it,
/// and a code answered while confirming it counts towards its lock.
///
/// # Errors
///
/// - `AppError::NotFound` if the user has no pending enrollment.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::authentication::mfa) async fn existing_pending_enrollment(
    store: &dyn MfaEnrollmentStore,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> Result<MfaEnrollment<ResolvedTenant>, AppError> {
    store
        .hold_by_user(tenant, user_id)
        .await
        .or_internal()?
        .filter(MfaEnrollment::is_pending)
        .or_not_found(message!(
            "authentication-no-pending-mfa-enrollment",
            "no pending MFA enrollment"
        ))
}

/// The user's MFA enrollment while it is in use: in force, or waiting to be
/// confirmed. A factor given up or turned off answers the same as none.
///
/// # Errors
///
/// - `AppError::NotFound` if the user has no factor in use.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::authentication::mfa) async fn existing_factor_in_use(
    store: &dyn MfaEnrollmentStore,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> Result<MfaEnrollment<ResolvedTenant>, AppError> {
    store
        .find_by_user(tenant, user_id)
        .await
        .or_internal()?
        .filter(|enrollment| enrollment.is_active() || enrollment.is_pending())
        .or_not_found(message!(
            "authentication-no-mfa-enrollment",
            "no MFA enrollment"
        ))
}

/// The user's set of recovery codes.
///
/// # Errors
///
/// - `AppError::NotFound` if the user has none.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::authentication::mfa) async fn existing_recovery_codes(
    store: &dyn RecoveryCodeStore,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> Result<RecoveryCodeSet<ResolvedTenant>, AppError> {
    store
        .find_by_user(tenant, user_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "authentication-no-recovery-codes",
            "no recovery codes"
        ))
}
