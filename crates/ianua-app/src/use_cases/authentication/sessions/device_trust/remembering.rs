//! What remembering a device asks wherever it is remembered, from the
//! dashboard or from an app's sign-in: room for one more device, the
//! digest of its secret bound to where it was presented, and the refusal
//! of a sign-in that may not remember one.

use ianua_domain::domains::authentication::device_trust::{DeviceTrustRefused, PresentedSecret};
use ianua_domain::message;
use ianua_domain::types::{TokenHash, UserId};

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::TrustedDeviceStore;
use crate::ports::oauth::CodeHasher;
use crate::tenancy::ScopedTenant;
use crate::use_cases::authentication::sessions::device_trust::trust_device::Policy;

/// Refuses another device once `person` holds as many trusted ones as
/// `policy` allows. A forgotten device frees its place.
///
/// # Errors
///
/// - `AppError::Conflict` when the person already holds as many as allowed.
/// - `AppError::Internal` when the devices cannot be read.
pub(super) async fn ensure_room_for_another(
    store: &dyn TrustedDeviceStore,
    tenant: &ScopedTenant,
    person: &UserId,
    policy: Policy,
) -> Result<(), AppError> {
    let held = store.list_by_user(tenant, person).await.or_internal()?;
    let trusted = held
        .iter()
        .filter(|device| device.status().is_trusted())
        .count();
    if trusted >= policy.max_devices_per_user {
        return Err(AppError::Conflict(message!(
            "authentication-maximum-trusted-devices-reached",
            "maximum trusted devices reached"
        )));
    }
    Ok(())
}

/// The digest kept for `secret`: of the secret bound to where it was
/// presented, so the device counts there alone.
///
/// # Errors
///
/// `AppError::Internal` when the secret cannot be hashed.
pub(super) async fn digest_of(
    hasher: &dyn CodeHasher,
    secret: &PresentedSecret,
) -> Result<TokenHash, AppError> {
    hasher.hash_code(&secret.bound()).await.or_internal()
}

/// The error a sign-in that may not remember a device answers with.
pub(super) fn refused(refusal: DeviceTrustRefused) -> AppError {
    match refusal {
        DeviceTrustRefused::SecondFactorNotProven => {
            AppError::Forbidden(refusal.to_string().into())
        }
    }
}
