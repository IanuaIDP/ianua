//! A log shipping target's credential: sealed as soon as it arrives, opened
//! only to ship a batch.
//!
//! The API key or token a tenant gives for its SIEM lets anyone holding it
//! write into, and often read from, the tenant's logs. It is sealed before
//! it is kept, never shown back, and never put in an event.

use ianua_domain::domains::proxy::log_shipping::ShippingCredential;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::LogShippingTargetId;

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use crate::services::sealing::{opened_text, sealed_text};
use crate::tenancy::ScopedTenant;

/// What a change does to a target's credential.
pub enum CredentialChange {
    /// Keeps the one it has.
    Keep,
    /// Ships without one from now on.
    Remove,
    /// Replaces it with this one, as the tenant typed it.
    Replace(Secret),
}

/// Where `tenant`'s target `target` keeps its credential.
pub(super) fn credential_place(tenant: &ScopedTenant, target: &LogShippingTargetId) -> SealedFor {
    SealedFor::new(
        SealOwner::from(tenant),
        SealedField::LogShippingCredential,
        target,
    )
}

/// `given`, sealed for storage at `place`, or no credential when none is
/// given.
///
/// # Errors
///
/// `AppError::Internal` when it cannot be sealed.
pub(super) async fn sealed_credential(
    encryptor: &dyn SecretEncryptor,
    given: Option<Secret>,
    place: &SealedFor,
) -> Result<ShippingCredential, AppError> {
    let Some(secret) = given else {
        return Ok(ShippingCredential::None);
    };
    let sealed = sealed_text(encryptor, secret.expose(), place).await?;
    Ok(ShippingCredential::Sealed(sealed))
}

/// The credential a target holds after `change`, given it holds `current`,
/// a new one sealed for `place`.
///
/// # Errors
///
/// `AppError::Internal` when a new credential cannot be sealed.
pub(super) async fn changed_credential(
    encryptor: &dyn SecretEncryptor,
    current: &ShippingCredential,
    change: CredentialChange,
    place: &SealedFor,
) -> Result<ShippingCredential, AppError> {
    match change {
        CredentialChange::Keep => Ok(current.clone()),
        CredentialChange::Remove => Ok(ShippingCredential::None),
        CredentialChange::Replace(secret) => {
            sealed_credential(encryptor, Some(secret), place).await
        }
    }
}

/// The secret `credential`, kept at `place`, holds, opened to ship one
/// batch, or `None` when the target has none.
///
/// # Errors
///
/// `AppError::Internal` when it cannot be opened there, or opens to
/// something that is not text.
pub(super) async fn opened_credential(
    encryptor: &dyn SecretEncryptor,
    credential: &ShippingCredential,
    place: &SealedFor,
) -> Result<Option<Secret>, AppError> {
    let ShippingCredential::Sealed(sealed) = credential else {
        return Ok(None);
    };
    opened_text(encryptor, sealed, place)
        .await
        .map(Some)
        .or_internal()
}
