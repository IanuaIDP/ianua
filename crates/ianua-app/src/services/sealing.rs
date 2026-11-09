//! Sealing a credential a caller typed as soon as it arrives, so only its
//! sealed form reaches the domain and storage, and opening sealed secrets
//! again only to use them once. Each is sealed for the place it is kept,
//! and opened only for that place.

use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::SealedSecret;

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{SealedFor, SecretEncryptor};

/// `plain`, sealed through `encryptor` for `place`.
///
/// # Errors
///
/// `AppError::Internal` when it cannot be sealed.
pub(crate) async fn sealed_text(
    encryptor: &dyn SecretEncryptor,
    plain: &str,
    place: &SealedFor,
) -> Result<SealedSecret, AppError> {
    encryptor
        .encrypt(plain.as_bytes(), place)
        .await
        .or_internal()
}

/// The text `sealed`, kept at `place`, opens to through `encryptor`.
///
/// # Errors
///
/// `DomainError::Infrastructure` when it cannot be opened there, or opens
/// to something that is not text. The error never holds the value.
pub(crate) async fn opened_text(
    encryptor: &dyn SecretEncryptor,
    sealed: &SealedSecret,
    place: &SealedFor,
) -> Result<Secret, DomainError> {
    let bytes = encryptor.decrypt(sealed, place).await?;
    String::from_utf8(bytes)
        .map(Secret::new)
        .map_err(|_| DomainError::infra_msg("a sealed secret does not open to text"))
}

/// Every secret in `sealed`, kept at `place`, opened through `encryptor`,
/// in the order given: a webhook's or a push subscription's signing
/// secrets, the current one first.
///
/// # Errors
///
/// `AppError::Internal` when one cannot be opened, or opens to something
/// that is not text.
pub(crate) async fn opened_secrets<'a>(
    encryptor: &dyn SecretEncryptor,
    sealed: impl IntoIterator<Item = &'a SealedSecret>,
    place: &SealedFor,
) -> Result<Vec<Secret>, AppError> {
    let mut opened = Vec::new();
    for secret in sealed {
        opened.push(opened_text(encryptor, secret, place).await.or_internal()?);
    }
    Ok(opened)
}
