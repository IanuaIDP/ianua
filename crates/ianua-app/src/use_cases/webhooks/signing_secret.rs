//! A webhook's signing secret: made fresh and sealed before it is stored, and
//! opened again only to sign a delivery.
//!
//! The receiving server checks every delivery's HMAC with the secret, so the
//! platform keeps the secret itself rather than a hash of it. Stored as
//! typed, anyone who could read the subscriptions table could sign messages
//! the tenant's servers take for real deliveries, so it is sealed first.

use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{SealedSecret, WebhookSubscriptionId};

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use crate::ports::webhooks::WebhookSecretGenerator;
use crate::services::sealing::sealed_text;
use crate::tenancy::ScopedTenant;

/// A secret just made: the raw value, shown once to whoever made it, and its
/// sealed form for the subscription.
pub(super) struct FreshSecret {
    /// The raw secret, for the caller to copy to their server.
    pub(super) raw: Secret,
    /// The same secret, sealed for storage.
    pub(super) sealed: SealedSecret,
}

/// Where `tenant`'s subscription `subscription` keeps its signing secrets,
/// the current one and the one before a rotation alike.
pub(super) fn secret_place(
    tenant: &ScopedTenant,
    subscription: &WebhookSubscriptionId,
) -> SealedFor {
    SealedFor::new(
        SealOwner::from(tenant),
        SealedField::WebhookSigningSecret,
        subscription,
    )
}

/// A new random signing secret, with its form sealed for `place`.
///
/// # Errors
///
/// `AppError::Internal` when no secret can be made or it cannot be sealed.
pub(super) async fn fresh_secret(
    generator: &dyn WebhookSecretGenerator,
    encryptor: &dyn SecretEncryptor,
    place: &SealedFor,
) -> Result<FreshSecret, AppError> {
    let raw = generator.generate().await.or_internal()?;
    let sealed = sealed_text(encryptor, raw.expose(), place).await?;
    Ok(FreshSecret { raw, sealed })
}
