//! A push subscription's signing secret: made fresh and sealed before it is
//! stored, and opened again only to sign a push.
//!
//! The service checks every push's signature with the secret, so the
//! platform keeps the secret itself rather than a hash of it. Stored as
//! typed, anyone who could read the subscriptions table could sign
//! messages the service takes for the topic's own, so it is sealed first.

use ianua_domain::domains::messaging::delivery::PushEndpoint;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{MessageSubscriptionId, PublicHttpsUrl, SealedSecret};

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use crate::ports::messaging::PushSecretGenerator;
use crate::services::sealing::sealed_text;
use crate::tenancy::ScopedTenant;

/// A secret just made: the raw value, shown once to whoever made it, and its
/// sealed form for the subscription.
pub(super) struct FreshPushSecret {
    /// The raw secret, for the caller to copy to their service.
    pub(super) raw: Secret,
    /// The same secret, sealed for storage.
    pub(super) sealed: SealedSecret,
}

impl FreshPushSecret {
    /// Pushes to `url` signed with this secret, and the raw secret to show.
    pub(super) fn endpoint_at(self, url: PublicHttpsUrl) -> (PushEndpoint, Secret) {
        (PushEndpoint::new(url, self.sealed), self.raw)
    }
}

/// Where `tenant`'s subscription `subscription` keeps its push signing
/// secrets, the current one and the one before a rotation alike.
pub(super) fn push_secret_place(
    tenant: &ScopedTenant,
    subscription: &MessageSubscriptionId,
) -> SealedFor {
    SealedFor::new(
        SealOwner::from(tenant),
        SealedField::PushSecret,
        subscription,
    )
}

/// A new random push signing secret, with its form sealed for `place`.
///
/// # Errors
///
/// `AppError::Internal` when no secret can be made or it cannot be sealed.
pub(super) async fn fresh_push_secret(
    generator: &dyn PushSecretGenerator,
    encryptor: &dyn SecretEncryptor,
    place: &SealedFor,
) -> Result<FreshPushSecret, AppError> {
    let raw = generator.generate().await.or_internal()?;
    let sealed = sealed_text(encryptor, raw.expose(), place).await?;
    Ok(FreshPushSecret { raw, sealed })
}
