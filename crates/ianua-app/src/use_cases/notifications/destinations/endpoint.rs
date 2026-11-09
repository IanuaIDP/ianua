//! Where a destination posts, as the caller typed it, and the same place
//! sealed before the organization keeps it.
//!
//! A Slack or Teams incoming-webhook address is itself the key that posts
//! to the channel, so it is sealed through the crypto port as soon as its
//! host was checked. A webhook of the organization's own gets a fresh
//! signing secret: shown once to whoever added it, and kept only sealed.

use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::destination::{
    DestinationEndpoint, DestinationFilter, NewDestination,
};
use ianua_domain::domains::notifications::severity::NotificationSeverity;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Label, PublicHttpsUrl};

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{SealedFor, SecretEncryptor};
use crate::ports::notifications::DestinationSecretGenerator;
use crate::services::sealing::sealed_text;

/// What a destination is to be: its name, where it posts and what it
/// receives, as the caller typed them.
pub struct DestinationSettings {
    /// What the organization calls it, such as "On-call Slack".
    pub name: Label,
    /// Where it posts.
    pub target: DestinationTarget,
    /// The categories it receives.
    pub categories: Vec<NotificationCategory>,
    /// The least severity it receives.
    pub minimum: NotificationSeverity,
}

/// Where a destination posts, as the caller typed it.
pub enum DestinationTarget {
    /// A Slack channel, through its incoming-webhook address.
    Slack(PublicHttpsUrl),
    /// A Microsoft Teams channel, through its webhook address.
    Teams(PublicHttpsUrl),
    /// An HTTPS endpoint of the organization's own, whose posts are signed.
    Webhook(PublicHttpsUrl),
}

/// The secret a destination's posts are signed with, when it has one. It
/// holds the raw secret, so it has no `Debug`.
pub enum SigningSecret {
    /// A Slack or Teams address carries its own key; nothing is signed.
    NotSigned,
    /// A webhook's new signing secret, shown this once and kept only
    /// sealed.
    Shown(Secret),
}

/// The ports a destination's endpoint is sealed through, and the place it
/// is sealed for.
#[derive(Clone, Copy)]
pub(super) struct Sealing<'a> {
    /// Seals addresses and secrets.
    pub(super) encryptor: &'a dyn SecretEncryptor,
    /// Makes a webhook's signing secret.
    pub(super) secrets: &'a dyn DestinationSecretGenerator,
    /// Where the destination keeps its endpoint, as
    /// [`destination_endpoint_place`](crate::ports::notifications::destination_endpoint_place)
    /// names it.
    pub(super) place: &'a SealedFor,
}

/// What `settings` ask a destination to be, its endpoint sealed, with the
/// signing secret to show once.
///
/// # Errors
///
/// - `AppError::Domain` when the filter names no category or one twice, or
///   a Slack or Teams address is not on their own hosts.
/// - `AppError::Internal` when an address or secret cannot be sealed.
pub(super) async fn new_destination(
    sealing: Sealing<'_>,
    settings: DestinationSettings,
) -> Result<(NewDestination, SigningSecret), AppError> {
    let filter = DestinationFilter::new(settings.categories, settings.minimum)
        .map_err(AppError::from_domain)?;
    let (endpoint, secret) = sealed_endpoint(sealing, settings.target).await?;
    let new = NewDestination {
        name: settings.name,
        endpoint,
        filter,
    };
    Ok((new, secret))
}

/// `target` as the endpoint the organization keeps, with the signing secret
/// to show once.
///
/// # Errors
///
/// - `AppError::Domain` when a Slack or Teams address is not on their own
///   hosts.
/// - `AppError::Internal` when an address or secret cannot be sealed, or
///   no secret can be made.
async fn sealed_endpoint(
    sealing: Sealing<'_>,
    target: DestinationTarget,
) -> Result<(DestinationEndpoint, SigningSecret), AppError> {
    match target {
        DestinationTarget::Slack(url) => {
            let sealed = sealed_text(sealing.encryptor, url.as_str(), sealing.place).await?;
            let endpoint =
                DestinationEndpoint::slack(&url, sealed).map_err(AppError::from_domain)?;
            Ok((endpoint, SigningSecret::NotSigned))
        }
        DestinationTarget::Teams(url) => {
            let sealed = sealed_text(sealing.encryptor, url.as_str(), sealing.place).await?;
            let endpoint =
                DestinationEndpoint::teams(&url, sealed).map_err(AppError::from_domain)?;
            Ok((endpoint, SigningSecret::NotSigned))
        }
        DestinationTarget::Webhook(url) => signed_webhook(sealing, url).await,
    }
}

/// A webhook at `url` with a fresh signing secret, sealed, and the raw
/// secret to show once.
///
/// # Errors
///
/// `AppError::Internal` when no secret can be made or it cannot be sealed.
async fn signed_webhook(
    sealing: Sealing<'_>,
    url: PublicHttpsUrl,
) -> Result<(DestinationEndpoint, SigningSecret), AppError> {
    let raw = sealing.secrets.generate().await.or_internal()?;
    let sealed = sealed_text(sealing.encryptor, raw.expose(), sealing.place).await?;
    Ok((
        DestinationEndpoint::webhook(url, sealed),
        SigningSecret::Shown(raw),
    ))
}
