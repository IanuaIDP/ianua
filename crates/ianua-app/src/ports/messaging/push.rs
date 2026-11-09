//! Push subscriptions: the secret a push is signed with, and the post that
//! carries a message to the service's endpoint.

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{PublicHttpsUrl, Seconds};

use crate::ports::messaging::ReceivedMessage;

/// Dyn-safe port for making the secrets push subscriptions sign with.
#[async_trait]
pub trait PushSecretGenerator: Send + Sync {
    /// A new random signing secret.
    ///
    /// The raw secret is shown once, when the subscription is made or its
    /// secret rotated. The caller seals it before it is stored, because
    /// signing a push needs the secret itself, not a hash of it. It is never
    /// logged or put in an event.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the randomness source fails.
    async fn generate(&self) -> Result<Secret, DomainError>;
}

/// How one push ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// The endpoint answered with a success code: the message is taken.
    Accepted,
    /// The endpoint refused it, answered with an error, could not be
    /// reached, or did not answer in time.
    Failed,
}

/// One message posted to a push subscription's endpoint.
#[derive(Debug, Clone, Copy)]
pub struct OutgoingPush<'a> {
    /// Where it is posted.
    pub url: &'a PublicHttpsUrl,
    /// The received payload and delivery metadata to post.
    pub message: &'a ReceivedMessage,
    /// Every secret the post is signed with, unsealed: the subscription's
    /// current one first, then the one before a rotation while its overlap
    /// lasts. The post carries one signature per secret.
    pub secrets: &'a [Secret],
    /// How long the endpoint has to answer: the subscription's
    /// acknowledgement deadline.
    pub timeout: Seconds,
}

/// Dyn-safe port for posting a message to a push endpoint.
///
/// The adapter re-resolves the host and refuses private, loopback and
/// link-local addresses before connecting, signs the body once with each
/// secret it is given (with the message's key and a timestamp in the
/// signature, so a captured push cannot be replayed), never logs a secret,
/// and gives up after the timeout it is given. A hung endpoint never holds
/// a worker. The key is the same on every delivery of the message, so an
/// endpoint sent it twice can drop the second.
#[async_trait]
pub trait PushDeliverer: Send + Sync {
    /// Posts `push.message` to `push.url`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when the address resolves to one
    /// the platform does not post to. Transport failures, a timeout among
    /// them, are a [`PushOutcome::Failed`], not an `Err`.
    async fn push(&self, push: OutgoingPush<'_>) -> Result<PushOutcome, DomainError>;
}
