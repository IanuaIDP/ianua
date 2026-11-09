//! Finding a service's backends.

use async_trait::async_trait;
use ianua_domain::domains::routing::backend::discovery::{DiscoveredBackends, Discovery};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::HttpUrl;

/// Asks what is behind a name.
///
/// Kept apart from the stores beside it because it is not storage: nothing
/// here is written, the answer is expected to change on its own, and the
/// thing being asked is outside the platform entirely.
#[async_trait]
pub trait BackendDiscovery: Send + Sync {
    /// Resolves `discovery` to the backends currently behind it.
    ///
    /// `configured` is the service's own upstream URL. Its scheme is the one
    /// every discovered backend is spoken to with, so a service written as
    /// `https://` stays encrypted, and its port is used for kinds whose
    /// records carry none.
    ///
    /// An answer with no backends is a result, not an error: a deployment
    /// scaled to zero resolves to nothing, and the caller must be able to tell
    /// that from a resolver it could not reach.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] if the resolver cannot be
    /// reached or answers with something that is not a usable address.
    async fn resolve(
        &self,
        discovery: &Discovery,
        configured: &HttpUrl,
    ) -> Result<DiscoveredBackends, DomainError>;
}
