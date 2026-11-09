//! What the runner beside an agent's sandbox needs from outside: the key it
//! signs with, the task tokens it holds for the agent, and the proofs of
//! possession it signs for each request.
//!
//! The agent holds none of them. The key is made in the runner's memory or
//! mounted into the runner alone, a token is exchanged by the runner and
//! never handed over, and every proof names one request.

use async_trait::async_trait;
use ianua_domain::domains::agents::authority::capability::TokenBinding;
use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{HttpMethod, KeyId};
use time::OffsetDateTime;

use crate::ports::agents::TaskToken;

/// The key the runner signs with for its agent: the key of one of the
/// agent's credentials.
///
/// `Debug` names the key and never its private half.
#[derive(Clone)]
pub struct RunnerKey {
    /// The key's id on the agent's credential, the `kid` its signatures
    /// name.
    pub kid: KeyId,
    /// The algorithm it signs with.
    pub algorithm: SigningAlgorithm,
    /// Its private half, as PKCS#8 PEM.
    pub private_key: Secret,
}

impl std::fmt::Debug for RunnerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerKey")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// Dyn-safe port for the key the runner signs with now.
///
/// A mounted key is the same for the runner's life. An attested key is
/// made in the runner's memory and enrolled by attesting the runner's
/// workload, and attested again before it lapses.
#[async_trait]
pub trait RunnerKeys: Send + Sync {
    /// The key to sign with now.
    ///
    /// # Errors
    ///
    /// - `DomainError::Unauthorized` when the platform refused the
    ///   attestation.
    /// - `DomainError::Infrastructure` when no key can be had: the key
    ///   does not read, or the platform cannot be reached.
    async fn current(&self) -> Result<RunnerKey, DomainError>;
}

/// Dyn-safe port for the task tokens the runner holds for its agent, one
/// for each binding, exchanged with an assertion `key` signs and renewed
/// before they lapse.
#[async_trait]
pub trait RunnerTokens: Send + Sync {
    /// A token of `binding` good for a while yet, exchanged anew when the
    /// held one nears its end or was obtained with another key.
    ///
    /// # Errors
    ///
    /// - `DomainError::Unauthorized` when the platform refused the
    ///   exchange.
    /// - `DomainError::Infrastructure` when the key cannot sign or the
    ///   platform cannot be reached.
    async fn current(
        &self,
        key: &RunnerKey,
        binding: TokenBinding,
    ) -> Result<TaskToken, DomainError>;

    /// Forgets the held token of `binding`, so the next request exchanges
    /// a new one: the destination refused it, as when it was revoked.
    async fn forget(&self, binding: TokenBinding);
}

/// One request a proof of possession is made for.
#[derive(Debug, Clone, Copy)]
pub struct ProofRequest<'a> {
    /// The request's method.
    pub method: HttpMethod,
    /// The address the proof names (`htu`), as
    /// [`GatewayAddress::proof_target`](ianua_domain::domains::agents::runner::GatewayAddress::proof_target)
    /// builds it.
    pub target: &'a str,
    /// The token the request carries, which the proof names by its hash.
    pub token: &'a TaskToken,
    /// When the proof is made.
    pub at: OffsetDateTime,
}

/// Port for signing proofs of possession (RFC 9449) with the runner's
/// key. Each proof carries its own id, so none is good twice.
pub trait RunnerProofs: Send + Sync {
    /// A proof that the holder of `key` sends `request` now.
    ///
    /// # Errors
    ///
    /// - `DomainError::Infrastructure` when the key does not read or
    ///   cannot sign.
    fn proof(&self, key: &RunnerKey, request: &ProofRequest<'_>) -> Result<Secret, DomainError>;
}
