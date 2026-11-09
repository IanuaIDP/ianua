//! Checking the workload tokens agents prove themselves with: Kubernetes
//! service account tokens, GitHub Actions OIDC tokens and tokens from an
//! OIDC issuer the tenant trusts.

use async_trait::async_trait;
use ianua_domain::domains::agents::identity::attestation::{
    WorkloadIssuer, WorkloadKind, WorkloadSubject,
};
use ianua_domain::domains::agents::identity::challenge::AttestationNonce;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;

use crate::ports::agents::EnrolledKey;

/// A workload token as an agent presented it, with the issuers its policy
/// trusts for that kind of token and the bootstrap it must be made for.
pub struct PresentedWorkloadToken<'a> {
    /// The kind of platform the token claims to come from.
    pub kind: WorkloadKind,
    /// The signed token, a bearer secret: never logged.
    pub token: &'a Secret,
    /// The only issuers whose keys the token may be checked against. The
    /// token's own `iss` is not trusted until its signature verifies, so
    /// the adapter fetches no keys for an issuer outside this list.
    pub trusted_issuers: &'a [WorkloadIssuer],
    /// The challenge the bootstrap spent, which the token's audience binds.
    pub nonce: &'a AttestationNonce,
    /// The key the bootstrap enrols, which the token's audience binds.
    pub key: &'a EnrolledKey,
}

/// The claims of a workload token whose signature, algorithm, times and
/// audience verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedWorkloadClaims {
    /// Who issued it, its `iss`.
    pub issuer: WorkloadIssuer,
    /// The workload it names, its `sub`.
    pub subject: WorkloadSubject,
}

/// Dyn-safe port for verifying a workload token.
///
/// The adapter refuses a token whose `iss` is not among the trusted
/// issuers before it fetches anything, fetches the issuer's published
/// keys (its JWKS) with a timeout and a bounded cache, verifies the
/// signature with the algorithm pinned for that kind (never the one the
/// token's header names, and never `none`), checks `exp`, `nbf` and `iat`
/// with a small allowed skew and a longest lifetime, and holds the
/// audience to the binding of `nonce` and `key`: a token made for another
/// key or another bootstrap is refused, so a token seen in passing cannot
/// enrol anyone else's key. Which issuer and subject prove which agent is
/// not decided here: the domain decides that from the claims, through the
/// agent's workload trusts.
#[async_trait]
pub trait WorkloadTokenVerifier: Send + Sync {
    /// The claims of `presented` once it verifies.
    ///
    /// # Errors
    ///
    /// - `DomainError::Unauthorized` when the issuer is not trusted, the
    ///   keys name no key for the token, the signature or algorithm does
    ///   not verify, the token is expired, not yet valid, issued in the
    ///   future or made to live too long, or its audience is not the
    ///   binding of the nonce and key.
    /// - `DomainError::Infrastructure` when the issuer's keys cannot be
    ///   fetched in time.
    async fn verify(
        &self,
        presented: &PresentedWorkloadToken<'_>,
    ) -> Result<VerifiedWorkloadClaims, DomainError>;
}
