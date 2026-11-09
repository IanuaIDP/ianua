//! Holding up under a password sign-in flood: the cap on password hashes
//! running at once, the count of failures across a tenant or organization,
//! and the challenge a device nobody trusted must pass while that count is
//! high.

use std::any::Any;
use std::fmt;

use async_trait::async_trait;
use ianua_domain::domains::authentication::risk_engine::challenge::{
    ChallengeKind, ChallengeProof, ChallengeVerdict,
};
use ianua_domain::domains::authentication::risk_engine::pressure::{FailureCount, Pressure};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Fact, IpAddress, OrganizationId, TenantId};
use time::OffsetDateTime;

/// One taken place among the password hashes a node runs at once.
///
/// Dropping it hands the place back. It holds whatever the adapter needs
/// to do that, such as a semaphore's permit, so the application never
/// names the adapter's types.
pub struct HashPermit {
    _held: Box<dyn Any + Send + Sync>,
}

impl HashPermit {
    /// A permit handing its place back when `held` is dropped.
    #[must_use]
    pub fn new(held: impl Any + Send + Sync) -> Self {
        Self {
            _held: Box::new(held),
        }
    }
}

impl fmt::Debug for HashPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HashPermit")
    }
}

/// Every place among the password hashes stayed taken for as long as the
/// adapter waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("every password hash permit stayed taken for the whole wait")]
pub struct HashingBusy;

/// Dyn-safe port capping how many password hashes run at once on this node.
///
/// A password hash costs real CPU and memory by design. Without a cap, a
/// flood of sign-ins, each under every per-address limit, runs enough of
/// them at once to exhaust the node. Every hash or check of a password
/// takes a permit first and holds it only while it runs.
///
/// The adapter is a bounded semaphore sized from the deployment's settings.
/// It waits a short, fixed bound for a place to free up, well under a
/// second, and then answers busy, so a queue of waiting sign-ins never
/// builds up behind it.
#[async_trait]
pub trait PasswordHashPermits: Send + Sync {
    /// A permit to run one password hash, once a place is free.
    ///
    /// # Errors
    ///
    /// Returns [`HashingBusy`] when no place freed up within the adapter's
    /// wait.
    async fn take(&self) -> Result<HashPermit, HashingBusy>;
}

/// Whose failed password sign-ins are counted together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureScope {
    /// Sign-ins to one tenant.
    Tenant(TenantId),
    /// Sign-ins naming one organization, or reaching an account in it.
    Organization(OrganizationId),
    /// Organization sign-ins that name no organization, across the
    /// platform. Which organization such a sign-in is for is only settled
    /// by the password, so it cannot be held to one organization's count
    /// before the password is hashed.
    UnnamedOrganizations,
}

/// Dyn-safe port counting failed password sign-ins per tenant and per
/// organization over a sliding window, and keeping the pressure last seen
/// for each.
///
/// Shaped like [`RateLimiter`](crate::ports::limits::RateLimiter), but
/// counting failures, not requests, and across every address at once: a
/// flood spread over many networks stays under every per-address limit,
/// and not under this one. The window's length is the deployment's
/// setting. The adapter keeps the counts in a store every node shares and
/// answers within a few hundred milliseconds, or fails.
#[async_trait]
pub trait SignInFailureBudget: Send + Sync {
    /// The failures counted against `scope` in the current window.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the count cannot be read.
    async fn failures(&self, scope: &FailureScope) -> Result<FailureCount, DomainError>;

    /// Counts one failure against `scope` and answers the count with it.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the failure cannot be counted.
    async fn record_failure(&self, scope: &FailureScope) -> Result<FailureCount, DomainError>;

    /// Keeps `now` as the pressure `scope` is under and answers the
    /// pressure kept before, in one step, so two nodes seeing the same
    /// change record it once. A scope never kept reads as normal.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the pressure cannot be kept.
    async fn swap_pressure(
        &self,
        scope: &FailureScope,
        now: Pressure,
    ) -> Result<Pressure, DomainError>;
}

/// Dyn-safe port checking the proof that a browser passed a challenge.
///
/// The adapter is the deployment's challenge provider: a puzzle ianua sets
/// and checks itself, or Cloudflare Turnstile. It accepts a proof once and
/// refuses it after, so a solved challenge cannot be replayed. It answers
/// within a few seconds; one that cannot is an error, which the caller
/// treats as a failed proof.
#[async_trait]
pub trait ChallengeVerifier: Send + Sync {
    /// The kind of challenge this provider sets.
    fn kind(&self) -> ChallengeKind;

    /// Whether `proof` is a solved challenge, not used before, sent from
    /// `client_ip`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the provider cannot be reached or did
    /// not answer in time.
    async fn verify(
        &self,
        proof: &ChallengeProof,
        client_ip: Fact<&IpAddress>,
    ) -> Result<ChallengeVerdict, DomainError>;
}

/// A puzzle the platform set for a browser to solve before it signs in
/// while sign-in is under pressure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengePuzzle {
    /// The sealed puzzle, sent back with its solution as the proof.
    pub challenge: String,
    /// How many leading zero bits the hash of the challenge and the
    /// solution must start with.
    pub difficulty_bits: u8,
    /// When the puzzle stops counting.
    pub expires_at: OffsetDateTime,
}

/// Dyn-safe port setting the puzzles a self-hosted challenge provider
/// checks: each sealed, bound to the address that asked and to its time,
/// and good for one sign-in. A deployment checking Turnstile sets none.
pub trait ChallengeIssuer: Send + Sync {
    /// A fresh puzzle for the browser at `client_ip`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when no random nonce can be made.
    fn issue(&self, client_ip: Fact<&IpAddress>) -> Result<ChallengePuzzle, DomainError>;
}
