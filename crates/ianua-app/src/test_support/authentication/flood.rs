//! Fakes for holding up under a sign-in flood: hash permits that count what
//! they hand out, a failure count kept in memory, and a challenge provider
//! that passes one known proof once.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authentication::credentials::password::PasswordHasher;
use ianua_domain::domains::authentication::risk_engine::challenge::{
    ChallengeKind, ChallengeProof, ChallengeVerdict,
};
use ianua_domain::domains::authentication::risk_engine::pressure::{FailureCount, Pressure};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Fact, IpAddress};

use crate::ports::authentication::{
    ChallengeIssuer, ChallengePuzzle, ChallengeVerifier, FailureScope, HashPermit, HashingBusy,
    PasswordHashPermits, SignInFailureBudget,
};
use crate::services::authentication::password_hashing::PasswordHashing;
use crate::test_support::Fake;

/// Hands out every permit asked for, counting how many are out now and how
/// many were ever taken, so a test can show each one came back.
#[derive(Default)]
pub struct FakeHashPermits {
    held: Arc<AtomicUsize>,
    taken: AtomicUsize,
}

impl FakeHashPermits {
    /// How many permits are out now.
    #[must_use]
    pub fn held(&self) -> usize {
        self.held.load(Ordering::SeqCst)
    }

    /// How many permits were ever taken.
    #[must_use]
    pub fn taken(&self) -> usize {
        self.taken.load(Ordering::SeqCst)
    }
}

/// Counts a permit back in when it is dropped.
struct Returned(Arc<AtomicUsize>);

impl Drop for Returned {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl PasswordHashPermits for FakeHashPermits {
    async fn take(&self) -> Result<HashPermit, HashingBusy> {
        self.taken.fetch_add(1, Ordering::SeqCst);
        self.held.fetch_add(1, Ordering::SeqCst);
        Ok(HashPermit::new(Returned(self.held.clone())))
    }
}

/// Every permit is taken and none frees up, as on a node in a flood.
pub struct BusyHashPermits;

#[async_trait]
impl PasswordHashPermits for BusyHashPermits {
    async fn take(&self) -> Result<HashPermit, HashingBusy> {
        Err(HashingBusy)
    }
}

/// Failed sign-ins counted in memory, with no window: a count only grows.
#[derive(Default)]
pub struct FakeSignInFailureBudget {
    counts: Mutex<HashMap<FailureScope, u64>>,
    kept: Mutex<HashMap<FailureScope, Pressure>>,
}

impl FakeSignInFailureBudget {
    /// A count already at `failures` for `scope`.
    #[must_use]
    pub fn over(scope: FailureScope, failures: u64) -> Self {
        let budget = Self::default();
        budget.counts.lock().unwrap().insert(scope, failures);
        budget
    }

    /// No failures counted for `scope`, but high pressure kept from before,
    /// as once a flood's failures have aged out of the window.
    #[must_use]
    pub fn under_pressure_kept(scope: FailureScope) -> Self {
        let budget = Self::default();
        budget.kept.lock().unwrap().insert(scope, Pressure::High);
        budget
    }

    /// The failures counted for `scope`.
    #[must_use]
    pub fn counted(&self, scope: &FailureScope) -> u64 {
        self.counts
            .lock()
            .unwrap()
            .get(scope)
            .copied()
            .unwrap_or_default()
    }
}

#[async_trait]
impl SignInFailureBudget for FakeSignInFailureBudget {
    async fn failures(&self, scope: &FailureScope) -> Result<FailureCount, DomainError> {
        Ok(FailureCount::from(self.counted(scope)))
    }

    async fn record_failure(&self, scope: &FailureScope) -> Result<FailureCount, DomainError> {
        let mut counts = self.counts.lock().unwrap();
        let count = counts.entry(*scope).or_default();
        *count += 1;
        Ok(FailureCount::from(*count))
    }

    async fn swap_pressure(
        &self,
        scope: &FailureScope,
        now: Pressure,
    ) -> Result<Pressure, DomainError> {
        let before = self.kept.lock().unwrap().insert(*scope, now);
        Ok(before.unwrap_or(Pressure::Normal))
    }
}

/// A failure count whose store cannot be reached.
pub struct UnreachableSignInFailureBudget;

#[async_trait]
impl SignInFailureBudget for UnreachableSignInFailureBudget {
    async fn failures(&self, _: &FailureScope) -> Result<FailureCount, DomainError> {
        Err(DomainError::infra_msg("the failure count is unreachable"))
    }

    async fn record_failure(&self, _: &FailureScope) -> Result<FailureCount, DomainError> {
        Err(DomainError::infra_msg("the failure count is unreachable"))
    }

    async fn swap_pressure(&self, _: &FailureScope, _: Pressure) -> Result<Pressure, DomainError> {
        Err(DomainError::infra_msg("the failure count is unreachable"))
    }
}

/// A proof-of-work provider passing one known proof, once. Any other proof,
/// and the known one sent again, fails.
pub struct FakeChallengeVerifier {
    solved: String,
    used: Mutex<HashSet<String>>,
}

impl FakeChallengeVerifier {
    /// A provider passing `solved` once.
    #[must_use]
    pub fn accepting(solved: &str) -> Self {
        Self {
            solved: solved.to_owned(),
            used: Mutex::new(HashSet::new()),
        }
    }
}

#[async_trait]
impl ChallengeVerifier for FakeChallengeVerifier {
    fn kind(&self) -> ChallengeKind {
        ChallengeKind::ProofOfWork
    }

    async fn verify(
        &self,
        proof: &ChallengeProof,
        _: Fact<&IpAddress>,
    ) -> Result<ChallengeVerdict, DomainError> {
        let fresh = self.used.lock().unwrap().insert(proof.as_str().to_owned());
        if proof.as_str() == self.solved && fresh {
            return Ok(ChallengeVerdict::Passed);
        }
        Ok(ChallengeVerdict::Failed)
    }
}

/// A puzzle setter handing out the same puzzle every time.
pub struct FakeChallengeIssuer;

impl ChallengeIssuer for FakeChallengeIssuer {
    fn issue(&self, _: Fact<&IpAddress>) -> Result<ChallengePuzzle, DomainError> {
        Ok(ChallengePuzzle {
            challenge: "puzzle".to_owned(),
            difficulty_bits: 8,
            expires_at: ianua_domain::shared::clock::now(),
        })
    }
}

/// Hashing with `hasher`, every permit handed out.
#[must_use]
pub fn hashing_with(hasher: Arc<dyn PasswordHasher>) -> PasswordHashing {
    PasswordHashing::new(hasher, Arc::new(FakeHashPermits::default()))
}

impl Fake for Arc<dyn PasswordHashPermits> {
    fn fake() -> Self {
        Arc::new(FakeHashPermits::default())
    }
}

impl Fake for Arc<dyn SignInFailureBudget> {
    fn fake() -> Self {
        Arc::new(FakeSignInFailureBudget::default())
    }
}
