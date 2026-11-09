//! How an agent proves it is itself, as a test says it: the nonces and
//! challenges of an attestation, the attestor, the assertions it signs and
//! the ledger that spends them, and the broker's credentials.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::agents::identity::attestation::{
    AttestationMethod, AttestedIdentity, AttestedSubject,
};
use ianua_domain::domains::agents::identity::challenge::{AttestationChallenge, AttestationNonce};
use ianua_domain::domains::agents::identity::token_attack::AssertionFault;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{AgentId, KeyId, TokenId};
use time::{Duration, OffsetDateTime};

use crate::ports::TenantScoped;
use crate::ports::agents::{
    AgentAssertionReplayGuard, AgentAssertionVerifier, AgentAttestor, AssertionCheck,
    AssertionVerification, AttestationChallengeStore, AttestationNonceGenerator,
    AttestationPresentation, EnrolledKey, VerifiedAssertion,
};
use crate::ports::broker::{AgentPrincipal, BrokerAuthenticator};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::agents::shelf::Shelf;

/// How long an assertion [`FakeAssertionVerifier`] accepts stays valid.
const ASSERTION_LIFETIME: Duration = Duration::minutes(5);

/// Nonce generator that hands out distinct nonces of a valid length.
#[derive(Default)]
pub struct FakeNonceGenerator {
    issued: Mutex<u64>,
}

#[async_trait]
impl AttestationNonceGenerator for FakeNonceGenerator {
    async fn generate(&self) -> Result<AttestationNonce, DomainError> {
        let mut issued = self.issued.lock().unwrap();
        *issued += 1;
        Ok(AttestationNonce::new(format!(
            "test-nonce-{:0>36}",
            *issued
        ))?)
    }
}

/// In-memory challenge store: challenges are kept per tenant, and consuming
/// one spends it, so a replayed nonce is refused as it would be in
/// production.
#[derive(Default)]
pub struct FakeAttestationChallengeStore {
    challenges: Shelf<AttestationChallenge<ResolvedTenant>>,
}

impl TenantScoped for FakeAttestationChallengeStore {}

impl FakeAttestationChallengeStore {
    /// A store holding no challenges.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many challenges are still unspent and unexpired, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        let now = clock::now();
        self.challenges
            .all()
            .iter()
            .filter(|challenge| challenge.is_valid_at(now))
            .count()
    }
}

#[async_trait]
impl AttestationChallengeStore for FakeAttestationChallengeStore {
    async fn issue(
        &self,
        tenant_id: &ScopedTenant,
        challenge: &AttestationChallenge<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let recorded = self
            .challenges
            .find(tenant_id, |stored| stored.nonce() == challenge.nonce());
        if recorded.is_none() {
            self.challenges.put(tenant_id, challenge.clone(), |_| false);
        }
        Ok(())
    }

    async fn consume(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
        nonce: &AttestationNonce,
    ) -> Result<Option<AttestationChallenge<ResolvedTenant>>, DomainError> {
        let now = clock::now();
        self.challenges.revise_first(
            tenant_id,
            |challenge| {
                challenge.nonce() == nonce
                    && challenge.agent_id() == agent_id
                    && challenge.is_valid_at(now)
            },
            spent,
        )
    }
}

/// Assertion verifier that names one `kid` for every assertion, and either
/// accepts each as signed by one agent or refuses it for one fault.
pub struct FakeAssertionVerifier {
    kid: KeyId,
    verified: Result<AgentId, AssertionFault>,
    signed_ago: time::Duration,
}

impl FakeAssertionVerifier {
    /// Accepts every assertion as signed by `subject` with the key `kid`.
    ///
    /// # Panics
    ///
    /// - If `kid` is not a valid key id. Tests pass literals that are.
    #[must_use]
    pub fn accepting(kid: &str, subject: AgentId) -> Self {
        Self {
            kid: KeyId::new(kid).expect("the test key id is valid"),
            verified: Ok(subject),
            signed_ago: time::Duration::ZERO,
        }
    }

    /// The same verifier, answering that each assertion was signed `ago`
    /// before now.
    #[must_use]
    pub fn signed_ago(self, ago: time::Duration) -> Self {
        Self {
            signed_ago: ago,
            ..self
        }
    }

    /// Refuses the signature of every assertion naming the key `kid`.
    ///
    /// # Panics
    ///
    /// - If `kid` is not a valid key id. Tests pass literals that are.
    #[must_use]
    pub fn rejecting(kid: &str) -> Self {
        Self::refusing(kid, AssertionFault::BadSignature)
    }

    /// Refuses every assertion naming the key `kid` for `fault`.
    ///
    /// # Panics
    ///
    /// - If `kid` is not a valid key id. Tests pass literals that are.
    #[must_use]
    pub fn refusing(kid: &str, fault: AssertionFault) -> Self {
        Self {
            kid: KeyId::new(kid).expect("the test key id is valid"),
            verified: Err(fault),
            signed_ago: time::Duration::ZERO,
        }
    }
}

#[async_trait]
impl AgentAssertionVerifier for FakeAssertionVerifier {
    fn key_id(&self, _assertion: &str) -> Result<KeyId, DomainError> {
        Ok(self.kid.clone())
    }

    async fn verify(
        &self,
        _assertion: &str,
        _against: &AssertionVerification<'_>,
    ) -> Result<AssertionCheck, DomainError> {
        let agent_id = match self.verified {
            Ok(agent_id) => agent_id,
            Err(fault) => return Ok(AssertionCheck::Refused(fault)),
        };
        Ok(AssertionCheck::Verified(VerifiedAssertion {
            agent_id,
            jti: TokenId::new(uuid::Uuid::now_v7().to_string())?,
            issued_at: clock::now() - self.signed_ago,
            expires_at: clock::now() + ASSERTION_LIFETIME,
        }))
    }
}

/// Replay guard that has spent no assertion before, so lets each through.
pub struct FakeReplayGuard;

impl TenantScoped for FakeReplayGuard {}

#[async_trait]
impl AgentAssertionReplayGuard for FakeReplayGuard {
    async fn consume(
        &self,
        _tenant_id: &ScopedTenant,
        _agent_id: &AgentId,
        _jti: &TokenId,
        _expires_at: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        Ok(true)
    }
}

/// Replay guard that reports every assertion as already spent.
pub struct ReplayedGuard;

impl TenantScoped for ReplayedGuard {}

#[async_trait]
impl AgentAssertionReplayGuard for ReplayedGuard {
    async fn consume(
        &self,
        _tenant_id: &ScopedTenant,
        _agent_id: &AgentId,
        _jti: &TokenId,
        _expires_at: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        Ok(false)
    }
}

/// Attestor that either vouches for one workload identity or refuses every
/// presentation, and when it was made for one key, refuses every other.
pub struct FakeAttestor {
    attested: Option<AttestedIdentity>,
    bound_to: Option<EnrolledKey>,
}

impl FakeAttestor {
    /// Attests every presentation as `subject`, proven by `method`, for any
    /// key.
    ///
    /// # Panics
    ///
    /// - If `subject` is not a valid attested subject. Tests pass literals
    ///   that are.
    #[must_use]
    pub fn accepting(method: AttestationMethod, subject: &str) -> Self {
        let subject = AttestedSubject::new(subject).expect("the test subject is valid");
        Self {
            attested: Some(AttestedIdentity::new(method, subject)),
            bound_to: None,
        }
    }

    /// The same attestor, refusing a presentation for any key but `key`, as
    /// a proof bound to that key is.
    #[must_use]
    pub fn bound_to(self, key: EnrolledKey) -> Self {
        Self {
            bound_to: Some(key),
            ..self
        }
    }

    /// Refuses every presentation.
    #[must_use]
    pub fn rejecting() -> Self {
        Self {
            attested: None,
            bound_to: None,
        }
    }
}

#[async_trait]
impl AgentAttestor for FakeAttestor {
    async fn verify(
        &self,
        _presentation: &AttestationPresentation,
        key: &EnrolledKey,
    ) -> Result<AttestedIdentity, DomainError> {
        if self.bound_to.as_ref().is_some_and(|bound| bound != key) {
            return Err(DomainError::unauthorized(
                "attestation made for another key",
            ));
        }
        self.attested
            .clone()
            .ok_or_else(|| DomainError::unauthorized("attestation failed"))
    }
}

/// Broker authenticator that knows a fixed table of credentials, and no
/// others.
pub struct FakeBrokerAuthenticator(HashMap<&'static str, AgentPrincipal>);

impl FakeBrokerAuthenticator {
    /// Accepts each credential in `table` as its principal, and nothing else.
    pub fn knowing(table: impl IntoIterator<Item = (&'static str, AgentPrincipal)>) -> Self {
        Self(table.into_iter().collect())
    }
}

#[async_trait]
impl BrokerAuthenticator for FakeBrokerAuthenticator {
    async fn authenticate(&self, credential: &Secret) -> Result<AgentPrincipal, DomainError> {
        self.0
            .get(credential.expose())
            .cloned()
            .ok_or_else(|| DomainError::unauthorized("unknown token"))
    }
}

/// `challenge`, spent on one proof.
fn spent(
    challenge: &AttestationChallenge<ResolvedTenant>,
) -> Result<AttestationChallenge<ResolvedTenant>, DomainError> {
    let mut spent = challenge.clone();
    spent.spend()?;
    Ok(spent)
}

impl Fake for Arc<dyn AgentAssertionVerifier> {
    fn fake() -> Self {
        Arc::new(FakeAssertionVerifier::rejecting("fake-kid"))
    }
}

impl Fake for Arc<dyn AgentAttestor> {
    fn fake() -> Self {
        Arc::new(FakeAttestor::rejecting())
    }
}

impl Fake for Arc<dyn AgentAssertionReplayGuard> {
    fn fake() -> Self {
        Arc::new(FakeReplayGuard)
    }
}

impl Fake for Arc<dyn AttestationChallengeStore> {
    fn fake() -> Self {
        Arc::new(FakeAttestationChallengeStore::empty())
    }
}

impl Fake for Arc<dyn AttestationNonceGenerator> {
    fn fake() -> Self {
        Arc::new(FakeNonceGenerator::default())
    }
}

impl Fake for Arc<dyn BrokerAuthenticator> {
    fn fake() -> Self {
        Arc::new(FakeBrokerAuthenticator::knowing([]))
    }
}
