//! Request attestation challenge: the nonce a bootstrap proof must sign.
//!
//! The first half of proof-of-possession bootstrap: the platform picks an
//! unpredictable nonce, binds it to one agent for a short window, and returns
//! it. The agent signs it with the private key behind its attestation and
//! presents both to
//! [`bootstrap`](crate::use_cases::agents::lifecycle::bootstrap),
//! which spends the challenge.
//!
//! Deliberately says nothing about the agent beyond that it exists and accepts
//! attestation. The endpoint is unauthenticated, so a caller learning "this
//! agent is bootstrappable" is the most it may reveal, and it reveals that
//! only for agents that already permit anonymous attestation.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::challenge::AttestationChallenge;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActingFor, ActorRef, AgentId, Lifetime};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::agents::{AgentStore, AttestationChallengeStore, AttestationNonceGenerator};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The ports [`RequestAttestationChallengeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequestAttestationChallengePorts {
    /// Loads the agent and its attestation policy.
    pub agent_store: Arc<dyn AgentStore>,
    /// Mints the nonce.
    pub nonce_generator: Arc<dyn AttestationNonceGenerator>,
    /// Records the issued challenge for the bootstrap to spend.
    pub challenge_store: Arc<dyn AttestationChallengeStore>,
}

/// Issues single-use attestation challenges.
pub struct RequestAttestationChallengeUseCase {
    lifetime: Lifetime,
    ports: RequestAttestationChallengePorts,
}

impl RequestAttestationChallengeUseCase {
    /// A use case issuing challenges that last `lifetime`, working through
    /// `ports`.
    #[must_use]
    pub fn new(lifetime: Lifetime, ports: RequestAttestationChallengePorts) -> Self {
        Self { lifetime, ports }
    }
}

impl Command for RequestAttestationChallengeUseCase {
    type Caller = ScopedTenant;
    type Input = AgentId;
    type Output = Result<AttestationChallenge<ResolvedTenant>, AppError>;

    /// Issues a challenge for the agent's next bootstrap. The challenge is
    /// recorded for the bootstrap to spend, and its issue is audited as
    /// asked for by the agent itself.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the agent doesn't exist, is inactive or
    ///   permits no attestation bootstrap, all alike: a challenge the
    ///   bootstrap would refuse anyway is not minted, and nobody signed in
    ///   learns which agents exist or how they stand.
    /// - `AppError::Internal` on generation or persistence failure.
    async fn execute(
        &self,
        tenant_id: &ScopedTenant,
        auditor: &RequestAuditor,
        agent_id: AgentId,
    ) -> Result<AttestationChallenge<ResolvedTenant>, AppError> {
        let found = self
            .ports
            .agent_store
            .find_by_id(tenant_id, &agent_id)
            .await
            .or_internal()?;
        let mut agent = ensure_bootstrappable(found)?;

        let nonce = self.ports.nonce_generator.generate().await.or_internal()?;
        let challenge = agent.issue_attestation_challenge(nonce, self.lifetime);

        self.ports
            .challenge_store
            .issue(tenant_id, &challenge)
            .await
            .or_internal()?;

        let itself = ActorRef::Agent {
            id: agent_id,
            on_behalf_of: ActingFor::Itself,
        };
        auditor
            .dispatch_by(&itself, agent.take_events(tenant_id))
            .await
            .or_internal()?;

        Ok(challenge)
    }
}

/// The agent `found`, when it could complete a bootstrap: it exists, is
/// active and permits attestation. Every other agent is refused alike, as
/// one the tenant does not have.
fn ensure_bootstrappable(
    found: Option<AgentIdentity<ResolvedTenant>>,
) -> Result<AgentIdentity<ResolvedTenant>, AppError> {
    found
        .filter(|agent| agent.is_active() && agent.attestation_policy().is_some())
        .or_not_found(message!("app-agent-not-found", "agent not found"))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::agent::{AgentIdentityRow, AgentProof};
    use ianua_domain::domains::agents::identity::attestation::{
        AttestationMethod, AttestationPolicy, AttestedOrigin,
    };
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::types::Seconds;

    use super::*;
    use crate::test_support::agents::{
        FakeAgentStore, FakeAttestationChallengeStore, FakeNonceGenerator, agent_row, caller_person,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Bench {
        agents: Arc<FakeAgentStore>,
        challenges: Arc<FakeAttestationChallengeStore>,
        nonces: Arc<FakeNonceGenerator>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Bench {
        fn new() -> Self {
            Self {
                agents: Arc::new(FakeAgentStore::empty()),
                challenges: Arc::new(FakeAttestationChallengeStore::empty()),
                nonces: Arc::new(FakeNonceGenerator::default()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn agent(&self, row: AgentIdentityRow) -> AgentId {
            let id = row.id;
            let agent = AgentIdentity::reconstitute(row).unwrap();
            block_on(self.agents.save(&test_ctx().tenant(), &agent)).unwrap();
            id
        }

        fn ask(&self, agent: AgentId) -> Result<AttestationChallenge<ResolvedTenant>, AppError> {
            let use_case = RequestAttestationChallengeUseCase::new(
                Lifetime::seconds(120).unwrap(),
                RequestAttestationChallengePorts {
                    agent_store: self.agents.clone(),
                    challenge_store: self.challenges.clone(),
                    nonce_generator: self.nonces.clone(),
                    ..RequestAttestationChallengePorts::fakes()
                },
            );
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                agent,
            ))
        }
    }

    fn attesting(status: AgentStatus) -> AgentIdentityRow {
        let policy = AttestationPolicy::new(
            vec![AttestationMethod::Spiffe],
            Seconds::new(3600),
            vec![AttestedOrigin::new("spiffe://cluster").unwrap()],
        )
        .unwrap();
        AgentIdentityRow {
            proof: AgentProof::Attestation(policy),
            status,
            ..agent_row(AgentId::new(), caller_person())
        }
    }

    /// Ann's agent attests from her cluster and asks for a challenge. It
    /// gets one bound to it, kept for the bootstrap to spend.
    #[test]
    fn issues_a_challenge_bound_to_the_agent() {
        let bench = Bench::new();
        let agent = bench.agent(attesting(AgentStatus::Active));

        let challenge = bench.ask(agent).unwrap();

        assert_eq!(challenge.agent_id(), &agent);
        assert_eq!(bench.challenges.count(), 1);
    }

    /// Ann's agent asks twice. Each challenge carries its own nonce, so
    /// one signed answer cannot be replayed against the next.
    #[test]
    fn successive_challenges_use_distinct_nonces() {
        let bench = Bench::new();
        let agent = bench.agent(attesting(AgentStatus::Active));

        let first = bench.ask(agent).unwrap();
        let second = bench.ask(agent).unwrap();

        assert_ne!(first.nonce(), second.nonce());
    }

    /// An agent that accepts only enrolled keys appears missing when asked
    /// for an attestation challenge, and no challenge is stored.
    #[test]
    fn an_agent_that_permits_no_attestation_gets_no_challenge() {
        let bench = Bench::new();
        let agent = bench.agent(agent_row(AgentId::new(), caller_person()));

        let result = bench.ask(agent);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(bench.challenges.count(), 0);
    }

    /// A suspended agent appears missing when requesting a bootstrap
    /// challenge, and no challenge is stored.
    #[test]
    fn a_suspended_agent_gets_no_challenge() {
        let bench = Bench::new();
        let agent = bench.agent(attesting(AgentStatus::Suspended));

        let result = bench.ask(agent);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(bench.challenges.count(), 0);
    }

    /// Requests for suspended agents and agents without attestation return
    /// the same refusal as an unknown agent.
    #[test]
    fn every_refusal_reads_as_an_unknown_agent() {
        let bench = Bench::new();
        let suspended = bench.agent(attesting(AgentStatus::Suspended));
        let enrolled_only = bench.agent(agent_row(AgentId::new(), caller_person()));
        let refusal = |agent| bench.ask(agent).err().map(|error| error.to_string());

        let unknown = refusal(AgentId::new());

        assert!(unknown.is_some());
        assert_eq!(refusal(suspended), unknown);
        assert_eq!(refusal(enrolled_only), unknown);
    }

    /// A challenge for an agent the tenant does not have is not found.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let bench = Bench::new();

        let result = bench.ask(AgentId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann's agent asks for a challenge. The issue is recorded in the audit
    /// trail, as asked for by the agent itself.
    #[test]
    fn an_issued_challenge_is_recorded_in_the_audit_trail() {
        let bench = Bench::new();
        let agent = bench.agent(attesting(AgentStatus::Active));

        bench.ask(agent).unwrap();

        assert_eq!(
            bench.sink.records.lock().unwrap().as_slice(),
            ["agents.attestation_challenge_issued"]
        );
    }
}
