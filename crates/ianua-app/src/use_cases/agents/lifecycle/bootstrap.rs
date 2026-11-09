//! Bootstrap agent: a credential from a platform attestation, with no
//! standing secret.
//!
//! Instead of holding a durable secret, an agent proves what it is on each
//! bootstrap. It presents a platform attestation (a SPIFFE SVID, a signed AWS
//! caller identity, a GCP instance identity, a TPM quote) or a workload
//! token (Kubernetes, GitHub Actions, an OIDC issuer), bound to a challenge
//! the platform issued and to the public key the workload made. The
//! platform verifies it, the agent's policy must trust it, and only then
//! is that key enrolled as a short-lived credential tied to the attested
//! identity. There is no standing secret to steal, the private key never
//! leaves the workload, and a proof seen in passing cannot enrol anyone
//! else's key.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::attestation::{
    AttestationRef, AttestedIdentity, WorkloadIssuer, WorkloadKind, WorkloadToken,
};
use ianua_domain::domains::agents::identity::credential::{
    AgentCredential, CredentialLifetimes, CredentialOrigin, KeySource,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActingFor, ActorRef, AgentId, Seconds, Setting};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{
    AgentAttestor, AgentCredentialStore, AgentStore, AgentVersion, AttestationChallengeStore,
    AttestationPresentation, EnrolledKey, PresentedWorkloadToken, WorkloadTokenVerifier,
};
use crate::ports::crypto::PublicKeyDecoder;
use crate::services::agents::standing::ensure_active;
use crate::services::lookup::existing_agent;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::credentials::key_enrolment::{Enrolment, enrol};

/// Request to bootstrap an agent from a platform attestation.
pub struct BootstrapAgentRequest {
    /// The agent being bootstrapped.
    pub agent_id: AgentId,
    /// The public key the workload made for itself.
    pub key: EnrolledKey,
    /// The platform attestation the agent presents.
    pub attestation: AttestationPresentation,
}

/// The ports [`BootstrapAgentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct BootstrapAgentPorts {
    /// Loads the agent and its attestation policy, and saves its fresh
    /// attestation.
    pub agent_store: Arc<dyn AgentStore>,
    /// Verifies the platform attestation.
    pub attestor: Arc<dyn AgentAttestor>,
    /// Verifies a workload token, one adapter per kind.
    pub workload_verifier: Arc<dyn WorkloadTokenVerifier>,
    /// Keeps the minted credential, and the ones before it.
    pub credential_store: Arc<dyn AgentCredentialStore>,
    /// Checks the offered key is a public key of its algorithm.
    pub key_decoder: Arc<dyn PublicKeyDecoder>,
    /// Spends the single-use attestation challenge.
    pub challenge_store: Arc<dyn AttestationChallengeStore>,
}

/// Bootstraps agents from platform attestations.
pub struct BootstrapAgentUseCase {
    ports: BootstrapAgentPorts,
    credential_ttl: Seconds,
    lifetimes: CredentialLifetimes,
}

impl BootstrapAgentUseCase {
    /// A use case minting credentials that live `credential_ttl`, capped by
    /// `lifetimes` as every credential is, working through `ports`. The
    /// lifetime is short on purpose: the agent attests again for a fresh one.
    #[must_use]
    pub fn new(
        ports: BootstrapAgentPorts,
        credential_ttl: Seconds,
        lifetimes: CredentialLifetimes,
    ) -> Self {
        Self {
            ports,
            credential_ttl,
            lifetimes,
        }
    }
}

impl Command for BootstrapAgentUseCase {
    type Caller = ScopedTenant;
    type Input = BootstrapAgentRequest;
    type Output = Result<AgentCredential<ResolvedTenant>, AppError>;

    /// Verifies the attestation and mints a short-lived credential for it,
    /// saved with the agent's fresh attestation and then recorded.
    ///
    /// The challenge is spent before the agent is looked at. Only an agent
    /// that could bootstrap is issued one, so a caller without one learns
    /// nothing of which agents exist or how they stand: every such
    /// bootstrap answers as a missing challenge.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the challenge is unknown, spent or
    ///   another agent's, the agent takes no attestation, the attestation
    ///   fails or its policy does not trust it, or the workload is bound to
    ///   another agent or this agent to another workload.
    /// - `AppError::NotFound` when the tenant has no such agent.
    /// - `AppError::Conflict` when the agent is not active, or changed
    ///   since it was read, as when a person suspended it meanwhile.
    /// - `AppError::Domain` when the key is not a public key of its
    ///   algorithm.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        req: BootstrapAgentRequest,
    ) -> Result<AgentCredential<ResolvedTenant>, AppError> {
        ensure_challenge_spent(self.ports.challenge_store.as_ref(), tenant, &req).await?;
        let mut agent =
            existing_agent(self.ports.agent_store.as_ref(), tenant, &req.agent_id).await?;
        let read = AgentVersion::of(&agent);
        ensure_active(&agent)?;
        ensure_takes_attestation(&agent)?;
        let attested = attested_workload(&self.ports, tenant, &req, &mut agent).await?;
        let mut credential = short_lived_credential(self, &req, &agent, &attested)?;
        save(&self.ports, tenant, &credential, &agent, read).await?;
        let itself = ActorRef::Agent {
            id: req.agent_id,
            on_behalf_of: ActingFor::Itself,
        };
        auditor
            .dispatch_by(&itself, credential.take_events(tenant))
            .await
            .or_internal()?;
        Ok(credential)
    }
}

/// Refuses an agent with no attestation policy: it proves itself with an
/// enrolled key, never by bootstrapping.
fn ensure_takes_attestation(agent: &AgentIdentity<ResolvedTenant>) -> Result<(), AppError> {
    if agent.attestation_policy().is_some() {
        return Ok(());
    }
    Err(AppError::Forbidden(message!(
        "agents-agent-does-not-permit-attestation",
        "agent does not permit attestation"
    )))
}

/// Spends the challenge this bootstrap claims, before anything expensive.
///
/// Spending first does two things. It authenticates the nonce: the store
/// yields only a challenge the platform issued, for this agent, that has
/// not expired, so the value the attestor checks the proof over is one the
/// platform chose. And because spending is atomic, a captured presentation
/// is worth exactly one attempt: a replay finds the nonce spent.
async fn ensure_challenge_spent(
    store: &dyn AttestationChallengeStore,
    tenant: &ScopedTenant,
    req: &BootstrapAgentRequest,
) -> Result<(), AppError> {
    store
        .consume(tenant, &req.agent_id, &req.attestation.proof.nonce)
        .await
        .or_internal()?
        .ok_or_else(|| {
            AppError::Forbidden(message!(
                "agents-attestation-challenge-is-unknown-or-spent",
                "attestation challenge is unknown or spent"
            ))
        })?;
    Ok(())
}

/// Confines an agent to the workload that first claimed it.
///
/// The policy names trusted methods and origins, not one subject, so a
/// verified attestation proves only "some workload this tenant trusts". The
/// endpoint takes no other proof, so without this any such workload could
/// bootstrap any agent and clear the re-attestation block a person set to
/// hold it. The attestation recorded on the agent's credentials, method and
/// subject both, is the binding. The same subject vouched for by another
/// method is another claim and is refused.
async fn ensure_own_workload(
    store: &dyn AgentCredentialStore,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
    presented: &AttestationRef,
) -> Result<(), AppError> {
    let existing = store.list_for_agent(tenant, agent_id).await.or_internal()?;
    let pinned = existing
        .iter()
        .find_map(|credential| match credential.origin() {
            CredentialOrigin::Attested(attestation) => Some(attestation),
            CredentialOrigin::Enrolled => None,
        });
    match pinned {
        None => Ok(()),
        Some(pinned) if pinned == presented => Ok(()),
        Some(_) => Err(AppError::Forbidden(message!(
            "agents-attestation-subject-does-not-match-the",
            "attestation subject does not match the workload that holds this agent"
        ))),
    }
}

/// Confines a workload to the one agent it first claimed. A workload that
/// bootstrapped two agents leaves the platform unable to tell which of them
/// made a call.
async fn ensure_unclaimed_elsewhere(
    store: &dyn AgentCredentialStore,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
    presented: &AttestationRef,
) -> Result<(), AppError> {
    let elsewhere = store
        .find_pinned_elsewhere(tenant, presented.subject(), agent_id)
        .await
        .or_internal()?;
    if elsewhere.is_none() {
        return Ok(());
    }
    Err(bound_elsewhere())
}

/// The workload identity the request proves, recorded on `agent` once the
/// attestation is verified and trusted, and the workload shown to be
/// neither foreign to this agent nor another's. The request's challenge is
/// spent before this.
async fn attested_workload(
    ports: &BootstrapAgentPorts,
    tenant: &ScopedTenant,
    req: &BootstrapAgentRequest,
    agent: &mut AgentIdentity<ResolvedTenant>,
) -> Result<AttestedIdentity, AppError> {
    let attested = verified_attestation(ports, agent, req).await?;
    agent
        .record_attestation(&attested)
        .map_err(AppError::from_domain)?;
    let presented = AttestationRef::new(attested.method(), attested.subject().clone());
    let credentials = ports.credential_store.as_ref();
    ensure_own_workload(credentials, tenant, &req.agent_id, &presented).await?;
    ensure_unclaimed_elsewhere(credentials, tenant, &req.agent_id, &presented).await?;
    Ok(attested)
}

/// The identity `req`'s attestation proves: vouched for by the platform the
/// workload runs on, through the attestor, or by a workload token, through
/// the verifier, checked only against the issuers `agent`'s policy trusts.
/// Both hold the proof to the challenge spent and the key `req` enrols.
/// Every failure reads the same, so a caller learns nothing of why.
async fn verified_attestation(
    ports: &BootstrapAgentPorts,
    agent: &AgentIdentity<ResolvedTenant>,
    req: &BootstrapAgentRequest,
) -> Result<AttestedIdentity, AppError> {
    let presentation = &req.attestation;
    let Some(kind) = presentation.method.workload_kind() else {
        return ports
            .attestor
            .verify(presentation, &req.key)
            .await
            .map_err(|_| rejected());
    };
    let trusted_issuers = trusted_issuers(agent, kind);
    let token = Secret::new(presentation.material.clone());
    let presented = PresentedWorkloadToken {
        kind,
        token: &token,
        trusted_issuers: &trusted_issuers,
        nonce: &presentation.proof.nonce,
        key: &req.key,
    };
    let claims = ports
        .workload_verifier
        .verify(&presented)
        .await
        .map_err(|_| rejected())?;
    WorkloadToken::new(kind, claims.issuer, claims.subject)
        .and_then(AttestedIdentity::from_token)
        .map_err(|_| rejected())
}

/// The issuers `agent`'s policy trusts for `kind` tokens. None when it
/// trusts no such token, so nothing is fetched.
fn trusted_issuers(
    agent: &AgentIdentity<ResolvedTenant>,
    kind: WorkloadKind,
) -> Vec<WorkloadIssuer> {
    agent
        .attestation_policy()
        .map(|policy| {
            policy
                .workload_trusts()
                .iter()
                .filter(|trust| trust.kind() == kind)
                .map(|trust| trust.issuer().clone())
                .collect()
        })
        .unwrap_or_default()
}

/// Why a bootstrap whose attestation did not verify is refused.
fn rejected() -> AppError {
    AppError::Forbidden(message!(
        "agents-attestation-rejected",
        "attestation rejected"
    ))
}

/// The workload's key enrolled as a credential tied to `attested`,
/// expiring after the configured short lifetime.
fn short_lived_credential(
    use_case: &BootstrapAgentUseCase,
    req: &BootstrapAgentRequest,
    agent: &AgentIdentity<ResolvedTenant>,
    attested: &AttestedIdentity,
) -> Result<AgentCredential<ResolvedTenant>, AppError> {
    enrol(
        use_case.ports.key_decoder.as_ref(),
        &Enrolment {
            agent,
            source: KeySource::Attested(attested),
            key: &req.key,
            expires_at: Setting::Set(clock::now() + use_case.credential_ttl.duration()),
            lifetimes: use_case.lifetimes,
        },
    )
}

/// Saves the agent's fresh attestation over the copy read at `read`, then
/// the minted credential.
///
/// The agent goes first: a bootstrap read before a person suspended,
/// contained or held the agent would clear what they did, so it is refused
/// before any key is enrolled. A workload that bootstrapped another agent
/// at the same moment is refused as the check before it would have been.
async fn save(
    ports: &BootstrapAgentPorts,
    tenant: &ScopedTenant,
    credential: &AgentCredential<ResolvedTenant>,
    agent: &AgentIdentity<ResolvedTenant>,
    read: AgentVersion,
) -> Result<(), AppError> {
    ports
        .agent_store
        .save_unchanged_since(tenant, agent, read)
        .await
        .map_err(AppError::from_domain)?;
    ports
        .credential_store
        .save(tenant, credential)
        .await
        .map_err(|error| match error {
            DomainError::Conflict(_) => bound_elsewhere(),
            other => AppError::internal(other),
        })
}

/// Why a workload already bound to another agent is refused.
fn bound_elsewhere() -> AppError {
    AppError::Forbidden(message!(
        "agents-attestation-subject-is-already-bound-to",
        "attestation subject is already bound to a different agent"
    ))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::agent::{AgentIdentityRow, AgentProof};
    use ianua_domain::domains::agents::identity::attestation::{
        AttestationMethod, AttestationPolicy, AttestedSubject,
    };
    use ianua_domain::domains::agents::identity::challenge::{
        AttestationChallenge, AttestationNonce,
    };
    use ianua_domain::domains::agents::identity::credential::AgentCredentialRow;
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
    use ianua_domain::types::{Lifetime, PublicKeyPem};
    use time::Duration;

    use super::*;
    use crate::ports::agents::{AttestationNonceGenerator, AttestationProof};
    use crate::test_support::agents::{
        FakeAgentCredentialStore, FakeAgentStore, FakeAttestationChallengeStore, FakeAttestor,
        FakeKeyDecoder, FakeNonceGenerator, FakeWorkloadTokenVerifier, REPORTS_MAIN, agent_row,
        enrolled_key, github_claims, key_row, reports_workflow_policy, someone, spiffe_policy,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const TTL: Seconds = Seconds::new(300);

    /// What a bootstrap reads and writes, shared by every attempt a test
    /// makes.
    struct Platform {
        agents: Arc<FakeAgentStore>,
        credentials: Arc<FakeAgentCredentialStore>,
        challenges: Arc<FakeAttestationChallengeStore>,
        nonces: FakeNonceGenerator,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Platform {
        fn new() -> Self {
            Self {
                agents: Arc::new(FakeAgentStore::empty()),
                credentials: Arc::new(FakeAgentCredentialStore::empty()),
                challenges: Arc::new(FakeAttestationChallengeStore::empty()),
                nonces: FakeNonceGenerator::default(),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// An agent of Ann's in `status`, attesting under `policy` when
        /// there is one.
        fn agent(&self, status: AgentStatus, policy: Option<AttestationPolicy>) -> AgentId {
            let id = AgentId::new();
            let row = AgentIdentityRow {
                status,
                proof: policy.map_or(AgentProof::EnrolledKey, AgentProof::Attestation),
                ..agent_row(id, someone("ann@example.test"))
            };
            let agent = AgentIdentity::reconstitute(row).unwrap();
            block_on(self.agents.save(&test_ctx().tenant(), &agent)).unwrap();
            id
        }

        /// A request presenting a challenge the platform just issued for
        /// `agent_id`, as the two-step flow does.
        fn request(&self, agent_id: AgentId) -> BootstrapAgentRequest {
            let nonce = block_on(self.nonces.generate()).unwrap();
            let lifetime = Lifetime::new(Duration::minutes(2)).unwrap();
            let challenge = AttestationChallenge::issue(nonce.clone(), agent_id, lifetime);
            block_on(self.challenges.issue(&test_ctx().tenant(), &challenge)).unwrap();
            presenting(agent_id, nonce)
        }

        fn bootstrap(
            &self,
            attestor: FakeAttestor,
            req: BootstrapAgentRequest,
        ) -> Result<AgentCredential<ResolvedTenant>, AppError> {
            self.bootstrap_over(attestor, FakeWorkloadTokenVerifier::rejecting(), req)
        }

        fn bootstrap_with_token(
            &self,
            verifier: FakeWorkloadTokenVerifier,
            req: BootstrapAgentRequest,
        ) -> Result<AgentCredential<ResolvedTenant>, AppError> {
            self.bootstrap_over(FakeAttestor::rejecting(), verifier, req)
        }

        fn bootstrap_over(
            &self,
            attestor: FakeAttestor,
            verifier: FakeWorkloadTokenVerifier,
            req: BootstrapAgentRequest,
        ) -> Result<AgentCredential<ResolvedTenant>, AppError> {
            let use_case = BootstrapAgentUseCase::new(
                BootstrapAgentPorts {
                    agent_store: self.agents.clone(),
                    attestor: Arc::new(attestor),
                    workload_verifier: Arc::new(verifier),
                    credential_store: self.credentials.clone(),
                    key_decoder: Arc::new(FakeKeyDecoder),
                    challenge_store: self.challenges.clone(),
                },
                TTL,
                CredentialLifetimes::default(),
            );
            block_on(use_case.execute(&test_ctx().tenant(), &test_auditor(self.sink.clone()), req))
        }

        /// A request presenting a GitHub Actions token over a challenge the
        /// platform just issued for `agent_id`.
        fn token_request(&self, agent_id: AgentId) -> BootstrapAgentRequest {
            let mut req = self.request(agent_id);
            req.attestation.method = AttestationMethod::GithubActions;
            req.attestation.material = "header.payload.signature".to_owned();
            req
        }
    }

    /// Ann's agent runs as the reports repository's main-branch workflow,
    /// which her policy trusts, and bootstraps with its GitHub Actions
    /// token. It gets a credential tied to the token's issuer and subject.
    #[test]
    fn a_trusted_workload_token_mints_a_credential() {
        let platform = Platform::new();
        let agent = platform.agent(AgentStatus::Active, Some(reports_workflow_policy()));
        let verifier = FakeWorkloadTokenVerifier::verifying(github_claims(REPORTS_MAIN))
            .bound_to(enrolled_key());

        let credential = platform
            .bootstrap_with_token(verifier, platform.token_request(agent))
            .unwrap();

        assert!(matches!(
            credential.origin(),
            CredentialOrigin::Attested(attestation)
                if attestation.method() == AttestationMethod::GithubActions
                    && attestation.subject().as_str().ends_with(REPORTS_MAIN)
        ));
    }

    /// A verified pull-request token does not satisfy a policy trusting
    /// only the main-branch workflow, so no credential is minted.
    #[test]
    fn a_token_for_another_workload_is_refused() {
        let platform = Platform::new();
        let agent = platform.agent(AgentStatus::Active, Some(reports_workflow_policy()));
        let verifier =
            FakeWorkloadTokenVerifier::verifying(github_claims("repo:corp/reports:pull_request"));

        let result = platform.bootstrap_with_token(verifier, platform.token_request(agent));

        assert!(refused(&result));
        assert_eq!(platform.credentials.count(), 0);
    }

    /// A workload token bound to a different public key is refused without
    /// enrolling the replacement key.
    #[test]
    fn a_workload_token_made_for_another_key_is_refused() {
        let platform = Platform::new();
        let agent = platform.agent(AgentStatus::Active, Some(reports_workflow_policy()));
        let verifier = FakeWorkloadTokenVerifier::verifying(github_claims(REPORTS_MAIN))
            .bound_to(enrolled_key());
        let mut req = platform.token_request(agent);
        req.key = EnrolledKey {
            algorithm: SigningAlgorithm::Es256,
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkwTWFsbG9yeQ==\n-----END PUBLIC KEY-----\n",
            )
            .unwrap(),
        };

        let result = platform.bootstrap_with_token(verifier, req);

        assert!(refused(&result));
        assert_eq!(platform.credentials.count(), 0);
    }

    /// A workload token rejected by the verifier creates no credential.
    #[test]
    fn a_workload_token_that_does_not_verify_is_refused() {
        let platform = Platform::new();
        let agent = platform.agent(AgentStatus::Active, Some(reports_workflow_policy()));

        let result = platform.bootstrap_with_token(
            FakeWorkloadTokenVerifier::rejecting(),
            platform.token_request(agent),
        );

        assert!(refused(&result));
        assert_eq!(platform.credentials.count(), 0);
    }

    /// A GitHub Actions token cannot bootstrap an agent trusting only
    /// SPIFFE, and no credential is created.
    #[test]
    fn a_workload_token_the_policy_does_not_trust_is_refused() {
        let platform = Platform::new();
        let agent = platform.agent(AgentStatus::Active, Some(spiffe_policy()));
        let verifier = FakeWorkloadTokenVerifier::verifying(github_claims(REPORTS_MAIN));

        let result = platform.bootstrap_with_token(verifier, platform.token_request(agent));

        assert!(refused(&result));
        assert_eq!(platform.credentials.count(), 0);
    }

    fn presenting(agent_id: AgentId, nonce: AttestationNonce) -> BootstrapAgentRequest {
        BootstrapAgentRequest {
            agent_id,
            key: enrolled_key(),
            attestation: AttestationPresentation {
                method: AttestationMethod::Spiffe,
                material: "spiffe://cluster/ns/sa".to_owned(),
                proof: AttestationProof {
                    nonce,
                    signature: "c2ln".to_owned(),
                },
            },
        }
    }

    fn spiffe(subject: &str) -> FakeAttestor {
        FakeAttestor::accepting(AttestationMethod::Spiffe, subject)
    }

    fn refused(result: &Result<AgentCredential<ResolvedTenant>, AppError>) -> bool {
        matches!(result, Err(AppError::Forbidden(_)))
    }

    /// Ann's agent runs as a trusted SPIFFE workload and bootstraps. It gets
    /// its own public key back as a credential that lives the configured
    /// lifetime, tied to the attestation, and the bootstrap is recorded.
    #[test]
    fn a_trusted_attestation_mints_a_short_lived_credential() {
        let platform = Platform::new();
        let agent = platform.agent(AgentStatus::Active, Some(spiffe_policy()));
        let req = platform.request(agent);
        let before = clock::now();

        let credential = platform
            .bootstrap(spiffe("spiffe://cluster/ns/sa"), req)
            .unwrap();

        let after = clock::now();
        assert_eq!(credential.public_key().as_str(), FakeKeyDecoder::VALID);
        assert!(credential.is_active());
        let ttl = TTL.duration();
        assert!((before + ttl..=after + ttl).contains(&credential.expires_at()));
        assert!(matches!(
            credential.origin(),
            CredentialOrigin::Attested(attestation) if attestation.method() == AttestationMethod::Spiffe
        ));
        assert_eq!(platform.credentials.count(), 1);
        assert_eq!(
            platform.sink.records.lock().unwrap().as_slice(),
            ["agents.agent_bootstrapped"]
        );
    }

    /// A bootstrap racing a fleet stop returns a conflict, stores no
    /// credential, and leaves the agent suspended.
    #[test]
    fn a_bootstrap_read_before_a_fleet_stop_does_not_undo_it() {
        let platform = Platform::new();
        let agent = platform.agent(AgentStatus::Active, Some(spiffe_policy()));
        platform.agents.stops_the_fleet_before_each_save();

        let result = platform.bootstrap(spiffe("spiffe://cluster/ns/sa"), platform.request(agent));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(platform.credentials.count(), 0);
        assert_eq!(
            platform.agents.find_by_id_direct(&agent).unwrap().status(),
            AgentStatus::Suspended
        );
    }

    /// Once a workload claims an agent, a different workload in the trusted
    /// cluster is refused and the original credential remains the only one.
    #[test]
    fn a_different_workload_cannot_take_over_a_bootstrapped_agent() {
        let platform = Platform::new();
        let agent = platform.agent(AgentStatus::Active, Some(spiffe_policy()));
        platform
            .bootstrap(spiffe("spiffe://cluster/ns/legit"), platform.request(agent))
            .unwrap();

        let result = platform.bootstrap(
            spiffe("spiffe://cluster/ns/impostor"),
            platform.request(agent),
        );

        assert!(refused(&result));
        assert_eq!(platform.credentials.count(), 1);
    }

    /// Replaying a successful bootstrap's nonce is refused without adding
    /// another credential.
    #[test]
    fn a_replayed_bootstrap_is_refused() {
        let platform = Platform::new();
        let agent = platform.agent(AgentStatus::Active, Some(spiffe_policy()));
        let req = platform.request(agent);
        let replay = presenting(agent, req.attestation.proof.nonce.clone());
        platform
            .bootstrap(spiffe("spiffe://cluster/ns/sa"), req)
            .unwrap();

        let result = platform.bootstrap(spiffe("spiffe://cluster/ns/sa"), replay);

        assert!(refused(&result));
        assert_eq!(platform.credentials.count(), 1);
    }

    /// A verified attestation from an untrusted origin is refused without
    /// creating a credential.
    #[test]
    fn an_attestation_from_an_unlisted_origin_is_refused() {
        let platform = Platform::new();
        let agent = platform.agent(AgentStatus::Active, Some(spiffe_policy()));

        let result =
            platform.bootstrap(spiffe("spiffe://elsewhere/ns/sa"), platform.request(agent));

        assert!(refused(&result));
        assert_eq!(platform.credentials.count(), 0);
    }

    /// An invented nonce cannot bootstrap an agent or create a credential.
    #[test]
    fn a_bootstrap_without_a_challenge_is_refused() {
        let platform = Platform::new();
        let agent = platform.agent(AgentStatus::Active, Some(spiffe_policy()));
        let invented = AttestationNonce::new("attacker-chosen-nonce-padded-to-length").unwrap();

        let result = platform.bootstrap(
            spiffe("spiffe://cluster/ns/sa"),
            presenting(agent, invented),
        );

        assert!(refused(&result));
        assert_eq!(platform.credentials.count(), 0);
    }

    /// A workload bound to one agent cannot bootstrap a second; only its
    /// original credential remains stored.
    #[test]
    fn a_workload_cannot_bootstrap_a_second_agent() {
        let platform = Platform::new();
        let first = platform.agent(AgentStatus::Active, Some(spiffe_policy()));
        let second = platform.agent(AgentStatus::Active, Some(spiffe_policy()));
        platform
            .bootstrap(
                spiffe("spiffe://cluster/ns/shared"),
                platform.request(first),
            )
            .unwrap();

        let result = platform.bootstrap(
            spiffe("spiffe://cluster/ns/shared"),
            platform.request(second),
        );

        assert!(refused(&result));
        assert_eq!(platform.credentials.count(), 1);
    }

    /// A challenge issued for another agent cannot create a credential for
    /// the requested agent.
    #[test]
    fn a_challenge_issued_for_another_agent_is_refused() {
        let platform = Platform::new();
        let mine = platform.agent(AgentStatus::Active, Some(spiffe_policy()));
        let theirs = platform.agent(AgentStatus::Active, Some(spiffe_policy()));
        let req = BootstrapAgentRequest {
            agent_id: theirs,
            ..platform.request(mine)
        };

        let result = platform.bootstrap(spiffe("spiffe://cluster/ns/sa"), req);

        assert!(refused(&result));
        assert_eq!(platform.credentials.count(), 0);
    }

    /// The workload that holds Ann's agent attests again for a fresh
    /// credential. It gets one.
    #[test]
    fn the_pinned_workload_may_bootstrap_again() {
        let platform = Platform::new();
        let agent = platform.agent(AgentStatus::Active, Some(spiffe_policy()));
        platform
            .bootstrap(spiffe("spiffe://cluster/ns/sa"), platform.request(agent))
            .unwrap();

        platform
            .bootstrap(spiffe("spiffe://cluster/ns/sa"), platform.request(agent))
            .unwrap();

        assert_eq!(platform.credentials.count(), 2);
    }

    /// A subject pinned through AWS cannot bootstrap through SPIFFE using
    /// the same text; the original credential remains the only one.
    #[test]
    fn the_same_subject_attested_another_way_is_refused() {
        let platform = Platform::new();
        let agent = platform.agent(AgentStatus::Active, Some(spiffe_policy()));
        let subject = AttestedSubject::new("spiffe://cluster/ns/sa").unwrap();
        let row = AgentCredentialRow {
            origin: CredentialOrigin::Attested(AttestationRef::new(
                AttestationMethod::AwsIam,
                subject,
            )),
            ..key_row(agent, "pinned")
        };
        let pinned = AgentCredential::reconstitute(row).unwrap();
        block_on(platform.credentials.save(&test_ctx().tenant(), &pinned)).unwrap();

        let result = platform.bootstrap(spiffe("spiffe://cluster/ns/sa"), platform.request(agent));

        assert!(refused(&result));
        assert_eq!(platform.credentials.count(), 1);
    }

    /// An attestation proof bound to a different public key is refused
    /// without enrolling the key supplied in the request.
    #[test]
    fn a_proof_made_for_another_key_is_refused() {
        let platform = Platform::new();
        let agent = platform.agent(AgentStatus::Active, Some(spiffe_policy()));
        let attestor = spiffe("spiffe://cluster/ns/sa").bound_to(enrolled_key());
        let mut req = platform.request(agent);
        req.key = EnrolledKey {
            algorithm: SigningAlgorithm::Es256,
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkwTWFsbG9yeQ==\n-----END PUBLIC KEY-----\n",
            )
            .unwrap(),
        };

        let result = platform.bootstrap(attestor, req);

        assert!(refused(&result));
        assert_eq!(platform.credentials.count(), 0);
    }

    /// The attestor is asked about the very key the request enrols, so a
    /// proof bound to it mints the credential.
    #[test]
    fn a_proof_made_for_the_enrolled_key_mints_a_credential() {
        let platform = Platform::new();
        let agent = platform.agent(AgentStatus::Active, Some(spiffe_policy()));
        let attestor = spiffe("spiffe://cluster/ns/sa").bound_to(enrolled_key());

        let result = platform.bootstrap(attestor, platform.request(agent));

        assert!(result.is_ok());
        assert_eq!(platform.credentials.count(), 1);
    }

    /// A workload bootstraps an agent the tenant does not have. It is not
    /// found.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let platform = Platform::new();

        let result = platform.bootstrap(
            spiffe("spiffe://cluster/ns/sa"),
            platform.request(AgentId::new()),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// An agent without an attestation policy cannot bootstrap a credential.
    #[test]
    fn an_agent_without_a_policy_is_refused() {
        let platform = Platform::new();
        let agent = platform.agent(AgentStatus::Active, None);

        let result = platform.bootstrap(spiffe("spiffe://cluster/ns/sa"), platform.request(agent));

        assert!(refused(&result));
        assert_eq!(platform.credentials.count(), 0);
    }

    /// A TPM attestation cannot bootstrap an agent trusting only SPIFFE;
    /// no credential is created.
    #[test]
    fn an_untrusted_method_is_refused() {
        let platform = Platform::new();
        let agent = platform.agent(AgentStatus::Active, Some(spiffe_policy()));
        let tpm = FakeAttestor::accepting(AttestationMethod::Tpm, "tpm:ek-1");

        let result = platform.bootstrap(tpm, platform.request(agent));

        assert!(refused(&result));
        assert_eq!(platform.credentials.count(), 0);
    }

    /// A rejected attestation prevents bootstrap from creating a credential.
    #[test]
    fn a_failed_attestation_is_refused() {
        let platform = Platform::new();
        let agent = platform.agent(AgentStatus::Active, Some(spiffe_policy()));

        let result = platform.bootstrap(FakeAttestor::rejecting(), platform.request(agent));

        assert!(refused(&result));
        assert_eq!(platform.credentials.count(), 0);
    }

    /// A suspended agent's bootstrap returns a conflict and creates no credential.
    #[test]
    fn a_suspended_agent_is_refused() {
        let platform = Platform::new();
        let agent = platform.agent(AgentStatus::Suspended, Some(spiffe_policy()));

        let result = platform.bootstrap(spiffe("spiffe://cluster/ns/sa"), platform.request(agent));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(platform.credentials.count(), 0);
    }

    /// Without an issued challenge, unknown, suspended and non-attesting
    /// agents all produce the same refusal.
    #[test]
    fn without_a_challenge_every_agent_answers_alike() {
        let platform = Platform::new();
        let suspended = platform.agent(AgentStatus::Suspended, Some(spiffe_policy()));
        let enrolled_only = platform.agent(AgentStatus::Active, None);
        let invented = || AttestationNonce::new("attacker-chosen-nonce-padded-to-length").unwrap();
        let answer = |agent| {
            platform
                .bootstrap(
                    spiffe("spiffe://cluster/ns/sa"),
                    presenting(agent, invented()),
                )
                .err()
                .map(|error| error.to_string())
        };

        let unknown = answer(AgentId::new());

        assert!(unknown.is_some());
        assert_eq!(answer(suspended), unknown);
        assert_eq!(answer(enrolled_only), unknown);
    }
}
