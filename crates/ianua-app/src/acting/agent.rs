//! An agent signing in as itself, with an assertion its own key signed.
//!
//! This is the resolver behind [`AgentActors`] in production.
//!
//! Every call an agent makes in its own name starts here: minting a task
//! token, passing part of a delegation on, giving a review verdict. The
//! agent's id alone proves nothing, since anyone can read it from a log.
//! The assertion's key must be one of the agent's credentials, the
//! assertion must verify against it for this tenant's token endpoint, and
//! it is spent on first use. Only then does the credential sign the agent
//! in, as the domain's [`ActingAgent`].

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::agents::identity::acting::ActingAgent;
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::credential::AgentCredential;
use ianua_domain::domains::agents::identity::token_attack::{
    AssertionFault, SignInRefusal, TokenAttack,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{ActingFor, ActorRef, Audience};

use crate::acting::AgentActors;
use crate::context::AgentAssertion;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{
    AgentAssertionReplayGuard, AgentAssertionVerifier, AgentCredentialStore, AgentStore,
    AssertionCheck, AssertionVerification, VerifiedAssertion,
};
use crate::services::lookup::existing_agent;
use crate::tenancy::ScopedTenant;

/// The stores and checks [`AgentActing`] reads an agent's sign-in from.
#[derive(Clone, ianua_macros::Fakes)]
pub struct AgentActingPorts {
    /// Loads the agent's current status and attestation policy.
    pub agent_store: Arc<dyn AgentStore>,
    /// The keys agents enrolled.
    pub credential_store: Arc<dyn AgentCredentialStore>,
    /// Checks an assertion's signature and claims.
    pub verifier: Arc<dyn AgentAssertionVerifier>,
    /// Spends each assertion once.
    pub replay_guard: Arc<dyn AgentAssertionReplayGuard>,
}

/// Signs agents in from the stored records for the assertion they present.
pub struct AgentActing {
    ports: AgentActingPorts,
}

impl AgentActing {
    /// A resolver reading from `ports`.
    #[must_use]
    pub fn new(ports: AgentActingPorts) -> Self {
        Self { ports }
    }
}

#[async_trait]
impl AgentActors for AgentActing {
    async fn attempted(
        &self,
        tenant: &ScopedTenant,
        presented: &AgentAssertion,
        audience: &Audience,
    ) -> Result<SignInAttempt, AppError> {
        attempt(&self.ports, tenant, presented, audience).await
    }
}

/// What an agent's attempt to sign in as itself came to.
pub enum SignInAttempt {
    /// It signed in. Boxed: the signed-in agent carries its whole identity
    /// and proof, many times the size of a refusal.
    SignedIn(Box<SignedInAgent>),
    /// It was refused.
    Refused(RefusedSignIn),
}

/// An agent's sign-in that was refused: why, and the agent it was made as
/// when the tenant has one.
pub struct RefusedSignIn {
    /// The agent the attempt named, when the tenant has it.
    pub agent: Option<Box<AgentIdentity<ResolvedTenant>>>,
    /// Why it was refused.
    pub refusal: SignInRefusal,
}

impl RefusedSignIn {
    /// The agent attacked and the kind of attack, when the refusal looks
    /// like one and names an agent the tenant has.
    #[must_use]
    pub fn attack(&self) -> Option<(&AgentIdentity<ResolvedTenant>, TokenAttack)> {
        let attack = self.refusal.attack()?;
        self.agent.as_deref().map(|agent| (agent, attack))
    }

    /// The refusal as the caller is answered: forbidden, saying no more
    /// than which step refused, never which agents exist.
    #[must_use]
    pub fn forbidden(&self) -> AppError {
        AppError::Forbidden(reason(self.refusal).to_owned().into())
    }
}

/// An agent signed in as itself, with its stored record.
pub struct SignedInAgent {
    /// The agent as stored.
    pub agent: AgentIdentity<ResolvedTenant>,
    /// The proof that it signed in just now.
    pub acting: ActingAgent,
}

impl SignedInAgent {
    /// The agent acting in its own name, as the record names it.
    #[must_use]
    pub fn actor(&self) -> ActorRef {
        ActorRef::Agent {
            id: *self.agent.id(),
            on_behalf_of: ActingFor::Itself,
        }
    }
}

/// Why one step of a sign-in did not go through: the agent was refused,
/// or nothing could be checked.
enum Stopped {
    /// Refused, for this reason.
    Refused(SignInRefusal),
    /// A store or the key could not be read.
    Failed(AppError),
}

impl From<AppError> for Stopped {
    fn from(error: AppError) -> Self {
        Self::Failed(error)
    }
}

/// The attempt of the agent `presented` names to sign in by an assertion
/// its own key signed for `audience`, spent here so it signs in once.
///
/// # Errors
///
/// - `AppError::Internal` on storage failure, or when the agent's key
///   cannot be read. Every refusal is an answer, never an error.
async fn attempt(
    ports: &AgentActingPorts,
    tenant: &ScopedTenant,
    presented: &AgentAssertion,
    audience: &Audience,
) -> Result<SignInAttempt, AppError> {
    let agent = match existing_agent(ports.agent_store.as_ref(), tenant, &presented.agent_id).await
    {
        Ok(agent) => agent,
        Err(AppError::NotFound(_)) => return Ok(refused(None, SignInRefusal::UnknownAgent)),
        Err(failed) => return Err(failed),
    };
    let signing = Signing {
        ports,
        tenant,
        presented,
        agent: &agent,
    };
    match signing.proven(audience).await {
        Ok(acting) => Ok(SignInAttempt::SignedIn(Box::new(SignedInAgent {
            agent,
            acting,
        }))),
        Err(Stopped::Refused(refusal)) => Ok(refused(Some(agent), refusal)),
        Err(Stopped::Failed(failed)) => Err(failed),
    }
}

/// One sign-in under way: the stores and checks, the tenant, what was
/// presented and the agent it names.
#[derive(Clone, Copy)]
struct Signing<'a> {
    ports: &'a AgentActingPorts,
    tenant: &'a ScopedTenant,
    presented: &'a AgentAssertion,
    agent: &'a AgentIdentity<ResolvedTenant>,
}

impl Signing<'_> {
    /// The proof the agent signed in, once its key signed the assertion
    /// for `audience`, the key signs it in now, and the assertion is spent.
    async fn proven(self, audience: &Audience) -> Result<ActingAgent, Stopped> {
        let credential = self.signing_credential().await?;
        let verified = self.verified_assertion(&credential, audience).await?;
        let acting = credential
            .signed_in(self.agent, verified.issued_at)
            .map_err(|_| Stopped::Refused(SignInRefusal::KeyNotUsable))?;
        self.ensure_first_use(&verified).await?;
        Ok(acting)
    }

    /// Refuses an assertion already spent, and spends it otherwise.
    async fn ensure_first_use(self, verified: &VerifiedAssertion) -> Result<(), Stopped> {
        let first_use = self
            .ports
            .replay_guard
            .consume(
                self.tenant,
                &verified.agent_id,
                &verified.jti,
                verified.expires_at,
            )
            .await
            .or_internal()?;
        if first_use {
            return Ok(());
        }
        Err(Stopped::Refused(SignInRefusal::Replayed))
    }

    /// The agent's credential the assertion's key id names, once the agent
    /// admits keys of its kind.
    async fn signing_credential(self) -> Result<AgentCredential<ResolvedTenant>, Stopped> {
        let kid = self
            .ports
            .verifier
            .key_id(&self.presented.assertion)
            .map_err(|_| Stopped::Refused(SignInRefusal::NoKeyId))?;
        let credential = self
            .ports
            .credential_store
            .list_for_agent(self.tenant, self.agent.id())
            .await
            .or_internal()?
            .into_iter()
            .find(|credential| credential.kid() == &kid)
            .ok_or(Stopped::Refused(SignInRefusal::UnknownKey))?;
        if self.agent.admits_credential(credential.origin()) {
            return Ok(credential);
        }
        Err(Stopped::Refused(SignInRefusal::KeyNotAdmitted))
    }

    /// The assertion, verified against `credential` for `audience` and
    /// naming the agent it was presented for.
    async fn verified_assertion(
        self,
        credential: &AgentCredential<ResolvedTenant>,
        audience: &Audience,
    ) -> Result<VerifiedAssertion, Stopped> {
        let check = self
            .ports
            .verifier
            .verify(
                &self.presented.assertion,
                &AssertionVerification {
                    public_key: credential.public_key(),
                    algorithm: credential.algorithm(),
                    expected_issuer: &self.presented.agent_id,
                    expected_audience: audience,
                },
            )
            .await
            .or_internal()?;
        let verified = match check {
            AssertionCheck::Verified(verified) => verified,
            AssertionCheck::Refused(fault) => {
                return Err(Stopped::Refused(SignInRefusal::Assertion(fault)));
            }
        };
        if verified.agent_id == self.presented.agent_id {
            return Ok(verified);
        }
        Err(Stopped::Refused(SignInRefusal::Assertion(
            AssertionFault::WrongAgent,
        )))
    }
}

/// The refusal of a sign-in as `agent`, when the tenant has it, for
/// `refusal`.
fn refused(agent: Option<AgentIdentity<ResolvedTenant>>, refusal: SignInRefusal) -> SignInAttempt {
    SignInAttempt::Refused(RefusedSignIn {
        agent: agent.map(Box::new),
        refusal,
    })
}

/// What a caller is told of `refusal`. An agent that is not there reads
/// like any refusal, so the answer says nothing about which agents exist.
fn reason(refusal: SignInRefusal) -> &'static str {
    match refusal {
        SignInRefusal::UnknownAgent => "unknown agent",
        SignInRefusal::NoKeyId => "assertion has no usable key id",
        SignInRefusal::UnknownKey => "no credential for assertion",
        SignInRefusal::KeyNotAdmitted => {
            "this agent proves itself by attestation; a key never attested cannot sign it in"
        }
        SignInRefusal::KeyNotUsable => "this credential does not sign this agent in now",
        SignInRefusal::Assertion(AssertionFault::WrongAgent) => "assertion subject mismatch",
        SignInRefusal::Assertion(_) => "agent assertion rejected",
        SignInRefusal::Replayed => "assertion has already been used",
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::agent::{AgentIdentityRow, AgentProof};
    use ianua_domain::domains::agents::identity::attestation::{
        AttestationMethod, AttestationPolicy, AttestedOrigin,
    };
    use ianua_domain::domains::agents::identity::credential::AgentCredentialRow;
    use ianua_domain::domains::crypto::key_status::{KeyState, PriorRotation};
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{AgentId, HumanAccount, Seconds};

    use super::*;
    use crate::listing::{Page, PageRequest, SortOrder};
    use crate::ports::TenantScoped;
    use crate::ports::agents::{AgentSortField, AgentVersion};
    use crate::test_support::agents::{
        FakeAgentCredentialStore, FakeAgentStore, FakeAssertionVerifier, ReplayedGuard, agent_row,
        caller_person, key_row, signing_in,
    };
    use crate::test_support::{block_on, test_ctx};

    const AUDIENCE: &str = "https://ianua.test/oauth/token";

    /// An agent store whose database cannot be reached.
    struct UnreachableAgents;

    impl TenantScoped for UnreachableAgents {}

    #[async_trait]
    impl AgentStore for UnreachableAgents {
        async fn find_by_ids(
            &self,
            _: &ScopedTenant,
            _: &[AgentId],
        ) -> Result<Vec<AgentIdentity<ResolvedTenant>>, DomainError> {
            Err(DomainError::infra_msg("the agent store is unreachable"))
        }

        async fn find_by_id(
            &self,
            _: &ScopedTenant,
            _: &AgentId,
        ) -> Result<Option<AgentIdentity<ResolvedTenant>>, DomainError> {
            Err(DomainError::infra_msg("the agent store is unreachable"))
        }

        async fn list_all(
            &self,
            _: &ScopedTenant,
            _: &SortOrder<AgentSortField>,
            _: &PageRequest,
        ) -> Result<Page<AgentIdentity<ResolvedTenant>>, DomainError> {
            Err(DomainError::infra_msg("the agent store is unreachable"))
        }

        async fn list_owned_by(
            &self,
            _: &ScopedTenant,
            _: HumanAccount,
        ) -> Result<Vec<AgentIdentity<ResolvedTenant>>, DomainError> {
            Err(DomainError::infra_msg("the agent store is unreachable"))
        }

        async fn list_offered_to(
            &self,
            _: &ScopedTenant,
            _: HumanAccount,
        ) -> Result<Vec<AgentIdentity<ResolvedTenant>>, DomainError> {
            Err(DomainError::infra_msg("the agent store is unreachable"))
        }

        async fn save(
            &self,
            _: &ScopedTenant,
            _: &AgentIdentity<ResolvedTenant>,
        ) -> Result<(), DomainError> {
            Err(DomainError::infra_msg("the agent store is unreachable"))
        }

        async fn save_unchanged_since(
            &self,
            _: &ScopedTenant,
            _: &AgentIdentity<ResolvedTenant>,
            _: AgentVersion,
        ) -> Result<AgentVersion, DomainError> {
            Err(DomainError::infra_msg("the agent store is unreachable"))
        }

        async fn delete(&self, _: &ScopedTenant, _: &AgentId) -> Result<(), DomainError> {
            Err(DomainError::infra_msg("the agent store is unreachable"))
        }

        async fn suspend_every_active(&self, _: &ScopedTenant) -> Result<u64, DomainError> {
            Err(DomainError::infra_msg("the agent store is unreachable"))
        }
    }

    fn stored(row: AgentIdentityRow) -> (Arc<FakeAgentStore>, AgentId) {
        let agents = Arc::new(FakeAgentStore::empty());
        let id = row.id;
        block_on(agents.save(
            &test_ctx().tenant(),
            &AgentIdentity::reconstitute(row).unwrap(),
        ))
        .unwrap();
        (agents, id)
    }

    fn ann_s_agent() -> (Arc<FakeAgentStore>, AgentId) {
        stored(agent_row(AgentId::new(), caller_person()))
    }

    fn sign_in(
        ports: &AgentActingPorts,
        presented: &AgentAssertion,
    ) -> Result<SignedInAgent, AppError> {
        block_on(AgentActing::new(ports.clone()).signed_in(
            &test_ctx().tenant(),
            presented,
            &Audience::new(AUDIENCE).unwrap(),
        ))
    }

    /// Why signing in as `presented` through `ports` was refused, and
    /// whether it named an agent the tenant has.
    fn refusal(ports: &AgentActingPorts, presented: &AgentAssertion) -> (SignInRefusal, bool) {
        let attempt = block_on(attempt(
            ports,
            &test_ctx().tenant(),
            presented,
            &Audience::new(AUDIENCE).unwrap(),
        ))
        .unwrap();
        let SignInAttempt::Refused(refused) = attempt else {
            panic!("the sign-in went through");
        };
        (refused.refusal, refused.agent.is_some())
    }

    /// Bad signatures, replay and subject mismatches retain distinct
    /// refusal reasons and the known agent's record for downstream handling.
    #[test]
    fn a_refusal_says_what_it_was_and_names_the_agent() {
        let (agents, agent) = ann_s_agent();
        let (ports, presented) = signing_in(agents, agent);
        let forged = AgentActingPorts {
            verifier: Arc::new(FakeAssertionVerifier::rejecting("agent-key")),
            ..ports.clone()
        };
        let replayed = AgentActingPorts {
            replay_guard: Arc::new(ReplayedGuard),
            ..ports.clone()
        };
        let misattributed = AgentActingPorts {
            verifier: Arc::new(FakeAssertionVerifier::accepting(
                "agent-key",
                AgentId::new(),
            )),
            ..ports
        };

        assert_eq!(
            refusal(&forged, &presented),
            (SignInRefusal::Assertion(AssertionFault::BadSignature), true)
        );
        assert_eq!(
            refusal(&replayed, &presented),
            (SignInRefusal::Replayed, true)
        );
        assert_eq!(
            refusal(&misattributed, &presented),
            (SignInRefusal::Assertion(AssertionFault::WrongAgent), true)
        );
    }

    /// Mallory names an agent the tenant does not have. The refusal names
    /// no agent, so there is nobody to warn about.
    #[test]
    fn a_refusal_for_an_unknown_agent_names_none() {
        let (agents, agent) = ann_s_agent();
        let (ports, _) = signing_in(agents, agent);

        let refused = refusal(&ports, &sign_in_for(AgentId::new()));

        assert_eq!(refused, (SignInRefusal::UnknownAgent, false));
    }

    /// Ann's agent signs an assertion with its own key. It is signed in as
    /// itself.
    #[test]
    fn an_agent_signs_in_with_its_own_key() {
        let (agents, agent) = ann_s_agent();
        let (ports, presented) = signing_in(agents, agent);

        let signed = sign_in(&ports, &presented).unwrap();

        assert_eq!(signed.acting.agent(), &agent);
        assert_eq!(signed.agent.id(), &agent);
    }

    /// The agent store cannot be reached when Ann's agent signs in. That is
    /// a failure on our side, answered as one, not a refusal of the agent.
    #[test]
    fn an_agent_store_that_cannot_be_read_fails_as_an_error() {
        let (agents, agent) = ann_s_agent();
        let (ports, presented) = signing_in(agents, agent);
        let ports = AgentActingPorts {
            agent_store: Arc::new(UnreachableAgents),
            ..ports
        };

        let result = sign_in(&ports, &presented);

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// Presenting an assertion for an unknown agent returns forbidden.
    #[test]
    fn an_unknown_agent_is_refused() {
        let (agents, agent) = ann_s_agent();
        let (ports, _) = signing_in(agents, agent);
        let presented = AgentAssertion {
            agent_id: AgentId::new(),
            assertion: "signed.assertion".to_owned(),
        };

        let result = sign_in(&ports, &presented);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An assertion naming a key absent from the agent's credentials is
    /// forbidden, even when the verifier would accept its signature.
    #[test]
    fn a_key_id_the_agent_does_not_hold_is_refused() {
        let (agents, agent) = ann_s_agent();
        let (ports, presented) = signing_in(agents, agent);
        let ports = AgentActingPorts {
            verifier: Arc::new(FakeAssertionVerifier::accepting("mallory-key", agent)),
            ..ports
        };

        let result = sign_in(&ports, &presented);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// The verifier's rejection of an assertion becomes a forbidden
    /// sign-in result.
    #[test]
    fn a_rejected_assertion_is_refused() {
        let (agents, agent) = ann_s_agent();
        let (ports, presented) = signing_in(agents, agent);
        let ports = AgentActingPorts {
            verifier: Arc::new(FakeAssertionVerifier::rejecting("agent-key")),
            ..ports
        };

        let result = sign_in(&ports, &presented);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A verified assertion identifying another agent is forbidden for
    /// the agent named by the request.
    #[test]
    fn an_assertion_about_another_agent_is_refused() {
        let (agents, agent) = ann_s_agent();
        let (ports, presented) = signing_in(agents, agent);
        let ports = AgentActingPorts {
            verifier: Arc::new(FakeAssertionVerifier::accepting(
                "agent-key",
                AgentId::new(),
            )),
            ..ports
        };

        let result = sign_in(&ports, &presented);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A replay guard reporting an already-consumed assertion prevents
    /// agent sign-in with a forbidden result.
    #[test]
    fn a_replayed_assertion_is_refused() {
        let (agents, agent) = ann_s_agent();
        let (ports, presented) = signing_in(agents, agent);
        let ports = AgentActingPorts {
            replay_guard: Arc::new(ReplayedGuard),
            ..ports
        };

        let result = sign_in(&ports, &presented);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A stored credential marked revoked cannot sign its agent in,
    /// despite an accepting assertion verifier.
    #[test]
    fn a_revoked_key_is_refused() {
        let (agents, agent) = ann_s_agent();
        let credentials = FakeAgentCredentialStore::empty();
        let key = AgentCredential::reconstitute(AgentCredentialRow {
            state: KeyState::Revoked {
                before: PriorRotation::NotRotated,
            },
            ..key_row(agent, "agent-key")
        })
        .unwrap();
        block_on(credentials.save(&test_ctx().tenant(), &key)).unwrap();
        let (ports, presented) = signing_in(agents, agent);
        let ports = AgentActingPorts {
            credential_store: Arc::new(credentials),
            ..ports
        };

        let result = sign_in(&ports, &presented);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann's agent's key was rotated out five seconds ago. An assertion it
    /// signed ten seconds ago, before the rotation, still signs the agent
    /// in, so a call in flight across a rotation is not cut off.
    #[test]
    fn an_assertion_signed_before_a_rotation_still_signs_in() {
        let (agents, agent) = ann_s_agent();
        let ports = rotated_out_seconds_ago(agents, agent, 5, 10);

        let signed = sign_in(&ports, &sign_in_for(agent));

        assert_eq!(signed.unwrap().acting.agent(), &agent);
    }

    /// An assertion issued after its key was rotated out is forbidden,
    /// even while the stored credential has not expired.
    #[test]
    fn an_assertion_signed_after_a_rotation_is_refused() {
        let (agents, agent) = ann_s_agent();
        let ports = rotated_out_seconds_ago(agents, agent, 5, 0);

        let result = sign_in(&ports, &sign_in_for(agent));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Sign-in ports whose only key for `agent` was rotated out `rotated`
    /// seconds ago, verifying assertions signed `signed` seconds ago.
    fn rotated_out_seconds_ago(
        agents: Arc<FakeAgentStore>,
        agent: AgentId,
        rotated: i64,
        signed: i64,
    ) -> AgentActingPorts {
        let credentials = FakeAgentCredentialStore::empty();
        let minted = clock::now() - time::Duration::hours(1);
        let rotated_at = clock::now() - time::Duration::seconds(rotated);
        let key = AgentCredential::reconstitute(AgentCredentialRow {
            state: KeyState::Rotated { at: rotated_at },
            created_at: minted,
            updated_at: rotated_at,
            expires_at: rotated_at + time::Duration::minutes(1),
            ..key_row(agent, "agent-key")
        })
        .unwrap();
        block_on(credentials.save(&test_ctx().tenant(), &key)).unwrap();
        let (ports, _) = signing_in(agents, agent);
        AgentActingPorts {
            credential_store: Arc::new(credentials),
            verifier: Arc::new(
                FakeAssertionVerifier::accepting("agent-key", agent)
                    .signed_ago(time::Duration::seconds(signed)),
            ),
            ..ports
        }
    }

    fn sign_in_for(agent: AgentId) -> AgentAssertion {
        AgentAssertion {
            agent_id: agent,
            assertion: "signed.assertion".to_owned(),
        }
    }

    /// An agent requiring SPIFFE attestation cannot sign in through a
    /// manually enrolled key; that credential origin is forbidden.
    #[test]
    fn an_attesting_agent_is_not_signed_in_by_an_enrolled_key() {
        let policy = AttestationPolicy::new(
            vec![AttestationMethod::Spiffe],
            Seconds::new(3600),
            vec![AttestedOrigin::new("spiffe://cluster").unwrap()],
        )
        .unwrap();
        let row = agent_row(AgentId::new(), caller_person());
        let (agents, agent) = stored(AgentIdentityRow {
            proof: AgentProof::Attestation(policy),
            last_attested_at: Some(row.created_at),
            ..row
        });
        let credentials = FakeAgentCredentialStore::empty();
        let key = AgentCredential::reconstitute(key_row(agent, "agent-key")).unwrap();
        block_on(credentials.save(&test_ctx().tenant(), &key)).unwrap();
        let (ports, presented) = signing_in(agents, agent);
        let ports = AgentActingPorts {
            credential_store: Arc::new(credentials),
            ..ports
        };

        let result = sign_in(&ports, &presented);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
