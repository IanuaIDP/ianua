//! Rotate credential: retire a key and enrol its replacement.
//!
//! The old credential moves to `Rotated`: it signs nothing new and still
//! verifies older assertions for a short grace. The new public key the agent
//! made is enrolled as its replacement, with the same expiry.
//!
//! Only keys enrolled by hand rotate this way. An agent that proves itself
//! by attesting takes no key by hand; it bootstraps again instead.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::agents::identity::credential::{
    AgentCredential, CredentialLifetimes, KeySource,
};
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentCredentialId, AgentId, Setting};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentCredentialStore, AgentStore, EnrolledKey};
use crate::ports::crypto::PublicKeyDecoder;
use crate::services::agents::standing::ensure_active;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::credentials::key_enrolment::{Enrolment, enrol};
use crate::use_cases::agents::lookup::{AgentReach, owned_agent, owned_credential};

/// Request to rotate a credential.
pub struct RotateRequest {
    /// The agent the credential must belong to.
    pub agent_id: AgentId,
    /// The credential to retire.
    pub credential_id: AgentCredentialId,
    /// The replacement public key the agent made for itself.
    pub key: EnrolledKey,
}

/// The ports [`RotateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RotatePorts {
    /// Loads the agent the credential signs in.
    pub agent_store: Arc<dyn AgentStore>,
    /// Loads and keeps credentials.
    pub credential_store: Arc<dyn AgentCredentialStore>,
    /// Checks the replacement is a public key of its algorithm.
    pub key_decoder: Arc<dyn PublicKeyDecoder>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Rotates an agent's key.
pub struct RotateUseCase {
    lifetimes: CredentialLifetimes,
    ports: RotatePorts,
}

impl RotateUseCase {
    /// A use case minting and retiring under `lifetimes`, working through
    /// `ports`.
    #[must_use]
    pub fn new(lifetimes: CredentialLifetimes, ports: RotatePorts) -> Self {
        Self { lifetimes, ports }
    }

    /// The credential for `key`, vouched for by the person rotating, ending
    /// when the one it replaces would have.
    fn replacement(
        &self,
        control: &AgentControl<'_>,
        agent: &AgentIdentity<ResolvedTenant>,
        retiring: &AgentCredential<ResolvedTenant>,
        key: &EnrolledKey,
    ) -> Result<AgentCredential<ResolvedTenant>, AppError> {
        enrol(
            self.ports.key_decoder.as_ref(),
            &Enrolment {
                agent,
                source: KeySource::Enrolled(*control),
                key,
                expires_at: Setting::Set(retiring.expires_at()),
                lifetimes: self.lifetimes,
            },
        )
    }
}

impl Command for RotateUseCase {
    type Caller = CallerContext;
    type Input = RotateRequest;
    type Output = Result<AgentCredential<ResolvedTenant>, AppError>;

    /// Rotates a credential, returning the replacement enrolled from the
    /// agent's new public key.
    ///
    /// The new key is checked before the old one is retired, so a refused
    /// key leaves the agent with the credential it had. The replacement is
    /// saved before the old key is retired, so a failure part way leaves the
    /// agent with a working key.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing/inaccessible agent or missing/foreign credential.
    /// - `AppError::Conflict` when the agent is inactive; `Forbidden` when it authenticates by attestation.
    /// - `AppError::Domain` for a key invalid for its algorithm or an already rotated/revoked credential.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: RotateRequest,
    ) -> Result<AgentCredential<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let store = self.ports.agent_store.as_ref();
        let reach = AgentReach::Acting(AgentAction::Update);
        let agent = owned_agent(store, &tenant, &req.agent_id, &control, reach).await?;
        let mut retiring = owned_credential(
            self.ports.credential_store.as_ref(),
            &tenant,
            &req.agent_id,
            &req.credential_id,
        )
        .await?;
        ensure_active(&agent)?;
        let mut replacement = self.replacement(&control, &agent, &retiring, &req.key)?;
        retiring
            .rotate(&control, &agent, self.lifetimes)
            .map_err(AppError::from_domain)?;
        let events = saved_rotation(&self.ports, &tenant, &mut replacement, &mut retiring).await?;
        auditor
            .dispatch_by(&ctx.actor(), events)
            .await
            .or_internal()?;
        Ok(replacement)
    }
}

/// Saves the replacement before the retired credential, so a failure part
/// way leaves the agent with a working key, and returns what the two
/// raised: the old key retired, then its replacement.
async fn saved_rotation(
    ports: &RotatePorts,
    tenant: &ScopedTenant,
    replacement: &mut AgentCredential<ResolvedTenant>,
    retiring: &mut AgentCredential<ResolvedTenant>,
) -> Result<Vec<DomainEvent>, AppError> {
    ports
        .credential_store
        .save(tenant, replacement)
        .await
        .or_internal()?;
    ports
        .credential_store
        .save(tenant, retiring)
        .await
        .or_internal()?;
    let mut events = retiring.take_events(tenant);
    events.extend(replacement.take_events(tenant));
    Ok(events)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::agent::{AgentIdentityRow, AgentProof};
    use ianua_domain::domains::agents::identity::attestation::{
        AttestationMethod, AttestationPolicy, AttestationRef, AttestedOrigin, AttestedSubject,
    };
    use ianua_domain::domains::agents::identity::credential::{
        AgentCredentialRow, CredentialOrigin,
    };
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::crypto::key_status::KeyStatus;
    use ianua_domain::types::{Human, PublicKeyPem, Seconds};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentCredentialStore, FakeAgentStore, FakeKeyDecoder, agent_row, caller_person,
        enrolled_key, key_row, someone_else,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Bench {
        agent: AgentId,
        old: AgentCredentialId,
        agents: Arc<FakeAgentStore>,
        credentials: Arc<FakeAgentCredentialStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Bench {
        fn with(agent: AgentIdentityRow, key: AgentCredentialRow) -> Self {
            let tenant = test_ctx().tenant();
            let agents = Arc::new(FakeAgentStore::empty());
            let id = agent.id;
            block_on(agents.save(&tenant, &AgentIdentity::reconstitute(agent).unwrap())).unwrap();
            let credentials = Arc::new(FakeAgentCredentialStore::empty());
            let credential = AgentCredential::reconstitute(key).unwrap();
            block_on(credentials.save(&tenant, &credential)).unwrap();
            Self {
                agent: id,
                old: *credential.id(),
                agents,
                credentials,
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn owned_by(owner: Human) -> Self {
            let id = AgentId::new();
            Self::with(agent_row(id, owner), key_row(id, "kid-old"))
        }

        fn rotate(
            &self,
            people: FakeTenantAuthorities,
            key: EnrolledKey,
        ) -> Result<AgentCredential<ResolvedTenant>, AppError> {
            let use_case = RotateUseCase::new(
                CredentialLifetimes::default(),
                RotatePorts {
                    agent_store: self.agents.clone(),
                    credential_store: self.credentials.clone(),
                    key_decoder: Arc::new(FakeKeyDecoder),
                    tenant_authorities: Arc::new(people),
                },
            );
            block_on(use_case.execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                RotateRequest {
                    agent_id: self.agent,
                    credential_id: self.old,
                    key,
                },
            ))
        }

        fn old_status(&self) -> KeyStatus {
            self.credentials.status_of(&self.old).unwrap()
        }
    }

    fn not_a_key() -> EnrolledKey {
        EnrolledKey {
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
            )
            .unwrap(),
            ..enrolled_key()
        }
    }

    /// Ann rotates her agent's key. The old key is rotated, the new one is
    /// active, and both moves are recorded under the agent's name.
    #[test]
    fn the_owner_rotates_a_key_and_it_is_recorded() {
        let bench = Bench::owned_by(caller_person());

        let replacement = bench
            .rotate(FakeTenantAuthorities::holding(&[]), enrolled_key())
            .unwrap();

        assert!(replacement.is_active());
        assert_ne!(*replacement.id(), bench.old);
        assert_eq!(bench.credentials.count(), 2);
        assert_eq!(bench.old_status(), KeyStatus::Rotated);
        assert_eq!(
            bench.sink.records.lock().unwrap().as_slice(),
            ["agents.credential_rotated", "agents.credential_minted"]
        );
        assert_eq!(
            bench.sink.label_of("agents.credential_rotated", "agent"),
            Some("ledger-bot".to_owned())
        );
    }

    /// Bob may update agents and rotates the key of Ann's agent. It goes
    /// through.
    #[test]
    fn someone_allowed_to_update_agents_rotates_a_key() {
        let bench = Bench::owned_by(someone_else());

        let result = bench.rotate(
            FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::Update)]),
            enrolled_key(),
        );

        assert!(result.is_ok());
        assert_eq!(bench.old_status(), KeyStatus::Rotated);
    }

    /// A viewer cannot rotate another person's agent key; the agent appears
    /// missing and its sole credential remains active.
    #[test]
    fn a_caller_who_neither_owns_nor_may_update_the_agent_is_refused() {
        let bench = Bench::owned_by(someone_else());

        let result = bench.rotate(
            FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)]),
            enrolled_key(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(bench.old_status(), KeyStatus::Active);
        assert_eq!(bench.credentials.count(), 1);
    }

    /// A signed-out caller cannot rotate the key, leaving it active.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let bench = Bench::owned_by(caller_person());

        let result = bench.rotate(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            enrolled_key(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(bench.old_status(), KeyStatus::Active);
    }

    /// Ann hands in a replacement that is not a public key. It is refused,
    /// and the agent keeps the key it had.
    #[test]
    fn a_refused_replacement_leaves_the_old_credential_active() {
        let bench = Bench::owned_by(caller_person());

        let result = bench.rotate(FakeTenantAuthorities::holding(&[]), not_a_key());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(bench.old_status(), KeyStatus::Active);
        assert_eq!(bench.credentials.count(), 1);
    }

    /// Manually rotating an attested agent's key is forbidden, leaving
    /// the attested credential active.
    #[test]
    fn an_attesting_agents_key_is_not_rotated_by_hand() {
        let id = AgentId::new();
        let policy = AttestationPolicy::new(
            vec![AttestationMethod::Spiffe],
            Seconds::new(3600),
            vec![AttestedOrigin::new("spiffe://cluster").unwrap()],
        )
        .unwrap();
        let attested = AttestationRef::new(
            AttestationMethod::Spiffe,
            AttestedSubject::new("spiffe://cluster/runner").unwrap(),
        );
        let row = agent_row(id, caller_person());
        let bench = Bench::with(
            AgentIdentityRow {
                proof: AgentProof::Attestation(policy),
                last_attested_at: Some(row.created_at),
                ..row
            },
            AgentCredentialRow {
                origin: CredentialOrigin::Attested(attested),
                ..key_row(id, "kid-attested")
            },
        );

        let result = bench.rotate(FakeTenantAuthorities::holding_everything(), enrolled_key());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(bench.old_status(), KeyStatus::Active);
    }

    /// A rotation naming an unknown parent agent is refused as missing;
    /// the existing agent's key remains active.
    #[test]
    fn a_key_of_another_agent_is_not_found() {
        let bench = Bench::owned_by(caller_person());
        let use_case = RotateUseCase::new(
            CredentialLifetimes::default(),
            RotatePorts {
                agent_store: bench.agents.clone(),
                credential_store: bench.credentials.clone(),
                ..RotatePorts::fakes()
            },
        );

        let result = block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(bench.sink.clone()),
            RotateRequest {
                agent_id: AgentId::new(),
                credential_id: bench.old,
                key: enrolled_key(),
            },
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(bench.old_status(), KeyStatus::Active);
    }

    /// Ann rotates a key the tenant does not have. It is not found.
    #[test]
    fn an_unknown_credential_is_not_found() {
        let use_case = RotateUseCase::new(CredentialLifetimes::default(), RotatePorts::fakes());

        let result = block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            RotateRequest {
                agent_id: AgentId::new(),
                credential_id: AgentCredentialId::new(),
                key: enrolled_key(),
            },
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
