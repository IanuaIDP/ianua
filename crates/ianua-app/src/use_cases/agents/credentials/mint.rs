//! Mint credential: enrol a key an agent signs in with.
//!
//! The agent makes the key pair and offers the public half; the platform
//! never sees the private one. Only the agent's owner, or someone allowed
//! to update agents, may enrol one: a key gives everything the agent holds.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::agents::identity::credential::{
    AgentCredential, CredentialLifetimes, KeySource,
};
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentId, Setting};
use time::OffsetDateTime;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentCredentialStore, AgentStore, EnrolledKey};
use crate::ports::crypto::PublicKeyDecoder;
use crate::services::agents::standing::ensure_active;
use crate::use_case::Command;
use crate::use_cases::agents::credentials::key_enrolment::{Enrolment, enrol};
use crate::use_cases::agents::lookup::{AgentReach, owned_agent};

/// Request to mint a credential for an agent.
pub struct MintRequest {
    /// The agent the credential signs in.
    pub agent_id: AgentId,
    /// The public key the agent made for itself.
    pub key: EnrolledKey,
    /// When the credential expires, or `Unset` for the default lifetime.
    /// Never later than the longest a credential may live.
    pub expires_at: Setting<OffsetDateTime>,
}

/// The ports [`MintUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct MintPorts {
    /// Loads the agent the key is for.
    pub agent_store: Arc<dyn AgentStore>,
    /// Keeps credentials.
    pub credential_store: Arc<dyn AgentCredentialStore>,
    /// Checks the offered key is a public key of its algorithm.
    pub key_decoder: Arc<dyn PublicKeyDecoder>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Enrols a key for an agent.
pub struct MintUseCase {
    lifetimes: CredentialLifetimes,
    ports: MintPorts,
}

impl MintUseCase {
    /// A use case minting under `lifetimes`, working through `ports`.
    #[must_use]
    pub fn new(lifetimes: CredentialLifetimes, ports: MintPorts) -> Self {
        Self { lifetimes, ports }
    }
}

impl Command for MintUseCase {
    type Caller = CallerContext;
    type Input = MintRequest;
    type Output = Result<AgentCredential<ResolvedTenant>, AppError>;

    /// Enrols the agent's public key as a fresh active credential, saved and
    /// then recorded.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing agent or one the caller neither owns nor may update.
    /// - `AppError::Conflict` when the agent is inactive; `Forbidden` when it requires attestation instead of an enrolled key.
    /// - `AppError::Domain` for a key invalid for its algorithm or an expiry outside the future.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: MintRequest,
    ) -> Result<AgentCredential<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let store = self.ports.agent_store.as_ref();
        let reach = AgentReach::Acting(AgentAction::Update);
        let agent = owned_agent(store, &tenant, &req.agent_id, &control, reach).await?;
        ensure_active(&agent)?;
        let mut credential = enrol(
            self.ports.key_decoder.as_ref(),
            &Enrolment {
                agent: &agent,
                source: KeySource::Enrolled(control),
                key: &req.key,
                expires_at: req.expires_at,
                lifetimes: self.lifetimes,
            },
        )?;
        self.ports
            .credential_store
            .save(&tenant, &credential)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), credential.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(credential)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::agent::{
        AgentIdentity, AgentIdentityRow, AgentProof,
    };
    use ianua_domain::domains::agents::identity::attestation::{
        AttestationMethod, AttestationPolicy, AttestedOrigin,
    };
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{PublicKeyPem, Seconds};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentCredentialStore, FakeAgentStore, FakeKeyDecoder, agent_row, caller_person,
        enrolled_key, someone_else,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Bench {
        agents: Arc<FakeAgentStore>,
        credentials: Arc<FakeAgentCredentialStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Bench {
        fn with(row: AgentIdentityRow) -> Self {
            let agents = Arc::new(FakeAgentStore::empty());
            let agent = AgentIdentity::reconstitute(row).unwrap();
            block_on(agents.save(&test_ctx().tenant(), &agent)).unwrap();
            Self {
                agents,
                credentials: Arc::new(FakeAgentCredentialStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn mint(
            &self,
            people: FakeTenantAuthorities,
            req: MintRequest,
        ) -> Result<AgentCredential<ResolvedTenant>, AppError> {
            let use_case = MintUseCase::new(
                CredentialLifetimes::default(),
                MintPorts {
                    agent_store: self.agents.clone(),
                    credential_store: self.credentials.clone(),
                    key_decoder: Arc::new(FakeKeyDecoder),
                    tenant_authorities: Arc::new(people),
                },
            );
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), req))
        }
    }

    fn req(agent_id: AgentId) -> MintRequest {
        MintRequest {
            agent_id,
            key: enrolled_key(),
            expires_at: Setting::Unset,
        }
    }

    fn attesting(row: AgentIdentityRow) -> AgentIdentityRow {
        let policy = AttestationPolicy::new(
            vec![AttestationMethod::Spiffe],
            Seconds::new(3600),
            vec![AttestedOrigin::new("spiffe://cluster").unwrap()],
        )
        .unwrap();
        AgentIdentityRow {
            proof: AgentProof::Attestation(policy),
            ..row
        }
    }

    /// Ann enrols the key her agent made. It is active, kept, and recorded.
    #[test]
    fn the_owner_enrols_a_key_and_it_is_recorded() {
        let id = AgentId::new();
        let bench = Bench::with(agent_row(id, caller_person()));

        let credential = bench
            .mint(FakeTenantAuthorities::holding(&[]), req(id))
            .unwrap();

        assert!(credential.is_active());
        assert_eq!(credential.public_key().as_str(), FakeKeyDecoder::VALID);
        assert_eq!(bench.credentials.count(), 1);
        assert_eq!(
            bench.sink.records.lock().unwrap().as_slice(),
            ["agents.credential_minted"]
        );
    }

    /// Bob may update agents. He enrols a key for Ann's agent, and it is
    /// kept.
    #[test]
    fn someone_allowed_to_update_agents_enrols_a_key() {
        let id = AgentId::new();
        let bench = Bench::with(agent_row(id, someone_else()));

        let result = bench.mint(
            FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::Update)]),
            req(id),
        );

        assert!(result.is_ok());
        assert_eq!(bench.credentials.count(), 1);
    }

    /// A viewer cannot enroll a key for another person's agent; the agent
    /// appears missing and no credential or audit record is created.
    #[test]
    fn a_caller_who_neither_owns_nor_may_update_the_agent_is_refused() {
        let id = AgentId::new();
        let bench = Bench::with(agent_row(id, someone_else()));

        let result = bench.mint(
            FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)]),
            req(id),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(bench.credentials.count(), 0);
        assert!(bench.sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller cannot enroll a key, leaving the credential store empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let id = AgentId::new();
        let bench = Bench::with(agent_row(id, caller_person()));

        let result = bench.mint(FakeTenantAuthorities::refusing(Refusal::SignedOut), req(id));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(bench.credentials.count(), 0);
    }

    /// An agent requiring attestation refuses manually enrolled keys,
    /// even from a caller with every permission, and stores no credential.
    #[test]
    fn an_attesting_agent_takes_no_key_enrolled_by_hand() {
        let id = AgentId::new();
        let bench = Bench::with(attesting(agent_row(id, caller_person())));

        let result = bench.mint(FakeTenantAuthorities::holding_everything(), req(id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(bench.credentials.count(), 0);
    }

    /// Ann asks for a key on an agent the tenant does not have. It is not
    /// found.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let bench = Bench::with(agent_row(AgentId::new(), caller_person()));

        let result = bench.mint(FakeTenantAuthorities::holding(&[]), req(AgentId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A suspended agent refuses key enrollment and gains no credential.
    #[test]
    fn a_suspended_agent_gets_no_key() {
        let id = AgentId::new();
        let bench = Bench::with(AgentIdentityRow {
            status: AgentStatus::Suspended,
            ..agent_row(id, caller_person())
        });

        let result = bench.mint(FakeTenantAuthorities::holding(&[]), req(id));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(bench.credentials.count(), 0);
    }

    /// Ann hands in something that is not a public key. It is refused
    /// rather than stored as a key nothing can verify against.
    #[test]
    fn a_key_that_is_not_a_public_key_is_refused() {
        let id = AgentId::new();
        let bench = Bench::with(agent_row(id, caller_person()));
        let mut request = req(id);
        request.key.public_key =
            PublicKeyPem::new("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")
                .unwrap();

        let result = bench.mint(FakeTenantAuthorities::holding(&[]), request);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(bench.credentials.count(), 0);
    }

    /// Ann asks for a key that lives ten years. It is enrolled, but ends at
    /// the longest a credential may live.
    #[test]
    fn a_credential_asked_to_outlive_the_cap_ends_at_the_cap() {
        let id = AgentId::new();
        let bench = Bench::with(agent_row(id, caller_person()));
        let longest = CredentialLifetimes::default().max_lifetime();

        let credential = bench
            .mint(
                FakeTenantAuthorities::holding(&[]),
                MintRequest {
                    expires_at: Setting::Set(clock::now() + time::Duration::days(3650)),
                    ..req(id)
                },
            )
            .unwrap();

        assert!(credential.expires_at() <= clock::now() + longest);
    }
}
