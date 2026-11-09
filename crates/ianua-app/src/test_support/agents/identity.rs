//! Who an agent is, kept in memory: the agents, their credentials and the
//! public keys they enrol.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use ianua_domain::domains::agents::identity::agent::{
    AgentIdentity, AgentIdentityRow, AgentProof, Containment, OwnershipOffer, SuspendedBy,
};
use ianua_domain::domains::agents::identity::attestation::AttestedSubject;
use ianua_domain::domains::agents::identity::credential::{AgentCredential, CredentialOrigin};
use ianua_domain::domains::agents::identity::status::AgentStatus;
use ianua_domain::domains::crypto::jwk::JwkComponents;
use ianua_domain::domains::crypto::key_status::KeyStatus;
use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::test_support::builders::label;
use ianua_domain::types::{
    AgentCredentialId, AgentId, Human, HumanAccount, KeyId, PersonKey, PublicKeyPem, UserId,
};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::agents::{
    AgentCredentialStore, AgentSortField, AgentStore, AgentVersion, EnrolledKey,
};
use crate::ports::crypto::PublicKeyDecoder;
use crate::tenancy::ScopedTenant;
use crate::test_support::agents::shelf::Shelf;
use crate::test_support::listing::page;
use crate::test_support::{Fake, test_ctx};

/// The address of the person who owns every agent [`FakeAgentStore`] seeds.
const OWNER_ADDRESS: &str = "owner@example.test";

/// In-memory agent store: agents are kept per tenant, saved in place and
/// deleted for good.
#[derive(Default)]
pub struct FakeAgentStore {
    agents: Shelf<AgentIdentity<ResolvedTenant>>,
    fleet_stop_first: AtomicBool,
    unique_names: AtomicBool,
    identity_reads_fail: AtomicBool,
}

impl TenantScoped for FakeAgentStore {}

impl FakeAgentStore {
    /// Makes subsequent identity lookups fail, as an unreachable store does.
    pub fn fail_identity_reads(&self) {
        self.identity_reads_fail.store(true, Ordering::SeqCst);
    }

    /// Refuses identity reads once the fixture has made storage unavailable.
    fn ensure_identity_readable(&self) -> Result<(), DomainError> {
        if self.identity_reads_fail.load(Ordering::SeqCst) {
            return Err(DomainError::infra_msg("the agent store is unreachable"));
        }
        Ok(())
    }

    /// A store holding no agents.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding one active agent with `id` in the test tenant.
    #[must_use]
    pub fn with_active(id: AgentId) -> Self {
        let store = Self::empty();
        store.add_active(id);
        store
    }

    /// Adds an active agent with `id`, owned by a fresh person, to the test
    /// tenant.
    pub fn add_active(&self, id: AgentId) {
        self.add_with_status(id, AgentStatus::Active);
    }

    /// Adds an agent with `id` and `status`, owned by a fresh person, to the
    /// test tenant.
    pub fn add_with_status(&self, id: AgentId, status: AgentStatus) {
        let agent = stored_agent(id, status);
        self.agents
            .put(&test_ctx().tenant(), agent, |stored| stored.id() == &id);
    }

    /// Adds an active agent with `id`, owned by `owner`, to the test tenant.
    pub fn add_owned_by(&self, id: AgentId, owner: Human) {
        self.add_owned(id, owner, AgentStatus::Active);
    }

    /// Adds an agent with `id` and `status`, owned by `owner`, to the test
    /// tenant.
    pub fn add_owned(&self, id: AgentId, owner: Human, status: AgentStatus) {
        let agent = stored_agent_of(id, status, owner);
        self.agents
            .put(&test_ctx().tenant(), agent, |stored| stored.id() == &id);
    }

    /// How many agents are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.agents.count()
    }

    /// Makes a fleet stop land before every later save over a version, as
    /// when someone stops every agent between a change's read and its save.
    pub fn stops_the_fleet_before_each_save(&self) {
        self.fleet_stop_first.store(true, Ordering::SeqCst);
    }

    /// The agent with `id`, in whichever tenant it is kept.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NotFound`] when no agent has that id.
    pub fn find_by_id_direct(
        &self,
        id: &AgentId,
    ) -> Result<AgentIdentity<ResolvedTenant>, DomainError> {
        self.agents
            .all()
            .into_iter()
            .find(|agent| agent.id() == id)
            .ok_or(DomainError::NotFound)
    }

    /// Makes every later save refuse a name another agent of the tenant
    /// holds, as the real store's unique name does. It is off until asked
    /// for, as the agents this fake and the test rows seed share a name.
    pub fn keeps_names_unique(&self) {
        self.unique_names.store(true, Ordering::SeqCst);
    }

    /// Refuses to give `agent` a name another agent of `tenant` holds, once
    /// [`keeps_names_unique`](Self::keeps_names_unique) asked for it.
    fn ensure_name_free(
        &self,
        tenant: &ScopedTenant,
        agent: &AgentIdentity<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        if !self.unique_names.load(Ordering::SeqCst) {
            return Ok(());
        }
        let rival = self.agents.find(tenant, |stored| {
            stored.id() != agent.id() && stored.name() == agent.name()
        });
        if rival.is_none() {
            return Ok(());
        }
        Err(DomainError::conflict(
            "another agent of the tenant has the name",
        ))
    }
}

#[async_trait]
impl AgentStore for FakeAgentStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AgentId,
    ) -> Result<Option<AgentIdentity<ResolvedTenant>>, DomainError> {
        self.ensure_identity_readable()?;
        Ok(self.agents.find(tenant_id, |agent| agent.id() == id))
    }

    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[AgentId],
    ) -> Result<Vec<AgentIdentity<ResolvedTenant>>, DomainError> {
        self.ensure_identity_readable()?;
        Ok(self
            .agents
            .filter(tenant_id, |agent| ids.contains(agent.id())))
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<AgentSortField>,
        request: &PageRequest,
    ) -> Result<Page<AgentIdentity<ResolvedTenant>>, DomainError> {
        page(self.agents.filter(tenant_id, |_| true), sort, request)
    }

    async fn list_owned_by(
        &self,
        tenant_id: &ScopedTenant,
        owner: HumanAccount,
    ) -> Result<Vec<AgentIdentity<ResolvedTenant>>, DomainError> {
        Ok(self
            .agents
            .filter(tenant_id, |agent| agent.owner().account() == owner))
    }

    async fn list_offered_to(
        &self,
        tenant_id: &ScopedTenant,
        recipient: HumanAccount,
    ) -> Result<Vec<AgentIdentity<ResolvedTenant>>, DomainError> {
        Ok(self.agents.filter(tenant_id, |agent| match agent.offer() {
            OwnershipOffer::Open { recipient: to, .. } => to.account() == recipient,
            OwnershipOffer::Unoffered => false,
        }))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentIdentity<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.ensure_name_free(tenant_id, agent)?;
        self.agents
            .put(tenant_id, agent.clone(), |stored| stored.id() == agent.id());
        Ok(())
    }

    async fn save_unchanged_since(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentIdentity<ResolvedTenant>,
        read: AgentVersion,
    ) -> Result<AgentVersion, DomainError> {
        if self.fleet_stop_first.load(Ordering::SeqCst) {
            self.suspend_every_active(tenant_id).await?;
        }
        let stored = self
            .agents
            .find(tenant_id, |stored| stored.id() == agent.id());
        if stored.is_none_or(|stored| AgentVersion::of(&stored) != read) {
            return Err(DomainError::conflict(
                "the agent changed since it was read, or is gone",
            ));
        }
        self.ensure_name_free(tenant_id, agent)?;
        self.agents
            .put(tenant_id, agent.clone(), |stored| stored.id() == agent.id());
        Ok(AgentVersion::of(agent))
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &AgentId) -> Result<(), DomainError> {
        self.agents.remove(tenant_id, |agent| agent.id() == id);
        Ok(())
    }

    async fn suspend_every_active(&self, tenant_id: &ScopedTenant) -> Result<u64, DomainError> {
        let suspended = self
            .agents
            .revise(tenant_id, AgentIdentity::is_active, |agent| {
                let mut agent = agent.clone();
                agent.suspend(SuspendedBy::Monitor)?;
                Ok(agent)
            })?;
        Ok(u64::try_from(suspended.len()).unwrap_or(u64::MAX))
    }
}

/// In-memory credential store: credentials are kept per tenant and saved in
/// place.
#[derive(Default)]
pub struct FakeAgentCredentialStore {
    credentials: Shelf<AgentCredential<ResolvedTenant>>,
}

impl TenantScoped for FakeAgentCredentialStore {}

impl FakeAgentCredentialStore {
    /// A store holding no credentials.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many credentials are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.credentials.count()
    }

    /// Every credential kept, in every tenant, oldest first.
    #[must_use]
    pub fn all(&self) -> Vec<AgentCredential<ResolvedTenant>> {
        self.credentials.all()
    }

    /// The status of the credential with `id`, or `None` when none is kept.
    #[must_use]
    pub fn status_of(&self, id: &AgentCredentialId) -> Option<KeyStatus> {
        self.credentials
            .all()
            .into_iter()
            .find(|credential| credential.id() == id)
            .map(|credential| credential.status())
    }
}

#[async_trait]
impl AgentCredentialStore for FakeAgentCredentialStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AgentCredentialId,
    ) -> Result<Option<AgentCredential<ResolvedTenant>>, DomainError> {
        Ok(self
            .credentials
            .find(tenant_id, |credential| credential.id() == id))
    }

    async fn list_for_agent(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
    ) -> Result<Vec<AgentCredential<ResolvedTenant>>, DomainError> {
        Ok(self
            .credentials
            .filter(tenant_id, |credential| credential.agent_id() == agent))
    }

    async fn find_pinned_elsewhere(
        &self,
        tenant_id: &ScopedTenant,
        subject: &AttestedSubject,
        excluding: &AgentId,
    ) -> Result<Option<AgentCredential<ResolvedTenant>>, DomainError> {
        Ok(self.credentials.find(tenant_id, |credential| {
            credential.agent_id() != excluding && pinned_to(credential, subject)
        }))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        credential: &AgentCredential<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        if self.bound_elsewhere(tenant_id, credential) {
            return Err(DomainError::conflict(
                "the workload is already bound to another agent",
            ));
        }
        self.credentials
            .put(tenant_id, credential.clone(), |stored| {
                stored.id() == credential.id()
            });
        Ok(())
    }
}

impl FakeAgentCredentialStore {
    /// Whether the workload `credential` was issued to already keys another
    /// agent of `tenant`, as storage holds one workload to one agent.
    fn bound_elsewhere(
        &self,
        tenant: &ScopedTenant,
        credential: &AgentCredential<ResolvedTenant>,
    ) -> bool {
        let CredentialOrigin::Attested(attestation) = credential.origin() else {
            return false;
        };
        self.credentials
            .find(tenant, |stored| {
                stored.agent_id() != credential.agent_id()
                    && pinned_to(stored, attestation.subject())
            })
            .is_some()
    }
}

/// Key decoder that accepts only [`FakeKeyDecoder::VALID`], standing in for a
/// parser that refuses anything not a public key of its algorithm.
pub struct FakeKeyDecoder;

impl FakeKeyDecoder {
    /// The one public key this decoder accepts.
    pub const VALID: &'static str =
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n";
}

impl PublicKeyDecoder for FakeKeyDecoder {
    fn decode(
        &self,
        pem: &PublicKeyPem,
        kid: &KeyId,
        _algorithm: SigningAlgorithm,
    ) -> Result<JwkComponents, DomainError> {
        if pem.as_str() != Self::VALID {
            return Err(DomainError::infra_msg("not a public key"));
        }
        Ok(JwkComponents::Okp {
            kid: kid.as_str().to_owned(),
            crv: "Ed25519".to_owned(),
            x: "test".to_owned(),
        })
    }
}

/// The public key a test agent enrols: [`FakeKeyDecoder::VALID`], signing
/// with Ed25519.
///
/// # Panics
///
/// - Never: the key is a well-formed PEM public key.
#[must_use]
pub fn enrolled_key() -> EnrolledKey {
    EnrolledKey {
        algorithm: SigningAlgorithm::EdDsa,
        public_key: PublicKeyPem::new(FakeKeyDecoder::VALID).expect("the test key is a PEM key"),
    }
}

/// An agent with `id` and `status`, owned by a fresh person, as storage
/// would read one back.
fn stored_agent(id: AgentId, status: AgentStatus) -> AgentIdentity<ResolvedTenant> {
    let owner = Human::new(
        HumanAccount::User(UserId::new()),
        PersonKey::new(OWNER_ADDRESS).expect("the owner address is valid"),
    );
    stored_agent_of(id, status, owner)
}

/// An agent with `id` and `status`, owned by `owner`, as storage would read
/// one back.
fn stored_agent_of(
    id: AgentId,
    status: AgentStatus,
    owner: Human,
) -> AgentIdentity<ResolvedTenant> {
    let now = clock::now();
    AgentIdentity::reconstitute(AgentIdentityRow {
        id,
        name: label("fake-agent"),
        description: None,
        owner,
        offer: OwnershipOffer::Unoffered,
        status,
        proof: AgentProof::EnrolledKey,
        containment: Containment::Free,
        last_attested_at: None,
        created_at: now,
        updated_at: now,
    })
    .expect("an agent registered just now is a consistent row")
}

/// Whether `credential` was issued against an attestation of `subject`.
fn pinned_to(credential: &AgentCredential<ResolvedTenant>, subject: &AttestedSubject) -> bool {
    match credential.origin() {
        CredentialOrigin::Attested(attestation) => attestation.subject() == subject,
        CredentialOrigin::Enrolled => false,
    }
}

impl Fake for Arc<dyn AgentCredentialStore> {
    fn fake() -> Self {
        Arc::new(FakeAgentCredentialStore::empty())
    }
}

impl Fake for Arc<dyn AgentStore> {
    fn fake() -> Self {
        Arc::new(FakeAgentStore::empty())
    }
}
