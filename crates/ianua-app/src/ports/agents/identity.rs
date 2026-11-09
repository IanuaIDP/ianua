//! Who an agent is: the agent, its credentials and attestation, the
//! assertions it signs, and the delegations it acts under.

use std::collections::HashMap;

use async_trait::async_trait;
use ianua_domain::domains::agents::authority::capability::{Relation, ResourceRef};
use ianua_domain::domains::agents::authority::delegation::Delegation;
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::attestation::{
    AttestationMethod, AttestedIdentity, AttestedSubject,
};
use ianua_domain::domains::agents::identity::challenge::{AttestationChallenge, AttestationNonce};
use ianua_domain::domains::agents::identity::credential::AgentCredential;
use ianua_domain::domains::agents::identity::status::AgentStatus;
use ianua_domain::domains::agents::identity::token_attack::AssertionFault;
use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{
    AgentCredentialId, AgentId, Audience, DelegationId, HumanAccount, KeyId, PrincipalRef,
    PublicKeyPem, TokenId,
};
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// The public half of a key pair an agent made for itself, offered for
/// enrolment as one of its credentials.
///
/// The private half stays with the agent. The platform never generates an
/// agent's key, so it never holds, stores or returns anything that could sign
/// as the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledKey {
    /// The algorithm the key signs with.
    pub algorithm: SigningAlgorithm,
    /// The PEM-encoded public key.
    pub public_key: PublicKeyPem,
}

/// One delegation torn down by [`DelegationStore::revoke_subtree`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokedDelegation {
    /// The delegation that was revoked.
    pub id: DelegationId,
    /// The agent that held it, and whose authority therefore changed.
    pub delegate: AgentId,
}

/// An agent holding rights on one object through a live delegation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceHolder {
    /// The identity receiving the delegated rights.
    pub agent: AgentId,
    /// The relation it holds on the object.
    pub relation: Relation,
}

define_sort_field! {
    /// Field an agent listing can be ordered by.
    pub enum AgentSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by last update time.
        UpdatedAt => "updated_at",
        /// Order by display name.
        Name => "name",
        /// Order by status.
        Status => "status",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<AgentSortField> for AgentIdentity<ResolvedTenant> {
    fn sort_key(&self, field: AgentSortField) -> SortKey {
        match field {
            AgentSortField::CreatedAt => self.created_at().into(),
            AgentSortField::UpdatedAt => self.updated_at().into(),
            AgentSortField::Name => self.name().as_str().into(),
            AgentSortField::Status => agent_status_word(self.status()).into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// The word an agent's status sorts by, as it is stored.
fn agent_status_word(status: AgentStatus) -> &'static str {
    match status {
        AgentStatus::Active => "active",
        AgentStatus::Suspended => "suspended",
        AgentStatus::Revoked => "revoked",
    }
}

/// The version of an agent as it was read: the time it last changed.
///
/// An agent is changed by people and by the platform at once: a fleet stop
/// or a monitor suspends it while someone edits it, and a bootstrap records
/// a fresh attestation while a person contains it. A change saved over a
/// version that moved on would undo the other's: an edit read before the
/// stop would save the agent `active` again. So every change to a stored
/// agent goes through [`AgentStore::save_unchanged_since`] with the version
/// it read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentVersion(OffsetDateTime);

impl AgentVersion {
    /// The version `agent` is at. Only an agent read back from the store,
    /// or the version a save gave back, names a version the store can
    /// compare: an agent changed in memory carries a time the store has not
    /// kept.
    #[must_use]
    pub fn of(agent: &AgentIdentity<ResolvedTenant>) -> Self {
        Self(agent.updated_at())
    }

    /// The version a store kept an agent at: `changed_at`, the time the
    /// agent last changed as the store wrote it.
    #[must_use]
    pub fn stored(changed_at: OffsetDateTime) -> Self {
        Self(changed_at)
    }

    /// The time the agent last changed at this version.
    #[must_use]
    pub fn changed_at(self) -> OffsetDateTime {
        self.0
    }
}

/// Dyn-safe port for persisting and retrieving agent identities.
#[async_trait]
pub trait AgentStore: Send + Sync + TenantScoped {
    /// Finds an agent by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AgentId,
    ) -> Result<Option<AgentIdentity<ResolvedTenant>>, DomainError>;

    /// Finds the requested agents within the tenant, once each, in no order.
    /// Missing ids are omitted.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[AgentId],
    ) -> Result<Vec<AgentIdentity<ResolvedTenant>>, DomainError>;

    /// Lists agents for a tenant with ordering and pagination.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<AgentSortField>,
        page: &PageRequest,
    ) -> Result<Page<AgentIdentity<ResolvedTenant>>, DomainError>;

    /// Every agent of the tenant `owner` owns, through that one account.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_owned_by(
        &self,
        tenant_id: &ScopedTenant,
        owner: HumanAccount,
    ) -> Result<Vec<AgentIdentity<ResolvedTenant>>, DomainError>;

    /// Every agent of the tenant offered to `recipient`, through that one
    /// account, open or lapsed. The caller reads whether each offer still
    /// stands.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_offered_to(
        &self,
        tenant_id: &ScopedTenant,
        recipient: HumanAccount,
    ) -> Result<Vec<AgentIdentity<ResolvedTenant>>, DomainError>;

    /// Saves a new agent. A change to a stored one goes through
    /// [`save_unchanged_since`](Self::save_unchanged_since), so it cannot
    /// undo a change made since it was read.
    ///
    /// # Errors
    ///
    /// - `DomainError::Conflict` when another agent of the tenant has the
    ///   name.
    /// - `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentIdentity<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Saves `agent` only when the stored agent is still at `read`, the
    /// version the caller read before changing it, and gives back the
    /// version it is stored at now.
    ///
    /// The check and the write are one statement, and every write moves
    /// the version on, so of two changes read from one version only the
    /// first is kept. The agent must already be stored.
    ///
    /// # Errors
    ///
    /// - `DomainError::Conflict` when the stored agent changed since `read`,
    ///   or is gone, or another agent of the tenant has the name.
    /// - `DomainError::Infrastructure` on persistence failure.
    async fn save_unchanged_since(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentIdentity<ResolvedTenant>,
        read: AgentVersion,
    ) -> Result<AgentVersion, DomainError>;

    /// Deletes an agent.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(&self, tenant_id: &ScopedTenant, id: &AgentId) -> Result<(), DomainError>;

    /// Suspends every active agent of the tenant in one statement, and
    /// returns how many it suspended. Agents already suspended or revoked
    /// are left alone and not counted, so repeating the call stops none.
    ///
    /// This is the one agent write that does not go through the aggregate.
    /// Suspending is a single status move from active with nothing else to
    /// keep, and loading and saving each agent in turn is what made the
    /// tenant-wide stop slow, and partial on failure, exactly when it has
    /// to be quick and whole. The statement runs in the request's unit of
    /// work, so it stops every agent or none.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn suspend_every_active(&self, tenant_id: &ScopedTenant) -> Result<u64, DomainError>;
}

/// Dyn-safe port for persisting and walking the delegation graph.
#[async_trait]
pub trait DelegationStore: Send + Sync + TenantScoped {
    /// Finds a delegation by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &DelegationId,
    ) -> Result<Option<Delegation<ResolvedTenant>>, DomainError>;

    /// Finds the requested delegations within the tenant, once each, in no
    /// order. Missing ids are omitted.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[DelegationId],
    ) -> Result<Vec<Delegation<ResolvedTenant>>, DomainError>;

    /// Lists the delegations held by an agent.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_for_agent(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
    ) -> Result<Vec<Delegation<ResolvedTenant>>, DomainError>;

    /// Lists the delegations directly granted by `delegator`.
    ///
    /// Used to cascade a principal's own status change (e.g. a user being
    /// deactivated) to authority they handed out. An attenuated child
    /// delegation's own `delegator` is the parent's delegate agent, not
    /// the original grantor, so for a person this only ever returns
    /// root-level grants. For an agent it returns the children it passed
    /// on and the task tokens it minted, which is how a new child's budget
    /// is held beside its siblings'.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_delegator(
        &self,
        tenant_id: &ScopedTenant,
        delegator: &PrincipalRef,
    ) -> Result<Vec<Delegation<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated delegation.
    ///
    /// A delegation already revoked stays revoked, whatever the saved copy
    /// says: revocation never goes backwards, so a copy read before a
    /// [`revoke_subtree`](Self::revoke_subtree) and saved after it does not
    /// make the delegation grant again.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        delegation: &Delegation<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Records that `delegation_id` derived its authority from `sources`.
    ///
    /// The token exchange mints a self-rooted delegation, which has no parent
    /// to cascade from; without this, revoking the grant that authorized it
    /// would leave the derived token live. Idempotent.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn record_provenance(
        &self,
        tenant_id: &ScopedTenant,
        delegation_id: &DelegationId,
        sources: &[DelegationId],
    ) -> Result<(), DomainError>;

    /// Every agent holding rights on `resource` through a delegation that is
    /// neither revoked nor expired.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn resource_holders(
        &self,
        tenant_id: &ScopedTenant,
        resource: &ResourceRef,
    ) -> Result<Vec<ResourceHolder>, DomainError>;

    /// Revokes `root` and everything descended from it, in one statement.
    ///
    /// Returns only what this call actually changed: a delegation already
    /// revoked is left alone and not reported, so repeating the call is a
    /// no-op and the result is a true record of the tear-down.
    ///
    /// This is the one delegation write that does not go through the
    /// aggregate. Revocation is a monotonic flag with no invariant beyond
    /// never going backwards, and loading, mutating, and saving each node in
    /// turn is what made containment slowest on the widest graphs, the exact
    /// case where the kill-switch has to be quick.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn revoke_subtree(
        &self,
        tenant_id: &ScopedTenant,
        root: &DelegationId,
    ) -> Result<Vec<RevokedDelegation>, DomainError>;

    /// Every delegation that loses its authority when `root` is revoked.
    ///
    /// Follows parent, minted-source and recorded provenance edges
    /// transitively, including authority a token exchange derived. Revoking a
    /// grant has to reach the tokens minted from it, or the revoke is
    /// cosmetic. The root itself is not included.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_revocation_closure(
        &self,
        tenant_id: &ScopedTenant,
        root: &DelegationId,
    ) -> Result<Vec<DelegationId>, DomainError>;

    /// Walks the revocation graph for all roots in one read, keeping each
    /// root's descendants separate. Parent, minted-source and recorded
    /// provenance edges all participate; cycles terminate and each root
    /// excludes only itself. Descendant order is unspecified.
    ///
    /// Roots without descendants may be absent from the map.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_revocation_closures(
        &self,
        tenant_id: &ScopedTenant,
        roots: &[DelegationId],
    ) -> Result<HashMap<DelegationId, Vec<DelegationId>>, DomainError>;
}

/// Dyn-safe port for persisting and retrieving agents' durable identity
/// credentials (per-agent signing keys used for self-authentication).
#[async_trait]
pub trait AgentCredentialStore: Send + Sync + TenantScoped {
    /// Finds a credential by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AgentCredentialId,
    ) -> Result<Option<AgentCredential<ResolvedTenant>>, DomainError>;

    /// Lists the credentials held by an agent (active and rotated).
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_for_agent(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
    ) -> Result<Vec<AgentCredential<ResolvedTenant>>, DomainError>;

    /// A credential already pinned to `subject`, belonging to an agent other
    /// than `excluding`.
    ///
    /// Bootstrap uses this to refuse one workload identity claiming more than
    /// one agent within a tenant: a subject that already authenticates a
    /// different agent must not also mint a credential for this one.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_pinned_elsewhere(
        &self,
        tenant_id: &ScopedTenant,
        subject: &AttestedSubject,
        excluding: &AgentId,
    ) -> Result<Option<AgentCredential<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated credential.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        credential: &AgentCredential<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}

/// What an agent's self-signed assertion is verified against.
///
/// The algorithm and public key come from the agent's stored credential. The
/// JWT header is never trusted to choose them: the algorithm is pinned and
/// `alg:none` is refused.
pub struct AssertionVerification<'a> {
    /// PEM public key of the credential that should have signed the assertion.
    pub public_key: &'a PublicKeyPem,
    /// The pinned signing algorithm (from the credential, not the JWT header).
    pub algorithm: SigningAlgorithm,
    /// The issuer the assertion must declare (`iss`): the agent's own id.
    pub expected_issuer: &'a AgentId,
    /// The audience the assertion must target (`aud`): the token endpoint.
    pub expected_audience: &'a Audience,
}

/// Dyn-safe port for verifying an agent's self-signed authentication assertion.
///
/// Backs the client-credentials token exchange: an autonomous agent proves
/// possession of its private key by signing a short-lived assertion, which the
/// platform verifies against the stored public key before minting a task token.
#[async_trait]
pub trait AgentAssertionVerifier: Send + Sync {
    /// Reads the assertion's (unverified) `kid` header to locate the signing
    /// credential. Signature is not checked here, only the header is parsed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when the assertion is malformed or
    /// carries no `kid`.
    fn key_id(&self, assertion: &str) -> Result<KeyId, DomainError>;

    /// Checks the assertion's signature and registered claims: the
    /// authenticated agent plus the single-use identity of the assertion,
    /// or why it does not check out, so a forgery is told apart from the
    /// agent's own slip.
    ///
    /// Pins `algorithm` (never trusts the JWT header), rejects `alg:none`, and
    /// checks `iss`, `aud`, `exp`, `nbf`, and `iat` skew.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the stored key cannot be
    /// read, so nothing could be checked.
    async fn verify(
        &self,
        assertion: &str,
        against: &AssertionVerification<'_>,
    ) -> Result<AssertionCheck, DomainError>;
}

/// What checking an agent's assertion came to.
pub enum AssertionCheck {
    /// It checks out.
    Verified(VerifiedAssertion),
    /// It does not, for this reason.
    Refused(AssertionFault),
}

/// A verified agent assertion.
pub struct VerifiedAssertion {
    /// The authenticated agent (`sub`).
    pub agent_id: AgentId,
    /// The assertion's unique id (`jti`), spent once.
    pub jti: TokenId,
    /// When the agent's key signed it (`iat`). A key rotated out still
    /// signs the agent in for what it signed before the rotation.
    pub issued_at: OffsetDateTime,
    /// When the assertion stops being valid (`exp`): how long its ledger entry
    /// must outlive it.
    pub expires_at: OffsetDateTime,
}

/// A platform attestation an agent presents to prove what it is (secret-zero).
///
/// The `material` is the method-specific payload (a SPIFFE SVID, a signed AWS
/// `sts:GetCallerIdentity` request, a GCP identity JWT, a TPM quote); the
/// composite attestor routes it to the per-platform adapter by `method`.
///
/// The `proof` is what makes presenting the material mean anything. An SVID is
/// a public certificate, so material alone proves possession of nothing.
/// See [`AttestationProof`].
pub struct AttestationPresentation {
    /// The attestation mechanism the material belongs to.
    pub method: AttestationMethod,
    /// The opaque, method-specific attestation payload.
    pub material: String,
    /// Proof that the caller holds the attested identity's private key.
    pub proof: AttestationProof,
}

/// The server-issued nonce a presentation answers, binding it to this
/// bootstrap and to the key it enrols.
///
/// The material does not carry the nonce itself. It carries the binding:
///
/// ```text
/// binding = SHA-256("ianua-attestation-binding-v1" || 0x00
///                   || nonce as UTF-8 || 0x00
///                   || DER of the enrolled key's SubjectPublicKeyInfo)
/// ```
///
/// written as 64 lower-case hex characters where text is needed. So a proof
/// made for one key is refused for any other: whoever sees a token or a
/// quote before it is used cannot enrol a key of their own with it. The
/// platform chose the nonce, was its only issuer and spends it on use, so
/// a captured proof cannot be presented twice either.
///
/// Where the binding goes depends on the method:
///
/// - **SPIFFE.** `signature` is the SVID key's signature over the ASCII
///   bytes `ianua-attestation-proof-v1:` followed by the binding in hex.
/// - **TPM.** The quote's qualifying data is the binding's 32 raw bytes.
/// - **Google Cloud.** The identity token's audience is the binding in hex.
/// - **AWS.** The `sts:GetCallerIdentity` request carries the binding in
///   hex in the signed header `x-ianua-attestation-binding`, so AWS
///   checked it under the role's signature.
pub struct AttestationProof {
    /// The challenge the platform issued for this bootstrap.
    pub nonce: AttestationNonce,
    /// For SPIFFE, the base64url (unpadded) signature described above; empty
    /// for the other methods.
    ///
    /// Encoded the way the attested identity's key type signs natively: DER for
    /// ECDSA and RSA (what `openssl dgst -sign` emits), raw 64 bytes for
    /// Ed25519. The scheme is taken from the presented key, never from here.
    pub signature: String,
}

/// Dyn-safe port for minting unpredictable attestation nonces.
///
/// Behind a port because the nonce's whole value is that it comes from a
/// cryptographically secure source the caller cannot anticipate.
#[async_trait]
pub trait AttestationNonceGenerator: Send + Sync {
    /// Generates a fresh, unpredictable nonce.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the randomness source fails.
    async fn generate(&self) -> Result<AttestationNonce, DomainError>;
}

/// Dyn-safe port for storing single-use attestation challenges.
#[async_trait]
pub trait AttestationChallengeStore: Send + Sync + TenantScoped {
    /// Records an issued challenge. A nonce already recorded keeps the
    /// challenge it holds, so issuing it again never makes a spent one
    /// whole.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn issue(
        &self,
        tenant_id: &ScopedTenant,
        challenge: &AttestationChallenge<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Spends the challenge `nonce` holds for `agent_id`, returning it.
    ///
    /// Must be atomic: a challenge that can be consumed twice is one an
    /// attacker can replay. Returns `None` when no such challenge exists for
    /// this agent, it was already spent, or it has expired. All of these deny.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn consume(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
        nonce: &AttestationNonce,
    ) -> Result<Option<AttestationChallenge<ResolvedTenant>>, DomainError>;
}

/// Dyn-safe port recording which agent assertions have already been spent.
///
/// A verified signature proves the agent produced the assertion, not that it
/// produced it *now*. So without a single-use ledger one captured assertion
/// mints tokens until its own expiry.
#[async_trait]
pub trait AgentAssertionReplayGuard: Send + Sync + TenantScoped {
    /// Records `jti` as spent, returning `false` if it already was.
    ///
    /// Must be atomic: two concurrent exchanges presenting the same assertion
    /// must not both be told they are the first.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn consume(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
        jti: &TokenId,
        expires_at: OffsetDateTime,
    ) -> Result<bool, DomainError>;
}

/// Dyn-safe port for verifying a platform attestation.
///
/// Per-platform adapters (SPIFFE/SPIRE, AWS IAM, GCP, TPM) verify the
/// presentation and return the identity it proves, before it is bound to an
/// agent and exchanged for a short-lived credential.
#[async_trait]
pub trait AgentAttestor: Send + Sync {
    /// Verifies a platform attestation made for enrolling `key`, returning
    /// the identity it proves.
    ///
    /// The presentation must carry the binding of its nonce and `key`, as
    /// [`AttestationProof`] describes. One made for another key is refused.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Unauthorized` when the attestation cannot be
    /// verified, is expired, is bound to another nonce or key, or is signed by
    /// an untrusted platform authority. Any other error is a refusal too.
    async fn verify(
        &self,
        presentation: &AttestationPresentation,
        key: &EnrolledKey,
    ) -> Result<AttestedIdentity, DomainError>;
}
