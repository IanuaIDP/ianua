//! Rows of the agents context: who an agent is, its keys and challenges,
//! the delegations it acts under and asks for, task templates and
//! sightings.
//!
//! Delegations are dated from now, so a test can ask which are live; the
//! other rows are dated from the fixed moment every test row starts from.

pub mod run;

use std::sync::Arc;

use ianua_app::ports::agents::{AgentCredentialStore, AgentStore, DelegationStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::authority::capability::{
    ActionApproval, CapabilitySet, DelegationConstraints, Relation, ResourceCapability, ResourceRef,
};
use ianua_domain::domains::agents::authority::delegation::{
    Delegation, DelegationRenewal, DelegationRow, DelegationStatus, Lineage,
};
use ianua_domain::domains::agents::authority::delegation_request::{
    DelegationReason, DelegationRequestRow, RequestState,
};
use ianua_domain::domains::agents::authority::intent::{
    IntentDigest, IntentEnvelope, IntentStatement,
};
use ianua_domain::domains::agents::authority::task_template::{
    TaskTemplateRow, TemplateLimits, TemplateState,
};
use ianua_domain::domains::agents::identity::agent::{
    AgentIdentity, AgentIdentityRow, AgentProof, Containment, OFFER_LIFETIME, OwnershipOffer,
};
use ianua_domain::domains::agents::identity::attestation::{
    AttestationMethod, AttestationPolicy, AttestationRef, AttestedOrigin, AttestedSubject,
};
use ianua_domain::domains::agents::identity::challenge::{
    AttestationChallengeRow, AttestationNonce,
};
use ianua_domain::domains::agents::identity::credential::{
    AgentCredential, AgentCredentialRow, CredentialOrigin,
};
use ianua_domain::domains::agents::identity::sighting::{
    AgentSightingRow, SightingFingerprint, SightingSource, SightingState,
};
use ianua_domain::domains::agents::identity::status::AgentStatus;
use ianua_domain::domains::crypto::key_status::KeyState;
use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{
    ActionClass, AgentCredentialId, AgentId, AgentSightingId, DelegationId, DelegationRequestId,
    Human, HumanAccount, KeyId, Label, PersonKey, PrincipalRef, PublicKeyPem, Seconds,
    TaskTemplateId, UntrustedText, Usage, UserId,
};
use time::OffsetDateTime;

use crate::postgres::Databases;
use crate::postgres::agents::{PgAgentCredentialStore, PgAgentStore, PgDelegationStore};
use crate::test_support::rows::at;
use crate::test_support::rows::identity::from_now;

/// How long a delegation these rows make lives, in seconds.
const DELEGATION_LIFETIME: u32 = 600;

/// The public key every agent credential these rows make holds.
const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n";

/// The person `address` belongs to, acting through a fresh tenant account.
///
/// # Panics
///
/// When `address` is not a valid address, which is a mistake in the test.
#[must_use]
pub fn human(address: &str) -> Human {
    Human::new(
        HumanAccount::User(UserId::new()),
        PersonKey::new(address).expect("a valid address"),
    )
}

/// An active agent named `name`, owned by a fresh person, proving itself
/// with an enrolled key, registered at the fixed moment.
///
/// # Panics
///
/// When `name` is not a valid label, which is a mistake in the test.
#[must_use]
pub fn agent_row(name: &str) -> AgentIdentityRow {
    AgentIdentityRow {
        id: AgentId::new(),
        name: Label::new("name", name).expect("a valid name"),
        description: None,
        owner: human("owner@acme.example"),
        offer: OwnershipOffer::Unoffered,
        status: AgentStatus::Active,
        proof: AgentProof::EnrolledKey,
        containment: Containment::Free,
        last_attested_at: None,
        created_at: at(0),
        updated_at: at(0),
    }
}

/// The agent named `name`, proving where it runs by SPIFFE from Acme's
/// agents, re-attesting every hour.
///
/// # Panics
///
/// Never for the fixed policy it builds.
#[must_use]
pub fn attesting_agent_row(name: &str) -> AgentIdentityRow {
    let policy = AttestationPolicy::new(
        vec![AttestationMethod::Spiffe],
        Seconds::new(3600),
        vec![AttestedOrigin::new("spiffe://acme/agents").expect("a valid origin")],
    )
    .expect("a valid policy");
    AgentIdentityRow {
        proof: AgentProof::Attestation(policy),
        ..agent_row(name)
    }
}

/// `row`, offered at `at(1)` to `recipient` for the week an offer stands.
#[must_use]
pub fn offered_row(row: AgentIdentityRow, recipient: Human) -> AgentIdentityRow {
    AgentIdentityRow {
        offer: OwnershipOffer::Open {
            recipient,
            offered_at: at(1),
            expires_at: at(1).saturating_add(OFFER_LIFETIME),
        },
        ..row
    }
}

/// An active agent named `name`, saved in `tenant` through the agent
/// store, as the rows that name an agent point at one the tenant keeps.
///
/// # Panics
///
/// When the agent cannot be saved, which is a broken test database.
pub async fn saved_agent(databases: &Arc<Databases>, tenant: &ScopedTenant, name: &str) -> AgentId {
    let agent = AgentIdentity::reconstitute(agent_row(name)).expect("a valid agent");
    PgAgentStore::new(Arc::clone(databases))
        .save(tenant, &agent)
        .await
        .expect("the agent is saved");
    *agent.id()
}

/// A delegation from a person of `tenant` to `agent`, saved through its
/// store, for the rows that act under one.
///
/// # Panics
///
/// When the delegation cannot be saved, which is a broken test database.
pub async fn saved_delegation(
    databases: &Arc<Databases>,
    tenant: &ScopedTenant,
    agent: AgentId,
) -> DelegationId {
    let person = PrincipalRef::User(UserId::new());
    let delegation = Delegation::reconstitute(root_row(person, agent)).expect("a valid delegation");
    PgDelegationStore::new(Arc::clone(databases))
        .save(tenant, &delegation)
        .await
        .expect("the delegation is saved");
    *delegation.id()
}

/// The origin of a key issued against a SPIFFE attestation of `subject`.
///
/// # Panics
///
/// When `subject` is not a valid subject, which is a mistake in the test.
#[must_use]
pub fn attested(subject: &str) -> CredentialOrigin {
    CredentialOrigin::Attested(AttestationRef::new(
        AttestationMethod::Spiffe,
        AttestedSubject::new(subject).expect("a valid subject"),
    ))
}

/// An active Ed25519 key `kid` of `agent`, enrolled by hand at the fixed
/// moment and good for an hour.
///
/// # Panics
///
/// When `kid` is not a valid key id, which is a mistake in the test.
#[must_use]
pub fn credential_row(agent: AgentId, kid: &str) -> AgentCredentialRow {
    AgentCredentialRow {
        id: AgentCredentialId::new(),
        agent_id: agent,
        kid: KeyId::new(kid).expect("a valid key id"),
        algorithm: SigningAlgorithm::EdDsa,
        public_key: PublicKeyPem::new(PUBLIC_KEY).expect("a valid public key"),
        state: KeyState::Active,
        created_at: at(0),
        expires_at: at(3600),
        origin: CredentialOrigin::Enrolled,
        updated_at: at(0),
    }
}

/// An unspent challenge for `agent`, its nonce named after `label`,
/// issued ten seconds ago and good for five minutes more.
///
/// # Panics
///
/// When `label` makes a nonce no challenge may hold, which is a mistake in
/// the test.
#[must_use]
pub fn challenge_row(agent: AgentId, label: &str) -> AttestationChallengeRow {
    AttestationChallengeRow {
        nonce: AttestationNonce::new(format!("test-nonce-{label}-{}", "0".repeat(32)))
            .expect("a valid nonce"),
        agent_id: agent,
        issued_at: from_now(-10),
        expires_at: from_now(300),
        usage: Usage::Unused,
    }
}

/// The limits every delegation these rows make carries: ten minutes,
/// passed on at most two levels deep.
fn delegation_limits() -> DelegationConstraints {
    DelegationConstraints::new(Seconds::new(DELEGATION_LIFETIME), 2)
        .expect("ten minutes and depth two are within bounds")
}

/// A delegation as these rows date it: issued a minute ago and living its
/// whole lifetime, granting nothing, at the top of its chain.
fn delegation_row(delegator: PrincipalRef, delegate: AgentId) -> DelegationRow {
    let issued_at = from_now(-60);
    DelegationRow {
        id: DelegationId::new(),
        delegator,
        delegate,
        granted: CapabilitySet::empty(),
        constraints: delegation_limits(),
        lineage: Lineage::Root,
        depth: 0,
        status: DelegationStatus::Active,
        issued_at,
        expires_at: issued_at.saturating_add(Seconds::new(DELEGATION_LIFETIME).duration()),
        renewed: DelegationRenewal::NotRenewed,
        updated_at: issued_at,
        name: None,
    }
}

/// A root delegation the person `delegator` granted `delegate`.
#[must_use]
pub fn root_row(delegator: PrincipalRef, delegate: AgentId) -> DelegationRow {
    delegation_row(delegator, delegate)
}

/// The part of `parent` its agent passed on to `delegate`, one level
/// under it.
#[must_use]
pub fn child_row(parent: &Delegation<ResolvedTenant>, delegate: AgentId) -> DelegationRow {
    DelegationRow {
        lineage: Lineage::Under(*parent.id()),
        depth: parent.depth().saturating_add(1),
        ..delegation_row(PrincipalRef::Agent(*parent.delegate()), delegate)
    }
}

/// The delegation behind a task token `agent` minted from `from`, signed
/// in with its key `key`, all of it granted by whoever granted the first.
///
/// # Panics
///
/// When `from` is empty: a token is minted from at least one delegation.
#[must_use]
pub fn minted_row(
    agent: AgentId,
    key: AgentCredentialId,
    from: &[&Delegation<ResolvedTenant>],
) -> DelegationRow {
    let first = from
        .first()
        .expect("a token is minted from at least one delegation");
    DelegationRow {
        lineage: Lineage::Minted {
            from: from.iter().map(|source| *source.id()).collect(),
            delegator: *first.delegator(),
            signed_in_with: key,
        },
        ..delegation_row(PrincipalRef::Agent(agent), agent)
    }
}

/// The key `kid` of `agent`, as [`credential_row`] makes it, saved through
/// its store, for the task tokens minted with it.
///
/// # Panics
///
/// When the key cannot be saved, which is a broken test database.
pub async fn saved_credential(
    databases: &Arc<Databases>,
    tenant: &ScopedTenant,
    agent: AgentId,
    kid: &str,
) -> AgentCredential<ResolvedTenant> {
    let credential =
        AgentCredential::reconstitute(credential_row(agent, kid)).expect("a valid credential");
    PgAgentCredentialStore::new(Arc::clone(databases))
        .save(tenant, &credential)
        .await
        .expect("the credential is saved");
    credential
}

/// A pending request of `agent` asking `asked_of` for nothing but ten
/// minutes one level deep, made at the fixed moment and waiting an hour.
///
/// # Panics
///
/// Never for the fixed limits and reason it builds.
#[must_use]
pub fn request_row(agent: AgentId, asked_of: Human) -> DelegationRequestRow {
    DelegationRequestRow {
        id: DelegationRequestId::new(),
        agent_id: agent,
        asked_of,
        granted: CapabilitySet::empty(),
        constraints: DelegationConstraints::new(Seconds::new(DELEGATION_LIFETIME), 1)
            .expect("ten minutes and one level are within bounds"),
        reason: DelegationReason::new("I need to read the monthly reports")
            .expect("a valid reason"),
        state: RequestState::Pending,
        created_at: at(0),
        expires_at: at(3600),
        updated_at: at(0),
    }
}

/// A proposed template named `name`, which Ann proposed at `proposed_at`:
/// reading the Q1 calendar and nothing but reads, for ten minutes one
/// level deep, on internal data.
///
/// # Panics
///
/// When `name` is not a valid label, which is a mistake in the test.
#[must_use]
pub fn template_row(name: &str, proposed_at: OffsetDateTime) -> TaskTemplateRow {
    let reading = ResourceCapability::new(
        Relation::new("reader").expect("a valid relation"),
        ResourceRef::new("calendar:q1").expect("a valid resource"),
    );
    TaskTemplateRow {
        id: TaskTemplateId::new(),
        name: Label::new("name", name).expect("a valid name"),
        purpose: IntentStatement::new("Reconcile the ledger").expect("a valid purpose"),
        digest: IntentDigest::new([7; 32]),
        ceiling: CapabilitySet::empty().with_resources(vec![reading]),
        classes: IntentEnvelope::new([ActionClass::Read]),
        limits: TemplateLimits {
            max_ttl_seconds: Seconds::new(DELEGATION_LIFETIME),
            max_depth: 1,
            max_data_class: DataClassLevel::Internal,
            resource_scope: Restriction::Unrestricted,
            budget: Restriction::Unrestricted,
            approval: ActionApproval::NotRequired,
        },
        proposed_by: human("ann@acme.example"),
        proposed_at,
        state: TemplateState::Proposed,
    }
}

/// A first sighting of the OAuth client `fingerprint`, calling itself
/// `nightly-bot`, seen once at the fixed moment and not looked at yet.
///
/// # Panics
///
/// When `fingerprint` is not a valid fingerprint, which is a mistake in
/// the test.
#[must_use]
pub fn sighting_row(fingerprint: &str) -> AgentSightingRow {
    AgentSightingRow {
        id: AgentSightingId::new(),
        source: SightingSource::OAuthClient,
        fingerprint: SightingFingerprint::new(fingerprint).expect("a valid fingerprint"),
        calls_itself: UntrustedText::record("nightly-bot"),
        seen_count: 1,
        first_seen_at: at(0),
        last_seen_at: at(0),
        state: SightingState::Unreviewed,
        updated_at: at(0),
    }
}
