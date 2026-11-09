//! An agent's own key, which it uses to sign in as itself.
//!
//! An agent can sign in as itself, not only through a delegation a person
//! gave it. Its credential is a key pair, using the same
//! [`SigningAlgorithm`] and [`KeyStatus`] as signing keys. The agent keeps the
//! private key and signs an assertion about itself. The platform checks it
//! against the stored public key. It then issues a task token for the agent's
//! own authority, with `on_behalf_of` empty.
//!
//! A key gives everything the agent holds. So a person enrols one only for
//! an agent they own, or when they may update agents. The agent itself gets
//! one only against an attestation its policy trusts.
//!
//! A credential moves like a signing key. `Active` can become `Rotated`: a
//! new credential takes over, and this one still verifies for a short grace.
//! `Active` or `Rotated` can become `Revoked`, which is final. An agent may
//! hold several credentials: one active, others rotated.
//!
//! **The platform never holds the private key.** The agent makes its own key
//! pair and enrols only the public key. So the private key never crosses the
//! network, and only the agent can sign a valid assertion. A leaked database
//! or a captured response cannot be used to pose as the agent. This type
//! holds no secret, so deriving `Debug` is safe.

mod lifetimes;

use std::marker::PhantomData;

pub use lifetimes::CredentialLifetimes;
use lifetimes::{MAX_CLOCK_SKEW, MAX_IN_FLIGHT};
use time::OffsetDateTime;

use crate::domains::agents::events::credentials::{
    AgentBootstrapped, AgentCredentialMinted, AgentCredentialRevoked, AgentCredentialRotated,
};
use crate::domains::agents::identity::acting::ActingAgent;
use crate::domains::agents::identity::agent::AgentIdentity;
use crate::domains::agents::identity::attestation::{AttestationRef, AttestedIdentity};
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::authorization::permission::AgentAction;
use crate::domains::crypto::key_status::{KeyState, KeyStatus};
use crate::domains::crypto::signing_key::SigningAlgorithm;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::types::{AgentCredentialId, AgentId, EventLabel, KeyId, PublicKeyPem, Setting};

/// How an agent credential came to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialOrigin {
    /// A key enrolled for the agent by hand.
    Enrolled,
    /// Issued against this attestation of where the agent runs.
    Attested(AttestationRef),
}

/// Who vouches for a new key.
#[derive(Debug, Clone, Copy)]
pub enum KeySource<'a> {
    /// A person enrols it by hand. They must own the agent or be allowed to
    /// update agents.
    Enrolled(AgentControl<'a>),
    /// The agent gets it against this verified attestation. The agent's
    /// policy must trust it.
    Attested(&'a AttestedIdentity),
}

/// What a new agent credential is made from.
pub struct MintAgentCredentialParams<'a, T: TenantScope> {
    /// The agent this credential authenticates.
    pub agent: &'a AgentIdentity<T>,
    /// Who vouches for the key.
    pub source: KeySource<'a>,
    /// The key id. It is also the JWT `kid` in the agent's assertions.
    pub kid: KeyId,
    /// The signing algorithm.
    pub algorithm: SigningAlgorithm,
    /// PEM-encoded public key, used to verify the agent's assertions.
    pub public_key: PublicKeyPem,
    /// When the credential expires.
    ///
    /// Unset means the default lifetime from now. Either way it is capped at
    /// the longest lifetime in [`CredentialLifetimes`]. A key that never
    /// expires lets whoever copies it sign assertions forever.
    pub expires_at: Setting<OffsetDateTime>,
}

/// Persisted state for reconstitution.
pub struct AgentCredentialRow {
    /// Unique identifier.
    pub id: AgentCredentialId,
    /// The agent this credential authenticates.
    pub agent_id: AgentId,
    /// The key id.
    pub kid: KeyId,
    /// The signing algorithm.
    pub algorithm: SigningAlgorithm,
    /// PEM-encoded public key.
    pub public_key: PublicKeyPem,
    /// Where the credential stands. See [`KeyState::from_stored`].
    pub state: KeyState,
    /// When it was minted.
    pub created_at: OffsetDateTime,
    /// When it expires. Every credential does.
    pub expires_at: OffsetDateTime,
    /// How the credential came to be.
    pub origin: CredentialOrigin,
    /// When it was last modified.
    pub updated_at: OffsetDateTime,
}

/// The time a rotated credential still verifies.
///
/// It ends at the credential's expiry, which may come before `rotated_at`
/// plus the grace. A credential rotated after its own expiry gets no time
/// at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationGrace {
    rotated_at: OffsetDateTime,
    ends_at: OffsetDateTime,
}

impl RotationGrace {
    /// When rotation retired the credential.
    #[must_use]
    pub fn rotated_at(self) -> OffsetDateTime {
        self.rotated_at
    }

    /// When the credential stops verifying.
    #[must_use]
    pub fn ends_at(self) -> OffsetDateTime {
        self.ends_at
    }

    /// The length in whole seconds. It is zero for a credential rotated after
    /// its own expiry.
    #[must_use]
    pub fn seconds(self) -> u32 {
        u32::try_from(crate::shared::clock::between(self.rotated_at, self.ends_at).whole_seconds())
            .unwrap_or(0)
    }
}

/// One key an agent signs in with, and where it stands.
#[derive(Debug, Clone)]
pub struct AgentCredential<T: TenantScope> {
    id: AgentCredentialId,
    agent_id: AgentId,
    kid: KeyId,
    algorithm: SigningAlgorithm,
    public_key: PublicKeyPem,
    state: KeyState,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    origin: CredentialOrigin,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> AgentCredential<T> {
    /// Mints an active credential for the agent. It expires no later than
    /// the longest of `lifetimes` from now.
    ///
    /// Sam may only view agents. Without the source check, Sam enrols his own
    /// public key for Ann's agent and signs in as it.
    ///
    /// Raises `agents.credential_minted` for a key a person enrolled, and
    /// `agents.agent_bootstrapped` for one the agent got against its
    /// attestation.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when a person enrols the key who is
    ///   neither the owner nor allowed to update agents.
    /// - [`DomainError::Forbidden`] when a key is enrolled by hand for an
    ///   agent that proves itself by attesting.
    /// - [`DomainError::Forbidden`] when the agent's policy does not trust the
    ///   attestation the key is issued against, or it has no policy.
    /// - [`DomainError::Validation`] when the expiry asked for is not in the
    ///   future.
    pub fn mint(
        params: MintAgentCredentialParams<'_, T>,
        lifetimes: CredentialLifetimes,
    ) -> Result<Self, DomainError> {
        let origin = Self::vouched_origin(params.agent, params.source)?;
        let now = crate::shared::clock::now();
        let expires_at = Self::expiry(params.expires_at, now, lifetimes)?;
        let mut credential = Self {
            id: AgentCredentialId::new(),
            agent_id: *params.agent.id(),
            kid: params.kid,
            algorithm: params.algorithm,
            public_key: params.public_key,
            state: KeyState::Active,
            created_at: now,
            expires_at,
            origin,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        credential.raise_minted(params.agent);
        Ok(credential)
    }

    /// Records how the credential came to be: enrolled by a person, or got
    /// by the agent against its attestation.
    fn raise_minted(&mut self, agent: &AgentIdentity<T>) {
        let (credential_id, credential_label) = (self.id, self.label());
        let occurred_at = self.created_at;
        match self.origin {
            CredentialOrigin::Enrolled => self.raised.raise(AgentCredentialMinted {
                agent_id: self.agent_id,
                agent_label: agent.label(),
                credential_id,
                credential_label,
                occurred_at,
            }),
            CredentialOrigin::Attested(_) => self.raised.raise(AgentBootstrapped {
                credential_id,
                credential_label,
                occurred_at,
            }),
        }
    }

    /// The name the credential's records show: its id, since a credential
    /// has no name of its own.
    fn label(&self) -> EventLabel {
        EventLabel::of(&self.id.to_string())
    }

    /// The origin a new key gets, once its source is checked against the
    /// agent.
    fn vouched_origin(
        agent: &AgentIdentity<T>,
        source: KeySource<'_>,
    ) -> Result<CredentialOrigin, DomainError> {
        let origin = match source {
            KeySource::Enrolled(control) => {
                control.ensure_may(agent.owner(), AgentAction::Update)?;
                CredentialOrigin::Enrolled
            }
            KeySource::Attested(attested) => {
                agent.ensure_trusts(attested)?;
                CredentialOrigin::Attested(AttestationRef::new(
                    attested.method(),
                    attested.subject().clone(),
                ))
            }
        };
        if agent.admits_credential(&origin) {
            return Ok(origin);
        }
        Err(DomainError::forbidden(message!(
            "agents-an-agent-that-proves-itself-by",
            "an agent that proves itself by attesting takes no key enrolled by hand"
        )))
    }

    /// When a credential minted at `now` expires.
    fn expiry(
        asked: Setting<OffsetDateTime>,
        now: OffsetDateTime,
        lifetimes: CredentialLifetimes,
    ) -> Result<OffsetDateTime, DomainError> {
        let asked = match asked {
            Setting::Set(at) => at,
            Setting::Unset => now.saturating_add(lifetimes.default_lifetime()),
        };
        if asked <= now {
            return Err(DomainError::invalid(message!(
                "agents-an-agent-credential-must-expire-in",
                "an agent credential must expire in the future"
            )));
        }
        Ok(asked.min(now.saturating_add(lifetimes.max_lifetime())))
    }

    /// Rebuilds an agent credential from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the credential
    ///   expires, changed or was rotated before it was minted.
    /// - [`DomainError::Infrastructure`] when it lives past
    ///   [`CredentialLifetimes::LONGEST_LIFETIME`], or a rotated one past
    ///   [`CredentialLifetimes::LONGEST_GRACE`] after its rotation.
    pub fn reconstitute(row: AgentCredentialRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            agent_id: row.agent_id,
            kid: row.kid,
            algorithm: row.algorithm,
            public_key: row.public_key,
            state: row.state,
            created_at: row.created_at,
            expires_at: row.expires_at,
            origin: row.origin,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    ///
    /// The lifetime limits are the hard ones every setting stays within. The
    /// row does not say which settings minted it.
    fn ensure_consistent(row: &AgentCredentialRow) -> Result<(), DomainError> {
        let lifetime = crate::shared::clock::between(row.created_at, row.expires_at);
        let within_grace = row.state.rotated_at().is_none_or(|at| {
            row.expires_at <= at.saturating_add(CredentialLifetimes::LONGEST_GRACE)
        });
        RowCheck::of("agent credential")
            .holds(
                row.created_at < row.expires_at,
                "expires before it was minted",
            )
            .holds(
                lifetime <= CredentialLifetimes::LONGEST_LIFETIME,
                "lives past the longest lifetime",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was minted",
            )
            .in_order_if(
                row.created_at,
                row.state.rotated_at(),
                "rotated before it was minted",
            )
            .holds(within_grace, "verifies past the end of its rotation grace")
            .finish()
    }

    /// Unique identifier.
    #[must_use]
    pub fn id(&self) -> &AgentCredentialId {
        &self.id
    }

    /// The agent this credential authenticates.
    #[must_use]
    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    /// The key id, used as the JWT `kid`.
    #[must_use]
    pub fn kid(&self) -> &KeyId {
        &self.kid
    }

    /// The signing algorithm.
    #[must_use]
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// The PEM-encoded public key used to verify the agent's assertions.
    #[must_use]
    pub fn public_key(&self) -> &PublicKeyPem {
        &self.public_key
    }

    /// Where the credential stands now.
    #[must_use]
    pub fn status(&self) -> KeyStatus {
        self.state.status()
    }

    /// When the credential expires. Every credential does.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// When this credential was rotated, if it was.
    ///
    /// A caller showing a countdown reads
    /// [`rotation_grace`](Self::rotation_grace) instead.
    #[must_use]
    pub fn rotated_at(&self) -> Option<OffsetDateTime> {
        self.state.rotated_at()
    }

    /// The grace this credential is counting down, if it is rotated.
    ///
    /// An active credential has none. A revoked one has none either, because
    /// revocation takes effect at once. So a caller shows a countdown for
    /// exactly the credentials that have one.
    #[must_use]
    pub fn rotation_grace(&self) -> Option<RotationGrace> {
        let KeyState::Rotated { at } = self.state else {
            return None;
        };
        Some(RotationGrace {
            rotated_at: at,
            ends_at: self.expires_at,
        })
    }

    /// How the credential came to be.
    #[must_use]
    pub fn origin(&self) -> &CredentialOrigin {
        &self.origin
    }

    /// Whether this credential is the active one, which signs new assertions.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == KeyState::Active
    }

    /// Whether a task token may be bound to this credential's key at `now`:
    /// it is not revoked and has not expired.
    ///
    /// A rotated key still binds during its grace: the agent signed in with
    /// it before the rotation, and its token proves possession of that key.
    /// A revoked key binds nothing, since whoever stole it would hold the
    /// token too.
    #[must_use]
    pub fn binds_tokens_at(&self, now: OffsetDateTime) -> bool {
        now < self.expires_at && !matches!(self.state, KeyState::Revoked { .. })
    }

    /// Whether an assertion this credential signed at `signed_at` lets
    /// `agent` sign in now.
    ///
    /// The credential must be the agent's own, and the agent must be able to
    /// act now. Its policy must still admit the credential's origin. And the
    /// key must verify the assertion. Ann suspends her agent after an
    /// incident. Without the agent check, its key still signs it in.
    #[must_use]
    pub fn verifies_for(&self, agent: &AgentIdentity<T>, signed_at: OffsetDateTime) -> bool {
        let now = crate::shared::clock::now();
        self.agent_id == *agent.id()
            && agent.may_act_at(now)
            && agent.admits_credential(&self.origin)
            && self.verifies_at(signed_at, now)
    }

    /// The proof that `agent` signed in, by an assertion this credential
    /// signed at `signed_at`.
    ///
    /// It holds what [`verifies_for`](Self::verifies_for) checks. Mallory's
    /// agent knows Ann's agent's id. Without this, it names that id and
    /// passes Ann's delegation on in its name.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when this credential does not sign
    ///   `agent` in now.
    pub fn signed_in(
        &self,
        agent: &AgentIdentity<T>,
        signed_at: OffsetDateTime,
    ) -> Result<ActingAgent, DomainError> {
        if !self.verifies_for(agent, signed_at) {
            return Err(DomainError::forbidden(message!(
                "app-this-credential-does-not-sign-this",
                "this credential does not sign this agent in now"
            )));
        }
        Ok(ActingAgent::proven(*agent.id(), self.id))
    }

    /// Whether the key verifies an assertion it signed at `signed_at`, at
    /// `now`.
    ///
    /// Nothing verifies at or after the expiry. No assertion verifies once
    /// it is more than `MAX_IN_FLIGHT` old, or dated more than
    /// `MAX_CLOCK_SKEW` ahead. An active credential verifies what it signs.
    /// A rotated one verifies only what it signed before the rotation. A
    /// revoked one verifies nothing.
    ///
    /// Whoever holds the key writes the signing time, so they can backdate
    /// it. Sam copies a key, and it is rotated. Sam backdates new assertions
    /// to before the rotation. The age limit stops this `MAX_IN_FLIGHT`
    /// after the rotation. Revoke a key known to be stolen.
    fn verifies_at(&self, signed_at: OffsetDateTime, now: OffsetDateTime) -> bool {
        if now >= self.expires_at || !is_fresh(signed_at, now) {
            return false;
        }
        match self.state {
            KeyState::Active => true,
            KeyState::Rotated { at } => signed_at < at,
            KeyState::Revoked { .. } => false,
        }
    }

    /// Rotates this credential. It signs nothing new, and verifies older
    /// assertions for the grace in `lifetimes`, so those already sent still
    /// arrive.
    ///
    /// The expiry moves to the end of the grace here, not in the caller. A
    /// key is usually rotated because it is suspect. With no end to the
    /// grace, the rotated key would keep working. An earlier expiry stays.
    ///
    /// `agent` is the agent this credential signs in. Its owner may rotate
    /// the key, and so may someone allowed to update agents, as for
    /// enrolling one. Sam may only view agents. Without this check, he
    /// rotates Ann's key during her nightly run and its calls start failing.
    ///
    /// Raises `agents.credential_rotated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `agent` is not the one this
    ///   credential signs in.
    /// - [`DomainError::Forbidden`] when the person is neither the agent's
    ///   owner nor allowed to update agents.
    /// - [`DomainError::InvalidTransition`] when the credential is already
    ///   rotated or revoked.
    pub fn rotate(
        &mut self,
        control: &AgentControl<'_>,
        agent: &AgentIdentity<T>,
        lifetimes: CredentialLifetimes,
    ) -> Result<(), DomainError> {
        self.ensure_may(control, agent, AgentAction::Update)?;
        let now = crate::shared::clock::now();
        self.move_to(KeyState::Rotated { at: now })?;

        let grace_ends = now.saturating_add(lifetimes.rotation_grace());
        self.expires_at = self.expires_at.min(grace_ends);
        self.raised.raise(AgentCredentialRotated {
            agent_id: self.agent_id,
            agent_label: agent.label(),
            credential_id: self.id,
            credential_label: self.label(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Revokes this credential for good.
    ///
    /// `agent` is the agent this credential signs in. Its owner may revoke
    /// the key, and so may someone allowed to delete agents, as for revoking
    /// the agent itself. Sam may only view agents. Without this check, he
    /// revokes every key of Ann's agent and it can no longer sign in.
    ///
    /// Raises `agents.credential_revoked`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `agent` is not the one this
    ///   credential signs in.
    /// - [`DomainError::Forbidden`] when the person is neither the agent's
    ///   owner nor allowed to delete agents.
    /// - [`DomainError::InvalidTransition`] when it is already revoked.
    pub fn revoke(
        &mut self,
        control: &AgentControl<'_>,
        agent: &AgentIdentity<T>,
    ) -> Result<(), DomainError> {
        self.ensure_may(control, agent, AgentAction::Delete)?;
        self.move_to(self.state.revoked())?;
        self.raised.raise(AgentCredentialRevoked {
            agent_id: self.agent_id,
            agent_label: agent.label(),
            credential_id: self.id,
            credential_label: self.label(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Refuses `action` on this credential unless `agent` is the one it
    /// signs in, and the person owns that agent or holds the agent right.
    fn ensure_may(
        &self,
        control: &AgentControl<'_>,
        agent: &AgentIdentity<T>,
        action: AgentAction,
    ) -> Result<(), DomainError> {
        if *agent.id() != self.agent_id {
            return Err(DomainError::forbidden(message!(
                "agents-the-agent-named-is-not-the-2",
                "the agent named is not the one this credential signs in"
            )));
        }
        control.ensure_may(agent.owner(), action)
    }

    fn move_to(&mut self, to: KeyState) -> Result<(), DomainError> {
        self.status().try_transition(to.status()).map_err(|e| {
            DomainError::invalid_transition(message!(
                "agents-cannot-transition-agent-credential-from-to",
                format!(
                    "cannot transition agent credential from {:?} to {:?}",
                    e.from, e.to
                )
            ))
        })?;
        self.state = to;
        self.updated_at = crate::shared::clock::now();
        Ok(())
    }
}

/// Whether an assertion signed at `signed_at` is recent enough at `now`, and
/// not dated too far ahead.
fn is_fresh(signed_at: OffsetDateTime, now: OffsetDateTime) -> bool {
    signed_at <= now.saturating_add(MAX_CLOCK_SKEW)
        && now <= signed_at.saturating_add(MAX_IN_FLIGHT)
}

impl<T: TenantScope> Raises for AgentCredential<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for AgentCredential<T> {
    type Id = AgentCredentialId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::agents::identity::agent::SuspendedBy;
    use crate::domains::agents::identity::agent::tests::fixtures::{
        acting, agent_of, ann, managing, person, sam, viewing,
    };
    use crate::domains::agents::identity::attestation::{
        AttestationMethod, AttestationPolicy, AttestedOrigin, AttestedSubject,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_names;
    use crate::types::{Human, Seconds};

    const GRACE: Duration = Duration::minutes(5);

    fn lifetimes() -> CredentialLifetimes {
        CredentialLifetimes::default()
    }

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    fn params<'a>(
        agent: &'a AgentIdentity<ResolvedTenant>,
        by: &'a Human,
    ) -> MintAgentCredentialParams<'a, ResolvedTenant> {
        MintAgentCredentialParams {
            agent,
            source: KeySource::Enrolled(acting(by)),
            kid: KeyId::new("kid-1").unwrap(),
            algorithm: SigningAlgorithm::EdDsa,
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----",
            )
            .unwrap(),
            expires_at: Setting::Unset,
        }
    }

    fn mint() -> AgentCredential<ResolvedTenant> {
        enrolled().1
    }

    /// Ann's agent, and a key she enrolled for it.
    fn enrolled() -> (
        AgentIdentity<ResolvedTenant>,
        AgentCredential<ResolvedTenant>,
    ) {
        let ann = ann();
        let agent = agent_of(&ann);
        let credential = AgentCredential::mint(params(&agent, &ann), lifetimes()).unwrap();
        (agent, credential)
    }

    /// Ann's agent, and a key she enrolled for it that expires at
    /// `expires_at`.
    fn enrolled_expiring(
        expires_at: OffsetDateTime,
    ) -> (
        AgentIdentity<ResolvedTenant>,
        AgentCredential<ResolvedTenant>,
    ) {
        let ann = ann();
        let agent = agent_of(&ann);
        let credential = AgentCredential::mint(
            MintAgentCredentialParams {
                expires_at: Setting::Set(expires_at),
                ..params(&agent, &ann)
            },
            lifetimes(),
        )
        .unwrap();
        (agent, credential)
    }

    /// Ann, who owns `agent`, rotates its `credential`.
    fn rotate(
        agent: &AgentIdentity<ResolvedTenant>,
        credential: &mut AgentCredential<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        credential.rotate(&acting(&ann()), agent, lifetimes())
    }

    /// Ann, who owns `agent`, revokes its `credential`.
    fn revoke(
        agent: &AgentIdentity<ResolvedTenant>,
        credential: &mut AgentCredential<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        credential.revoke(&acting(&ann()), agent)
    }

    fn cluster_policy() -> AttestationPolicy {
        AttestationPolicy::new(
            vec![AttestationMethod::Spiffe],
            Seconds::new(3600),
            vec![AttestedOrigin::new("spiffe://cluster").unwrap()],
        )
        .unwrap()
    }

    fn workload(subject: &str) -> AttestedIdentity {
        AttestedIdentity::new(
            AttestationMethod::Spiffe,
            AttestedSubject::new(subject).unwrap(),
        )
    }

    /// An agent of `owner`'s that attests from `spiffe://cluster`, and has.
    fn attesting_agent(owner: &Human) -> AgentIdentity<ResolvedTenant> {
        let mut agent = agent_of(owner);
        agent
            .trust_attestation(&acting(owner), cluster_policy())
            .unwrap();
        agent
            .record_attestation(&workload("spiffe://cluster/runner"))
            .unwrap();
        agent
    }

    /// A newly minted credential is active and verifies an assertion signed
    /// now.
    #[test]
    fn mint_produces_an_active_verifiable_credential() {
        let credential = mint();
        assert!(credential.is_active());
        assert!(credential.verifies_at(now(), now()));
        assert_eq!(credential.status(), KeyStatus::Active);
    }

    /// Ann enrols a key for her agent. An assertion it signs now signs the
    /// agent in.
    #[test]
    fn a_key_signs_in_the_agent_it_was_enrolled_for() {
        let ann = ann();
        let agent = agent_of(&ann);
        let credential = AgentCredential::mint(params(&agent, &ann), lifetimes()).unwrap();

        assert!(credential.verifies_for(&agent, now()));
    }

    /// A viewer cannot enrol a key for another person's agent. A manager
    /// can enrol a key for the same agent.
    #[test]
    fn a_person_with_no_say_cannot_enrol_a_key_for_someone_elses_agent() {
        let ann = ann();
        let sam = sam();
        let bob = person("bob@corp.test");
        let agent = agent_of(&ann);

        let by_sam = AgentCredential::mint(
            MintAgentCredentialParams {
                source: KeySource::Enrolled(viewing(&sam)),
                ..params(&agent, &ann)
            },
            lifetimes(),
        );
        let by_bob = AgentCredential::mint(
            MintAgentCredentialParams {
                source: KeySource::Enrolled(managing(&bob)),
                ..params(&agent, &ann)
            },
            lifetimes(),
        );

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(by_bob.is_ok());
    }

    /// An owner cannot enrol a key by hand for an agent configured to
    /// attest, even after that agent has successfully attested.
    #[test]
    fn an_enrolled_key_is_refused_for_an_agent_that_attests() {
        let ann = ann();
        let agent = attesting_agent(&ann);

        let minted = AgentCredential::mint(params(&agent, &ann), lifetimes());

        assert!(matches!(minted, Err(DomainError::Forbidden(_))));
    }

    /// An attestation from an untrusted cluster cannot mint a credential.
    /// A trusted workload gets an attested credential that signs the agent in.
    #[test]
    fn an_attested_key_needs_an_attestation_the_policy_trusts() {
        let ann = ann();
        let agent = attesting_agent(&ann);
        let mallorys = workload("spiffe://mallory/runner");
        let ours = workload("spiffe://cluster/runner");

        let refused = AgentCredential::mint(
            MintAgentCredentialParams {
                source: KeySource::Attested(&mallorys),
                ..params(&agent, &ann)
            },
            lifetimes(),
        );
        let issued = AgentCredential::mint(
            MintAgentCredentialParams {
                source: KeySource::Attested(&ours),
                ..params(&agent, &ann)
            },
            lifetimes(),
        )
        .unwrap();

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(matches!(issued.origin(), CredentialOrigin::Attested(_)));
        assert!(issued.verifies_for(&agent, now()));
    }

    /// An agent without an attestation policy cannot receive a credential
    /// on the strength of a workload attestation.
    #[test]
    fn an_attested_key_is_refused_for_an_agent_without_a_policy() {
        let ann = ann();
        let agent = agent_of(&ann);
        let attested = workload("spiffe://cluster/runner");

        let minted = AgentCredential::mint(
            MintAgentCredentialParams {
                source: KeySource::Attested(&attested),
                ..params(&agent, &ann)
            },
            lifetimes(),
        );

        assert!(matches!(minted, Err(DomainError::Forbidden(_))));
    }

    /// Suspending an agent prevents its credential from signing it in,
    /// even though the credential itself remains active.
    #[test]
    fn a_suspended_agents_key_does_not_sign_it_in() {
        let ann = ann();
        let mut agent = agent_of(&ann);
        let credential = AgentCredential::mint(params(&agent, &ann), lifetimes()).unwrap();

        agent.suspend(SuspendedBy::Person(acting(&ann))).unwrap();

        assert!(credential.is_active());
        assert!(!credential.verifies_for(&agent, now()));
    }

    /// Requiring re-attestation prevents an existing attested credential
    /// from signing the agent in.
    #[test]
    fn a_key_does_not_sign_in_an_agent_that_must_reattest() {
        let ann = ann();
        let mut agent = attesting_agent(&ann);
        let attested = workload("spiffe://cluster/runner");
        let credential = AgentCredential::mint(
            MintAgentCredentialParams {
                source: KeySource::Attested(&attested),
                ..params(&agent, &ann)
            },
            lifetimes(),
        )
        .unwrap();

        agent.require_reattestation(&acting(&ann)).unwrap();

        assert!(!credential.verifies_for(&agent, now()));
    }

    /// A credential enrolled for one agent does not verify an assertion
    /// presented for another agent.
    #[test]
    fn a_key_does_not_sign_in_another_agent() {
        let sam = sam();
        let sams_agent = agent_of(&sam);
        let anns_agent = agent_of(&ann());
        let credential = AgentCredential::mint(params(&sams_agent, &sam), lifetimes()).unwrap();

        assert!(!credential.verifies_for(&anns_agent, now()));
    }

    /// Ann's agent signs in with its own key. The proof it gets names that
    /// agent.
    #[test]
    fn a_key_proves_the_agent_it_signs_in() {
        let (agent, credential) = enrolled();

        let acting = credential.signed_in(&agent, now()).unwrap();

        assert_eq!(acting.agent(), agent.id());
    }

    /// When an agent has two credentials, signing in with the second
    /// produces a proof naming that credential rather than the first.
    #[test]
    fn the_proof_names_the_key_that_signed_the_agent_in() {
        let ann = ann();
        let agent = agent_of(&ann);
        let first = AgentCredential::mint(params(&agent, &ann), lifetimes()).unwrap();
        let second = AgentCredential::mint(params(&agent, &ann), lifetimes()).unwrap();

        let acting = second.signed_in(&agent, now()).unwrap();

        assert_eq!(acting.credential(), second.id());
        assert_ne!(acting.credential(), first.id());
    }

    /// A credential enrolled for one agent cannot produce a sign-in proof
    /// for another agent; the attempt is forbidden.
    #[test]
    fn a_key_proves_no_other_agent() {
        let sam = sam();
        let sams_agent = agent_of(&sam);
        let anns_agent = agent_of(&ann());
        let credential = AgentCredential::mint(params(&sams_agent, &sam), lifetimes()).unwrap();

        let result = credential.signed_in(&anns_agent, now());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// After an agent moves to attestation and attests successfully, its
    /// existing manually enrolled credential no longer signs it in.
    #[test]
    fn an_enrolled_key_stops_working_once_the_agent_attests() {
        let ann = ann();
        let mut agent = agent_of(&ann);
        let credential = AgentCredential::mint(params(&agent, &ann), lifetimes()).unwrap();

        agent
            .trust_attestation(&acting(&ann), cluster_policy())
            .unwrap();
        agent
            .record_attestation(&workload("spiffe://cluster/runner"))
            .unwrap();

        assert!(!credential.verifies_for(&agent, now()));
    }

    /// An active credential accepts an assertion at the maximum in-flight
    /// age but refuses the same assertion an hour after it was signed.
    #[test]
    fn an_active_key_refuses_an_old_assertion() {
        let credential = mint();
        let signed_at = now();

        assert!(credential.verifies_at(signed_at, signed_at + MAX_IN_FLIGHT));
        assert!(!credential.verifies_at(signed_at, signed_at + Duration::hours(1)));
    }

    /// An active credential accepts a signing time at the clock-skew limit
    /// but refuses an assertion dated a day ahead.
    #[test]
    fn an_active_key_refuses_a_future_dated_assertion() {
        let credential = mint();
        let at = now();

        assert!(credential.verifies_at(at + MAX_CLOCK_SKEW, at));
        assert!(!credential.verifies_at(at + Duration::days(1), at));
    }

    /// An assertion is signed one second before the credential is rotated.
    /// It still verifies, so a request already on its way gets through.
    #[test]
    fn rotated_credential_still_verifies_what_it_signed_before() {
        let (agent, mut credential) = enrolled();
        let signed_before = now() - Duration::seconds(1);
        rotate(&agent, &mut credential).unwrap();
        assert!(!credential.is_active());
        assert!(credential.verifies_at(signed_before, now()));
    }

    /// A rotated credential refuses assertions dated at the rotation or
    /// ten seconds after it, while its grace period is still open.
    #[test]
    fn a_rotated_credential_verifies_nothing_signed_after_its_rotation() {
        let (agent, mut credential) = enrolled();
        rotate(&agent, &mut credential).unwrap();
        let rotated_at = credential.rotated_at().unwrap();

        assert!(!credential.verifies_at(rotated_at, rotated_at + Duration::seconds(1)));
        assert!(!credential.verifies_at(
            rotated_at + Duration::seconds(10),
            rotated_at + Duration::seconds(10)
        ));
    }

    /// An assertion dated just before rotation is refused once it exceeds
    /// the maximum in-flight age, even while the credential's grace remains open.
    #[test]
    fn a_backdated_assertion_from_a_rotated_credential_stops_verifying() {
        let (agent, mut credential) = enrolled();
        rotate(&agent, &mut credential).unwrap();
        let rotated_at = credential.rotated_at().unwrap();
        let backdated = rotated_at - Duration::seconds(1);

        let late = backdated + MAX_IN_FLIGHT + Duration::seconds(1);

        assert!(late < credential.expires_at(), "still inside the grace");
        assert!(!credential.verifies_at(backdated, late));
    }

    /// A credential minted with no expiry gets the 30 day default. One asked
    /// to live ten years is cut to the 90 day maximum.
    #[test]
    fn every_credential_expires_within_the_cap() {
        let latest = now() + lifetimes().max_lifetime() + Duration::seconds(5);
        let defaulted = mint();
        let (_, far) = enrolled_expiring(now() + Duration::days(3650));

        let defaulted_expiry = defaulted.expires_at();
        assert!(defaulted_expiry < latest - Duration::days(59));
        assert!(far.expires_at() <= latest);
    }

    /// A 30 day credential is rotated with five minutes of grace. Its expiry
    /// moves to the end of the grace, and nothing verifies after it.
    #[test]
    fn rotation_shortens_a_credential_to_its_grace() {
        let (agent, mut credential) = enrolled();

        rotate(&agent, &mut credential).unwrap();

        let grace_ends = now() + GRACE;
        let expiry = credential.expires_at();
        assert!(expiry <= grace_ends);
        assert!(!credential.verifies_at(grace_ends, grace_ends + Duration::seconds(1)));
    }

    /// A credential that expires in 30 seconds is rotated with five minutes
    /// of grace. It still expires in 30 seconds.
    #[test]
    fn rotation_never_extends_an_earlier_expiry() {
        let soon = now() + Duration::seconds(30);
        let (agent, mut credential) = enrolled_expiring(soon);

        rotate(&agent, &mut credential).unwrap();

        assert_eq!(credential.expires_at(), soon);
    }

    /// A credential that has not been rotated has no grace to count down.
    #[test]
    fn an_active_credential_has_no_grace_window() {
        assert!(mint().rotation_grace().is_none());
    }

    /// A credential rotated with five minutes of grace reports a grace that
    /// starts at the rotation, ends at the new expiry and lasts 300 seconds.
    #[test]
    fn rotation_opens_a_grace_window_that_ends_at_the_expiry() {
        let (agent, mut credential) = enrolled();

        rotate(&agent, &mut credential).unwrap();

        let grace = credential
            .rotation_grace()
            .expect("rotation opens a window");
        assert_eq!(grace.rotated_at(), credential.rotated_at().unwrap());
        assert_eq!(grace.ends_at(), credential.expires_at());
        assert_eq!(i64::from(grace.seconds()), GRACE.whole_seconds());
    }

    /// A credential that expires in 30 seconds is rotated. Its grace ends at
    /// that expiry and lasts 30 seconds at most.
    #[test]
    fn an_earlier_expiry_shortens_the_grace_window() {
        let soon = now() + Duration::seconds(30);
        let (agent, mut credential) = enrolled_expiring(soon);

        rotate(&agent, &mut credential).unwrap();

        let grace = credential
            .rotation_grace()
            .expect("rotation opens a window");
        assert_eq!(grace.ends_at(), soon);
        assert!(grace.seconds() <= 30);
    }

    /// A credential is asked to expire one second in the past. Minting it is
    /// refused as invalid input.
    #[test]
    fn a_credential_that_would_expire_before_it_is_minted_is_refused() {
        let ann = ann();
        let agent = agent_of(&ann);

        let minted = AgentCredential::<ResolvedTenant>::mint(
            MintAgentCredentialParams {
                expires_at: Setting::Set(now() - Duration::SECOND),
                ..params(&agent, &ann)
            },
            lifetimes(),
        );

        assert!(matches!(minted, Err(DomainError::Validation(_))));
    }

    fn stored(credential: &AgentCredential<ResolvedTenant>) -> AgentCredentialRow {
        AgentCredentialRow {
            id: credential.id,
            agent_id: credential.agent_id,
            kid: credential.kid.clone(),
            algorithm: credential.algorithm,
            public_key: credential.public_key.clone(),
            state: credential.state,
            created_at: credential.created_at,
            expires_at: credential.expires_at,
            origin: credential.origin.clone(),
            updated_at: credential.updated_at,
        }
    }

    /// A stored credential expires at the same instant it was minted. The row
    /// is refused as corrupt.
    #[test]
    fn a_stored_credential_that_expires_before_it_was_minted_is_refused() {
        let mut row = stored(&mint());
        row.expires_at = row.created_at;

        assert!(refused_as_corrupt(
            &AgentCredential::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored credential with a ten-year lifetime is refused as corrupt
    /// during reconstitution.
    #[test]
    fn a_stored_credential_living_past_the_longest_lifetime_is_refused() {
        let mut row = stored(&mint());
        row.expires_at = row.created_at + Duration::days(3650);

        assert!(refused_as_corrupt(
            &AgentCredential::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored rotated credential expiring thirty days after rotation is
    /// refused as corrupt because it outlives the permitted grace.
    #[test]
    fn a_stored_rotated_credential_outliving_its_grace_is_refused() {
        let (agent, mut credential) = enrolled();
        rotate(&agent, &mut credential).unwrap();
        let mut row = stored(&credential);
        row.expires_at = credential.rotated_at().unwrap() + Duration::days(30);

        assert!(refused_as_corrupt(
            &AgentCredential::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A credential that expired a minute ago is rotated. Its grace lasts zero
    /// seconds, not a negative or wrapped-around number.
    #[test]
    fn a_credential_rotated_past_its_expiry_has_a_zero_length_window() {
        let (agent, minted) = enrolled();
        let mut row = stored(&minted);
        row.created_at -= Duration::hours(2);
        row.expires_at = now() - Duration::seconds(60);
        let mut credential = AgentCredential::<ResolvedTenant>::reconstitute(row).unwrap();

        rotate(&agent, &mut credential).unwrap();

        assert_eq!(credential.rotation_grace().unwrap().seconds(), 0);
    }

    /// A rotated credential is then revoked. It has no grace left, but still
    /// records when it was rotated.
    #[test]
    fn revoking_a_rotated_credential_closes_its_grace_window() {
        let (agent, mut credential) = enrolled();
        rotate(&agent, &mut credential).unwrap();

        revoke(&agent, &mut credential).unwrap();

        assert!(credential.rotation_grace().is_none());
        assert!(credential.rotated_at().is_some());
    }

    /// A revoked credential does not verify an assertion signed now.
    #[test]
    fn revoked_credential_does_not_verify() {
        let (agent, mut credential) = enrolled();
        revoke(&agent, &mut credential).unwrap();
        assert!(!credential.verifies_at(now(), now()));
    }

    /// Rotating a revoked credential fails as an invalid transition, so it
    /// cannot get a grace back.
    #[test]
    fn cannot_rotate_a_revoked_credential() {
        let (agent, mut credential) = enrolled();
        revoke(&agent, &mut credential).unwrap();
        assert!(matches!(
            rotate(&agent, &mut credential),
            Err(DomainError::InvalidTransition(_))
        ));
    }

    /// A viewer cannot rotate or revoke another person's agent credential,
    /// which stays active after both refusals. A manager can then revoke it.
    #[test]
    fn a_person_with_no_say_cannot_rotate_or_revoke_someone_elses_key() {
        let (agent, mut credential) = enrolled();
        let sam = sam();
        let bob = person("bob@corp.test");

        let rotated = credential.rotate(&viewing(&sam), &agent, lifetimes());
        let revoked = credential.revoke(&viewing(&sam), &agent);

        assert!(matches!(rotated, Err(DomainError::Forbidden(_))));
        assert!(matches!(revoked, Err(DomainError::Forbidden(_))));
        assert!(credential.is_active());
        assert!(credential.revoke(&managing(&bob), &agent).is_ok());
    }

    /// Naming an agent the caller owns cannot authorize rotation of another
    /// agent's credential. The attempt is refused and the credential stays active.
    #[test]
    fn a_key_is_changed_only_against_the_agent_it_signs_in() {
        let (_, mut anns_key) = enrolled();
        let sam = sam();
        let sams_agent = agent_of(&sam);

        let rotated = anns_key.rotate(&acting(&sam), &sams_agent, lifetimes());

        assert!(matches!(rotated, Err(DomainError::Forbidden(_))));
        assert!(anns_key.is_active());
    }

    /// An active credential that expired a second ago does not verify an
    /// assertion signed now.
    #[test]
    fn expiry_bounds_verification() {
        let mut credential = mint();
        credential.expires_at = now() - Duration::seconds(1);
        assert!(!credential.verifies_at(now(), now()));
    }

    /// A credential verifies one second before its expiry. At the expiry
    /// itself, and after it, it verifies nothing.
    #[test]
    fn a_credential_stops_verifying_at_its_expiry_not_after_it() {
        let mut credential = mint();
        let expiry = now() + Duration::seconds(60);
        credential.expires_at = expiry;

        assert!(credential.verifies_at(expiry, expiry - Duration::seconds(1)));
        assert!(
            !credential.verifies_at(expiry, expiry),
            "the expiry is not part of the window"
        );
        assert!(!credential.verifies_at(expiry, expiry + Duration::seconds(1)));
    }

    /// A credential minted from an enrolled key reads back its public key and
    /// an enrolled origin. Verification checks both, so both must be as minted.
    #[test]
    fn a_credential_reports_its_agent_public_key_and_attestation() {
        let credential = mint();

        assert!(!credential.public_key().as_str().is_empty());
        assert_eq!(Aggregate::id(&credential), credential.id());
        assert_eq!(
            credential.origin(),
            &CredentialOrigin::Enrolled,
            "a credential minted without an attestation is bound to none"
        );
    }

    /// Ann enrols a key for her agent. Its minting is raised.
    #[test]
    fn enrolling_a_key_raises_its_minting() {
        let mut credential = mint();

        assert_eq!(raised_names(&mut credential), ["agents.credential_minted"]);
    }

    /// A workload in Ann's cluster gets a key against its attestation. The
    /// bootstrap is raised, not a minting by hand.
    #[test]
    fn a_key_got_by_attesting_raises_the_bootstrap() {
        let ann = ann();
        let agent = attesting_agent(&ann);
        let ours = workload("spiffe://cluster/runner");

        let mut issued = AgentCredential::mint(
            MintAgentCredentialParams {
                source: KeySource::Attested(&ours),
                ..params(&agent, &ann)
            },
            lifetimes(),
        )
        .unwrap();

        assert_eq!(raised_names(&mut issued), ["agents.agent_bootstrapped"]);
    }

    /// Ann rotates her agent's key and then revokes it. Each is raised, in
    /// order.
    #[test]
    fn rotating_and_revoking_raise_each() {
        let (agent, mut credential) = enrolled();
        raised_names(&mut credential);

        rotate(&agent, &mut credential).unwrap();
        revoke(&agent, &mut credential).unwrap();

        assert_eq!(
            raised_names(&mut credential),
            ["agents.credential_rotated", "agents.credential_revoked"]
        );
    }

    /// A viewer's attempts to rotate and revoke another person's agent key
    /// both fail without raising any events.
    #[test]
    fn a_refused_change_to_a_key_raises_nothing() {
        let (agent, mut credential) = enrolled();
        raised_names(&mut credential);
        let sam = sam();

        let rotated = credential.rotate(&viewing(&sam), &agent, lifetimes());
        let revoked = credential.revoke(&viewing(&sam), &agent);

        assert!(rotated.is_err());
        assert!(revoked.is_err());
        assert!(raised_names(&mut credential).is_empty());
    }

    /// A key read back from storage has raised nothing.
    #[test]
    fn a_key_read_back_from_storage_has_raised_nothing() {
        let mut read_back =
            AgentCredential::<ResolvedTenant>::reconstitute(stored(&mint())).unwrap();

        assert!(raised_names(&mut read_back).is_empty());
    }
}
