//! How an agent proves what it is, and whether it owes a new proof.

use time::{Duration, OffsetDateTime};

use crate::domains::agents::events::identity::{
    AgentAttestationChallengeIssued, AgentReattestationRequired,
};
use crate::domains::agents::identity::agent::AgentIdentity;
use crate::domains::agents::identity::attestation::{AttestationPolicy, AttestedIdentity};
use crate::domains::agents::identity::challenge::{AttestationChallenge, AttestationNonce};
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::agents::identity::credential::CredentialOrigin;
use crate::domains::agents::identity::standing::Reattestation;
use crate::domains::authorization::permission::AgentAction;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::Lifetime;

/// How an agent proves it is itself when it asks for a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentProof {
    /// With a key enrolled for it by hand.
    EnrolledKey,
    /// By attesting where it runs, under this policy. An enrolled key does
    /// not count.
    Attestation(AttestationPolicy),
}

/// Whether an agent is held until it re-attests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Containment {
    /// Free to act within its delegations.
    Free,
    /// Blocked at the proxy until it re-attests.
    ReattestationRequired {
        /// When re-attestation was required.
        since: OffsetDateTime,
    },
}

impl Containment {
    /// When the agent was held, if it is.
    #[must_use]
    pub fn since(self) -> Option<OffsetDateTime> {
        match self {
            Self::Free => None,
            Self::ReattestationRequired { since } => Some(since),
        }
    }
}

impl<T: TenantScope> AgentIdentity<T> {
    /// How the agent proves it is itself.
    #[must_use]
    pub fn proof(&self) -> &AgentProof {
        &self.proof
    }

    /// The attestation policy, when the agent proves itself by attesting.
    #[must_use]
    pub fn attestation_policy(&self) -> Option<&AttestationPolicy> {
        let AgentProof::Attestation(policy) = &self.proof else {
            return None;
        };
        Some(policy)
    }

    /// Whether a credential of `origin` may speak for this agent.
    ///
    /// An agent that proves itself by attesting accepts only a credential
    /// tied to an attestation. That attestation must still pass the agent's
    /// current policy.
    ///
    /// A key enrolled by hand would work from any machine. The policy exists
    /// to remove such a long-lived secret. And when an operator stops
    /// trusting an origin, its credentials stop working at once, not when
    /// they expire.
    #[must_use]
    pub fn admits_credential(&self, origin: &CredentialOrigin) -> bool {
        match (&self.proof, origin) {
            (AgentProof::EnrolledKey, _) => true,
            (AgentProof::Attestation(_), CredentialOrigin::Enrolled) => false,
            (AgentProof::Attestation(policy), CredentialOrigin::Attested(attested)) => {
                policy.trusts(attested.method(), attested.subject())
            }
        }
    }

    /// Makes the agent prove itself by attesting under `policy`.
    ///
    /// It replaces any policy set before. The agent may then bootstrap with
    /// no secret of its own.
    ///
    /// Raises `agents.agent_updated`, unless the agent was created in the
    /// same edit.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person is neither the owner nor
    ///   allowed to update agents.
    pub fn trust_attestation(
        &mut self,
        control: &AgentControl<'_>,
        policy: AttestationPolicy,
    ) -> Result<(), DomainError> {
        self.ensure_may(control, AgentAction::Update)?;
        self.proof = AgentProof::Attestation(policy);
        self.touch();
        self.raise_updated();
        Ok(())
    }

    /// Removes the attestation policy.
    ///
    /// The agent proves itself with an enrolled key. It accepts no bootstrap
    /// attestation until a new policy is set. Ann moved her agent off
    /// hand-enrolled keys. Without the owner check, Sam clears the policy and
    /// an old key Mallory copied works again.
    ///
    /// Raises `agents.agent_updated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person is neither the owner nor
    ///   allowed to update agents.
    pub fn clear_attestation_policy(
        &mut self,
        control: &AgentControl<'_>,
    ) -> Result<(), DomainError> {
        self.ensure_may(control, AgentAction::Update)?;
        self.proof = AgentProof::EnrolledKey;
        self.touch();
        self.raise_updated();
        Ok(())
    }

    /// Requires the agent to re-attest before it may act again.
    ///
    /// The proxy blocks the agent until it re-attests through
    /// [`record_attestation`](Self::record_attestation). Calling it again only
    /// moves the time it was required. An agent with no attestation policy
    /// stays blocked until one is set and it attests under it.
    ///
    /// Raises `agents.reattestation_required`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person is neither the owner nor
    ///   allowed to update agents.
    pub fn require_reattestation(&mut self, control: &AgentControl<'_>) -> Result<(), DomainError> {
        self.ensure_may(control, AgentAction::Update)?;
        let now = crate::shared::clock::now();
        self.containment = Containment::ReattestationRequired { since: now };
        self.updated_at = now;
        self.raised.raise(AgentReattestationRequired {
            agent_id: self.id,
            agent_label: self.label(),
            occurred_at: now,
        });
        Ok(())
    }

    /// Records a fresh attestation the agent's policy trusts, made now.
    ///
    /// It clears any re-attestation block and starts a new interval.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the agent is not active. An
    ///   operator may suspend an agent that must re-attest. If it could attest
    ///   while suspended, it would clear the block on its own.
    /// - [`DomainError::Forbidden`] when the agent has no attestation policy,
    ///   or its policy does not trust `attested`.
    pub fn record_attestation(&mut self, attested: &AttestedIdentity) -> Result<(), DomainError> {
        if !self.is_active() {
            return Err(DomainError::invalid_transition(message!(
                "agents-an-inactive-agent-cannot-clear-its",
                "an inactive agent cannot clear its own re-attestation block"
            )));
        }
        self.ensure_trusts(attested)?;
        let now = crate::shared::clock::now();
        self.containment = Containment::Free;
        self.last_attested_at = Some(now);
        self.updated_at = now;
        Ok(())
    }

    /// Issues the agent the challenge `nonce` for its next bootstrap, valid
    /// for `lifetime`.
    ///
    /// The agent asks for it itself, before it can prove anything, so no
    /// person's say is needed. The challenge grants nothing on its own: only
    /// a bootstrap that spends it with an attestation the agent's policy
    /// trusts gets a credential. The agent itself does not change.
    ///
    /// Raises `agents.attestation_challenge_issued`.
    #[must_use]
    pub fn issue_attestation_challenge(
        &mut self,
        nonce: AttestationNonce,
        lifetime: Lifetime,
    ) -> AttestationChallenge<T> {
        let challenge = AttestationChallenge::issue(nonce, self.id, lifetime);
        self.raised.raise(AgentAttestationChallengeIssued {
            agent_id: self.id,
            agent_label: self.label(),
            occurred_at: challenge.issued_at(),
        });
        challenge
    }

    /// Refuses an attestation the agent's policy does not trust.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the agent has no attestation policy,
    ///   or its policy does not trust `attested`.
    pub(in crate::domains::agents::identity) fn ensure_trusts(
        &self,
        attested: &AttestedIdentity,
    ) -> Result<(), DomainError> {
        let trusted = self
            .attestation_policy()
            .is_some_and(|policy| attested.is_trusted_by(policy));
        if trusted {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "agents-the-agent-s-attestation-policy-does",
            "the agent's attestation policy does not trust this attestation"
        )))
    }

    /// When the agent last proved what it is.
    #[must_use]
    pub fn last_attested_at(&self) -> Option<OffsetDateTime> {
        self.last_attested_at
    }

    /// Whether the agent's last attestation is older than its policy's
    /// re-attestation interval.
    ///
    /// An agent with a policy that has never attested is stale. An agent
    /// with no policy is never stale.
    #[must_use]
    pub fn attestation_is_stale_at(&self, now: OffsetDateTime) -> bool {
        let AgentProof::Attestation(policy) = &self.proof else {
            return false;
        };
        let Some(last) = self.last_attested_at else {
            return true;
        };
        crate::shared::clock::between(last, now)
            >= Duration::seconds(i64::from(policy.reattest_interval_seconds().get()))
    }

    /// Whether the agent is blocked until it re-attests because someone
    /// required it.
    #[must_use]
    pub fn reattestation_required(&self) -> bool {
        matches!(self.containment, Containment::ReattestationRequired { .. })
    }

    /// Whether the agent is held until it re-attests, and since when.
    #[must_use]
    pub fn containment(&self) -> Containment {
        self.containment
    }

    /// Whether the agent owes a re-attestation at `now`: someone required
    /// one, or its last one is stale.
    pub(super) fn reattestation_at(&self, now: OffsetDateTime) -> Reattestation {
        if self.reattestation_required() || self.attestation_is_stale_at(now) {
            return Reattestation::Required;
        }
        Reattestation::Current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::identity::agent::SuspendedBy;
    use crate::domains::agents::identity::agent::tests::fixtures::{
        acting, agent_of, ann, sam, viewing,
    };
    use crate::domains::agents::identity::attestation::{
        AttestationMethod, AttestationRef, AttestedOrigin, AttestedSubject,
    };
    use crate::domains::agents::identity::standing::AgentStanding;
    use crate::isolation::scope::ResolvedTenant;
    use crate::types::{Human, Seconds};

    fn trusting(origin: &str) -> AttestationPolicy {
        AttestationPolicy::new(
            vec![AttestationMethod::Spiffe],
            Seconds::new(3600),
            vec![AttestedOrigin::new(origin).unwrap()],
        )
        .unwrap()
    }

    fn runner() -> AttestedIdentity {
        AttestedIdentity::new(
            AttestationMethod::Spiffe,
            AttestedSubject::new("spiffe://cluster/runner").unwrap(),
        )
    }

    fn attested() -> AttestationRef {
        AttestationRef::new(
            AttestationMethod::Spiffe,
            AttestedSubject::new("spiffe://cluster/runner").unwrap(),
        )
    }

    /// An agent of Ann's that attests from `spiffe://cluster`.
    fn attesting_agent(ann: &Human) -> AgentIdentity<ResolvedTenant> {
        let mut agent = agent_of(ann);
        agent
            .trust_attestation(&acting(ann), trusting("spiffe://cluster"))
            .unwrap();
        agent
    }

    /// An agent with no attestation policy accepts a credential from an
    /// enrolled key.
    #[test]
    fn an_agent_without_a_policy_admits_a_plain_key() {
        assert!(agent_of(&ann()).admits_credential(&CredentialOrigin::Enrolled));
    }

    /// An agent configured to attest refuses an enrolled credential and
    /// accepts a credential attested in its trusted cluster.
    #[test]
    fn an_attested_agent_admits_only_attested_credentials() {
        let agent = attesting_agent(&ann());

        assert!(!agent.admits_credential(&CredentialOrigin::Enrolled));
        assert!(agent.admits_credential(&CredentialOrigin::Attested(attested())));
    }

    /// A credential attested in one cluster is refused when the agent's
    /// policy trusts only another cluster.
    #[test]
    fn a_credential_from_an_origin_no_longer_trusted_is_not_admitted() {
        let ann = ann();
        let mut agent = agent_of(&ann);
        agent
            .trust_attestation(&acting(&ann), trusting("spiffe://other-cluster"))
            .unwrap();

        assert!(!agent.admits_credential(&CredentialOrigin::Attested(attested())));
    }

    /// Ann tells her agent to re-attest and it is blocked. Once it attests
    /// from the trusted cluster, the block is gone.
    #[test]
    fn requiring_reattestation_blocks_until_recorded() {
        let ann = ann();
        let mut a = attesting_agent(&ann);
        a.require_reattestation(&acting(&ann)).unwrap();
        assert!(a.reattestation_required());

        a.record_attestation(&runner()).unwrap();

        assert!(!a.reattestation_required());
    }

    /// An untrusted cluster's attestation cannot clear a re-attestation
    /// requirement. The block remains and no attestation time is recorded.
    #[test]
    fn an_attestation_the_policy_does_not_trust_leaves_the_block() {
        let ann = ann();
        let mut a = attesting_agent(&ann);
        a.require_reattestation(&acting(&ann)).unwrap();
        let mallorys = AttestedIdentity::new(
            AttestationMethod::Spiffe,
            AttestedSubject::new("spiffe://mallory/runner").unwrap(),
        );

        let result = a.record_attestation(&mallorys);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(a.reattestation_required(), "the block survives");
        assert_eq!(a.last_attested_at(), None);
    }

    /// An agent without an attestation policy refuses an attempt to record
    /// a workload attestation.
    #[test]
    fn an_agent_without_a_policy_records_no_attestation() {
        let mut a = agent_of(&ann());

        assert!(matches!(
            a.record_attestation(&runner()),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Recording a trusted attestation uses the current time, and the
    /// attestation becomes stale one hour later under the agent's policy.
    #[test]
    fn an_attestation_is_stamped_with_the_current_time() {
        let ann = ann();
        let mut a = attesting_agent(&ann);
        let now = crate::shared::clock::now();
        let frozen = crate::shared::clock::freeze(now);

        a.record_attestation(&runner()).unwrap();

        assert_eq!(a.last_attested_at(), Some(now));
        assert!(a.attestation_is_stale_at(now + Duration::seconds(3600)));
        drop(frozen);
    }

    /// A suspended agent cannot record a trusted attestation to clear its
    /// re-attestation requirement; the refusal leaves the block in place.
    #[test]
    fn a_suspended_agent_cannot_clear_its_own_reattestation_block() {
        let ann = ann();
        let mut a = attesting_agent(&ann);
        a.require_reattestation(&acting(&ann)).unwrap();
        a.suspend(SuspendedBy::Person(acting(&ann))).unwrap();

        let result = a.record_attestation(&runner());

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
        assert!(a.reattestation_required(), "the block survives");
    }

    /// An agent with an hourly policy is stale before it first attests. After
    /// attesting it is fresh for 3599 seconds and stale at 3600.
    #[test]
    fn attestation_goes_stale_once_the_policy_interval_elapses() {
        let ann = ann();
        let mut a = attesting_agent(&ann);
        let now = crate::shared::clock::now();
        let frozen = crate::shared::clock::freeze(now);

        assert!(
            a.attestation_is_stale_at(now),
            "a policy with no attestation yet is stale"
        );

        a.record_attestation(&runner()).unwrap();
        assert!(!a.attestation_is_stale_at(now + Duration::seconds(3599)));
        assert!(a.attestation_is_stale_at(now + Duration::seconds(3600)));
        drop(frozen);
    }

    /// An agent with an hourly policy may act immediately after attesting,
    /// but must re-attest and cannot act once the hour elapses.
    #[test]
    fn a_stale_attestation_makes_the_agent_reattest() {
        let ann = ann();
        let mut a = attesting_agent(&ann);
        let now = crate::shared::clock::now();
        let frozen = crate::shared::clock::freeze(now);
        a.record_attestation(&runner()).unwrap();

        let later = now + Duration::seconds(3600);

        assert_eq!(a.standing(now), AgentStanding::Active);
        assert_eq!(a.standing(later), AgentStanding::MustReattest);
        assert!(!a.may_act_at(later));
        drop(frozen);
    }

    /// An agent with no attestation policy is not stale even a year on.
    #[test]
    fn an_agent_without_a_policy_never_goes_stale() {
        let a = agent_of(&ann());
        assert!(!a.attestation_is_stale_at(crate::shared::clock::now() + Duration::days(365)));
    }

    /// A new agent has no attestation policy. After a SPIFFE policy is set,
    /// the agent's policy permits SPIFFE.
    #[test]
    fn attestation_policy_starts_unset_and_can_be_configured() {
        let ann = ann();
        assert!(agent_of(&ann).attestation_policy().is_none());

        let a = attesting_agent(&ann);

        assert!(
            a.attestation_policy()
                .is_some_and(|p| p.permits(AttestationMethod::Spiffe))
        );
    }

    /// Ann clears her agent's attestation policy. No policy is left, so
    /// bootstrap attestations stop being accepted and nothing goes stale.
    #[test]
    fn clearing_the_attestation_policy_leaves_no_policy_behind() {
        let ann = ann();
        let mut a = attesting_agent(&ann);

        a.clear_attestation_policy(&acting(&ann)).unwrap();

        assert_eq!(a.attestation_policy(), None);
        assert!(
            !a.attestation_is_stale_at(crate::shared::clock::now()),
            "with no policy there is nothing to go stale"
        );
    }

    /// A viewer cannot clear another person's agent attestation policy;
    /// the refusal leaves a policy in place.
    #[test]
    fn a_person_with_no_say_cannot_clear_the_attestation_policy() {
        let mut a = attesting_agent(&ann());

        let result = a.clear_attestation_policy(&viewing(&sam()));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(a.attestation_policy().is_some());
    }

    /// A viewer cannot set another person's agent policy or require it to
    /// re-attest. Both refusals leave it without a policy or re-attestation block.
    #[test]
    fn a_person_with_no_say_cannot_change_how_an_agent_attests() {
        let mut a = agent_of(&ann());
        let sam = sam();

        let trusted = a.trust_attestation(&viewing(&sam), trusting("spiffe://sam"));
        let blocked = a.require_reattestation(&viewing(&sam));

        assert!(matches!(trusted, Err(DomainError::Forbidden(_))));
        assert!(matches!(blocked, Err(DomainError::Forbidden(_))));
        assert!(a.attestation_policy().is_none());
        assert!(!a.reattestation_required());
    }

    /// Ann tells her agent to re-attest. The block records the current time,
    /// and its last attestation stays unset, because being asked proves
    /// nothing.
    #[test]
    fn requiring_reattestation_records_when_it_was_demanded() {
        let ann = ann();
        let mut a = agent_of(&ann);
        let at = crate::shared::clock::now();
        let frozen = crate::shared::clock::freeze(at);
        assert_eq!(a.containment(), Containment::Free);

        a.require_reattestation(&acting(&ann)).unwrap();

        assert_eq!(
            a.containment(),
            Containment::ReattestationRequired { since: at }
        );
        assert_eq!(
            a.last_attested_at(),
            None,
            "being asked to re-attest is not an attestation"
        );
        drop(frozen);
    }
}
