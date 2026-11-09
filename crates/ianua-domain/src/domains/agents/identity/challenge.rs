//! The nonce the server picks and an agent must sign to bootstrap.
//!
//! A platform attestation such as a SPIFFE X.509-SVID is a public document.
//! Showing one proves only that the caller has seen it. Anyone who talked
//! mTLS with the workload, read its certificate off disk, or captured a
//! handshake can replay the same bytes. A valid certificate chain says the
//! identity is real, not that the caller holds it.
//!
//! So the platform issues a single-use nonce for one agent and a short time.
//! The attestation must carry it, bound to the public key the bootstrap
//! enrols: signed with the attestation's private key, in what a chip or a
//! cloud signed, or in a token's audience. Only the workload the attestation
//! names can make that proof, and only for its own key, so replaying the
//! attestation alone fails, and so does presenting a proof seen in passing
//! with another key.
//!
//! The store keeps each nonce single-use by consuming it atomically. A nonce
//! that verifies twice is one an attacker can reuse.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{AgentId, Lifetime, Usage};

text_value! {
    /// A single-use, server-issued nonce for an attestation proof.
    ///
    /// The domain does not read it. The adapter that makes it picks the
    /// encoding, and only its unpredictability matters. It is 32 to 256
    /// characters: too long to guess, short enough to refuse a megabyte.
    pub struct AttestationNonce;
}

impl TextValue for AttestationNonce {
    const FIELD: &'static str = "nonce";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(Self::MIN_LEN..=Self::MAX_LEN)
    }
}

impl AttestationNonce {
    /// Shortest accepted nonce, in characters.
    const MIN_LEN: usize = 32;
    /// Longest accepted nonce, in characters.
    const MAX_LEN: usize = 256;
}

/// Persisted state for reconstitution.
pub struct AttestationChallengeRow {
    /// The issued nonce.
    pub nonce: AttestationNonce,
    /// The agent this challenge may bootstrap.
    pub agent_id: AgentId,
    /// When it was issued.
    pub issued_at: OffsetDateTime,
    /// When it stops being accepted.
    pub expires_at: OffsetDateTime,
    /// Whether it was spent, and when.
    pub usage: Usage,
}

/// A nonce issued for one agent's next bootstrap.
///
/// It names one agent. Sam may bootstrap agent A and takes a challenge for
/// it. He cannot then spend that challenge to bootstrap agent B.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationChallenge<T: TenantScope> {
    nonce: AttestationNonce,
    agent_id: AgentId,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    usage: Usage,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> AttestationChallenge<T> {
    /// Issues a challenge for `agent_id`, valid for `lifetime`.
    ///
    /// A proof is signed and sent back at once, so the lifetime need only
    /// cover one round trip. A short lifetime limits how long a captured
    /// challenge is worth anything.
    #[must_use]
    pub fn issue(nonce: AttestationNonce, agent_id: AgentId, lifetime: Lifetime) -> Self {
        let now = crate::shared::clock::now();
        Self {
            nonce,
            agent_id,
            issued_at: now,
            expires_at: now.saturating_add(lifetime.duration()),
            usage: Usage::Unused,
            _scope: PhantomData,
        }
    }

    /// Rebuilds a challenge from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the challenge
    ///   expires before it was issued.
    /// - [`DomainError::Infrastructure`] when it says it was spent before it
    ///   was issued or after it expired.
    pub fn reconstitute(row: AttestationChallengeRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            nonce: row.nonce,
            agent_id: row.agent_id,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            usage: row.usage,
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &AttestationChallengeRow) -> Result<(), DomainError> {
        RowCheck::of("attestation challenge")
            .holds(
                row.issued_at < row.expires_at,
                "expires before it was issued",
            )
            .holds(
                row.usage
                    .used_at()
                    .is_none_or(|at| row.issued_at <= at && at < row.expires_at),
                "spent outside the time it was valid",
            )
            .finish()
    }

    /// The issued nonce.
    #[must_use]
    pub fn nonce(&self) -> &AttestationNonce {
        &self.nonce
    }

    /// The agent this challenge may bootstrap.
    #[must_use]
    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    /// When it was issued.
    #[must_use]
    pub fn issued_at(&self) -> OffsetDateTime {
        self.issued_at
    }

    /// When it stops being accepted.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Whether the challenge may still be spent at `now`: not spent, and
    /// not expired.
    #[must_use]
    pub fn is_valid_at(&self, now: OffsetDateTime) -> bool {
        !self.usage.is_used() && now < self.expires_at
    }

    /// Whether it was spent, and when.
    #[must_use]
    pub fn usage(&self) -> Usage {
        self.usage
    }

    /// Spends the challenge on one proof. It accepts nothing after.
    ///
    /// The store also spends it atomically. This keeps the rule in the
    /// challenge itself, so a second proof against a challenge already
    /// spent is refused wherever it is read.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it was already spent or has
    ///   expired.
    pub fn spend(&mut self) -> Result<(), DomainError> {
        let now = crate::shared::clock::now();
        if !self.is_valid_at(now) {
            return Err(DomainError::invalid_transition(message!(
                "agents-the-attestation-challenge-was-already-spent",
                "the attestation challenge was already spent or has expired"
            )));
        }
        self.usage = Usage::Used { at: now };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;

    const LIFETIME: Duration = Duration::minutes(2);

    fn nonce() -> AttestationNonce {
        AttestationNonce::new("n".repeat(43)).unwrap()
    }

    /// A five character nonce and an empty one are refused. Anything under 32
    /// characters could be guessed.
    #[test]
    fn new_rejects_a_nonce_short_enough_to_guess() {
        assert!(AttestationNonce::new("short").is_err());
        assert!(AttestationNonce::new("").is_err());
    }

    /// A 257 character nonce is refused, one over the limit.
    #[test]
    fn new_rejects_an_unbounded_nonce() {
        assert!(AttestationNonce::new("n".repeat(257)).is_err());
    }

    /// A challenge issued for one agent with a two minute lifetime names that
    /// agent, is valid now, and expires exactly two minutes after issue.
    #[test]
    fn issue_binds_the_challenge_to_one_agent_and_a_window() {
        let agent = AgentId::new();
        let challenge: AttestationChallenge<ResolvedTenant> =
            AttestationChallenge::issue(nonce(), agent, Lifetime::new(LIFETIME).unwrap());

        assert_eq!(challenge.agent_id(), &agent);
        assert!(challenge.is_valid_at(crate::shared::clock::now()));
        assert_eq!(challenge.expires_at() - challenge.issued_at(), LIFETIME);
    }

    /// A challenge is checked at the instant it expires and a second later.
    /// It is invalid both times.
    #[test]
    fn a_challenge_stops_being_valid_at_its_expiry() {
        let challenge: AttestationChallenge<ResolvedTenant> =
            AttestationChallenge::issue(nonce(), AgentId::new(), Lifetime::new(LIFETIME).unwrap());

        assert!(!challenge.is_valid_at(challenge.expires_at()));
        assert!(!challenge.is_valid_at(challenge.expires_at() + Duration::seconds(1)));
    }

    /// A nonce built from issued text reads back as the same text. The caller
    /// signs it and the server checks the signature against it.
    #[test]
    fn a_nonce_reads_back_as_issued() {
        let issued = nonce();
        let text = issued.as_str().to_owned();

        assert!(!text.is_empty());
        assert_eq!(AttestationNonce::new(text.clone()).unwrap().as_str(), text);
    }

    /// A stored challenge expires at the same instant it was issued. The row
    /// is refused as corrupt.
    #[test]
    fn a_stored_challenge_that_expires_before_it_was_issued_is_refused() {
        let now = crate::shared::clock::now();

        let challenge =
            AttestationChallenge::<ResolvedTenant>::reconstitute(AttestationChallengeRow {
                nonce: nonce(),
                agent_id: AgentId::new(),
                issued_at: now,
                expires_at: now,
                usage: Usage::Unused,
            });

        assert!(refused_as_corrupt(&challenge));
    }

    /// Spending a challenge twice is refused, and a spent challenge no longer
    /// passes its validity check.
    #[test]
    fn a_challenge_is_spent_once() {
        let mut challenge = AttestationChallenge::<ResolvedTenant>::issue(
            nonce(),
            AgentId::new(),
            Lifetime::seconds(60).unwrap(),
        );

        challenge.spend().unwrap();

        assert!(matches!(
            challenge.spend(),
            Err(DomainError::InvalidTransition(_))
        ));
        assert!(!challenge.is_valid_at(crate::shared::clock::now()));
    }
}
