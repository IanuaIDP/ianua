//! The second-factor step of signing in on an app's host.

use std::marker::PhantomData;
use std::num::NonZeroU8;

use time::{Duration, OffsetDateTime};

use crate::domains::authentication::sessions::session::Session;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::types::{Lifetime, SessionId, TokenHash, Usage};

/// The longest a second-factor challenge may stay open.
pub(crate) const CHALLENGE_LONGEST: Duration = Duration::minutes(15);

/// A second factor still owed after a password was accepted on an app's host.
///
/// The browser holds a random token for it, and only the token's hash is
/// kept here. The session id is not a secret. It appears in session cookies
/// and audit records. So the token, not the id, proves that this browser is
/// the one that entered the password. A challenge is good for one successful
/// factor, a few minutes and a few wrong codes.
///
/// Answering it closes it for good. Ann answers her challenge and the app
/// signs her in. Without that, Mallory, who copied Ann's challenge token,
/// answers it again with a code she watched Ann type and gets a second
/// sign-in of her own.
#[derive(Debug)]
pub struct MfaChallenge<T: TenantScope> {
    token_hash: TokenHash,
    session_id: SessionId,
    expires_at: OffsetDateTime,
    failed_attempts: u8,
    usage: Usage,
    _scope: PhantomData<T>,
}

/// Persisted state for repository hydration.
pub struct MfaChallengeRow {
    /// One-way hash of the token the browser holds.
    pub token_hash: TokenHash,
    /// The session waiting on the second factor.
    pub session_id: SessionId,
    /// When the challenge lapses.
    pub expires_at: OffsetDateTime,
    /// Wrong codes entered against it so far.
    pub failed_attempts: u8,
    /// Whether it was answered, and when. An answer comes before the
    /// challenge lapses.
    pub usage: Usage,
}

impl<T: TenantScope> MfaChallenge<T> {
    /// Opens a challenge for `session`, held by whoever has the token
    /// hashing to `token_hash`, open for `lifetime`.
    ///
    /// Only an active, in-date session that still owes a factor gets one.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the session is not active, has
    ///   expired, or owes nothing.
    /// - [`DomainError::Validation`] when `lifetime` is longer than
    ///   `CHALLENGE_LONGEST`.
    pub fn issue(
        session: &Session<T>,
        token_hash: TokenHash,
        lifetime: Lifetime,
    ) -> Result<Self, DomainError> {
        let now = crate::shared::clock::now();
        let waiting =
            session.status().is_active() && !session.is_expired(now) && !session.mfa_satisfied();
        if !waiting {
            return Err(DomainError::forbidden(message!(
                "authentication-a-challenge-opens-only-for-a",
                "a challenge opens only for a live sign-in that still owes a factor"
            )));
        }
        lifetime.ensure_at_most(CHALLENGE_LONGEST, "a second-factor challenge")?;
        Ok(Self {
            token_hash,
            session_id: *session.id(),
            expires_at: now.saturating_add(lifetime.duration()),
            failed_attempts: 0,
            usage: Usage::Unused,
            _scope: PhantomData,
        })
    }

    /// Rebuilds a challenge from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the challenge was
    ///   answered once it had lapsed.
    pub fn reconstitute(row: MfaChallengeRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            token_hash: row.token_hash,
            session_id: row.session_id,
            expires_at: row.expires_at,
            failed_attempts: row.failed_attempts,
            usage: row.usage,
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &MfaChallengeRow) -> Result<(), DomainError> {
        RowCheck::of("second-factor challenge")
            .holds(
                row.usage.used_at().is_none_or(|at| at < row.expires_at),
                "answered after it lapsed",
            )
            .finish()
    }

    /// One-way hash of the token the browser holds.
    #[must_use]
    pub fn token_hash(&self) -> &TokenHash {
        &self.token_hash
    }

    /// The session waiting on the second factor.
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// When the challenge lapses.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Wrong codes entered against it so far.
    #[must_use]
    pub fn failed_attempts(&self) -> u8 {
        self.failed_attempts
    }

    /// When the challenge was answered, if it was.
    #[must_use]
    pub fn consumed_at(&self) -> Option<OffsetDateTime> {
        self.usage.used_at()
    }

    /// Whether a code may still be tried against this challenge at `now`,
    /// when it closes after `max_failed_attempts` wrong codes. An answered
    /// challenge takes no more.
    ///
    /// The limit has the same width as the counter. A counter that stopped
    /// at its maximum is always at or past the limit. So no limit can be set
    /// that the count never reaches.
    #[must_use]
    pub fn is_open(&self, now: OffsetDateTime, max_failed_attempts: NonZeroU8) -> bool {
        !self.usage.is_used()
            && now < self.expires_at
            && self.failed_attempts < max_failed_attempts.get()
    }

    /// Closes the challenge at `now`, once the factor given against it was
    /// accepted, and gives back the session it was for. This is the only way
    /// it is answered.
    ///
    /// A refused call leaves the challenge as it was.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the challenge was answered already,
    ///   has lapsed, or took `max_failed_attempts` wrong codes.
    pub fn consume(
        &mut self,
        now: OffsetDateTime,
        max_failed_attempts: NonZeroU8,
    ) -> Result<SessionId, DomainError> {
        if !self.is_open(now, max_failed_attempts) {
            return Err(DomainError::forbidden(message!(
                "authentication-the-second-factor-challenge-is-answered",
                "the second-factor challenge is answered, lapsed or closed"
            )));
        }
        self.usage = Usage::Used { at: now };
        Ok(self.session_id)
    }

    /// Counts a wrong code.
    pub fn record_failure(&mut self) {
        self.failed_attempts = self.failed_attempts.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::sessions::session::tests::{
        signed_in_session, test_session,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;

    const MAX_ATTEMPTS: NonZeroU8 = NonZeroU8::new(5).unwrap();

    fn challenge_for(
        session: &Session<ResolvedTenant>,
        lifetime: Duration,
    ) -> Result<MfaChallenge<ResolvedTenant>, DomainError> {
        MfaChallenge::issue(
            session,
            TokenHash::from_stored("hash".to_owned()),
            Lifetime::new(lifetime).unwrap(),
        )
    }

    fn challenge() -> MfaChallenge<ResolvedTenant> {
        challenge_for(&test_session(), Duration::minutes(5)).unwrap()
    }

    /// Ann's sign-in is finished and owes nothing. No challenge opens for
    /// it, so no code typed there can change her session.
    #[test]
    fn a_finished_sign_in_gets_no_challenge() {
        assert!(matches!(
            challenge_for(&signed_in_session(), Duration::minutes(5)),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A challenge asked to stay open for a day is refused. Fifteen minutes
    /// is the most.
    #[test]
    fn a_challenge_stays_open_at_most_fifteen_minutes() {
        assert!(matches!(
            challenge_for(&test_session(), Duration::days(1)),
            Err(DomainError::Validation(_))
        ));
    }

    /// Ann's password is accepted on an app's host and a challenge opens. It
    /// takes codes straight away.
    #[test]
    fn a_new_challenge_is_open() {
        let challenge = challenge();

        assert!(challenge.is_open(crate::shared::clock::now(), MAX_ATTEMPTS));
    }

    /// At the instant a five minute challenge expires, it takes no more
    /// codes.
    #[test]
    fn a_challenge_closes_after_its_lifetime() {
        let challenge = challenge();

        assert!(!challenge.is_open(challenge.expires_at(), MAX_ATTEMPTS));
    }

    /// A challenge remains open until its fifth failed attempt reaches the limit.
    #[test]
    fn a_challenge_closes_after_too_many_wrong_codes() {
        let mut challenge = challenge();
        let now = crate::shared::clock::now();

        for _ in 0..MAX_ATTEMPTS.get() {
            assert!(challenge.is_open(now, MAX_ATTEMPTS));
            challenge.record_failure();
        }

        assert!(!challenge.is_open(now, MAX_ATTEMPTS));
    }

    /// Three hundred recorded failures leave the challenge closed even under
    /// the highest representable attempt limit.
    #[test]
    fn a_challenge_at_the_counter_ceiling_is_closed_under_the_highest_limit() {
        let mut challenge = challenge();
        let now = crate::shared::clock::now();

        for _ in 0..300 {
            challenge.record_failure();
        }

        assert!(!challenge.is_open(now, NonZeroU8::MAX));
    }

    /// Consuming a challenge returns its session id and records the use time.
    /// A second consume is refused and the challenge remains closed.
    #[test]
    fn a_challenge_is_answered_once() {
        let session = test_session();
        let mut challenge = challenge_for(&session, Duration::minutes(5)).unwrap();
        let now = crate::shared::clock::now();

        let answered = challenge.consume(now, MAX_ATTEMPTS).unwrap();
        let replayed = challenge.consume(now, MAX_ATTEMPTS);

        assert_eq!(answered, *session.id());
        assert!(matches!(replayed, Err(DomainError::Forbidden(_))));
        assert_eq!(challenge.consumed_at(), Some(now));
        assert!(!challenge.is_open(now, MAX_ATTEMPTS));
    }

    /// A challenge closed by failed attempts cannot be consumed and retains
    /// no successful-use time.
    #[test]
    fn a_closed_challenge_is_not_answered() {
        let mut challenge = challenge();
        let now = crate::shared::clock::now();
        for _ in 0..MAX_ATTEMPTS.get() {
            challenge.record_failure();
        }

        let refused = challenge.consume(now, MAX_ATTEMPTS);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(challenge.consumed_at(), None);
    }

    fn stored(usage: Usage) -> MfaChallengeRow {
        MfaChallengeRow {
            token_hash: TokenHash::from_stored("hash".to_owned()),
            session_id: SessionId::new(),
            expires_at: crate::shared::clock::now() + Duration::minutes(5),
            failed_attempts: 0,
            usage,
        }
    }

    /// A stored, consumed challenge remains closed, rejects another consume
    /// and preserves the original use time.
    #[test]
    fn a_stored_answered_challenge_stays_answered() {
        let answered_at = crate::shared::clock::now();
        let row = stored(Usage::Used { at: answered_at });
        let mut challenge = MfaChallenge::<ResolvedTenant>::reconstitute(row).unwrap();

        let replayed = challenge.consume(answered_at, MAX_ATTEMPTS);

        assert!(matches!(replayed, Err(DomainError::Forbidden(_))));
        assert!(!challenge.is_open(answered_at, MAX_ATTEMPTS));
        assert_eq!(challenge.consumed_at(), Some(answered_at));
    }

    /// A stored challenge says it was answered a second after it lapsed. No
    /// answer is taken once a challenge lapses, so loading it is refused as
    /// corrupt.
    #[test]
    fn a_stored_challenge_answered_after_it_lapsed_is_refused() {
        let mut row = stored(Usage::Unused);
        row.usage = Usage::Used {
            at: row.expires_at + Duration::SECOND,
        };

        assert!(refused_as_corrupt(
            &MfaChallenge::<ResolvedTenant>::reconstitute(row)
        ));
    }
}
