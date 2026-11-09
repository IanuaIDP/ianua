//! The credentials a consumer signs in with: the one in use, and the one it
//! replaced while the consumer's callers move over.
//!
//! A partner integration cannot switch to a new API key at the instant an
//! admin rotates it. Its deploy takes minutes or hours. So a rotation may keep
//! the old credential working for a short, bounded overlap, and never longer.
//! Each credential also carries its own expiry, so a key handed to a
//! contractor for a month stops working without anyone remembering it.

use time::{Duration, OffsetDateTime};

use crate::domains::consumers::credential::ConsumerCredentialKind;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{Expiry, RotationOverlap};

/// The longest an old credential keeps working after a rotation.
///
/// A week is enough for any caller to deploy its new credential. A longer
/// overlap would leave a leaked key working long after it was replaced.
pub(crate) const MAX_OVERLAP: Duration = Duration::days(7);

/// One credential a consumer holds, with when it stops working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldCredential {
    kind: ConsumerCredentialKind,
    expiry: Expiry,
}

impl HeldCredential {
    /// `kind`, working until `expiry`.
    #[must_use]
    pub fn new(kind: ConsumerCredentialKind, expiry: Expiry) -> Self {
        Self { kind, expiry }
    }

    /// How the consumer signs in with it.
    #[must_use]
    pub fn kind(&self) -> &ConsumerCredentialKind {
        &self.kind
    }

    /// When it stops working.
    #[must_use]
    pub fn expiry(&self) -> Expiry {
        self.expiry
    }

    /// Whether it still works at `now`.
    fn is_live(&self, now: OffsetDateTime) -> bool {
        !self.expiry.has_passed(now)
    }
}

/// The credential a consumer used before its last rotation, if it still
/// works.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviousCredential {
    /// The old credential no longer works, or there never was one.
    Retired,
    /// The old credential works until `until`, so callers can move over.
    Overlapping {
        /// The old credential.
        credential: HeldCredential,
        /// When the overlap ends. From this instant on it is refused.
        until: OffsetDateTime,
    },
}

/// A move to a new credential.
pub struct CredentialRotation {
    /// How the consumer signs in from now on.
    pub credential: ConsumerCredentialKind,
    /// When the new credential stops working.
    pub expiry: Expiry,
    /// How long the old credential keeps working.
    pub overlap: RotationOverlap,
}

/// What a consumer signs in with: its current credential, and the previous
/// one while an overlap lasts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerCredentials {
    current: HeldCredential,
    previous: PreviousCredential,
}

impl ConsumerCredentials {
    /// A first credential, `kind`, working until `expiry`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `expiry` has already passed.
    pub fn issue(kind: ConsumerCredentialKind, expiry: Expiry) -> Result<Self, DomainError> {
        ensure_ahead(expiry)?;
        Ok(Self {
            current: HeldCredential::new(kind, expiry),
            previous: PreviousCredential::Retired,
        })
    }

    /// The credentials as stored, once the consumer's row was checked with
    /// [`Self::stored_parts_fit`].
    pub(crate) fn stored(current: HeldCredential, previous: PreviousCredential) -> Self {
        Self { current, previous }
    }

    /// The credential in use.
    #[must_use]
    pub fn current(&self) -> &HeldCredential {
        &self.current
    }

    /// The credential used before the last rotation, while it still works.
    #[must_use]
    pub fn previous(&self) -> &PreviousCredential {
        &self.previous
    }

    /// These credentials with the one `rotation` names in use, and the
    /// current one kept as its overlap says.
    ///
    /// Only two credentials ever work at once. A credential kept from an
    /// earlier rotation is dropped here. An old credential that has already
    /// expired is not kept, whatever `overlap` says.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the new credential has already
    ///   expired.
    /// - [`DomainError::Validation`] when it is the credential in use.
    /// - [`DomainError::Validation`] when the overlap is longer than
    ///   `MAX_OVERLAP`.
    pub(crate) fn rotated(&self, rotation: CredentialRotation) -> Result<Self, DomainError> {
        ensure_ahead(rotation.expiry)?;
        if rotation.credential == self.current.kind {
            return Err(DomainError::invalid(message!(
                "consumers-the-new-credential-is-the-one",
                "the new credential is the one already in use"
            )));
        }
        let previous = self.kept(rotation.overlap)?;
        Ok(Self {
            current: HeldCredential::new(rotation.credential, rotation.expiry),
            previous,
        })
    }

    /// When the previous credential stops working: the end of its overlap,
    /// or `now` when none is kept.
    pub(crate) fn previous_works_until(&self, now: OffsetDateTime) -> OffsetDateTime {
        match &self.previous {
            PreviousCredential::Overlapping { until, .. } => *until,
            PreviousCredential::Retired => now,
        }
    }

    /// What becomes of the current credential when it is replaced.
    fn kept(&self, overlap: RotationOverlap) -> Result<PreviousCredential, DomainError> {
        let now = crate::shared::clock::now();
        let Some(until) = overlap.ends(now, MAX_OVERLAP, "an old credential")? else {
            return Ok(PreviousCredential::Retired);
        };
        if !self.current.is_live(now) {
            return Ok(PreviousCredential::Retired);
        }
        Ok(PreviousCredential::Overlapping {
            credential: self.current.clone(),
            until,
        })
    }

    /// These credentials with the previous one stopped now.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when no previous credential is
    ///   kept.
    pub(crate) fn without_previous(&self) -> Result<Self, DomainError> {
        if self.previous == PreviousCredential::Retired {
            return Err(DomainError::invalid_transition(message!(
                "consumers-no-previous-credential-is-kept",
                "no previous credential is kept"
            )));
        }
        Ok(Self {
            current: self.current.clone(),
            previous: PreviousCredential::Retired,
        })
    }

    /// These credentials with the current one working until `expiry`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `expiry` has already passed.
    pub(crate) fn expiring(&self, expiry: Expiry) -> Result<Self, DomainError> {
        ensure_ahead(expiry)?;
        Ok(Self {
            current: HeldCredential::new(self.current.kind.clone(), expiry),
            previous: self.previous.clone(),
        })
    }

    /// Every credential that works now: the current one unless it expired,
    /// and the previous one while its overlap lasts and it has not expired.
    pub fn live(&self) -> impl Iterator<Item = &ConsumerCredentialKind> {
        self.live_until().map(|(kind, _)| kind)
    }

    /// Every credential that works now, as [`live`](Self::live) gives them,
    /// each with when it stops working: its own expiry, and for the
    /// previous one the end of its overlap if that comes first.
    pub fn live_until(&self) -> impl Iterator<Item = (&ConsumerCredentialKind, Expiry)> {
        let now = crate::shared::clock::now();
        let previous = match &self.previous {
            PreviousCredential::Overlapping { credential, until } if now < *until => {
                Some((credential, credential.expiry.earliest(Expiry::At(*until))))
            }
            PreviousCredential::Overlapping { .. } | PreviousCredential::Retired => None,
        };
        std::iter::once((&self.current, self.current.expiry))
            .chain(previous)
            .filter(move |(held, _)| held.is_live(now))
            .map(|(held, until)| (held.kind(), until))
    }

    /// Whether stored credentials, `current` and `previous`, keep the rules
    /// a rotation keeps, for a consumer created at `created_at` and last
    /// changed at `updated_at`.
    ///
    /// A kept credential is never the current one, and its overlap ends after
    /// the consumer was made and no more than `MAX_OVERLAP` after its last
    /// change.
    pub(crate) fn stored_parts_fit(
        current: &HeldCredential,
        previous: &PreviousCredential,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> bool {
        match previous {
            PreviousCredential::Retired => true,
            PreviousCredential::Overlapping { credential, until } => {
                credential.kind != current.kind
                    && *until > created_at
                    && *until <= updated_at.saturating_add(MAX_OVERLAP)
            }
        }
    }
}

/// Refuses an expiry that has already passed. A credential made expired
/// would read as set up while nothing could sign in with it.
fn ensure_ahead(expiry: Expiry) -> Result<(), DomainError> {
    if expiry.has_passed(crate::shared::clock::now()) {
        return Err(DomainError::invalid(message!(
            "consumers-a-credential-s-expiry-must-lie",
            "a credential's expiry must lie in the future"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{KeyPrefix, Lifetime, TokenHash};

    fn start() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
    }

    fn key(digest: &str) -> ConsumerCredentialKind {
        ConsumerCredentialKind::ApiKey {
            prefix: KeyPrefix::new("sk_live_abc").unwrap(),
            key_hash: TokenHash::from_stored(digest.to_owned()),
        }
    }

    fn lasting(hours: i64) -> Expiry {
        Expiry::At(start() + Duration::hours(hours))
    }

    /// A rotation to the never-expiring key `digest`, keeping the old one
    /// for `hours`.
    fn to(digest: &str, hours: i64) -> CredentialRotation {
        CredentialRotation {
            credential: key(digest),
            expiry: Expiry::Never,
            overlap: RotationOverlap::For(Lifetime::new(Duration::hours(hours)).unwrap()),
        }
    }

    fn live_count(credentials: &ConsumerCredentials) -> usize {
        credentials.live().count()
    }

    /// Fay issues "billing-sync" a key that expired an hour ago. It is
    /// refused, since nothing could sign in with it.
    #[test]
    fn a_credential_cannot_be_issued_already_expired() {
        let _frozen = crate::shared::clock::freeze(start());

        assert!(ConsumerCredentials::issue(key("old"), lasting(-1)).is_err());
        assert!(ConsumerCredentials::issue(key("new"), lasting(1)).is_ok());
    }

    /// A key issued for one day is absent from the live credential list
    /// when checked two days after issuance.
    #[test]
    fn an_expired_credential_does_not_work() {
        let credentials = {
            let _frozen = crate::shared::clock::freeze(start());
            ConsumerCredentials::issue(key("contractor"), lasting(24)).unwrap()
        };

        let _later = crate::shared::clock::freeze(start() + Duration::hours(48));

        assert_eq!(live_count(&credentials), 0);
    }

    /// Ann rotates the key of "billing-sync", keeping the old one for a day.
    /// For that day both keys work. Afterwards only the new one does.
    #[test]
    fn the_old_credential_works_only_while_the_overlap_lasts() {
        let _frozen = crate::shared::clock::freeze(start());
        let credentials = ConsumerCredentials::issue(key("old"), Expiry::Never)
            .unwrap()
            .rotated(to("new", 24))
            .unwrap();

        assert_eq!(live_count(&credentials), 2);
        let _after = crate::shared::clock::freeze(start() + Duration::hours(24));
        let live: Vec<_> = credentials.live().collect();
        assert_eq!(live, vec![&key("new")]);
    }

    /// Rotation rejects a thirty-day overlap for the old key while
    /// accepting an overlap of exactly one week.
    #[test]
    fn an_overlap_longer_than_a_week_is_refused() {
        let _frozen = crate::shared::clock::freeze(start());
        let credentials = ConsumerCredentials::issue(key("old"), Expiry::Never).unwrap();

        let month = credentials.rotated(to("new", 720));
        let week = credentials.rotated(to("new", 168));

        assert!(month.is_err());
        assert!(week.is_ok());
    }

    /// Ann rotates twice in a row, keeping old keys each time. Only the
    /// newest two keys work, never three.
    #[test]
    fn at_most_two_credentials_work_at_once() {
        let _frozen = crate::shared::clock::freeze(start());
        let credentials = ConsumerCredentials::issue(key("first"), Expiry::Never)
            .unwrap()
            .rotated(to("second", 24))
            .unwrap()
            .rotated(to("third", 24))
            .unwrap();

        let live: Vec<_> = credentials.live().collect();

        assert_eq!(live, vec![&key("third"), &key("second")]);
    }

    /// Ann rotates to the key already in use. It is refused, since nothing
    /// would change.
    #[test]
    fn rotating_to_the_same_credential_is_refused() {
        let _frozen = crate::shared::clock::freeze(start());
        let credentials = ConsumerCredentials::issue(key("same"), Expiry::Never).unwrap();

        let rotated = credentials.rotated(to("same", 1));

        assert!(rotated.is_err());
    }

    /// The old key had already expired when Ann rotated, keeping it for a
    /// day. It is not kept, so it does not come back to life.
    #[test]
    fn an_expired_credential_is_not_kept_by_a_rotation() {
        let credentials = {
            let _frozen = crate::shared::clock::freeze(start());
            ConsumerCredentials::issue(key("old"), lasting(1)).unwrap()
        };
        let _later = crate::shared::clock::freeze(start() + Duration::hours(2));

        let rotated = credentials.rotated(to("new", 24)).unwrap();

        assert_eq!(rotated.previous(), &PreviousCredential::Retired);
    }

    /// Ann ends the overlap early once every caller moved over. The old key
    /// stops working. Ending it again is refused, as there is none left.
    #[test]
    fn ending_the_overlap_stops_the_old_credential() {
        let _frozen = crate::shared::clock::freeze(start());
        let credentials = ConsumerCredentials::issue(key("old"), Expiry::Never)
            .unwrap()
            .rotated(to("new", 24))
            .unwrap();

        let ended = credentials.without_previous().unwrap();

        assert_eq!(live_count(&ended), 1);
        assert!(ended.without_previous().is_err());
    }

    /// Ann moves the key's expiry to tomorrow; moving it to yesterday is
    /// refused.
    #[test]
    fn a_new_expiry_must_lie_ahead() {
        let _frozen = crate::shared::clock::freeze(start());
        let credentials = ConsumerCredentials::issue(key("key"), Expiry::Never).unwrap();

        assert!(credentials.expiring(lasting(24)).is_ok());
        assert!(credentials.expiring(lasting(-24)).is_err());
    }

    /// A stored overlap ending a month after the consumer last changed, one
    /// ending before it was made, and one keeping the current key are each
    /// out of rule. A day's overlap fits.
    #[test]
    fn stored_overlaps_are_held_to_the_rotation_rules() {
        let fits = |previous: ConsumerCredentialKind, until: OffsetDateTime| {
            ConsumerCredentials::stored_parts_fit(
                &HeldCredential::new(key("new"), Expiry::Never),
                &PreviousCredential::Overlapping {
                    credential: HeldCredential::new(previous, Expiry::Never),
                    until,
                },
                start(),
                start(),
            )
        };

        assert!(!fits(key("old"), start() + Duration::days(30)));
        assert!(!fits(key("old"), start() - Duration::days(1)));
        assert!(!fits(key("new"), start() + Duration::days(1)));
        assert!(fits(key("old"), start() + Duration::days(1)));
    }
}
