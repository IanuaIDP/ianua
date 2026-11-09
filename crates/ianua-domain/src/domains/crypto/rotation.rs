//! The platform rotating a tenant's signing key on a schedule, by age.
//!
//! A key that signs for years gives a thief who copies it years of tokens
//! every relying party believes. So the platform rotates each tenant's key
//! once it is older than the schedule's longest age, with nobody asking.
//! The old key stays published for the overlap, so tokens it signed just
//! before still verify, and is gone before the next rotation: at most two
//! keys are ever published.

use std::num::NonZeroU32;

use time::OffsetDateTime;

use crate::domains::crypto::signing_key::{SigningKey, SigningKeySet};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::Lifetime;

/// How often the platform rotates signing keys, and how long a rotated key
/// stays published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRotationSchedule {
    max_age: Lifetime,
    overlap: Lifetime,
}

impl KeyRotationSchedule {
    /// The schedule of every tenant's assertion keys: rotated after thirty
    /// days, a rotated key published for one more. An assertion lasts
    /// seconds, so the overlap only has to outlast what an upstream caches
    /// of the published set. No setting names it: nobody gains from a key
    /// the gateway holds signing for longer.
    pub const FOR_ASSERTION_KEYS: Self = Self {
        max_age: Lifetime::from_secs(NonZeroU32::new(30 * 86_400).unwrap()),
        overlap: Lifetime::from_secs(NonZeroU32::new(86_400).unwrap()),
    };

    /// A schedule rotating keys older than `max_age`, a rotated key staying
    /// published for `overlap`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `overlap` is not shorter than
    ///   `max_age`: rotated keys would pile up in the JWKS, each still
    ///   believed when the next rotation comes.
    pub fn new(max_age: Lifetime, overlap: Lifetime) -> Result<Self, DomainError> {
        if overlap.duration() >= max_age.duration() {
            return Err(DomainError::invalid(message!(
                "crypto-a-rotated-key-must-stop-being",
                "a rotated key must stop being published before the next rotation"
            )));
        }
        Ok(Self { max_age, overlap })
    }

    /// The longest a key signs before it is rotated.
    #[must_use]
    pub fn max_age(&self) -> Lifetime {
        self.max_age
    }

    /// How long a rotated key stays published.
    #[must_use]
    pub fn overlap(&self) -> Lifetime {
        self.overlap
    }

    /// The time before which a signing key made at `now` is due: one made
    /// earlier is older than the longest age.
    #[must_use]
    pub fn due_before(&self, now: OffsetDateTime) -> OffsetDateTime {
        now.saturating_sub(self.max_age.duration())
    }

    /// The key in `set` signing at `now`, when it is older than the longest
    /// age. A set where nothing signs has nothing to rotate.
    #[must_use]
    pub fn due_key<'k, T: TenantScope>(
        &self,
        set: &'k SigningKeySet<T>,
        now: OffsetDateTime,
    ) -> Option<&'k SigningKey> {
        set.active_key(now)
            .filter(|key| key.created_at() <= self.due_before(now))
    }

    /// Rotates `set` onto `new_key` at `now`, on this schedule. Raises
    /// `crypto.key_rotated`. The platform does it, so no person's right is
    /// asked; the schedule is what allows it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the key signing now is not older
    ///   than the longest age. A job run twice rotates once.
    /// - The cases [`SigningKeySet::rotate_to`] lists, but the right.
    pub fn rotate<T: TenantScope>(
        &self,
        set: &mut SigningKeySet<T>,
        new_key: SigningKey,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if self.due_key(set, now).is_none() {
            return Err(DomainError::conflict(message!(
                "crypto-the-signing-key-is-not-due",
                "the signing key is not due for rotation"
            )));
        }
        set.rotate_onto(new_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::crypto::key_status::KeyStatus;
    use crate::domains::crypto::signing_key::{NewSigningKey, SigningAlgorithm};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::security::secret::Secret;
    use crate::test_support::events::raised_names;
    use crate::types::{Expiry, KeyId, PublicKeyPem};

    /// Rotating every ninety days, a rotated key published for a day.
    fn quarterly() -> KeyRotationSchedule {
        KeyRotationSchedule::new(
            Lifetime::seconds(90 * 86_400).unwrap(),
            Lifetime::seconds(86_400).unwrap(),
        )
        .unwrap()
    }

    /// A fresh key under `kid`.
    fn key(kid: &str) -> SigningKey {
        SigningKey::create(NewSigningKey {
            kid: KeyId::new(kid).unwrap(),
            algorithm: SigningAlgorithm::Rs256,
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----",
            )
            .unwrap(),
            private_key: Secret::new(format!("private-{kid}")),
            expires_at: Expiry::Never,
        })
    }

    /// Acme's key has signed for ninety-one days. It is due, the job
    /// rotates it, the new key signs, and the old one stays published
    /// through the overlap.
    #[test]
    fn a_key_older_than_the_longest_age_is_rotated() {
        let made = crate::shared::clock::now();
        let mut set = SigningKeySet::<ResolvedTenant>::new(key("key-old"));
        let _ = raised_names(&mut set);
        let later = made + time::Duration::days(91);
        let _frozen = crate::shared::clock::freeze(later);

        quarterly().rotate(&mut set, key("key-new"), later).unwrap();

        let signer = set.active_key(later).unwrap();
        assert_eq!(signer.kid().as_str(), "key-new");
        assert_eq!(set.keys()[0].status(), KeyStatus::Rotated);
        assert_eq!(set.jwks_keys(quarterly().overlap(), later).len(), 2);
        assert_eq!(raised_names(&mut set), ["crypto.key_rotated"]);
    }

    /// A fresh key is not due for rotation. Attempting it returns a conflict
    /// and leaves the set with its single key.
    #[test]
    fn a_young_key_is_not_rotated() {
        let now = crate::shared::clock::now();
        let mut set = SigningKeySet::<ResolvedTenant>::new(key("key-1"));

        let refused = quarterly().rotate(&mut set, key("key-2"), now);

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
        assert!(quarterly().due_key(&set, now).is_none());
        assert_eq!(set.keys().len(), 1);
    }

    /// An overlap equal to the rotation interval is refused, so schedules
    /// cannot keep a rotated key published until the next rotation.
    #[test]
    fn the_overlap_must_end_before_the_next_rotation() {
        let day = Lifetime::seconds(86_400).unwrap();

        let result = KeyRotationSchedule::new(day, day);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// The assertion keys' fixed schedule keeps the rule every schedule
    /// keeps: a rotated key is gone before the next rotation.
    #[test]
    fn the_assertion_keys_schedule_is_one_new_would_accept() {
        let fixed = KeyRotationSchedule::FOR_ASSERTION_KEYS;

        let checked = KeyRotationSchedule::new(fixed.max_age(), fixed.overlap());

        assert_eq!(checked.unwrap(), fixed);
    }
}
