//! A tenant's assertion keys: the key pairs the gateway signs
//! `X-Ianua-Assertion` with, the identity it hands the services behind it,
//! and what else it hands them: the narrowed token a TokenExchange stage
//! mints and its message signatures, each typed apart.
//!
//! They are not the tenant's signing keys. The gateway faces the internet,
//! so it never holds the keys that sign the tenant's access tokens: a
//! gateway broken into could mint tokens every relying party believes.
//! Each tenant gets key pairs of its own for assertions alone, published
//! apart from its JWKS, and an assertion is typed apart from an access
//! token, so neither check takes the other. The worst a gateway broken
//! into can do with them is forge an assertion for traffic it carries
//! already.
//!
//! A tenant holds one key that signs. The platform rotates it by age, with
//! nobody asking: the old key stops signing and stays published for the
//! overlap, so an assertion it signed a moment before still verifies, and
//! is retired once the overlap is over. No person changes these keys, so
//! nothing here asks for a right.
//!
//! The private half is made by the platform, sealed as it is stored and
//! opened only for the gateway. Every other side, the worker rotating keys
//! and the API publishing them, works on the public half and the key's
//! standing and never reads the private half back.

use std::fmt;

use time::OffsetDateTime;

use crate::domains::crypto::events::assertion_keys::{
    AssertionKeyCreated, AssertionKeyRetired, AssertionKeyRotated,
};
use crate::domains::crypto::key_status::{KeyState, KeyStatus};
use crate::domains::crypto::rotation::KeyRotationSchedule;
use crate::domains::crypto::signing_key::SigningAlgorithm;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::security::secret::Secret;
use crate::shared::validation::distinct::first_repeat;
use crate::types::{Expiry, KeyId, Lifetime, PublicKeyPem};

/// The private half of an assertion key, as far as this side holds it.
#[derive(Clone)]
pub enum PrivateHalf {
    /// Just made and not stored yet. The store seals it as it writes the
    /// key.
    Fresh(Secret),
    /// Kept sealed in storage, and not opened here.
    Stored,
}

impl fmt::Debug for PrivateHalf {
    /// Names which it is, and never prints a fresh key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fresh(_) => f.write_str("Fresh(<redacted>)"),
            Self::Stored => f.write_str("Stored"),
        }
    }
}

/// One assertion key of a tenant: its public half, where it stands, and
/// its private half when it was just made.
#[derive(Debug, Clone)]
pub struct AssertionKey {
    kid: KeyId,
    algorithm: SigningAlgorithm,
    public_key: PublicKeyPem,
    private_half: PrivateHalf,
    state: KeyState,
    created_at: OffsetDateTime,
}

/// Persisted state of an [`AssertionKey`], without its private half.
pub struct AssertionKeyRow {
    /// The `kid` an assertion's header names.
    pub kid: KeyId,
    /// The algorithm it signs with.
    pub algorithm: SigningAlgorithm,
    /// The PEM-encoded public half.
    pub public_key: PublicKeyPem,
    /// Where the key stands. See [`KeyState::from_stored`].
    pub state: KeyState,
    /// When the key was made.
    pub created_at: OffsetDateTime,
}

/// A freshly generated assertion key pair.
pub struct NewAssertionKey {
    /// The key id an assertion's header names.
    pub kid: KeyId,
    /// The public half, PEM-encoded.
    pub public_key: PublicKeyPem,
    /// The private half, PEM-encoded.
    pub private_key: Secret,
}

impl AssertionKey {
    /// The algorithm every new assertion key signs with: ES256, which every
    /// common JWT library verifies, with small keys and fast signing on the
    /// request path. Upstreams verify with the algorithm the published key
    /// names, never the one an assertion's header claims.
    pub const ALGORITHM: SigningAlgorithm = SigningAlgorithm::Es256;

    /// A new key, active from now, signing with [`Self::ALGORITHM`].
    #[must_use]
    pub fn create(key: NewAssertionKey) -> Self {
        let NewAssertionKey {
            kid,
            public_key,
            private_key,
        } = key;
        Self {
            kid,
            algorithm: Self::ALGORITHM,
            public_key,
            private_half: PrivateHalf::Fresh(private_key),
            state: KeyState::Active,
            created_at: crate::shared::clock::now(),
        }
    }

    /// Rebuilds a key from storage. Its private half stays where it is
    /// kept.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the key was
    ///   rotated before it was made.
    pub fn reconstitute(row: AssertionKeyRow) -> Result<Self, DomainError> {
        RowCheck::of("assertion key")
            .in_order_if(
                row.created_at,
                row.state.rotated_at(),
                "rotated before it was made",
            )
            .finish()?;
        Ok(Self {
            kid: row.kid,
            algorithm: row.algorithm,
            public_key: row.public_key,
            private_half: PrivateHalf::Stored,
            state: row.state,
            created_at: row.created_at,
        })
    }

    /// The `kid` an assertion's header names.
    #[must_use]
    pub fn kid(&self) -> &KeyId {
        &self.kid
    }

    /// The algorithm it signs with.
    #[must_use]
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// The PEM-encoded public half, published for upstreams.
    #[must_use]
    pub fn public_key(&self) -> &PublicKeyPem {
        &self.public_key
    }

    /// The private half when the key was just made, or that it is kept in
    /// storage.
    #[must_use]
    pub fn private_half(&self) -> &PrivateHalf {
        &self.private_half
    }

    /// Where the key stands, with its rotation time once it was rotated.
    #[must_use]
    pub fn state(&self) -> KeyState {
        self.state
    }

    /// Active, rotated or retired.
    #[must_use]
    pub fn status(&self) -> KeyStatus {
        self.state.status()
    }

    /// When the key was made.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When the key stopped signing, if it has been rotated out.
    #[must_use]
    pub fn rotated_at(&self) -> Option<OffsetDateTime> {
        self.state.rotated_at()
    }

    /// Whether the key signs assertions.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == KeyState::Active
    }

    /// Whether an upstream may still accept assertions this key signed at
    /// `now`, so the published set lists it: while it signs, and for
    /// `overlap` after it was rotated out. A retired key never is.
    #[must_use]
    pub fn is_published(&self, overlap: Lifetime, now: OffsetDateTime) -> bool {
        self.state.is_published(Expiry::Never, overlap, now)
    }

    /// Whether a rotated key has stayed published for the whole `overlap`.
    fn overlap_is_over(&self, overlap: Lifetime, now: OffsetDateTime) -> bool {
        match self.state {
            KeyState::Rotated { at } => overlap.ends_after(at) <= now,
            KeyState::Active | KeyState::Revoked { .. } => false,
        }
    }

    fn rotate(&mut self) -> Result<(), DomainError> {
        self.move_to(KeyState::Rotated {
            at: crate::shared::clock::now(),
        })
    }

    fn move_to(&mut self, to: KeyState) -> Result<(), DomainError> {
        self.status()
            .try_transition(to.status())
            .map_err(|refused| {
                DomainError::invalid_transition(message!(
                    "crypto-assertion-key-cannot-move-from-to",
                    format!(
                        "assertion key {} cannot move from {:?} to {:?}",
                        self.kid, refused.from, refused.to
                    )
                ))
            })?;
        self.state = to;
        Ok(())
    }
}

/// The key that signs a tenant's assertions now, with its private half
/// opened. Only the gateway holds one.
///
/// It has no `Debug` that prints the private half: a log line or an error
/// chain that printed it would hand out the key.
#[derive(Clone)]
pub struct AssertionSigningKey {
    kid: KeyId,
    algorithm: SigningAlgorithm,
    private_key: Secret,
}

impl fmt::Debug for AssertionSigningKey {
    /// Names the key and its algorithm, the private half redacted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssertionSigningKey")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .field("private_key", &self.private_key)
            .finish()
    }
}

impl AssertionSigningKey {
    /// The key `set` signs with at `now`, with `private_key`, its private
    /// half as storage opened it.
    ///
    /// `None` when nothing in the set signs. Then nothing is signed, and
    /// nothing is forwarded with an identity.
    #[must_use]
    pub fn of<T: TenantScope>(set: &AssertionKeySet<T>, private_key: Secret) -> Option<Self> {
        set.signing_key().map(|key| Self {
            kid: key.kid.clone(),
            algorithm: key.algorithm,
            private_key,
        })
    }

    /// The `kid` the assertion's header names.
    #[must_use]
    pub fn kid(&self) -> &KeyId {
        &self.kid
    }

    /// The algorithm it signs with.
    #[must_use]
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// The private half, PEM-encoded.
    #[must_use]
    pub fn private_key(&self) -> &Secret {
        &self.private_key
    }
}

/// A tenant's assertion keys: the one that signs, and those rotated out
/// that upstreams may still accept.
///
/// The platform changes them on its own, and each change raises an event
/// for the trail: a key made where none signed, a key rotated by age, a
/// key retired after the overlap.
#[derive(Debug, Clone)]
pub struct AssertionKeySet<T: TenantScope> {
    keys: Vec<AssertionKey>,
    raised: Raised<T>,
}

impl<T: TenantScope> AssertionKeySet<T> {
    /// A tenant's first set, holding only `first`. Raises
    /// `crypto.assertion_key_created`.
    #[must_use]
    pub fn new(first: AssertionKey) -> Self {
        let mut set = Self {
            keys: Vec::new(),
            raised: Raised::default(),
        };
        set.raise_created(&first);
        set.keys.push(first);
        set
    }

    /// A set rebuilt from stored keys.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when two keys share a `kid`, so
    ///   retiring one would leave its twin published, or when more than one
    ///   key is active, so which one signs would be a guess.
    pub fn from_keys(keys: Vec<AssertionKey>) -> Result<Self, DomainError> {
        let active = keys.iter().filter(|key| key.is_active()).count();
        RowCheck::of("assertion key set")
            .holds(
                first_repeat(keys.iter().map(|key| key.kid().as_str())).is_none(),
                "two keys with the same kid",
            )
            .holds(active <= 1, "more than one key signs")
            .finish()?;
        Ok(Self {
            keys,
            raised: Raised::default(),
        })
    }

    /// Every key of the set.
    #[must_use]
    pub fn keys(&self) -> &[AssertionKey] {
        &self.keys
    }

    /// The key that signs assertions. `None` when every key is rotated out
    /// or retired: then nothing signs.
    #[must_use]
    pub fn signing_key(&self) -> Option<&AssertionKey> {
        self.keys.iter().find(|key| key.is_active())
    }

    /// The keys an upstream may accept at `now`, as
    /// [`AssertionKey::is_published`] judges with `overlap`.
    #[must_use]
    pub fn published(&self, overlap: Lifetime, now: OffsetDateTime) -> Vec<&AssertionKey> {
        self.keys
            .iter()
            .filter(|key| key.is_published(overlap, now))
            .collect()
    }

    /// Whether the set is due a new key at `now` on `schedule`: its signing
    /// key is older than the longest age, or nothing in it signs.
    #[must_use]
    pub fn is_due(&self, schedule: &KeyRotationSchedule, now: OffsetDateTime) -> bool {
        self.signing_key()
            .is_none_or(|key| key.created_at() <= schedule.due_before(now))
    }

    /// Rotates the signing key out onto `new_key` at `now`, on `schedule`.
    /// The old key stays published for the schedule's overlap. Raises
    /// `crypto.assertion_key_rotated` from the key that signed until now,
    /// or `crypto.assertion_key_created` when none did.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the set is not due, so a sweep run
    ///   twice rotates once, or when it holds a key with `new_key`'s `kid`.
    /// - [`DomainError::InvalidTransition`] when the active key refuses to
    ///   rotate, which its state machine never does.
    pub fn rotate_by_age(
        &mut self,
        schedule: &KeyRotationSchedule,
        new_key: AssertionKey,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if !self.is_due(schedule, now) {
            return Err(DomainError::conflict(message!(
                "crypto-the-assertion-key-is-not-due",
                "the assertion key is not due for rotation"
            )));
        }
        if self.keys.iter().any(|key| key.kid() == new_key.kid()) {
            return Err(DomainError::conflict(message!(
                "crypto-the-assertion-key-set-already-holds",
                format!(
                    "the assertion key set already holds a key with kid {}",
                    new_key.kid()
                )
            )));
        }
        let mut rotated_out = None;
        for key in self.keys.iter_mut().filter(|key| key.is_active()) {
            key.rotate()?;
            rotated_out = Some(key.kid().clone());
        }
        match rotated_out {
            Some(old_kid) => self.raise_rotated(old_kid, &new_key),
            None => self.raise_created(&new_key),
        }
        self.keys.push(new_key);
        Ok(())
    }

    /// Retires every key rotated out longer than `overlap` ago, and returns
    /// their ids. Until then the published set already leaves such a key
    /// out, since publishing is judged from the clock; this makes the
    /// stored standing say so too. Raises `crypto.assertion_key_retired`
    /// for each.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when a rotated key refuses to be
    ///   retired, which its state machine never does.
    pub fn retire_after_overlap(&mut self, overlap: Lifetime) -> Result<Vec<KeyId>, DomainError> {
        let now = crate::shared::clock::now();
        let mut retired = Vec::new();
        for key in self
            .keys
            .iter_mut()
            .filter(|key| key.overlap_is_over(overlap, now))
        {
            key.move_to(key.state.revoked())?;
            retired.push(key.kid().clone());
        }
        for kid in &retired {
            self.raise_retired(kid.clone());
        }
        Ok(retired)
    }

    /// Raises `crypto.assertion_key_created` for `key`, which signs where
    /// no key did.
    fn raise_created(&mut self, key: &AssertionKey) {
        self.raised.raise(AssertionKeyCreated {
            kid: key.kid().clone(),
            occurred_at: key.created_at(),
        });
    }

    /// Raises `crypto.assertion_key_rotated` from `old_kid`, the key that
    /// signed until now, to `new_key`.
    fn raise_rotated(&mut self, old_kid: KeyId, new_key: &AssertionKey) {
        self.raised.raise(AssertionKeyRotated {
            old_kid,
            new_kid: new_key.kid().clone(),
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// Raises `crypto.assertion_key_retired` for `kid`.
    fn raise_retired(&mut self, kid: KeyId) {
        self.raised.raise(AssertionKeyRetired {
            kid,
            occurred_at: crate::shared::clock::now(),
        });
    }
}

impl<T: TenantScope> Raises for AssertionKeySet<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::{raised, raised_names};

    const PUBLIC: &str = "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----";

    fn fresh(kid: &str) -> AssertionKey {
        AssertionKey::create(NewAssertionKey {
            kid: KeyId::new(kid).unwrap(),
            public_key: PublicKeyPem::new(PUBLIC).unwrap(),
            private_key: Secret::new(format!("private-{kid}")),
        })
    }

    fn stored(kid: &str, state: KeyState, created_at: OffsetDateTime) -> AssertionKey {
        AssertionKey::reconstitute(AssertionKeyRow {
            kid: KeyId::new(kid).unwrap(),
            algorithm: SigningAlgorithm::Es256,
            public_key: PublicKeyPem::new(PUBLIC).unwrap(),
            state,
            created_at,
        })
        .unwrap()
    }

    /// Rotating every thirty days, a rotated key published for a day.
    fn monthly() -> KeyRotationSchedule {
        KeyRotationSchedule::new(
            Lifetime::seconds(30 * 86_400).unwrap(),
            Lifetime::seconds(86_400).unwrap(),
        )
        .unwrap()
    }

    fn kids(keys: &[&AssertionKey]) -> Vec<String> {
        keys.iter()
            .map(|key| key.kid().as_str().to_owned())
            .collect()
    }

    /// A new key signs with ES256, is active and carries the private half
    /// it was made with until it is stored.
    #[test]
    fn a_new_key_signs_with_es256_and_holds_its_fresh_private_half() {
        let key = fresh("a1");

        assert_eq!(key.algorithm(), SigningAlgorithm::Es256);
        assert!(key.is_active());
        assert!(matches!(
            key.private_half(),
            PrivateHalf::Fresh(secret) if secret.expose() == "private-a1"
        ));
    }

    /// A key read back from storage holds no private half: the side that
    /// rotates and publishes keys never opens one.
    #[test]
    fn a_stored_key_holds_no_private_half() {
        let key = stored("a1", KeyState::Active, crate::shared::clock::now());

        assert!(matches!(key.private_half(), PrivateHalf::Stored));
    }

    /// Debug output for fresh and signing keys retains the key id but omits
    /// their private material.
    #[test]
    fn debug_never_prints_a_private_half() {
        let key = fresh("a1");
        let set = AssertionKeySet::<ResolvedTenant>::new(key.clone());
        let signing = AssertionSigningKey::of(&set, Secret::new("private-a1")).unwrap();

        let printed = format!("{key:?} {signing:?}");

        assert!(!printed.contains("private-a1"), "{printed}");
        assert!(printed.contains("a1"), "{printed}");
    }

    /// A stored rotation before the key's creation is refused as corrupt.
    #[test]
    fn a_key_rotated_before_it_was_made_is_refused() {
        let made = crate::shared::clock::now();

        let row = AssertionKey::reconstitute(AssertionKeyRow {
            kid: KeyId::new("a1").unwrap(),
            algorithm: SigningAlgorithm::Es256,
            public_key: PublicKeyPem::new(PUBLIC).unwrap(),
            state: KeyState::Rotated {
                at: made - time::Duration::SECOND,
            },
            created_at: made,
        });

        assert!(refused_as_corrupt(&row));
    }

    /// Stored sets with duplicate key ids or two active signers are refused
    /// as corrupt because neither gives an unambiguous signing key.
    #[test]
    fn a_stored_set_with_twins_or_two_signers_is_refused() {
        let now = crate::shared::clock::now();

        let twins = AssertionKeySet::<ResolvedTenant>::from_keys(vec![
            stored("a1", KeyState::Active, now),
            stored("a1", KeyState::Rotated { at: now }, now),
        ]);
        let two_signers = AssertionKeySet::<ResolvedTenant>::from_keys(vec![
            stored("a1", KeyState::Active, now),
            stored("a2", KeyState::Active, now),
        ]);

        assert!(refused_as_corrupt(&twins));
        assert!(refused_as_corrupt(&two_signers));
    }

    /// Acme's key has signed for 31 days. It is rotated: the new key signs,
    /// the old one stays published through the overlap and not after it.
    #[test]
    fn an_old_key_is_rotated_and_published_through_the_overlap() {
        let now = crate::shared::clock::now();
        let mut set = AssertionKeySet::<ResolvedTenant>::from_keys(vec![stored(
            "old",
            KeyState::Active,
            now - time::Duration::days(31),
        )])
        .unwrap();
        {
            let _frozen = crate::shared::clock::freeze(now);
            set.rotate_by_age(&monthly(), fresh("new"), now).unwrap();
        }

        let within = set.published(monthly().overlap(), now + time::Duration::hours(23));
        let after = set.published(monthly().overlap(), now + time::Duration::days(2));

        assert_eq!(set.signing_key().unwrap().kid().as_str(), "new");
        assert_eq!(kids(&within), ["old", "new"]);
        assert_eq!(kids(&after), ["new"]);
    }

    /// Rotating a fresh key returns a conflict and adds no key to the set.
    #[test]
    fn a_young_key_is_not_rotated() {
        let now = crate::shared::clock::now();
        let mut set = AssertionKeySet::<ResolvedTenant>::new(fresh("a1"));

        let refused = set.rotate_by_age(&monthly(), fresh("a2"), now);

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
        assert_eq!(set.keys().len(), 1);
    }

    /// A set where nothing signs, because a key was retired by hand in the
    /// database, is due at once, so the sweep gives the tenant a key again
    /// instead of leaving its routes refused.
    #[test]
    fn a_set_where_nothing_signs_is_due() {
        let now = crate::shared::clock::now();
        let mut set = AssertionKeySet::<ResolvedTenant>::from_keys(vec![stored(
            "a1",
            KeyState::Rotated { at: now },
            now,
        )])
        .unwrap();

        set.rotate_by_age(&monthly(), fresh("a2"), now).unwrap();

        assert_eq!(set.signing_key().unwrap().kid().as_str(), "a2");
    }

    /// Rotation cannot reuse an existing key id; the conflict leaves the
    /// current key active.
    #[test]
    fn rotating_onto_a_known_kid_is_refused() {
        let now = crate::shared::clock::now();
        let mut set = AssertionKeySet::<ResolvedTenant>::from_keys(vec![stored(
            "a1",
            KeyState::Active,
            now - time::Duration::days(31),
        )])
        .unwrap();

        let refused = set.rotate_by_age(&monthly(), fresh("a1"), now);

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
        assert!(set.keys()[0].is_active());
    }

    /// A key rotated out two days ago is retired under a day's overlap; one
    /// rotated an hour ago and the one that signs are left.
    #[test]
    fn only_keys_past_their_overlap_are_retired() {
        let now = crate::shared::clock::now();
        let mut set = AssertionKeySet::<ResolvedTenant>::from_keys(vec![
            stored(
                "old",
                KeyState::Rotated {
                    at: now - time::Duration::days(2),
                },
                now - time::Duration::days(40),
            ),
            stored(
                "recent",
                KeyState::Rotated {
                    at: now - time::Duration::HOUR,
                },
                now - time::Duration::days(31),
            ),
            stored("current", KeyState::Active, now - time::Duration::HOUR),
        ])
        .unwrap();

        let retired = set.retire_after_overlap(monthly().overlap()).unwrap();

        assert_eq!(retired, [KeyId::new("old").unwrap()]);
        assert_eq!(set.keys()[0].status(), KeyStatus::Revoked);
        assert_eq!(set.keys()[1].status(), KeyStatus::Rotated);
        assert!(set.keys()[2].is_active());
    }

    /// The key that signs is the set's active one; a set where nothing
    /// signs gives no key to sign with.
    #[test]
    fn the_signing_key_is_the_active_one_or_none() {
        let now = crate::shared::clock::now();
        let signing = AssertionKeySet::<ResolvedTenant>::from_keys(vec![
            stored("old", KeyState::Rotated { at: now }, now),
            stored("current", KeyState::Active, now),
        ])
        .unwrap();
        let silent = AssertionKeySet::<ResolvedTenant>::from_keys(vec![stored(
            "old",
            KeyState::Rotated { at: now },
            now,
        )])
        .unwrap();

        let key = AssertionSigningKey::of(&signing, Secret::new("pem")).unwrap();

        assert_eq!(key.kid().as_str(), "current");
        assert!(AssertionSigningKey::of(&silent, Secret::new("pem")).is_none());
    }

    /// Acme's first assertion key is made at its setup. The new set raises
    /// that a key was made, and a set read back from storage raises
    /// nothing.
    #[test]
    fn a_first_set_raises_a_key_made_and_a_stored_one_nothing() {
        let now = crate::shared::clock::now();
        let mut first = AssertionKeySet::<ResolvedTenant>::new(fresh("a1"));
        let mut stored_set =
            AssertionKeySet::<ResolvedTenant>::from_keys(vec![stored("a1", KeyState::Active, now)])
                .unwrap();

        assert_eq!(raised_names(&mut first), ["crypto.assertion_key_created"]);
        assert!(raised_names(&mut stored_set).is_empty());
    }

    /// Acme's key has signed for 31 days and the sweep rotates it. The
    /// rotation is raised from the old kid to the new one.
    #[test]
    fn rotating_raises_the_rotation_from_the_key_that_signed() {
        let now = crate::shared::clock::now();
        let mut set = AssertionKeySet::<ResolvedTenant>::from_keys(vec![stored(
            "old",
            KeyState::Active,
            now - time::Duration::days(31),
        )])
        .unwrap();

        set.rotate_by_age(&monthly(), fresh("new"), now).unwrap();

        let events = raised(&mut set);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "crypto.assertion_key_rotated"
        );
        let payload = events[0].payload();
        let Some(FieldValue::Change(change)) = payload.value("kid") else {
            panic!("expected a kid change");
        };
        assert_eq!(change.from(), Some("old"));
        assert_eq!(change.to(), Some("new"));
    }

    /// A set where nothing signs gets a key from the sweep. Nothing was
    /// rotated out, so a key made is raised, not a rotation.
    #[test]
    fn a_key_given_where_nothing_signed_raises_a_key_made() {
        let now = crate::shared::clock::now();
        let mut set = AssertionKeySet::<ResolvedTenant>::from_keys(vec![stored(
            "a1",
            KeyState::Rotated { at: now },
            now,
        )])
        .unwrap();

        set.rotate_by_age(&monthly(), fresh("a2"), now).unwrap();

        assert_eq!(raised_names(&mut set), ["crypto.assertion_key_created"]);
    }

    /// A key that is not due cannot be rotated, and the refusal raises no
    /// event for the audit trail.
    #[test]
    fn a_refused_rotation_raises_nothing() {
        let now = crate::shared::clock::now();
        let mut set =
            AssertionKeySet::<ResolvedTenant>::from_keys(vec![stored("a1", KeyState::Active, now)])
                .unwrap();

        let refused = set.rotate_by_age(&monthly(), fresh("a2"), now);

        assert!(refused.is_err());
        assert!(raised_names(&mut set).is_empty());
    }

    /// The sweep retires two keys past their overlap. Each is raised once;
    /// the one still in its overlap is not.
    #[test]
    fn retiring_raises_one_event_per_key_retired() {
        let now = crate::shared::clock::now();
        let long_ago = KeyState::Rotated {
            at: now - time::Duration::days(3),
        };
        let mut set = AssertionKeySet::<ResolvedTenant>::from_keys(vec![
            stored("a1", long_ago, now - time::Duration::days(70)),
            stored("a2", long_ago, now - time::Duration::days(40)),
            stored(
                "a3",
                KeyState::Rotated {
                    at: now - time::Duration::HOUR,
                },
                now - time::Duration::days(31),
            ),
        ])
        .unwrap();

        set.retire_after_overlap(monthly().overlap()).unwrap();

        assert_eq!(
            raised_names(&mut set),
            [
                "crypto.assertion_key_retired",
                "crypto.assertion_key_retired"
            ]
        );
    }
}
