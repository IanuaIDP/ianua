use std::fmt;
use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::crypto::control::CryptoControlCheck;
use crate::domains::crypto::events::keys::{KeyCreated, KeyRevoked, KeyRotated};
use crate::domains::crypto::key_status::{KeyState, KeyStatus};
use crate::domains::crypto::verifying_key::VerifyingKey;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::security::secret::Secret;
use crate::shared::validation::distinct::first_repeat;
use crate::types::{Expiry, KeyId, Lifetime, PublicKeyPem};

/// The signing algorithm used for JWT tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SigningAlgorithm {
    /// RSA with SHA-256. Widely supported, with larger keys.
    #[cfg_attr(feature = "serde", serde(rename = "RS256"))]
    Rs256,

    /// ECDSA with P-256 and SHA-256. Smaller keys and faster signing.
    #[cfg_attr(feature = "serde", serde(rename = "ES256"))]
    Es256,

    /// Edwards-curve DSA with Ed25519. The fastest, with the smallest keys.
    #[cfg_attr(feature = "serde", serde(rename = "EdDSA"))]
    EdDsa,
}

impl SigningAlgorithm {
    /// The algorithm a new tenant's first key signs with: RS256, the one
    /// every OpenID Connect relying party must accept, so no client of a
    /// new tenant is turned away by its first token. A tenant moves to
    /// another through an algorithm migration.
    pub const FOR_NEW_TENANTS: Self = Self::Rs256;
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rs256 => f.write_str("RS256"),
            Self::Es256 => f.write_str("ES256"),
            Self::EdDsa => f.write_str("EdDSA"),
        }
    }
}

/// A single signing key within a tenant's key set.
///
/// The private key is held as a [`Secret`]. With the software signer it is
/// the PEM itself. With a key service it names where the key lives. Either
/// way it is treated as key material, so it never prints. If it printed, it
/// would appear wherever the struct is printed, such as a `tracing` field,
/// an error chain or a panic message.
#[derive(Clone)]
pub struct SigningKey {
    kid: KeyId,
    algorithm: SigningAlgorithm,
    public_key: PublicKeyPem,
    private_key: Secret,
    state: KeyState,
    created_at: OffsetDateTime,
    expires_at: Expiry,
}

impl fmt::Debug for SigningKey {
    /// Prints every field, with the private key shown redacted. The rest
    /// stays readable in a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .field("public_key", &self.public_key)
            .field("private_key", &self.private_key)
            .field("state", &self.state)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Persisted state for repository hydration.
pub struct SigningKeyRow {
    /// The `kid` value for JWT headers and JWKS.
    pub kid: KeyId,
    /// The signing algorithm, RS256, ES256 or EdDSA.
    pub algorithm: SigningAlgorithm,
    /// PEM-encoded public key for JWKS.
    pub public_key: PublicKeyPem,
    /// The private key PEM, or where the key lives for a key service.
    pub private_key: Secret,
    /// Where the key stands. See [`KeyState::from_stored`].
    pub state: KeyState,
    /// When this key was created.
    pub created_at: OffsetDateTime,
    /// When it stops signing, or that it never does.
    pub expires_at: Expiry,
}

/// Everything a freshly generated signing key starts with.
pub struct NewSigningKey {
    /// The key id published in the JWKS.
    pub kid: KeyId,
    /// The algorithm it signs with.
    pub algorithm: SigningAlgorithm,
    /// The public half, PEM-encoded.
    pub public_key: PublicKeyPem,
    /// The private half, PEM-encoded, or where it is kept for a key service.
    pub private_key: Secret,
    /// When it stops signing, or that it never does.
    pub expires_at: Expiry,
}

impl SigningKey {
    /// A new signing key, active from now.
    ///
    /// It signs nothing until a [`SigningKeySet`] takes it. The platform
    /// makes the first one as it provisions the tenant; any later one joins
    /// the set only through a change that needs the right to change keys.
    #[must_use]
    pub fn create(key: NewSigningKey) -> Self {
        let NewSigningKey {
            kid,
            algorithm,
            public_key,
            private_key,
            expires_at,
        } = key;
        Self {
            kid,
            algorithm,
            public_key,
            private_key,
            state: KeyState::Active,
            created_at: crate::shared::clock::now(),
            expires_at,
        }
    }

    /// Rebuilds a signing key from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the key was
    ///   rotated before it was created.
    pub fn reconstitute(row: SigningKeyRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            kid: row.kid,
            algorithm: row.algorithm,
            public_key: row.public_key,
            private_key: row.private_key,
            state: row.state,
            created_at: row.created_at,
            expires_at: row.expires_at,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &SigningKeyRow) -> Result<(), DomainError> {
        RowCheck::of("signing key")
            .in_order_if(
                row.created_at,
                row.state.rotated_at(),
                "rotated before it was created",
            )
            .finish()
    }

    /// The `kid` value used in JWT headers and JWKS.
    #[must_use]
    pub fn kid(&self) -> &KeyId {
        &self.kid
    }

    /// The signing algorithm, RS256, ES256 or EdDSA.
    #[must_use]
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// The PEM-encoded public key, published in the JWKS so tokens can be
    /// verified.
    #[must_use]
    pub fn public_key(&self) -> &PublicKeyPem {
        &self.public_key
    }

    /// The private key. It is the PEM with the software signer, or where the
    /// key lives with a key service.
    #[must_use]
    pub fn private_key(&self) -> &Secret {
        &self.private_key
    }

    /// The current lifecycle status, active, rotated or revoked.
    #[must_use]
    pub fn status(&self) -> KeyStatus {
        self.state.status()
    }

    /// Where the key stands, with its rotation time once it was rotated.
    #[must_use]
    pub fn state(&self) -> KeyState {
        self.state
    }

    /// When this key was generated.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When the key stops signing, or that it never does.
    #[must_use]
    pub fn expires_at(&self) -> Expiry {
        self.expires_at
    }

    /// When the key stopped signing, if it has been rotated out.
    #[must_use]
    pub fn rotated_at(&self) -> Option<OffsetDateTime> {
        self.state.rotated_at()
    }

    /// Whether the key is in its active state.
    ///
    /// Rotation moves active keys on. Whether the key may sign right now also
    /// depends on its expiry. See [`signs_at`](Self::signs_at).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == KeyState::Active
    }

    /// Whether the key may sign a new token at `now`. It must be active and
    /// not past its expiry. An expired key stops signing at once, whether or
    /// not anything has rotated it yet.
    #[must_use]
    pub fn signs_at(&self, now: OffsetDateTime) -> bool {
        self.is_active() && !self.expires_at.has_passed(now)
    }

    /// Whether a rotated key has stayed published for the whole `grace`
    /// period, so tokens it signed have had time to expire.
    #[must_use]
    pub fn grace_is_over(&self, grace: Lifetime, now: OffsetDateTime) -> bool {
        match self.state {
            KeyState::Rotated { at } => grace.ends_after(at) <= now,
            KeyState::Active | KeyState::Revoked { .. } => false,
        }
    }

    /// Whether a verifier may still accept tokens this key signed, so the
    /// JWKS publishes it at `now`, as [`KeyState::is_published`] judges.
    #[must_use]
    pub fn is_in_jwks(&self, grace: Lifetime, now: OffsetDateTime) -> bool {
        self.state.is_published(self.expires_at, grace, now)
    }

    /// Marks this key as rotated. It stays in the JWKS for a grace period
    /// but stops signing new tokens.
    ///
    /// Only its [`SigningKeySet`] does this, after checking who asked or
    /// that the clock did.
    fn rotate(&mut self) -> Result<(), DomainError> {
        self.move_to(KeyState::Rotated {
            at: crate::shared::clock::now(),
        })
    }

    /// Revokes this key for good and takes it out of the JWKS.
    ///
    /// Tokens signed with it cannot be verified from then on. Only its
    /// [`SigningKeySet`] does this, after checking who asked or that the
    /// grace period is over.
    fn revoke(&mut self) -> Result<(), DomainError> {
        self.move_to(self.state.revoked())
    }

    fn move_to(&mut self, to: KeyState) -> Result<(), DomainError> {
        self.status()
            .try_transition(to.status())
            .map_err(|refused| {
                DomainError::invalid_transition(message!(
                    "crypto-signing-key-cannot-move-from-to",
                    format!(
                        "signing key {} cannot move from {:?} to {:?}",
                        self.kid, refused.from, refused.to
                    )
                ))
            })?;
        self.state = to;
        Ok(())
    }
}

/// A tenant's set of signing keys.
///
/// It picks the key that signs, rotates keys and says which ones the JWKS
/// publishes. On rotation the new key signs and the old one stays published
/// for a grace period.
#[derive(Debug, Clone)]
pub struct SigningKeySet<T: TenantScope> {
    keys: Vec<SigningKey>,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> SigningKeySet<T> {
    /// A new key set holding only `initial_key`. Raises
    /// `crypto.key_created`.
    #[must_use]
    pub fn new(initial_key: SigningKey) -> Self {
        let mut set = Self {
            keys: Vec::new(),
            raised: Raised::default(),
            _scope: PhantomData,
        };
        set.raise_created(&initial_key);
        set.keys.push(initial_key);
        set
    }

    /// A key set rebuilt from stored keys.
    ///
    /// Each `kid` names one key. Two stored keys with the same `kid` would
    /// let revoking one leave its twin signing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when two stored keys share a `kid`.
    pub fn from_keys(keys: Vec<SigningKey>) -> Result<Self, DomainError> {
        RowCheck::of("signing key set")
            .holds(
                first_repeat(keys.iter().map(|key| key.kid().as_str())).is_none(),
                "two keys with the same kid",
            )
            .finish()?;
        Ok(Self {
            keys,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// All keys in the set.
    #[must_use]
    pub fn keys(&self) -> &[SigningKey] {
        &self.keys
    }

    /// The public halves of every key not revoked, newest first, as a
    /// verifier reads them: what a verifying key store answers for this set.
    #[must_use]
    pub fn verifying_keys(&self) -> Vec<VerifyingKey> {
        let mut kept: Vec<&SigningKey> = self
            .keys
            .iter()
            .filter(|key| key.status() != KeyStatus::Revoked)
            .collect();
        kept.sort_by_key(|key| std::cmp::Reverse(key.created_at()));
        kept.into_iter().map(VerifyingKey::of).collect()
    }

    /// The key that signs new tokens at `now`, which is the oldest key that
    /// may sign.
    ///
    /// `None` when every key is rotated, revoked or past its expiry. Then
    /// nothing signs, instead of an expired key carrying on.
    ///
    /// The oldest wins because two keys are active only during an algorithm
    /// migration, where the source key keeps signing until the target is
    /// promoted. Deciding by age keeps that true whatever order storage
    /// returns the keys in.
    #[must_use]
    pub fn active_key(&self, now: OffsetDateTime) -> Option<&SigningKey> {
        self.keys
            .iter()
            .filter(|k| k.signs_at(now))
            .min_by(|a, b| (a.created_at, a.kid.as_str()).cmp(&(b.created_at, b.kid.as_str())))
    }

    /// The keys the JWKS publishes at `now`: those a verifier may still
    /// accept, as [`SigningKey::is_in_jwks`] judges with `grace`.
    #[must_use]
    pub fn jwks_keys(&self, grace: Lifetime, now: OffsetDateTime) -> Vec<&SigningKey> {
        self.keys
            .iter()
            .filter(|k| k.is_in_jwks(grace, now))
            .collect()
    }

    /// Adds a key to the set without rotating the current active key.
    ///
    /// An algorithm migration uses it. The new key is published next to the
    /// old one, and the old key stays the primary signer. It raises nothing:
    /// the migration records the step as `crypto.migration_started`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change signing keys.
    /// - [`DomainError::Conflict`] when the set already holds a key with
    ///   that `kid`.
    pub fn add_key(
        &mut self,
        key: SigningKey,
        by: &impl CryptoControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_keys()?;
        self.ensure_new_kid(key.kid())?;
        self.keys.push(key);
        Ok(())
    }

    /// Rotates all active keys into verification-only JWKS entries and adds the signing key.
    /// Raises `crypto.key_rotated` from the former signer, or `crypto.key_created` if none.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] without key-management rights.
    /// [`DomainError::Conflict`] for a duplicate `kid`, leaving every key unchanged.
    /// [`DomainError::InvalidTransition`] if an active key refuses rotation.
    pub fn rotate_to(
        &mut self,
        new_key: SigningKey,
        by: &impl CryptoControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_keys()?;
        self.rotate_onto(new_key)
    }

    /// Rotates every active key out onto `new_key`, as [`rotate_to`]
    /// describes, for a rotation already allowed: a person's, or the
    /// platform's own on a [`KeyRotationSchedule`].
    ///
    /// [`rotate_to`]: Self::rotate_to
    /// [`KeyRotationSchedule`]: crate::domains::crypto::rotation::KeyRotationSchedule
    pub(crate) fn rotate_onto(&mut self, new_key: SigningKey) -> Result<(), DomainError> {
        self.ensure_new_kid(new_key.kid())?;
        let replaced = self
            .active_key(crate::shared::clock::now())
            .map(|key| key.kid().clone());
        for key in self.keys.iter_mut().filter(|k| k.is_active()) {
            key.rotate()?;
        }
        match replaced {
            Some(old_kid) => self.raise_rotated(old_kid, &new_key),
            None => self.raise_created(&new_key),
        }
        self.keys.push(new_key);
        Ok(())
    }

    /// Revokes a specific key by its `kid`. Raises `crypto.key_revoked`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change signing keys.
    /// - [`DomainError::NotFound`] when no key in the set has that `kid`.
    /// - [`DomainError::Conflict`] when it is the only key that can sign now.
    ///   The tenant would have nothing left to sign with.
    /// - [`DomainError::InvalidTransition`] when it is already revoked.
    pub fn revoke_key(
        &mut self,
        kid: &KeyId,
        by: &impl CryptoControlCheck,
    ) -> Result<(), DomainError> {
        self.revoke_migrated_key(kid, by)?;
        self.raise_revoked(kid.clone());
        Ok(())
    }

    /// Revokes a key an algorithm migration leaves behind: the source key
    /// once it completes, or the target key once it is rolled back. It
    /// raises nothing: the migration records the step as
    /// `crypto.migration_completed` or `crypto.migration_rolled_back`.
    ///
    /// # Errors
    ///
    /// As [`revoke_key`](Self::revoke_key).
    pub fn revoke_migrated_key(
        &mut self,
        kid: &KeyId,
        by: &impl CryptoControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_keys()?;
        self.ensure_not_last_signer(kid)?;
        self.key_mut(kid)?.revoke()
    }

    /// Stops a specific key signing while keeping it published for the grace
    /// period, as promoting an algorithm migration does to the old key. It
    /// raises nothing: the migration records the step as
    /// `crypto.migration_promoted`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change signing keys.
    /// - [`DomainError::NotFound`] when no key in the set has that `kid`.
    /// - [`DomainError::Conflict`] when it is the only key that can sign now.
    /// - [`DomainError::InvalidTransition`] when the key is not active.
    pub fn rotate_out(
        &mut self,
        kid: &KeyId,
        by: &impl CryptoControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_keys()?;
        self.ensure_not_last_signer(kid)?;
        self.key_mut(kid)?.rotate()
    }

    /// Revokes every rotated key that has been published for the whole
    /// `grace` period, and returns their ids. Raises `crypto.key_revoked`
    /// for each.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when a rotated key refuses to be
    ///   revoked, which its state machine never does.
    pub fn revoke_after_grace(&mut self, grace: Lifetime) -> Result<Vec<KeyId>, DomainError> {
        let now = crate::shared::clock::now();
        let mut revoked = Vec::new();
        for key in self.keys.iter_mut().filter(|k| k.grace_is_over(grace, now)) {
            key.revoke()?;
            revoked.push(key.kid().clone());
        }
        for kid in &revoked {
            self.raise_revoked(kid.clone());
        }
        Ok(revoked)
    }

    /// Raises `crypto.key_created` for `key`, the first key that signs.
    fn raise_created(&mut self, key: &SigningKey) {
        self.raised.raise(KeyCreated {
            kid: key.kid().clone(),
            algorithm: key.algorithm(),
            occurred_at: key.created_at(),
        });
    }

    /// Raises `crypto.key_rotated` from `old_kid`, the key that signed until
    /// now, to `new_key`.
    fn raise_rotated(&mut self, old_kid: KeyId, new_key: &SigningKey) {
        self.raised.raise(KeyRotated {
            old_kid,
            new_kid: new_key.kid().clone(),
            algorithm: new_key.algorithm(),
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// Raises `crypto.key_revoked` for `kid`.
    fn raise_revoked(&mut self, kid: KeyId) {
        self.raised.raise(KeyRevoked {
            kid,
            occurred_at: crate::shared::clock::now(),
        });
    }

    fn key_mut(&mut self, kid: &KeyId) -> Result<&mut SigningKey, DomainError> {
        self.keys
            .iter_mut()
            .find(|k| k.kid() == kid)
            .ok_or(DomainError::NotFound)
    }

    /// Refuses a key whose `kid` the set already holds.
    ///
    /// Sam adds a second key named `key-1`. Revoking `key-1` would then
    /// revoke only one of them, and the other would keep signing.
    fn ensure_new_kid(&self, kid: &KeyId) -> Result<(), DomainError> {
        if self.keys.iter().all(|key| key.kid() != kid) {
            return Ok(());
        }
        Err(DomainError::conflict(message!(
            "crypto-the-key-set-already-holds-a",
            format!("the key set already holds a key with kid {kid}")
        )))
    }

    /// Refuses taking `kid` out of service while it is the only key that can
    /// sign right now. A key that is active but past its expiry signs
    /// nothing, so it does not count as another signer.
    fn ensure_not_last_signer(&self, kid: &KeyId) -> Result<(), DomainError> {
        let now = crate::shared::clock::now();
        let signs = |key: &&SigningKey| key.signs_at(now);
        let this_signs = self.keys.iter().filter(signs).any(|k| k.kid() == kid);
        let another_signs = self.keys.iter().filter(signs).any(|k| k.kid() != kid);
        if this_signs && !another_signs {
            return Err(DomainError::conflict(message!(
                "crypto-cannot-take-the-only-signing-key",
                "cannot take the only signing key out of service"
            )));
        }
        Ok(())
    }
}

impl<T: TenantScope> Raises for SigningKeySet<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::authority::TenantAuthority;
    use crate::domains::authorization::permission::{CryptoAction, SystemPermission};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::events::{raised, raised_names};

    fn test_key(kid: &str) -> SigningKey {
        SigningKey::create(new_key(kid))
    }

    fn keeper() -> &'static TenantAuthority {
        anyone_holding(&[SystemPermission::Crypto(CryptoAction::Update)])
    }

    fn viewer() -> &'static TenantAuthority {
        anyone_holding(&[SystemPermission::Crypto(CryptoAction::View)])
    }

    /// A one-day grace period for rotated keys.
    fn grace() -> Lifetime {
        Lifetime::seconds(86_400).unwrap()
    }

    /// The kids the set's JWKS publishes now, with a one-day grace.
    fn published(set: &SigningKeySet<ResolvedTenant>) -> Vec<&str> {
        set.jwks_keys(grace(), crate::shared::clock::now())
            .into_iter()
            .map(|key| key.kid().as_str())
            .collect()
    }

    /// An active key stops signing on expiry but remains published during
    /// its grace period. The JWKS excludes it once that period ends.
    #[test]
    fn an_expired_active_key_is_published_only_through_its_grace() {
        let start = crate::shared::clock::now();
        let key = SigningKey::create(NewSigningKey {
            expires_at: Expiry::At(start + time::Duration::HOUR),
            ..new_key("key-1")
        });

        let just_expired = start + time::Duration::hours(2);
        let grace_over = start + time::Duration::HOUR + grace().duration();

        assert!(key.is_in_jwks(grace(), start));
        assert!(!key.signs_at(just_expired));
        assert!(key.is_in_jwks(grace(), just_expired));
        assert!(!key.is_in_jwks(grace(), grace_over));
    }

    /// A rotated key remains published during its one-day grace, then leaves
    /// the JWKS without explicit revocation. The replacement stays published.
    #[test]
    fn a_rotated_key_past_its_grace_is_not_published_even_unrevoked() {
        let start = crate::shared::clock::now();
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));
        {
            let _frozen = crate::shared::clock::freeze(start);
            set.rotate_to(test_key("key-2"), keeper()).unwrap();
        }

        let within = set.jwks_keys(grace(), start + time::Duration::hours(23));
        let after = set.jwks_keys(grace(), start + time::Duration::days(2));

        assert_eq!(within.len(), 2);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].kid().as_str(), "key-2");
    }

    /// A key viewer cannot rotate, revoke, rotate out or add a key. Each
    /// attempt is forbidden, leaving both existing keys active.
    #[test]
    fn a_viewer_may_not_rotate_or_revoke_keys() {
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));
        set.add_key(test_key("key-2"), keeper()).unwrap();

        let rotated = set.rotate_to(test_key("sams-key"), viewer());
        let revoked = set.revoke_key(&KeyId::new("key-1").unwrap(), viewer());
        let rotated_out = set.rotate_out(&KeyId::new("key-1").unwrap(), viewer());
        let added = set.add_key(test_key("sams-key"), viewer());

        for refused in [rotated, revoked, rotated_out, added] {
            assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        }
        assert_eq!(set.keys().len(), 2);
        assert!(set.keys().iter().all(SigningKey::is_active));
    }

    /// Debug formatting a signing key reveals neither its private material
    /// nor the private PEM header.
    #[test]
    fn debug_does_not_print_the_private_key() {
        let key = SigningKey::create(NewSigningKey {
            kid: KeyId::new("key-1").unwrap(),
            algorithm: SigningAlgorithm::Rs256,
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----",
            )
            .unwrap(),
            private_key: Secret::new(concat!(
                "-----BEGIN PRIVATE ",
                "KEY-----\nsupersecretkeymaterial\n-----END PRIVATE KEY-----"
            )),
            expires_at: Expiry::Never,
        });

        let rendered = format!("{key:?}");

        assert!(
            !rendered.contains("supersecretkeymaterial"),
            "the private key appears in Debug output: {rendered}"
        );
        assert!(
            !rendered.contains("BEGIN PRIVATE KEY"),
            "the private key appears in Debug output: {rendered}"
        );
    }

    /// Debug output still names the key `key-1` and its algorithm `Rs256`,
    /// so a log is useful when something goes wrong.
    #[test]
    fn debug_still_names_the_key_and_its_algorithm() {
        let rendered = format!("{:?}", test_key("key-1"));

        assert!(rendered.contains("key-1"), "{rendered}");
        assert!(rendered.contains("Rs256"), "{rendered}");
    }

    /// The algorithms print as "RS256", "ES256" and "EdDSA", the names JWT
    /// headers and JWKS use.
    #[test]
    fn signing_algorithms_print_as_their_jose_names() {
        assert_eq!(SigningAlgorithm::Rs256.to_string(), "RS256");
        assert_eq!(SigningAlgorithm::Es256.to_string(), "ES256");
    }

    /// A new RS256 key is active and published in the JWKS.
    #[test]
    fn create_produces_active_key() {
        let key = test_key("key-1");

        assert!(key.is_active());
        assert!(key.is_in_jwks(grace(), crate::shared::clock::now()));
        assert_eq!(key.algorithm(), SigningAlgorithm::Rs256);
    }

    /// A rotated key stops being active but stays in the JWKS.
    #[test]
    fn rotate_moves_to_rotated_status() {
        let mut key = test_key("key-1");

        key.rotate().unwrap();

        assert!(!key.is_active());
        assert!(key.is_in_jwks(grace(), crate::shared::clock::now()));
        assert_eq!(key.status(), KeyStatus::Rotated);
    }

    /// A revoked key is neither active nor in the JWKS.
    #[test]
    fn revoke_removes_from_jwks() {
        let mut key = test_key("key-1");

        key.revoke().unwrap();

        assert!(!key.is_active());
        assert!(!key.is_in_jwks(grace(), crate::shared::clock::now()));
        assert_eq!(key.status(), KeyStatus::Revoked);
    }

    /// A verifier reads the public halves of a rotated set, the key that
    /// signs now and the one rotated out, with their kids and nothing
    /// private.
    #[test]
    fn a_verifier_reads_the_public_halves_of_the_set() {
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));
        set.rotate_to(test_key("key-2"), keeper()).unwrap();

        let verifying = set.verifying_keys();

        let kids: Vec<&str> = verifying.iter().map(|key| key.kid().as_str()).collect();
        assert_eq!(kids.len(), 2);
        assert!(kids.contains(&"key-1") && kids.contains(&"key-2"));
    }

    /// A new key set holds its one key, which signs and is published.
    #[test]
    fn new_set_has_one_active_key() {
        let set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));

        assert_eq!(set.keys().len(), 1);
        assert!(set.active_key(crate::shared::clock::now()).is_some());
        assert_eq!(published(&set).len(), 1);
    }

    /// A tenant rotates from `key-1` to `key-2`. `key-2` signs, and both stay
    /// in the JWKS so tokens `key-1` signed still verify.
    #[test]
    fn rotate_keeps_old_key_in_jwks() {
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));

        set.rotate_to(test_key("key-2"), keeper()).unwrap();

        assert_eq!(set.keys().len(), 2);
        assert_eq!(
            set.active_key(crate::shared::clock::now())
                .unwrap()
                .kid()
                .as_str(),
            "key-2"
        );
        assert_eq!(published(&set).len(), 2);
    }

    /// After rotating to `key-2`, the tenant revokes `key-1`. Only `key-2`
    /// is left in the JWKS.
    #[test]
    fn revoke_removes_key_from_jwks() {
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));
        set.rotate_to(test_key("key-2"), keeper()).unwrap();

        set.revoke_key(&KeyId::new("key-1").unwrap(), keeper())
            .unwrap();

        assert_eq!(published(&set), ["key-2"]);
    }

    /// Revoking a kid the set does not hold fails as not found.
    #[test]
    fn revoking_an_unknown_key_is_not_found() {
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));

        let result = set.revoke_key(&KeyId::new("nonexistent").unwrap(), keeper());

        assert!(matches!(result, Err(DomainError::NotFound)));
    }

    /// A key was revoked after it leaked. Rotating it is refused, so it
    /// never goes back into the JWKS.
    #[test]
    fn a_revoked_key_cannot_be_rotated_back_into_the_jwks() {
        let mut key = test_key("key-1");
        key.revoke().unwrap();

        let result = key.rotate();

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
        assert!(!key.is_in_jwks(grace(), crate::shared::clock::now()));
    }

    /// Revoking `key-1` a second time is refused as a wrong transition.
    #[test]
    fn a_revoked_key_cannot_be_revoked_again() {
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));
        set.rotate_to(test_key("key-2"), keeper()).unwrap();
        set.revoke_key(&KeyId::new("key-1").unwrap(), keeper())
            .unwrap();

        let result = set.revoke_key(&KeyId::new("key-1").unwrap(), keeper());

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
    }

    /// A tenant has one key and tries to revoke it. It is refused, and the
    /// key still signs, so the tenant is never left unable to sign.
    #[test]
    fn the_only_active_key_cannot_be_revoked() {
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));

        let result = set.revoke_key(&KeyId::new("key-1").unwrap(), keeper());

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert!(set.active_key(crate::shared::clock::now()).is_some());
    }

    /// A day on, `key-2` is active but expired an hour in. Revoking `key-1`,
    /// the only key that still signs, is refused. Revoking expired `key-2` is
    /// allowed.
    #[test]
    fn an_expired_key_does_not_count_as_another_signer() {
        let start = crate::shared::clock::now();
        let expiring = SigningKey::create(NewSigningKey {
            expires_at: Expiry::At(start + time::Duration::HOUR),
            ..new_key("key-2")
        });
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));
        set.add_key(expiring, keeper()).unwrap();

        let _frozen = crate::shared::clock::freeze(start + time::Duration::DAY);
        let result = set.revoke_key(&KeyId::new("key-1").unwrap(), keeper());

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert!(
            set.revoke_key(&KeyId::new("key-2").unwrap(), keeper())
                .is_ok()
        );
    }

    fn new_key(kid: &str) -> NewSigningKey {
        NewSigningKey {
            kid: KeyId::new(kid).unwrap(),
            algorithm: SigningAlgorithm::Rs256,
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----",
            )
            .unwrap(),
            private_key: Secret::new("arn:aws:kms:us-east-1:123:key/abc"),
            expires_at: Expiry::Never,
        }
    }

    /// During an algorithm migration both keys are active. Revoking `key-1`
    /// is allowed and `key-2` then signs.
    #[test]
    fn one_of_two_active_keys_can_be_revoked() {
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));
        set.add_key(test_key("key-2"), keeper()).unwrap();

        set.revoke_key(&KeyId::new("key-1").unwrap(), keeper())
            .unwrap();

        assert_eq!(
            set.active_key(crate::shared::clock::now())
                .unwrap()
                .kid()
                .as_str(),
            "key-2"
        );
    }

    /// A migration is promoted and `key-1` is rotated out. It is rotated,
    /// still in the JWKS and records when, so tokens it just signed still
    /// verify.
    #[test]
    fn rotating_out_a_key_keeps_it_published() {
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));
        set.add_key(test_key("key-2"), keeper()).unwrap();

        set.rotate_out(&KeyId::new("key-1").unwrap(), keeper())
            .unwrap();

        let old = &set.keys()[0];
        assert_eq!(old.status(), KeyStatus::Rotated);
        assert!(old.is_in_jwks(grace(), crate::shared::clock::now()));
        assert!(old.rotated_at().is_some());
    }

    /// Rotating out a tenant's only key, with nothing to replace it, is
    /// refused.
    #[test]
    fn the_only_active_key_cannot_be_rotated_out() {
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));

        let result = set.rotate_out(&KeyId::new("key-1").unwrap(), keeper());

        assert!(matches!(result, Err(DomainError::Conflict(_))));
    }

    /// `key-1` is rotated out with a one day grace period. After 23 hours
    /// nothing is revoked. At 24 hours `key-1` is revoked and leaves the
    /// JWKS.
    #[test]
    fn a_rotated_key_is_revoked_once_its_grace_period_is_over() {
        let start = crate::shared::clock::now();
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));
        {
            let _frozen = crate::shared::clock::freeze(start);
            set.rotate_to(test_key("key-2"), keeper()).unwrap();
        }
        let grace = Lifetime::seconds(86_400).unwrap();

        let early = {
            let _frozen = crate::shared::clock::freeze(start + time::Duration::hours(23));
            set.revoke_after_grace(grace).unwrap()
        };
        let late = {
            let _frozen = crate::shared::clock::freeze(start + time::Duration::hours(24));
            set.revoke_after_grace(grace).unwrap()
        };

        assert!(early.is_empty());
        assert_eq!(late, vec![KeyId::new("key-1").unwrap()]);
        assert_eq!(published(&set).len(), 1);
    }

    /// After rotating to `key-2` and then `key-3`, `key-3` signs and all
    /// three are still in the JWKS.
    #[test]
    fn after_two_rotations_the_newest_key_signs() {
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));
        set.rotate_to(test_key("key-2"), keeper()).unwrap();
        set.rotate_to(test_key("key-3"), keeper()).unwrap();

        assert_eq!(set.keys().len(), 3);
        assert_eq!(
            set.active_key(crate::shared::clock::now())
                .unwrap()
                .kid()
                .as_str(),
            "key-3"
        );
        assert_eq!(published(&set).len(), 3);
    }

    /// During a migration storage returns the new target key before the
    /// 30-day-old source key. The source still signs, because the oldest
    /// active key wins whatever the order.
    #[test]
    fn the_oldest_active_key_signs_whatever_order_the_keys_are_in() {
        let now = crate::shared::clock::now();
        let key = |kid: &str, created_at: OffsetDateTime| {
            SigningKey::reconstitute(SigningKeyRow {
                kid: KeyId::new(kid).unwrap(),
                algorithm: SigningAlgorithm::Es256,
                public_key: PublicKeyPem::new(
                    "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----",
                )
                .unwrap(),
                private_key: Secret::new("private_ref"),
                state: KeyState::Active,
                created_at,
                expires_at: Expiry::Never,
            })
            .unwrap()
        };
        let set = SigningKeySet::<ResolvedTenant>::from_keys(vec![
            key("target", now),
            key("source", now - time::Duration::days(30)),
        ])
        .unwrap();

        assert_eq!(set.active_key(now).unwrap().kid().as_str(), "source");
    }

    /// A stored rotated ES256 key loads back with its kid, algorithm and
    /// status, not active and still in the JWKS.
    #[test]
    fn reconstitute_signing_key() {
        let now = crate::shared::clock::now();
        let key = SigningKey::reconstitute(SigningKeyRow {
            kid: KeyId::new("restored").unwrap(),
            algorithm: SigningAlgorithm::Es256,
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----",
            )
            .unwrap(),
            private_key: Secret::new("private_ref"),
            state: KeyState::Rotated { at: now },
            created_at: now,
            expires_at: Expiry::Never,
        })
        .unwrap();

        assert_eq!(key.kid().as_str(), "restored");
        assert_eq!(key.algorithm(), SigningAlgorithm::Es256);
        assert_eq!(key.status(), KeyStatus::Rotated);
        assert!(!key.is_active());
        assert!(key.is_in_jwks(grace(), crate::shared::clock::now()));
    }

    /// A key hands back the exact public PEM and private key reference it
    /// was made with. Relying parties verify with the first, and the signer
    /// loads the private half through the second.
    #[test]
    fn a_key_carries_its_public_half_and_the_reference_to_its_private_one() {
        let key = test_key("key-1");

        assert_eq!(
            key.public_key().as_str(),
            "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----"
        );
        assert_eq!(
            key.private_key().expose(),
            "arn:aws:kms:us-east-1:123:key/abc"
        );
    }

    /// A key made to expire in 90 days reports that expiry, and one made
    /// with no expiry reports never. A rotation schedule reads this.
    #[test]
    fn a_keys_expiry_reads_back_as_the_one_it_was_given() {
        let expires_at = crate::shared::clock::now() + time::Duration::days(90);
        let key = SigningKey::create(NewSigningKey {
            kid: KeyId::new("key-1").unwrap(),
            algorithm: SigningAlgorithm::Rs256,
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----",
            )
            .unwrap(),
            private_key: Secret::new("arn:aws:kms:us-east-1:123:key/abc"),
            expires_at: Expiry::At(expires_at),
        });

        assert_eq!(key.expires_at(), Expiry::At(expires_at));
        assert_eq!(test_key("key-2").expires_at(), Expiry::Never);
    }

    /// A key expiring in 90 days signs one second before its expiry and not
    /// at it, even though nothing has rotated it. A failed rotation job never
    /// leaves an expired key signing.
    #[test]
    fn a_key_past_its_expiry_signs_nothing() {
        let expires_at = crate::shared::clock::now() + time::Duration::days(90);
        let key = SigningKey::create(NewSigningKey {
            kid: KeyId::new("key-1").unwrap(),
            algorithm: SigningAlgorithm::Rs256,
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----",
            )
            .unwrap(),
            private_key: Secret::new("arn:aws:kms:us-east-1:123:key/abc"),
            expires_at: Expiry::At(expires_at),
        });
        let set = SigningKeySet::<ResolvedTenant>::new(key);

        assert!(
            set.active_key(expires_at - time::Duration::seconds(1))
                .is_some()
        );
        assert!(set.active_key(expires_at).is_none());
    }

    /// A key added to the set is held in it. The JWKS is built from the set,
    /// and a key missing from it signs tokens nobody can verify.
    #[test]
    fn a_key_added_to_the_set_is_published_in_it() {
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));

        set.add_key(test_key("key-2"), keeper()).unwrap();

        assert_eq!(set.keys().len(), 2);
        assert!(set.keys().iter().any(|k| k.kid().as_str() == "key-2"));
    }

    /// Adding a duplicate key id is refused, leaving the set with one key
    /// rather than two keys that a revocation could confuse.
    #[test]
    fn adding_a_key_with_a_known_kid_is_refused() {
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));

        let result = set.add_key(test_key("key-1"), keeper());

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert_eq!(set.keys().len(), 1);
    }

    /// Rotation onto a duplicate key id is refused; the existing key remains
    /// active and the set gains no replacement.
    #[test]
    fn rotating_to_a_key_with_a_known_kid_is_refused() {
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));

        let result = set.rotate_to(test_key("key-1"), keeper());

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert_eq!(set.keys().len(), 1);
        assert!(set.keys()[0].is_active());
    }

    /// A stored set with duplicate key ids is refused as corrupt because a
    /// revocation could not identify one key unambiguously.
    #[test]
    fn a_stored_set_with_two_keys_of_one_kid_is_refused() {
        let set =
            SigningKeySet::<ResolvedTenant>::from_keys(vec![test_key("key-1"), test_key("key-1")]);

        assert!(refused_as_corrupt(&set));
    }

    /// A stored key says it was rotated one second before it was created.
    /// Loading it is refused as corrupt.
    #[test]
    fn a_stored_key_rotated_before_it_was_created_is_refused() {
        let key = test_key("k1");
        let row = SigningKeyRow {
            kid: key.kid.clone(),
            algorithm: key.algorithm,
            public_key: key.public_key.clone(),
            private_key: key.private_key.clone(),
            state: KeyState::Rotated {
                at: key.created_at - time::Duration::SECOND,
            },
            created_at: key.created_at,
            expires_at: key.expires_at,
        };

        assert!(refused_as_corrupt(&SigningKey::reconstitute(row)));
    }

    /// A tenant gets its first key set with `key-1`. The key's creation is
    /// raised.
    #[test]
    fn a_new_key_set_raises_crypto_key_created() {
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));

        assert_eq!(raised_names(&mut set), ["crypto.key_created"]);
    }

    /// Ann rotates from `key-1` to `key-2`. The rotation is raised, from the
    /// old kid to the new one.
    #[test]
    fn rotating_raises_crypto_key_rotated_from_the_signer_it_replaced() {
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));
        raised_names(&mut set);

        set.rotate_to(test_key("key-2"), keeper()).unwrap();

        let events = raised(&mut set);
        assert_eq!(events[0].event_type().to_string(), "crypto.key_rotated");
        let payload = events[0].payload();
        let Some(FieldValue::Change(change)) = payload.value("kid") else {
            panic!("the kid is not a change");
        };
        assert_eq!((change.from(), change.to()), (Some("key-1"), Some("key-2")));
    }

    /// A stored key set holds no key that signs. Ann rotates onto `key-2`,
    /// which replaces nothing, so its creation is raised.
    #[test]
    fn rotating_onto_a_set_where_nothing_signs_raises_crypto_key_created() {
        let mut set = SigningKeySet::<ResolvedTenant>::from_keys(Vec::new()).unwrap();

        set.rotate_to(test_key("key-2"), keeper()).unwrap();

        assert_eq!(raised_names(&mut set), ["crypto.key_created"]);
    }

    /// Ann adds `key-2` beside `key-1` and revokes `key-1`. Adding raises
    /// nothing; the revocation is raised.
    #[test]
    fn revoking_raises_crypto_key_revoked_and_adding_raises_nothing() {
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));
        raised_names(&mut set);

        set.add_key(test_key("key-2"), keeper()).unwrap();
        set.revoke_key(&KeyId::new("key-1").unwrap(), keeper())
            .unwrap();

        assert_eq!(raised_names(&mut set), ["crypto.key_revoked"]);
    }

    /// A migration retires its source key and rotates a key out. Neither
    /// is raised by the key set; the migration records its own steps.
    #[test]
    fn keys_a_migration_moves_raise_nothing() {
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));
        set.add_key(test_key("key-2"), keeper()).unwrap();
        set.add_key(test_key("key-3"), keeper()).unwrap();
        raised_names(&mut set);

        set.rotate_out(&KeyId::new("key-1").unwrap(), keeper())
            .unwrap();
        set.revoke_migrated_key(&KeyId::new("key-2").unwrap(), keeper())
            .unwrap();

        assert!(raised_names(&mut set).is_empty());
    }

    /// `key-1` was rotated out a day ago. The sweep revokes it and raises
    /// its revocation.
    #[test]
    fn the_grace_sweep_raises_crypto_key_revoked_per_key() {
        let start = crate::shared::clock::now();
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));
        {
            let _frozen = crate::shared::clock::freeze(start);
            set.rotate_to(test_key("key-2"), keeper()).unwrap();
        }
        raised_names(&mut set);

        {
            let _frozen = crate::shared::clock::freeze(start + time::Duration::hours(24));
            set.revoke_after_grace(grace()).unwrap();
        }

        assert_eq!(raised_names(&mut set), ["crypto.key_revoked"]);
    }

    /// A viewer's rotation and revocation attempts are refused without
    /// raising events for either change.
    #[test]
    fn a_refused_key_change_raises_nothing() {
        let mut set = SigningKeySet::<ResolvedTenant>::new(test_key("key-1"));
        set.add_key(test_key("key-2"), keeper()).unwrap();
        raised_names(&mut set);

        let rotated = set.rotate_to(test_key("sams-key"), viewer());
        let revoked = set.revoke_key(&KeyId::new("key-1").unwrap(), viewer());

        assert!(rotated.is_err());
        assert!(revoked.is_err());
        assert!(raised_names(&mut set).is_empty());
    }

    /// A key set read back from storage has raised nothing; only a change
    /// made after loading is recorded.
    #[test]
    fn a_key_set_read_back_from_storage_has_raised_nothing() {
        let mut set = SigningKeySet::<ResolvedTenant>::from_keys(vec![test_key("key-1")]).unwrap();

        assert!(raised_names(&mut set).is_empty());
    }
}
