//! Secrets sealed at rest with AES-256-GCM, under keys that can be
//! rotated, each bound to the place it is kept.
//!
//! A sealed value reads `s2.<key id>.<nonce and ciphertext>`, the last part
//! as URL-safe base64. A fresh 96-bit nonce is drawn for every seal. The
//! associated data the tag covers is the format, the key id and the place
//! the value is sealed for: whose it is, the field it is kept in and the
//! record that holds it, each written with its length before it so no two
//! places read alike. A value moved under another key id, into another
//! row, field or tenant, or asked to open for any place but its own, does
//! not open, and is refused as a corrupt row. The place is not written into
//! the value: the row it is read from names it.
//!
//! New values are sealed under the current key; a retired key still opens
//! what it sealed, until a sweep seals those values again.

use std::fmt;

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_app::ports::authentication::{SealOwner, SealedFor, SecretEncryptor};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::SealedSecret;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::issued::made;
use crate::crypto::keys::{KEY_BYTES, decoded_key};
use crate::crypto::random::random_bytes;

/// The format a sealed value starts with. The first format bound only the
/// key id; values written in it are not read.
const FORMAT: &str = "s2";

/// What a refusal of a value that does not open names.
const SEALED_VALUE: &str = "sealed value";

/// The length of the nonce sealed in front of the ciphertext.
const NONCE_BYTES: usize = 12;

/// Why a value could not be sealed or opened. None of it names the value.
#[derive(Debug, thiserror::Error)]
pub enum SealingError {
    /// The key id is not 1 to 16 lowercase letters and digits.
    #[error("a sealing key id is 1 to 16 lowercase letters and digits")]
    BadKeyId,
    /// The configured key is not 32 bytes written as hex or base64.
    #[error("a sealing key must be 32 bytes, written as 64 hex characters or as base64")]
    BadKey,
    /// The value is not written in the sealed format.
    #[error("the value is not a sealed secret")]
    NotSealed,
    /// The value names a key this process does not hold.
    #[error("the value was sealed under a key this process does not hold")]
    UnknownKey,
    /// The cipher refused: the value was changed, or the key is wrong.
    #[error("the sealed value does not open under its key")]
    DoesNotOpen,
    /// The cipher could not seal.
    #[error("the value could not be sealed")]
    CouldNotSeal,
}

/// One key secrets are sealed under, with the id its values carry.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SealingKey {
    id: String,
    key: [u8; KEY_BYTES],
}

impl fmt::Debug for SealingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealingKey")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl SealingKey {
    /// The key `bytes`, filed under `id`.
    ///
    /// # Errors
    ///
    /// Returns [`SealingError::BadKeyId`] when `id` is not 1 to 16
    /// lowercase letters and digits.
    pub fn new(id: &str, bytes: [u8; KEY_BYTES]) -> Result<Self, SealingError> {
        let fits = (1..=16).contains(&id.len())
            && id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
        if !fits {
            return Err(SealingError::BadKeyId);
        }
        Ok(Self {
            id: id.to_owned(),
            key: bytes,
        })
    }

    /// The key the configured `value` writes, as hex or base64, filed
    /// under `id`.
    ///
    /// # Errors
    ///
    /// Returns [`SealingError::BadKey`] when `value` is not 32 bytes in
    /// either, and [`SealingError::BadKeyId`] when `id` breaks its rules.
    pub fn parse(id: &str, value: &str) -> Result<Self, SealingError> {
        Self::new(id, decoded_key(value).ok_or(SealingError::BadKey)?)
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(&self.key.into())
    }

    /// The associated data a value sealed under this key for `place` is
    /// bound to.
    fn bound(&self, place: &SealedFor) -> Vec<u8> {
        let owner = owner_of(place.owner());
        let parts = [
            FORMAT,
            self.id.as_str(),
            owner.as_str(),
            place.field().label(),
            place.record(),
        ];
        let mut bound = Vec::new();
        for part in parts {
            bound.extend_from_slice(&part_length(part).to_be_bytes());
            bound.extend_from_slice(part.as_bytes());
        }
        bound
    }
}

/// The length `part` is written after, as four bytes. No part comes near
/// four gigabytes, so the length always fits; one that did would be written
/// as the largest length, which still binds the part after it.
fn part_length(part: &str) -> u32 {
    u32::try_from(part.len()).unwrap_or(u32::MAX)
}

/// How `owner` is written into the associated data.
fn owner_of(owner: SealOwner) -> String {
    match owner {
        SealOwner::Platform => "platform".to_owned(),
        SealOwner::Organization(organization) => format!("organization:{organization}"),
        SealOwner::Tenant(tenant) => format!("tenant:{tenant}"),
    }
}

/// The sealer of secrets at rest: AES-256-GCM under the current key,
/// opening values of retired keys too.
#[derive(Debug, Clone)]
pub struct AesGcmSecretEncryptor {
    current: SealingKey,
    retired: Vec<SealingKey>,
}

impl AesGcmSecretEncryptor {
    /// A sealer sealing under `current`, opening values of `retired` too.
    #[must_use]
    pub fn new(current: SealingKey, retired: Vec<SealingKey>) -> Self {
        Self { current, retired }
    }

    /// `plaintext` sealed under the current key for `place`.
    fn seal(&self, plaintext: &[u8], place: &SealedFor) -> Result<String, SealingError> {
        let nonce = random_bytes::<NONCE_BYTES>().map_err(|_| SealingError::CouldNotSeal)?;
        let sealed = self
            .current
            .cipher()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &self.current.bound(place),
                },
            )
            .map_err(|_| SealingError::CouldNotSeal)?;
        let body: Vec<u8> = nonce.into_iter().chain(sealed).collect();
        Ok(format!(
            "{FORMAT}.{}.{}",
            self.current.id,
            URL_SAFE_NO_PAD.encode(body)
        ))
    }

    /// The plaintext `sealed` holds, opened under the key it names for
    /// `place`.
    fn open(&self, sealed: &str, place: &SealedFor) -> Result<Vec<u8>, SealingError> {
        let mut parts = sealed.splitn(3, '.');
        let (Some(FORMAT), Some(id), Some(body)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(SealingError::NotSealed);
        };
        let key = self.key_named(id)?;
        let body = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| SealingError::NotSealed)?;
        let (nonce, ciphertext) = body
            .split_at_checked(NONCE_BYTES)
            .ok_or(SealingError::NotSealed)?;
        key.cipher()
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &key.bound(place),
                },
            )
            .map_err(|_| SealingError::DoesNotOpen)
    }

    fn key_named(&self, id: &str) -> Result<&SealingKey, SealingError> {
        std::iter::once(&self.current)
            .chain(&self.retired)
            .find(|key| key.id == id)
            .ok_or(SealingError::UnknownKey)
    }
}

#[async_trait]
impl SecretEncryptor for AesGcmSecretEncryptor {
    async fn encrypt(
        &self,
        plaintext: &[u8],
        place: &SealedFor,
    ) -> Result<SealedSecret, DomainError> {
        let sealed = self.seal(plaintext, place).map_err(DomainError::infra)?;
        made(SealedSecret::new(sealed))
    }

    async fn decrypt(
        &self,
        ciphertext: &SealedSecret,
        place: &SealedFor,
    ) -> Result<Vec<u8>, DomainError> {
        self.open(ciphertext.as_str(), place).map_err(refused)
    }
}

/// The error a value that does not open answers with: a corrupt row when
/// the cipher refused it, as one changed or moved from another place is,
/// and the sealing failure itself otherwise. Neither names the value.
fn refused(error: SealingError) -> DomainError {
    match error {
        SealingError::DoesNotOpen => {
            DomainError::corrupt_row(SEALED_VALUE, "a value changed, or sealed for another place")
        }
        SealingError::BadKeyId
        | SealingError::BadKey
        | SealingError::NotSealed
        | SealingError::UnknownKey
        | SealingError::CouldNotSeal => DomainError::infra(error),
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::authentication::SealedField;
    use ianua_domain::types::{OrganizationId, TenantId, UserId};

    use super::*;

    fn key(id: &str, byte: u8) -> SealingKey {
        SealingKey::new(id, [byte; KEY_BYTES]).unwrap()
    }

    fn sealer() -> AesGcmSecretEncryptor {
        AesGcmSecretEncryptor::new(key("r1", 3), Vec::new())
    }

    /// Where Acme keeps Ann's authenticator seed.
    fn anns_seed(acme: TenantId, ann: UserId) -> SealedFor {
        SealedFor::new(SealOwner::Tenant(acme), SealedField::TotpSeed, ann)
    }

    fn seed_place() -> SealedFor {
        anns_seed(
            TenantId::from_uuid(uuid::Uuid::nil()),
            UserId::from_uuid(uuid::Uuid::nil()),
        )
    }

    /// A TOTP seed sealed and opened again is the seed, and the sealed text
    /// names its format and key but not the seed or its place.
    #[tokio::test]
    async fn a_sealed_secret_opens_to_itself() {
        let sealer = sealer();

        let sealed = sealer
            .encrypt(b"totp-seed-bytes", &seed_place())
            .await
            .unwrap();
        let opened = sealer.decrypt(&sealed, &seed_place()).await.unwrap();

        assert_eq!(opened, b"totp-seed-bytes");
        assert!(sealed.as_str().starts_with("s2.r1."));
        assert!(!sealed.as_str().contains("totp"));
        assert!(!sealed.as_str().contains("mfa_enrollments"));
    }

    /// The same secret sealed twice reads differently each time, so equal
    /// secrets cannot be told apart in a table.
    #[tokio::test]
    async fn each_seal_draws_a_fresh_nonce() {
        let sealer = sealer();

        let first = sealer.encrypt(b"same", &seed_place()).await.unwrap();
        let second = sealer.encrypt(b"same", &seed_place()).await.unwrap();

        assert_ne!(first.as_str(), second.as_str());
    }

    /// After a rotation, a value sealed under the retired key still opens,
    /// and new values are sealed under the current one.
    #[tokio::test]
    async fn a_retired_key_still_opens_what_it_sealed() {
        let before = AesGcmSecretEncryptor::new(key("k1", 1), Vec::new());
        let old = before.encrypt(b"kept", &seed_place()).await.unwrap();
        let after = AesGcmSecretEncryptor::new(key("k2", 2), vec![key("k1", 1)]);

        let opened = after.decrypt(&old, &seed_place()).await.unwrap();
        let fresh = after.encrypt(b"kept", &seed_place()).await.unwrap();

        assert_eq!(opened, b"kept");
        assert!(fresh.as_str().starts_with("s2.k2."));
    }

    /// Unknown key IDs and unsupported sealed-value formats produce infrastructure errors.
    #[tokio::test]
    async fn a_value_of_an_unknown_key_or_format_is_refused() {
        let sealer = sealer();
        let elsewhere = AesGcmSecretEncryptor::new(key("k9", 9), Vec::new())
            .encrypt(b"x", &seed_place())
            .await
            .unwrap();
        let first_format = sealer
            .encrypt(b"x", &seed_place())
            .await
            .unwrap()
            .as_str()
            .replacen("s2.", "s1.", 1);

        for value in [
            elsewhere.as_str(),
            "v1.AAECAwQF",
            "s2.r1.not-base64!",
            first_format.as_str(),
        ] {
            let read = sealer
                .decrypt(&SealedSecret::new(value).unwrap(), &seed_place())
                .await;
            assert!(
                matches!(read, Err(DomainError::Infrastructure(_))),
                "{value} opened"
            );
        }
    }

    /// Altering ciphertext or substituting an ID for identical key bytes prevents decryption.
    #[tokio::test]
    async fn a_changed_value_does_not_open() {
        let sealer = AesGcmSecretEncryptor::new(key("k1", 1), vec![key("k2", 1)]);
        let sealed = sealer.encrypt(b"secret", &seed_place()).await.unwrap();
        let mut flipped = sealed.as_str().to_owned();
        let last = flipped
            .pop()
            .map_or('A', |c| if c == 'A' { 'B' } else { 'A' });
        flipped.push(last);
        let moved = sealed.as_str().replacen("s2.k1.", "s2.k2.", 1);

        for value in [flipped, moved] {
            let read = sealer
                .decrypt(&SealedSecret::new(value).unwrap(), &seed_place())
                .await;
            assert!(read.is_err());
        }
    }

    /// The sealed seed opens in its original location. Changing its owner, tenant,
    /// field or organization/platform scope prevents decryption.
    #[tokio::test]
    async fn a_value_moved_to_another_place_does_not_open() {
        let sealer = sealer();
        let (acme, ann) = (TenantId::new(), UserId::new());
        let sealed = sealer
            .encrypt(b"anns-seed", &anns_seed(acme, ann))
            .await
            .unwrap();
        let elsewhere = [
            anns_seed(acme, UserId::new()),
            anns_seed(TenantId::new(), ann),
            SealedFor::new(
                SealOwner::Tenant(acme),
                SealedField::WebhookSigningSecret,
                ann,
            ),
            SealedFor::new(
                SealOwner::Organization(OrganizationId::from_uuid(*acme.as_uuid())),
                SealedField::TotpSeed,
                ann,
            ),
            SealedFor::new(SealOwner::Platform, SealedField::TotpSeed, ann),
        ];

        let own = sealer.decrypt(&sealed, &anns_seed(acme, ann)).await;

        assert_eq!(own.unwrap(), b"anns-seed");
        for place in elsewhere {
            let read = sealer.decrypt(&sealed, &place).await;
            assert!(
                matches!(read, Err(DomainError::Infrastructure(_))),
                "{place:?} opened"
            );
        }
    }

    /// A key configured as hex and the same key as base64 seal alike, and
    /// a key of the wrong length is refused.
    #[tokio::test]
    async fn a_configured_key_reads_from_hex_or_base64() {
        let hex = SealingKey::parse("k1", &"07".repeat(KEY_BYTES)).unwrap();
        let base64 = SealingKey::parse(
            "k1",
            &base64::engine::general_purpose::STANDARD.encode([7_u8; KEY_BYTES]),
        )
        .unwrap();
        let sealed = AesGcmSecretEncryptor::new(hex, Vec::new())
            .encrypt(b"x", &seed_place())
            .await
            .unwrap();

        let opened = AesGcmSecretEncryptor::new(base64, Vec::new())
            .decrypt(&sealed, &seed_place())
            .await
            .unwrap();

        assert_eq!(opened, b"x");
        assert!(SealingKey::parse("k1", &"07".repeat(16)).is_err());
    }

    /// Empty, dotted, uppercase and overlong key IDs fail validation.
    #[test]
    fn a_key_id_outside_its_rules_is_refused() {
        for id in ["", "k.1", "K1", "a-very-long-key-id"] {
            assert!(
                SealingKey::new(id, [0; KEY_BYTES]).is_err(),
                "{id} was taken"
            );
        }
    }
}
