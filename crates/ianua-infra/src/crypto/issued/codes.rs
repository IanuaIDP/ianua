//! The codes people type or carry back: OAuth authorization and device
//! codes, the user code a device shows, the one-time codes sent by mail
//! or text, and MFA recovery codes.
//!
//! Each is kept only as its keyed digest. A sent code is six digits and a
//! recovery code ten letters and digits, so a bare digest of either is
//! reversed by trying every one; under a key the database never holds, a
//! copied table gives none of them away.

use async_trait::async_trait;
use ianua_app::ports::authentication::{
    RecoveryCodeGenerator, RecoveryCodePair, SentCodeGenerator,
};
use ianua_app::ports::oauth::CodeHasher;
use ianua_domain::domains::authentication::mfa::one_time_code::new_code;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{DeviceUserCode, TokenHash};
use rand::Rng as _;
use rand::rngs::OsRng;

use crate::crypto::OsRandomSource;
use crate::crypto::issued::{Issuer, made};
use crate::crypto::keys::{Purpose, RootSecret};
use crate::crypto::random::{base32, random_bytes};
use crate::crypto::seals::digests::KeyedDigest;

/// The letters a device's user code is drawn from: consonants that read
/// alike in every font, as RFC 8628 suggests, so nobody types a wrong one.
const USER_CODE_LETTERS: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

/// The letters in each half of a user code.
const USER_CODE_HALF: usize = 4;

/// The letters and digits in a recovery code, written as two groups.
const RECOVERY_CODE_LENGTH: usize = 10;

/// A user code of two groups of four, such as `BCDF-GHJK`, about 34 bits.
fn user_code() -> String {
    let mut drawn = (0..USER_CODE_HALF.saturating_mul(2)).map(|_| {
        let index = OsRng.gen_range(0..USER_CODE_LETTERS.len());
        char::from(USER_CODE_LETTERS.get(index).copied().unwrap_or(b'B'))
    });
    let first: String = drawn.by_ref().take(USER_CODE_HALF).collect();
    let second: String = drawn.collect();
    format!("{first}-{second}")
}

/// The maker and hasher of OAuth authorization codes and device codes,
/// each kept as its keyed digest.
#[derive(Debug, Clone)]
pub struct HmacCodeHasher {
    authorization: Issuer,
    device: Issuer,
}

impl HmacCodeHasher {
    /// A maker digesting under the key `root` derives for codes.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            authorization: Issuer::new(root, Purpose::AuthorizationCodes, "ac_"),
            device: Issuer::new(root, Purpose::AuthorizationCodes, "dc_"),
        }
    }
}

#[async_trait]
impl CodeHasher for HmacCodeHasher {
    async fn hash_code(&self, raw_code: &Secret) -> Result<TokenHash, DomainError> {
        Ok(self.authorization.digest_of(raw_code))
    }

    async fn generate_code(&self) -> Result<(Secret, TokenHash), DomainError> {
        self.authorization.issue()
    }

    async fn generate_user_code(&self) -> Result<DeviceUserCode, DomainError> {
        made(DeviceUserCode::new(user_code()))
    }

    async fn generate_device_code(&self) -> Result<(Secret, TokenHash), DomainError> {
        self.device.issue()
    }
}

/// The maker of the one-time codes sent by mail or text, each kept as its
/// keyed digest.
#[derive(Debug, Clone)]
pub struct HmacSentCodeGenerator {
    digest: KeyedDigest,
}

impl HmacSentCodeGenerator {
    /// A maker digesting under the key `root` derives for sent codes.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            digest: KeyedDigest::of(root, Purpose::SentCodes),
        }
    }
}

impl SentCodeGenerator for HmacSentCodeGenerator {
    fn generate(&self) -> Result<Secret, DomainError> {
        new_code(&mut OsRandomSource)
    }

    fn hash(&self, code: &Secret) -> TokenHash {
        self.digest.digest(code)
    }
}

/// The maker of MFA recovery codes, each kept as its keyed digest.
///
/// A code reads `xxxxx-xxxxx`. A typed one is read without case, spaces or
/// the dash, so `ABCDE FGHIJ` finds the code `abcde-fghij`.
#[derive(Debug, Clone)]
pub struct HmacRecoveryCodeGenerator {
    digest: KeyedDigest,
}

impl HmacRecoveryCodeGenerator {
    /// A maker digesting under the key `root` derives for recovery codes.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            digest: KeyedDigest::of(root, Purpose::RecoveryCodes),
        }
    }

    /// One fresh code, written in two groups.
    fn fresh() -> Result<Secret, DomainError> {
        let letters = base32(&random_bytes::<7>()?);
        let (first, second) = letters
            .get(..RECOVERY_CODE_LENGTH)
            .and_then(|code| code.split_at_checked(RECOVERY_CODE_LENGTH / 2))
            .ok_or_else(|| DomainError::infra_msg("a recovery code was drawn too short"))?;
        Ok(Secret::new(format!("{first}-{second}")))
    }
}

/// `typed` as its digest is taken: lowercase, without spaces or dashes.
fn plain(typed: &str) -> String {
    typed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

#[async_trait]
impl RecoveryCodeGenerator for HmacRecoveryCodeGenerator {
    async fn generate_batch(&self, count: u8) -> Result<Vec<RecoveryCodePair>, DomainError> {
        (0..count)
            .map(|_| {
                let raw = Self::fresh()?;
                let hash = self.hash_raw(&raw);
                Ok(RecoveryCodePair { raw, hash })
            })
            .collect()
    }

    fn hash_raw(&self, raw: &Secret) -> TokenHash {
        self.digest.digest_text(&plain(raw.expose()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::tests::test_root;

    /// A device's user code is two groups of four from the letters that
    /// read alike, and passes the domain's rules.
    #[tokio::test]
    async fn a_user_code_is_two_groups_of_unmistakable_letters() {
        let codes = HmacCodeHasher::new(&test_root());

        let code = codes.generate_user_code().await.unwrap();

        let (first, second) = code.as_str().split_once('-').unwrap();
        assert_eq!((first.len(), second.len()), (4, 4));
        assert!(
            first
                .bytes()
                .chain(second.bytes())
                .all(|letter| USER_CODE_LETTERS.contains(&letter))
        );
    }

    /// An authorization code is found by its digest, and a device code is
    /// not mistaken for one: each has its prefix.
    #[tokio::test]
    async fn an_authorization_code_is_found_by_its_digest() {
        let codes = HmacCodeHasher::new(&test_root());

        let (code, digest) = codes.generate_code().await.unwrap();
        let (device, _) = codes.generate_device_code().await.unwrap();

        assert_eq!(codes.hash_code(&code).await.unwrap(), digest);
        assert!(code.expose().starts_with("ac_"));
        assert!(device.expose().starts_with("dc_"));
    }

    /// A sent code is six digits, and the same code always digests alike.
    #[test]
    fn a_sent_code_is_six_digits_found_by_its_digest() {
        let codes = HmacSentCodeGenerator::new(&test_root());

        let code = codes.generate().unwrap();

        assert_eq!(code.expose().len(), 6);
        assert!(code.expose().bytes().all(|digit| digit.is_ascii_digit()));
        assert_eq!(codes.hash(&code), codes.hash(&Secret::new(code.expose())));
    }

    /// A batch of ten recovery codes holds ten different codes, and one
    /// typed in capitals with a space for the dash is found.
    #[tokio::test]
    async fn recovery_codes_are_found_however_they_are_typed() {
        let codes = HmacRecoveryCodeGenerator::new(&test_root());

        let batch = codes.generate_batch(10).await.unwrap();

        let distinct: std::collections::HashSet<&str> =
            batch.iter().map(|pair| pair.raw.expose()).collect();
        assert_eq!(distinct.len(), 10);
        let first = batch.first().unwrap();
        let typed = first.raw.expose().to_uppercase().replace('-', " ");
        assert_eq!(codes.hash_raw(&Secret::new(typed)), first.hash);
        assert_eq!(first.raw.expose().len(), 11);
    }
}
