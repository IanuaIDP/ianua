use crate::domains::authentication::credentials::password::PasswordHasher;
use crate::domains::authentication::mfa::time_step::TimeStep;
use crate::domains::authentication::mfa::verifier::{MfaVerifier, TotpSeed};
use crate::domains::authentication::tokens::refresh::{RefreshToken, RefreshTokenGenerator};
use crate::shared::errors::DomainError;
use crate::shared::random::RandomSource;
use crate::shared::security::secret::Secret;
use crate::types::{PasswordHash, TokenHash};

/// Test hasher that stores a password as `fake$` plus the password.
///
/// It does no real cryptography, so tests run fast. It exists only under
/// `#[cfg(test)]` or the `test-support` feature.
///
/// # Example
///
/// ```ignore
/// let hasher = FakeHasher;
/// let hash = hasher.hash("my_password").unwrap();
/// assert!(hasher.verify("my_password", &hash).unwrap());
/// ```
pub struct FakeHasher;

impl PasswordHasher for FakeHasher {
    /// Produces a fake hash by prefixing the plaintext with `"fake$"`.
    fn hash(&self, raw_password: &str) -> Result<PasswordHash, DomainError> {
        Ok(PasswordHash::from_stored(format!("fake${raw_password}")))
    }

    /// Verifies by comparing `"fake${raw_password}"` to the stored hash.
    fn verify(&self, raw_password: &str, hash: &PasswordHash) -> Result<bool, DomainError> {
        Ok(hash.as_str() == format!("fake${raw_password}"))
    }
}

/// Test hasher that salts like a real one.
///
/// The same password hashes differently every time, and only
/// [`verify`](PasswordHasher::verify) recognises it.
///
/// [`FakeHasher`] hashes a password the same way twice, so code that
/// compares hashes instead of verifying passwords passes its tests and
/// fails in production. Use this one wherever that difference matters.
#[derive(Default)]
pub struct SaltedFakeHasher {
    salt: std::sync::atomic::AtomicU64,
}

impl PasswordHasher for SaltedFakeHasher {
    /// Produces `"salted$<n>$<password>"` with a fresh `n` on every call.
    fn hash(&self, raw_password: &str) -> Result<PasswordHash, DomainError> {
        let salt = self.salt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(PasswordHash::from_stored(format!(
            "salted${salt}${raw_password}"
        )))
    }

    /// Verifies by reading the password back out from behind the salt.
    fn verify(&self, raw_password: &str, hash: &PasswordHash) -> Result<bool, DomainError> {
        let password = hash
            .as_str()
            .strip_prefix("salted$")
            .and_then(|rest| rest.split_once('$'))
            .map(|(_, password)| password);
        Ok(password == Some(raw_password))
    }
}

/// Test MFA verifier that accepts one fixed code.
///
/// It does no real TOTP work, so tests run fast. It exists only under
/// `#[cfg(test)]` or the `test-support` feature.
///
/// # Example
///
/// ```ignore
/// let verifier = FakeMfaVerifier { valid_code: "123456".to_owned() };
/// assert!(verifier.matched_step(&TotpSeed::new(vec![0xAB]), "123456", now).unwrap().is_some());
/// ```
pub struct FakeMfaVerifier {
    /// The one code it accepts.
    pub valid_code: String,
}

impl MfaVerifier for FakeMfaVerifier {
    /// Returns a fixed 8-byte secret.
    fn generate_secret(&self) -> Result<TotpSeed, DomainError> {
        Ok(TotpSeed::new(vec![
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33,
        ]))
    }

    /// Builds a fake `otpauth://` URI with a placeholder secret.
    fn build_otpauth_uri(&self, _seed: &TotpSeed, issuer: &str, account: &str) -> Secret {
        Secret::new(format!(
            "otpauth://totp/{issuer}:{account}?secret=FAKE&issuer={issuer}"
        ))
    }

    /// Accepts only the configured `valid_code`, as the code of the step
    /// containing `at`.
    fn matched_step(
        &self,
        _seed: &TotpSeed,
        code: &str,
        at: time::OffsetDateTime,
    ) -> Result<Option<TimeStep>, DomainError> {
        Ok(TimeStep::containing(at).filter(|_| code == self.valid_code))
    }
}

/// Test refresh token generator with predictable values.
///
/// Tokens start with `fake_refresh_` and hashes with `fake_hash_`. A
/// counter makes each token unique.
///
/// # Example
///
/// ```ignore
/// let gen = FakeRefreshTokenGenerator::new();
/// let token = gen.generate().unwrap();
/// assert!(token.raw().expose().starts_with("fake_refresh_"));
/// assert!(token.hash().starts_with("fake_hash_"));
/// ```
pub struct FakeRefreshTokenGenerator {
    /// The number the next token carries.
    counter: std::sync::atomic::AtomicU64,
}

impl FakeRefreshTokenGenerator {
    /// Creates a new fake generator starting at counter 0.
    #[must_use]
    pub fn new() -> Self {
        Self {
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl Default for FakeRefreshTokenGenerator {
    /// Creates a new fake generator starting at counter 0.
    fn default() -> Self {
        Self::new()
    }
}

impl RefreshTokenGenerator for FakeRefreshTokenGenerator {
    /// Returns a predictable token with an incrementing counter.
    fn generate(&self) -> Result<RefreshToken, DomainError> {
        let n = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let raw = format!("fake_refresh_{n}");
        let hash = self.hash_raw(&raw);
        Ok(RefreshToken::new(Secret::new(raw), hash))
    }

    /// Hashes by replacing the `fake_refresh_` prefix with `fake_hash_`.
    fn hash_raw(&self, raw: &str) -> TokenHash {
        TokenHash::from_stored(format!(
            "fake_hash_{}",
            raw.strip_prefix("fake_refresh_").unwrap_or(raw)
        ))
    }
}

/// Test passkey verifier that returns fixed challenges.
///
/// It accepts any list of credential ids. App-layer tests of `WebAuthn`
/// flows use it.
pub struct FakePasskeyVerifier;

impl crate::domains::authentication::credentials::passkey::PasskeyVerifier for FakePasskeyVerifier {
    /// Returns a fixed 32-byte challenge.
    fn generate_registration_challenge(
        &self,
        _user_id: &crate::types::UserId,
        _user_name: &str,
    ) -> Result<Vec<u8>, DomainError> {
        Ok(vec![0xAA; 32])
    }

    /// Returns a fixed 32-byte challenge.
    fn generate_authentication_challenge(
        &self,
        _credential_ids: &[Vec<u8>],
    ) -> Result<Vec<u8>, DomainError> {
        Ok(vec![0xBB; 32])
    }
}

/// Test random source that walks a fixed sequence of numbers.
///
/// Each draw takes the next number, modulo the range asked for, so a test
/// gets the same "random" choices every run.
pub struct SequenceRandom {
    next: usize,
}

impl SequenceRandom {
    /// A source starting its sequence at `seed`.
    #[must_use]
    pub fn new(seed: usize) -> Self {
        Self { next: seed }
    }
}

impl RandomSource for SequenceRandom {
    fn index_below(&mut self, upper: usize) -> usize {
        let index = self.next % upper;
        self.next = self.next.wrapping_mul(31).wrapping_add(7);
        index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hashing "my_password" gives a value that starts with `fake$` and still
    /// holds the password, so a test can read what was stored.
    #[test]
    fn fake_hasher_produces_prefixed_hash() {
        let hasher = FakeHasher;
        let hash = hasher.hash("my_password").unwrap();

        assert!(hash.as_str().starts_with("fake$"));
        assert!(hash.as_str().contains("my_password"));
    }

    /// A password hashed by the fake verifies against its own hash.
    #[test]
    fn fake_hasher_verifies_correct_password() {
        let hasher = FakeHasher;
        let hash = hasher.hash("correct_password").unwrap();

        assert!(hasher.verify("correct_password", &hash).unwrap());
    }

    /// A hash of "correct_password" does not verify "wrong_password", so
    /// tests of a failed sign-in behave as they would with a real hasher.
    #[test]
    fn fake_hasher_rejects_wrong_password() {
        let hasher = FakeHasher;
        let hash = hasher.hash("correct_password").unwrap();

        assert!(!hasher.verify("wrong_password", &hash).unwrap());
    }

    /// Two different passwords give two different hashes, so a test cannot
    /// mistake one user's password for another's.
    #[test]
    fn fake_hasher_different_passwords_produce_different_hashes() {
        let hasher = FakeHasher;
        let hash_a = hasher.hash("password_a").unwrap();
        let hash_b = hasher.hash("password_b").unwrap();

        assert_ne!(hash_a, hash_b);
    }

    /// An empty password hashes and verifies against itself, but its hash
    /// does not accept "notempty".
    #[test]
    fn fake_hasher_empty_password_works() {
        let hasher = FakeHasher;
        let hash = hasher.hash("").unwrap();

        assert!(hasher.verify("", &hash).unwrap());
        assert!(!hasher.verify("notempty", &hash).unwrap());
    }

    /// The fake verifier gives a non-empty TOTP secret, so enrollment code
    /// under test has bytes to store.
    #[test]
    fn fake_verifier_generates_secret() {
        let verifier = FakeMfaVerifier {
            valid_code: "123456".to_owned(),
        };

        let secret = verifier.generate_secret().unwrap();
        assert!(!secret.expose().is_empty());
    }

    fn seed() -> TotpSeed {
        TotpSeed::new(vec![0xAB])
    }

    /// The setup URI for issuer "Ianua" and account "alice@acme.com" is an
    /// `otpauth://totp/` link naming both.
    #[test]
    fn fake_verifier_builds_uri() {
        let verifier = FakeMfaVerifier {
            valid_code: "123456".to_owned(),
        };

        let built = verifier.build_otpauth_uri(&seed(), "Ianua", "alice@acme.com");
        let uri = built.expose();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("Ianua"));
        assert!(uri.contains("alice@acme.com"));
    }

    /// The configured code "123456" matches, and the match is the time step
    /// that holds the moment it was checked.
    #[test]
    fn fake_verifier_accepts_valid_code() {
        let verifier = FakeMfaVerifier {
            valid_code: "123456".to_owned(),
        };

        let now = crate::shared::clock::now();

        assert_eq!(
            verifier.matched_step(&seed(), "123456", now).unwrap(),
            TimeStep::containing(now)
        );
    }

    /// A user types "000000" when the fake expects "123456". No step
    /// matches.
    #[test]
    fn fake_verifier_rejects_invalid_code() {
        let verifier = FakeMfaVerifier {
            valid_code: "123456".to_owned(),
        };

        let matched = verifier
            .matched_step(&seed(), "000000", crate::shared::clock::now())
            .unwrap();

        assert!(matched.is_none());
    }

    /// A user submits the MFA form with no code. No step matches.
    #[test]
    fn fake_verifier_rejects_empty_code() {
        let verifier = FakeMfaVerifier {
            valid_code: "123456".to_owned(),
        };

        let matched = verifier
            .matched_step(&seed(), "", crate::shared::clock::now())
            .unwrap();

        assert!(matched.is_none());
    }

    /// A generated refresh token starts with `fake_refresh_` and its hash
    /// with `fake_hash_`, so tests can tell the two apart.
    #[test]
    fn fake_token_generator_produces_prefixed_values() {
        let generator = FakeRefreshTokenGenerator::new();
        let token = generator.generate().unwrap();

        assert!(token.raw().expose().starts_with("fake_refresh_"));
        assert!(token.hash().as_str().starts_with("fake_hash_"));
    }

    /// Two tokens from the same generator differ in both raw value and hash,
    /// so a rotation test sees a new token each time.
    #[test]
    fn fake_token_generator_produces_unique_tokens() {
        let generator = FakeRefreshTokenGenerator::new();
        let a = generator.generate().unwrap();
        let b = generator.generate().unwrap();

        assert_ne!(a.raw().expose(), b.raw().expose());
        assert_ne!(a.hash(), b.hash());
    }

    /// Splitting a generated token gives back the raw value and the hash,
    /// each with its own prefix.
    #[test]
    fn fake_token_generator_into_parts() {
        let generator = FakeRefreshTokenGenerator::new();
        let token = generator.generate().unwrap();
        let (raw, hash) = token.into_parts();

        assert!(raw.expose().starts_with("fake_refresh_"));
        assert!(hash.as_str().starts_with("fake_hash_"));
    }
}
