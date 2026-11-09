//! Passwords hashed with Argon2id, written in the PHC string format, and
//! the check that a stored hash is in the platform's own format.
//!
//! A hash names its algorithm and settings, so one made with weaker
//! settings, or brought over by an import in bcrypt, scrypt or
//! PBKDF2-SHA256, still checks its password and is replaced the first time
//! a sign-in proves it. One naming more work than a check may spend is
//! refused before any of that work is done. Every hash draws a salt of its
//! own; a password is compared with its hash in constant time.

use argon2::password_hash::{Error as PhcError, Output, PasswordHash as Phc, SaltString};
use argon2::{Algorithm, Argon2, Params, PasswordHasher as _, PasswordVerifier as _, Version};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use ianua_app::ports::authentication::PasswordHashFormat;
use ianua_domain::domains::authentication::credentials::password::PasswordHasher;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::PasswordHash;
use pbkdf2::pbkdf2_hmac;
use scrypt::Scrypt;
use sha2::Sha256;

use crate::crypto::random::random_bytes;

/// Why a password could not be hashed or checked. None of it names the
/// password or the hash.
#[derive(Debug, thiserror::Error)]
pub enum PasswordHashError {
    /// The settings are outside what Argon2 accepts.
    #[error("the Argon2 settings are outside what Argon2 accepts")]
    BadSettings,
    /// No salt could be drawn.
    #[error("no salt could be drawn for the password")]
    NoSalt,
    /// The hash could not be computed.
    #[error("the password could not be hashed")]
    CouldNotHash,
    /// The stored hash is not in a format this release reads.
    #[error("the stored password hash is not one this release reads")]
    Unreadable,
    /// The stored hash asks for more work than one sign-in may spend.
    #[error("the stored password hash asks for more work than a sign-in may spend")]
    TooCostly,
}

/// The most work a stored Argon2 hash may ask one check for, whatever its
/// own settings say: 256 MiB, ten passes and sixteen lanes. A hash brought
/// over by an import names its own costs, and one naming gigabytes would
/// let anyone who tries its password exhaust the server's memory.
const MOST_WORK: Argon2Settings = Argon2Settings {
    memory_kib: 262_144,
    iterations: 10,
    lanes: 16,
};

/// The highest bcrypt cost a stored hash may name: 2^14 rounds, about a
/// second of one core.
const BCRYPT_MOST_COST: u32 = 14;

/// The highest scrypt cost a stored hash may name, as the power of two
/// `ln` gives. With the largest block size it is 128 MiB of memory.
const SCRYPT_MOST_LOG_COST: u8 = 17;

/// The largest scrypt block size a stored hash may name.
const SCRYPT_MOST_BLOCK_SIZE: u32 = 8;

/// The most scrypt blocks one check may mix, cost times block size times
/// parallelism: what `ln=17,r=8,p=1` asks, however a hash splits it.
const SCRYPT_MOST_WORK: u64 = 1 << 20;

/// The most PBKDF2 rounds a stored hash may name.
const PBKDF2_MOST_ROUNDS: u32 = 1_000_000;

/// How hard each hash works: memory in KiB, passes and lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Settings {
    /// Memory each hash uses, in KiB.
    pub memory_kib: u32,
    /// Passes over that memory.
    pub iterations: u32,
    /// Lanes computed side by side.
    pub lanes: u32,
}

impl Default for Argon2Settings {
    /// 64 MiB, three passes and four lanes.
    fn default() -> Self {
        Self {
            memory_kib: 65_536,
            iterations: 3,
            lanes: 4,
        }
    }
}

impl Argon2Settings {
    fn params(self) -> Result<Params, PasswordHashError> {
        Params::new(self.memory_kib, self.iterations, self.lanes, None)
            .map_err(|_| PasswordHashError::BadSettings)
    }

    /// Whether `params` work at least as hard as these settings.
    fn met_by(self, params: &Params) -> bool {
        params.m_cost() >= self.memory_kib
            && params.t_cost() >= self.iterations
            && params.p_cost() >= self.lanes
    }

    /// Whether `params` work no harder than these settings.
    fn bound(self, params: &Params) -> bool {
        params.m_cost() <= self.memory_kib
            && params.t_cost() <= self.iterations
            && params.p_cost() <= self.lanes
    }

    /// The harder of these settings and `other`, field by field.
    fn or_harder(self, other: Self) -> Self {
        Self {
            memory_kib: self.memory_kib.max(other.memory_kib),
            iterations: self.iterations.max(other.iterations),
            lanes: self.lanes.max(other.lanes),
        }
    }
}

/// The hasher of passwords: Argon2id under the platform's settings. It
/// checks a password against Argon2, bcrypt, scrypt and PBKDF2-SHA256
/// hashes, the formats an import brings.
pub struct Argon2PasswordHasher {
    argon: Argon2<'static>,
    ceiling: Argon2Settings,
}

impl Argon2PasswordHasher {
    /// A hasher working as hard as `settings` say. A stored Argon2 hash is
    /// checked only when it asks for no more than 256 MiB, ten passes and
    /// sixteen lanes, or than `settings` when they are harder.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordHashError::BadSettings`] when Argon2 refuses them.
    pub fn new(settings: Argon2Settings) -> Result<Self, PasswordHashError> {
        Ok(Self {
            argon: Argon2::new(Algorithm::Argon2id, Version::V0x13, settings.params()?),
            ceiling: settings.or_harder(MOST_WORK),
        })
    }

    /// Whether `password` is the one `stored` was made from, in whichever
    /// supported format `stored` is written.
    fn checked(&self, password: &[u8], stored: &str) -> Result<bool, PasswordHashError> {
        let parts: Vec<&str> = stored.split('$').collect();
        match parts.as_slice() {
            ["", "2a" | "2b" | "2y", ..] => bcrypt_checked(password, stored),
            ["", "pbkdf2-sha256", rounds, salt, digest] if is_bare_number(rounds) => {
                Pbkdf2Sha256::passlib(rounds, salt, digest)?.checked(password)
            }
            ["pbkdf2_sha256", rounds, salt, digest] => {
                Pbkdf2Sha256::django(rounds, salt, digest)?.checked(password)
            }
            _ => self.phc_checked(password, stored),
        }
    }

    /// Whether `password` is the one `stored`, a PHC string, was made from.
    fn phc_checked(&self, password: &[u8], stored: &str) -> Result<bool, PasswordHashError> {
        let parsed = Phc::new(stored).map_err(|_| PasswordHashError::Unreadable)?;
        match parsed.algorithm.as_str() {
            "argon2id" | "argon2i" | "argon2d" => self.argon2_checked(password, &parsed),
            "scrypt" => scrypt_checked(password, &parsed),
            "pbkdf2-sha256" => Pbkdf2Sha256::phc(&parsed)?.checked(password),
            _ => Err(PasswordHashError::Unreadable),
        }
    }

    /// Checks an Argon2 hash, refused when it asks for more work than a
    /// check may spend.
    fn argon2_checked(&self, password: &[u8], parsed: &Phc<'_>) -> Result<bool, PasswordHashError> {
        let params = Params::try_from(parsed).map_err(|_| PasswordHashError::Unreadable)?;
        if !self.ceiling.bound(&params) {
            return Err(PasswordHashError::TooCostly);
        }
        outcome(Argon2::default().verify_password(password, parsed))
    }

    fn hashed(&self, raw_password: &str) -> Result<String, PasswordHashError> {
        let salt_bytes = random_bytes::<16>().map_err(|_| PasswordHashError::NoSalt)?;
        let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| PasswordHashError::NoSalt)?;
        let hash = self
            .argon
            .hash_password(raw_password.as_bytes(), &salt)
            .map_err(|_| PasswordHashError::CouldNotHash)?;
        Ok(hash.to_string())
    }
}

impl PasswordHasher for Argon2PasswordHasher {
    fn hash(&self, raw_password: &str) -> Result<PasswordHash, DomainError> {
        let hashed = self.hashed(raw_password).map_err(DomainError::infra)?;
        Ok(PasswordHash::from_stored(hashed))
    }

    fn verify(&self, raw_password: &str, hash: &PasswordHash) -> Result<bool, DomainError> {
        self.checked(raw_password.as_bytes(), hash.as_str())
            .map_err(DomainError::infra)
    }
}

/// Checks a bcrypt hash, refused when its cost is past
/// [`BCRYPT_MOST_COST`]. The digests are compared in constant time.
fn bcrypt_checked(password: &[u8], stored: &str) -> Result<bool, PasswordHashError> {
    let parts = stored
        .parse::<bcrypt::HashParts>()
        .map_err(|_| PasswordHashError::Unreadable)?;
    if parts.get_cost() > BCRYPT_MOST_COST {
        return Err(PasswordHashError::TooCostly);
    }
    bcrypt::verify(password, stored).map_err(|_| PasswordHashError::Unreadable)
}

/// Checks an scrypt hash, refused when it asks for more work than a check
/// may spend.
fn scrypt_checked(password: &[u8], parsed: &Phc<'_>) -> Result<bool, PasswordHashError> {
    let params = scrypt::Params::try_from(parsed).map_err(|_| PasswordHashError::Unreadable)?;
    if !scrypt_affordable(&params) {
        return Err(PasswordHashError::TooCostly);
    }
    outcome(Scrypt.verify_password(password, parsed))
}

/// Whether `params` stay within the scrypt ceilings. The work saturates,
/// so a cost past every bound reads as too much rather than wrapping.
fn scrypt_affordable(params: &scrypt::Params) -> bool {
    let work = 1_u64
        .checked_shl(u32::from(params.log_n()))
        .unwrap_or(u64::MAX)
        .saturating_mul(u64::from(params.r()))
        .saturating_mul(u64::from(params.p()));
    params.log_n() <= SCRYPT_MOST_LOG_COST
        && params.r() <= SCRYPT_MOST_BLOCK_SIZE
        && work <= SCRYPT_MOST_WORK
}

/// What a PHC hasher's check says: a match, a mismatch, or a hash it could
/// not read.
fn outcome(checked: Result<(), PhcError>) -> Result<bool, PasswordHashError> {
    match checked {
        Ok(()) => Ok(true),
        Err(PhcError::Password) => Ok(false),
        Err(_) => Err(PasswordHashError::Unreadable),
    }
}

/// Whether `part` is digits alone, as passlib writes PBKDF2 rounds.
fn is_bare_number(part: &str) -> bool {
    !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
}

/// A PBKDF2-SHA256 hash, read from any of the forms an import brings.
struct Pbkdf2Sha256 {
    rounds: u32,
    salt: Vec<u8>,
    expected: Output,
}

impl Pbkdf2Sha256 {
    /// The PHC form, `$pbkdf2-sha256$i=600000[,l=32]$salt$digest`: salt
    /// and digest in unpadded base64. Without `l`, the digest is as long
    /// as the one written.
    fn phc(parsed: &Phc<'_>) -> Result<Self, PasswordHashError> {
        let params = pbkdf2::Params::try_from(parsed).map_err(|_| PasswordHashError::Unreadable)?;
        let (Some(salt), Some(expected)) = (parsed.salt, parsed.hash) else {
            return Err(PasswordHashError::Unreadable);
        };
        let mut buffer = [0_u8; 64];
        let salt = salt
            .decode_b64(&mut buffer)
            .map_err(|_| PasswordHashError::Unreadable)?;
        Self::new(params.rounds, salt.to_vec(), expected)
    }

    /// passlib's form, `$pbkdf2-sha256$29000$salt$digest`: salt and digest
    /// in base64 with `.` for `+` and no padding.
    fn passlib(rounds: &str, salt: &str, digest: &str) -> Result<Self, PasswordHashError> {
        let expected = output_of(&adapted_base64(digest)?)?;
        Self::new(rounds_of(rounds)?, adapted_base64(salt)?, expected)
    }

    /// Django's form, `pbkdf2_sha256$600000$salt$digest`: the salt used as
    /// written, the digest in padded base64.
    fn django(rounds: &str, salt: &str, digest: &str) -> Result<Self, PasswordHashError> {
        let digest = STANDARD
            .decode(digest)
            .map_err(|_| PasswordHashError::Unreadable)?;
        Self::new(
            rounds_of(rounds)?,
            salt.as_bytes().to_vec(),
            output_of(&digest)?,
        )
    }

    /// A hash of `rounds` rounds; none at all is no hash.
    fn new(rounds: u32, salt: Vec<u8>, expected: Output) -> Result<Self, PasswordHashError> {
        if rounds == 0 {
            return Err(PasswordHashError::Unreadable);
        }
        Ok(Self {
            rounds,
            salt,
            expected,
        })
    }

    /// Whether `password` derives the digest, refused unrun past
    /// [`PBKDF2_MOST_ROUNDS`]. The digests are compared in constant time.
    fn checked(&self, password: &[u8]) -> Result<bool, PasswordHashError> {
        if self.rounds > PBKDF2_MOST_ROUNDS {
            return Err(PasswordHashError::TooCostly);
        }
        let computed = Output::init_with(self.expected.len(), |out| {
            pbkdf2_hmac::<Sha256>(password, &self.salt, self.rounds, out);
            Ok(())
        })
        .map_err(|_| PasswordHashError::Unreadable)?;
        Ok(computed == self.expected)
    }
}

/// The rounds a PBKDF2 hash names.
fn rounds_of(rounds: &str) -> Result<u32, PasswordHashError> {
    rounds.parse().map_err(|_| PasswordHashError::Unreadable)
}

/// The bytes passlib's base64 holds: `.` for `+`, no padding.
fn adapted_base64(encoded: &str) -> Result<Vec<u8>, PasswordHashError> {
    STANDARD_NO_PAD
        .decode(encoded.replace('.', "+"))
        .map_err(|_| PasswordHashError::Unreadable)
}

/// A digest as a value compared in constant time.
fn output_of(digest: &[u8]) -> Result<Output, PasswordHashError> {
    Output::new(digest).map_err(|_| PasswordHashError::Unreadable)
}

/// The check that a stored hash is Argon2id under settings at least as
/// hard as the platform's own.
#[derive(Debug, Clone, Copy)]
pub struct Argon2PasswordHashFormat {
    settings: Argon2Settings,
}

impl Argon2PasswordHashFormat {
    /// A check against `settings`.
    #[must_use]
    pub fn new(settings: Argon2Settings) -> Self {
        Self { settings }
    }
}

impl PasswordHashFormat for Argon2PasswordHashFormat {
    fn needs_rehash(&self, hash: &PasswordHash) -> bool {
        let Ok(parsed) = Phc::new(hash.as_str()) else {
            return true;
        };
        let Ok(params) = Params::try_from(&parsed) else {
            return true;
        };
        let ours = parsed.algorithm == Algorithm::Argon2id.ident()
            && parsed.version == Some(Version::V0x13.into());
        !(ours && self.settings.met_by(&params))
    }
}

#[cfg(test)]
mod tests {
    use pbkdf2::Pbkdf2;

    use super::*;

    /// The password every imported hash below was made from.
    const PASSWORD: &str = "correct horse";

    /// PBKDF2-SHA256 of [`PASSWORD`] in passlib's form, made with Python's
    /// `hashlib` and passlib's encoding; its salt holds a `.`.
    const PASSLIB: &str =
        "$pbkdf2-sha256$1000$.N7be09prfXee2/NOUeotQ$AA1AF76IG6n8xlLtjr97aE66FDvM8OoEY91ZiMoEKSY";

    /// PBKDF2-SHA256 of [`PASSWORD`] in Django's form, made with Python's
    /// `hashlib` as Django makes it.
    const DJANGO: &str =
        "pbkdf2_sha256$1000$ZVlWbFwXqbQx$wLTQYm8J6eVP7NoWvw581zOgbFDdfTUxrr6YZ+sr2dE=";

    /// PBKDF2-SHA256 of [`PASSWORD`] in its PHC form without `l=`, made
    /// with Python's `hashlib`.
    const PHC_PBKDF2: &str =
        "$pbkdf2-sha256$i=1000$c2l4dGVlbiBieXRlIHNsdA$c5QUhhzJnj7wFB9c2d0a39fA2UDUysXCg74o4Wch4QE";

    /// scrypt of [`PASSWORD`] in its PHC form, made with Python's
    /// `hashlib`.
    const PHC_SCRYPT: &str =
        "$scrypt$ln=10,r=8,p=1$c2l4dGVlbiBieXRlIHNsdA$pm8pKHMuzBMnzWjY+J2K8bOo4zfV05STJL8ONhhN0II";

    /// Settings light enough for tests, which hash many passwords.
    fn light() -> Argon2Settings {
        Argon2Settings {
            memory_kib: 1024,
            iterations: 1,
            lanes: 1,
        }
    }

    fn hasher() -> Argon2PasswordHasher {
        Argon2PasswordHasher::new(light()).unwrap()
    }

    fn stored(encoded: &str) -> PasswordHash {
        PasswordHash::from_stored(encoded.to_owned())
    }

    /// A salt for the hashes the tests make with each crate.
    fn salt() -> SaltString {
        SaltString::encode_b64(b"sixteen byte slt").unwrap()
    }

    fn bcrypt_hash() -> String {
        bcrypt::hash(PASSWORD, 4).unwrap()
    }

    fn scrypt_hash() -> String {
        let params = scrypt::Params::new(10, 8, 1, 32).unwrap();
        Scrypt
            .hash_password_customized(PASSWORD.as_bytes(), None, None, params, &salt())
            .unwrap()
            .to_string()
    }

    fn pbkdf2_hash() -> String {
        let params = pbkdf2::Params {
            rounds: 1_000,
            output_length: 32,
        };
        Pbkdf2
            .hash_password_customized(PASSWORD.as_bytes(), None, None, params, &salt())
            .unwrap()
            .to_string()
    }

    /// Whether checking `encoded` is refused as too costly to run.
    fn refused_as_costly(encoded: &str) -> bool {
        matches!(
            hasher().checked(PASSWORD.as_bytes(), encoded),
            Err(PasswordHashError::TooCostly)
        )
    }

    /// A password checks against its own hash and no other password does;
    /// the hash says it is Argon2id and holds nothing of the password.
    #[test]
    fn a_password_checks_against_its_own_hash() {
        let hasher = hasher();

        let hash = hasher.hash("correct horse battery").unwrap();

        assert!(hasher.verify("correct horse battery", &hash).unwrap());
        assert!(!hasher.verify("correct horse batterz", &hash).unwrap());
        assert!(hash.as_str().starts_with("$argon2id$v=19$"));
        assert!(!hash.as_str().contains("horse"));
    }

    /// The same password hashed twice reads differently, each with a salt
    /// of its own, so equal passwords cannot be told apart in a table.
    #[test]
    fn each_hash_draws_its_own_salt() {
        let hasher = hasher();

        let first = hasher.hash("same password").unwrap();
        let second = hasher.hash("same password").unwrap();

        assert_ne!(first.as_str(), second.as_str());
    }

    /// Unreadable stored hash text produces an infrastructure error rather than a password mismatch.
    #[test]
    fn an_unreadable_hash_is_refused() {
        let read = hasher().verify("anything", &stored("plain"));

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Argon2 parameters requesting four GiB and a hundred passes exceed the work limits.
    #[test]
    fn a_hash_asking_for_more_work_than_a_check_may_spend_is_refused() {
        let costly = "$argon2id$v=19$m=4194304,t=100,p=255$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";

        let read = hasher().verify("anything", &stored(costly));

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
        assert!(refused_as_costly(costly));
    }

    /// A hash made under settings harder than the usual ceiling still
    /// checks with the hasher that made it.
    #[test]
    fn a_hash_under_the_hashers_own_harder_settings_checks() {
        let hard = Argon2PasswordHasher::new(Argon2Settings {
            lanes: 32,
            ..light()
        })
        .unwrap();

        let hash = hard.hash("pw").unwrap();

        assert!(hard.verify("pw", &hash).unwrap());
    }

    /// An imported bcrypt hash verifies its original password and rejects another password.
    #[test]
    fn an_imported_bcrypt_hash_checks_its_password() {
        let hash = stored(&bcrypt_hash());

        assert!(hasher().verify(PASSWORD, &hash).unwrap());
        assert!(!hasher().verify("correct horsf", &hash).unwrap());
    }

    /// Both supported scrypt encodings accept the matching password and reject a different one.
    #[test]
    fn an_imported_scrypt_hash_checks_its_password() {
        for encoded in [scrypt_hash(), PHC_SCRYPT.to_owned()] {
            let hash = stored(&encoded);

            assert!(hasher().verify(PASSWORD, &hash).unwrap(), "{encoded}");
            assert!(
                !hasher().verify("correct horsf", &hash).unwrap(),
                "{encoded}"
            );
        }
    }

    /// PHC, passlib and Django PBKDF2 encodings accept the original password
    /// and reject another, including PHC with or without an explicit length.
    #[test]
    fn an_imported_pbkdf2_hash_checks_its_password_in_every_form() {
        for encoded in [
            pbkdf2_hash(),
            PHC_PBKDF2.to_owned(),
            PASSLIB.to_owned(),
            DJANGO.to_owned(),
        ] {
            let hash = stored(&encoded);

            assert!(hasher().verify(PASSWORD, &hash).unwrap(), "{encoded}");
            assert!(
                !hasher().verify("correct horsf", &hash).unwrap(),
                "{encoded}"
            );
        }
    }

    /// Bcrypt cost 15 exceeds the accepted verification ceiling.
    #[test]
    fn a_bcrypt_hash_past_its_ceiling_is_refused() {
        let costly = bcrypt_hash().replacen("$04$", "$15$", 1);

        assert!(refused_as_costly(&costly));
    }

    /// Scrypt hashes exceeding the cost, block-size or combined work ceilings are rejected.
    #[test]
    fn an_scrypt_hash_past_its_ceiling_is_refused() {
        let made = scrypt_hash();

        for costly in ["ln=18,r=8,p=1", "ln=10,r=16,p=1", "ln=17,r=8,p=2"] {
            assert!(
                refused_as_costly(&made.replacen("ln=10,r=8,p=1", costly, 1)),
                "{costly}"
            );
        }
    }

    /// Every supported PBKDF2 encoding rejects a count above one million rounds.
    #[test]
    fn a_pbkdf2_hash_past_its_ceiling_is_refused() {
        for costly in [
            pbkdf2_hash().replacen("i=1000,", "i=1000001,", 1),
            PASSLIB.replacen("$1000$", "$1000001$", 1),
            DJANGO.replacen("$1000$", "$1000001$", 1),
        ] {
            assert!(refused_as_costly(&costly), "{costly}");
        }
    }

    /// Malformed imported hashes produce infrastructure errors, preserving the distinction
    /// between corrupt storage and an incorrect password.
    #[test]
    fn a_malformed_imported_hash_is_refused() {
        for encoded in [
            "$2b$04$tooshort".to_owned(),
            scrypt_hash().replacen("ln=10", "ln=x", 1),
            "$pbkdf2-sha256$1000$!!!$AA1AF76IG6n8xlLtjr97aE66FDvM8OoEY91ZiMoEKSY".to_owned(),
            "pbkdf2_sha256$many$ZVlWbFwXqbQx$wLTQYm8J6eVP7NoWvw581zOgbFDdfTUxrr6YZ+sr2dE="
                .to_owned(),
            "pbkdf2_sha256$0$ZVlWbFwXqbQx$wLTQYm8J6eVP7NoWvw581zOgbFDdfTUxrr6YZ+sr2dE=".to_owned(),
        ] {
            let read = hasher().verify(PASSWORD, &stored(&encoded));

            assert!(
                matches!(read, Err(DomainError::Infrastructure(_))),
                "{encoded}"
            );
        }
    }

    /// A hash under the platform's settings is kept; one under weaker
    /// settings, of another algorithm, or unreadable is replaced.
    #[test]
    fn only_a_hash_in_the_platforms_format_is_kept() {
        let format = Argon2PasswordHashFormat::new(light());
        let ours = hasher().hash("pw").unwrap();
        let weaker = Argon2PasswordHasher::new(Argon2Settings {
            memory_kib: 512,
            ..light()
        })
        .unwrap()
        .hash("pw")
        .unwrap();
        let other = stored("$argon2i$v=19$m=1024,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA");

        assert!(!format.needs_rehash(&ours));
        assert!(format.needs_rehash(&weaker));
        assert!(format.needs_rehash(&other));
        assert!(format.needs_rehash(&stored("$2b$12$bcrypt")));
    }

    /// Bcrypt, scrypt and PBKDF2 imports are all marked as needing an Argon2id rehash.
    #[test]
    fn every_imported_format_is_replaced_once_proved() {
        let format = Argon2PasswordHashFormat::new(light());

        for encoded in [
            bcrypt_hash(),
            scrypt_hash(),
            pbkdf2_hash(),
            PASSLIB.to_owned(),
            DJANGO.to_owned(),
        ] {
            assert!(format.needs_rehash(&stored(&encoded)), "{encoded}");
        }
    }
}
