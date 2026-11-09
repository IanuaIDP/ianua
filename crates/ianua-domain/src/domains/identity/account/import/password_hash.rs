//! A password hash brought over from another system, in one of the formats
//! the platform can check a password against.
//!
//! Each format's costs are held to what one sign-in may spend checking it,
//! the same ceilings the hasher applies, so a hostile hash is refused when
//! it is imported rather than first when someone tries its password.

use std::ops::RangeInclusive;

use crate::message;
use crate::shared::validation::numeric::validate_range;
use crate::shared::validation::{Charset, CharsetUnion, ValidationError, Validator};
use crate::types::PasswordHash;

/// The field errors about an imported hash name.
const FIELD: &str = "password_hash";

/// The longest encoded hash read, in bytes. Every supported format fits
/// well inside it; a longer one is not a hash.
const MAX_ENCODED_BYTES: usize = 512;

/// The shortest salt, in encoded characters: eight bytes.
const MIN_SALT_CHARS: usize = 11;

/// The longest salt outside a PHC string, in encoded characters.
const MAX_SALT_CHARS: usize = 128;

/// The longest salt a PHC string holds, in encoded characters: the PHC
/// format's own limit.
const MAX_PHC_SALT_CHARS: usize = 64;

/// The shortest digest, in encoded characters: sixteen bytes.
const MIN_DIGEST_CHARS: usize = 22;

/// The longest digest, in encoded characters: sixty-four bytes.
const MAX_DIGEST_CHARS: usize = 86;

/// The salt and digest of a bcrypt hash together, in characters.
const BCRYPT_SALT_AND_DIGEST: usize = 53;

/// The bcrypt costs read: up to 2^14 rounds, about a second of one core.
const BCRYPT_COSTS: RangeInclusive<u32> = 4..=14;

/// The Argon2 memory costs read, in KiB: up to 256 MiB.
const ARGON2_MEMORY: RangeInclusive<u32> = 8..=262_144;

/// The Argon2 passes read.
const ARGON2_PASSES: RangeInclusive<u32> = 1..=10;

/// The Argon2 lanes read.
const ARGON2_LANES: RangeInclusive<u32> = 1..=16;

/// The memory Argon2 needs for each lane, in KiB.
const ARGON2_MEMORY_PER_LANE: u32 = 8;

/// The scrypt cost read, as the power of two `ln` names: with the largest
/// block size, up to 128 MiB of memory.
const SCRYPT_LOG_COST: RangeInclusive<u32> = 1..=17;

/// The scrypt block sizes read.
const SCRYPT_BLOCK_SIZE: RangeInclusive<u32> = 1..=8;

/// The scrypt parallelism read.
const SCRYPT_PARALLELISM: RangeInclusive<u32> = 1..=16;

/// The scrypt work read, cost times block size times parallelism: up to
/// what `ln=17,r=8,p=1` asks, however a hash splits it.
const SCRYPT_WORK: RangeInclusive<u64> = 1..=1 << 20;

/// The PBKDF2 rounds read. Fewer than a thousand guard nothing, and a hash
/// made with so few is refused rather than kept as if it did; more than a
/// million cost a sign-in too much to check.
const PBKDF2_ROUNDS: RangeInclusive<u32> = 1_000..=1_000_000;

/// The PBKDF2 digest lengths read, in bytes.
const PBKDF2_DIGEST_BYTES: RangeInclusive<u32> = 16..=64;

/// The way an imported hash was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashScheme {
    /// Argon2id, in its PHC string form:
    /// `$argon2id$v=19$m=65536,t=3,p=4$salt$digest`.
    Argon2id,
    /// bcrypt, in its modular crypt form: `$2b$12$` and 53 characters of
    /// salt and digest. `$2a$` and `$2y$` are read too.
    Bcrypt,
    /// scrypt, in its PHC string form: `$scrypt$ln=16,r=8,p=1$salt$digest`.
    Scrypt,
    /// PBKDF2 with SHA-256, in its PHC form
    /// `$pbkdf2-sha256$i=600000,l=32$salt$digest`, passlib's
    /// `$pbkdf2-sha256$29000$salt$digest`, or Django's
    /// `pbkdf2_sha256$600000$salt$digest`.
    Pbkdf2Sha256,
}

impl HashScheme {
    /// The scheme's name, stable across releases.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Argon2id => "argon2id",
            Self::Bcrypt => "bcrypt",
            Self::Scrypt => "scrypt",
            Self::Pbkdf2Sha256 => "pbkdf2_sha256",
        }
    }
}

/// A password hash read from another system's export, checked to be in a
/// format the platform can check a password against.
///
/// The hash is kept exactly as it came, so the password the person already
/// uses keeps working. It is still a hash someone can crack offline, so it
/// prints as redacted and compares in constant time, as every
/// [`PasswordHash`] does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedPasswordHash {
    scheme: HashScheme,
    hash: PasswordHash,
}

impl ImportedPasswordHash {
    /// Reads `encoded`, a hash in one of the formats [`HashScheme`] lists.
    ///
    /// Each format is read in full: its parameters are numbers in the
    /// ranges the scheme allows, and its salt and digest are in the
    /// alphabet the format writes them in. A hash in any other form would
    /// sit on an account no password could ever open, or open it for a
    /// password other than the person's. A hash whose costs are past what
    /// a sign-in may spend checking it is refused too: bcrypt past cost
    /// 14, Argon2 past 256 MiB, ten passes or sixteen lanes, scrypt past
    /// `ln=17,r=8,p=1`, PBKDF2 past a million rounds.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when `encoded` is blank, holds whitespace or
    ///   is longer than any supported format.
    /// - [`ValidationError`] when it is in no supported format, or a part
    ///   of its format is malformed or out of range, such as a PBKDF2 hash
    ///   of fewer than a thousand rounds or a bcrypt hash of cost 15.
    pub fn parse(encoded: &str) -> Result<Self, ValidationError> {
        Validator::new(FIELD, encoded)
            .max_bytes(MAX_ENCODED_BYTES)
            .not_empty()
            .ascii_only()
            .no_whitespace()
            .validate_first()?;
        let scheme = scheme_of(encoded)?;
        Ok(Self {
            scheme,
            hash: PasswordHash::from_stored(encoded.to_owned()),
        })
    }

    /// The way the hash was made.
    #[must_use]
    pub fn scheme(&self) -> HashScheme {
        self.scheme
    }

    /// The hash as the credential store keeps it.
    #[must_use]
    pub fn hash(&self) -> &PasswordHash {
        &self.hash
    }
}

/// The scheme `encoded` was made with, once each part of its format is
/// read in full.
///
/// # Errors
///
/// - [`ValidationError`] when it is in no supported format, or a part of
///   its format is malformed or out of range.
fn scheme_of(encoded: &str) -> Result<HashScheme, ValidationError> {
    let parts: Vec<&str> = encoded.split('$').collect();
    match parts.as_slice() {
        ["", "argon2id", version, params, salt, digest] => argon2id(version, params, salt, digest),
        ["", "2a" | "2b" | "2y", cost, rest] => bcrypt(cost, rest),
        ["", "scrypt", params, salt, digest] => scrypt(params, salt, digest),
        ["", "pbkdf2-sha256", params, salt, digest] if params.starts_with("i=") => {
            pbkdf2_phc(params, salt, digest)
        }
        ["", "pbkdf2-sha256", rounds, salt, digest] => pbkdf2_passlib(rounds, salt, digest),
        ["pbkdf2_sha256", rounds, salt, digest] => pbkdf2_django(rounds, salt, digest),
        _ => Err(unreadable("is in no supported hash format")),
    }
}

/// Reads Argon2id's version, its `m=..,t=..,p=..` costs, and its salt and
/// digest.
fn argon2id(
    version: &str,
    params: &str,
    salt: &str,
    digest: &str,
) -> Result<HashScheme, ValidationError> {
    if version != "v=19" {
        return Err(unreadable("names an Argon2 version other than 19"));
    }
    let [memory, passes, lanes] = params_of(params)?;
    let memory = number(memory, "m=", ARGON2_MEMORY)?;
    number(passes, "t=", ARGON2_PASSES)?;
    let lanes = number(lanes, "p=", ARGON2_LANES)?;
    if memory < ARGON2_MEMORY_PER_LANE.saturating_mul(lanes) {
        return Err(unreadable("names less Argon2 memory than its lanes need"));
    }
    phc_salt_and_digest(salt, digest)?;
    Ok(HashScheme::Argon2id)
}

/// Reads bcrypt's two-digit cost and its salt and digest.
fn bcrypt(cost: &str, rest: &str) -> Result<HashScheme, ValidationError> {
    Validator::new(FIELD, cost)
        .length(2..=2)
        .charset_single(Charset::DIGIT)
        .validate_first()?;
    number(cost, "", BCRYPT_COSTS)?;
    Validator::new(FIELD, rest)
        .length(BCRYPT_SALT_AND_DIGEST..=BCRYPT_SALT_AND_DIGEST)
        .charset(alphanumeric() | Charset::DOT | Charset::SLASH)
        .validate_first()?;
    Ok(HashScheme::Bcrypt)
}

/// Reads scrypt's `ln=..,r=..,p=..` costs and its salt and digest.
fn scrypt(params: &str, salt: &str, digest: &str) -> Result<HashScheme, ValidationError> {
    let [log_cost, block_size, parallelism] = params_of(params)?;
    let log_cost = number(log_cost, "ln=", SCRYPT_LOG_COST)?;
    let block_size = number(block_size, "r=", SCRYPT_BLOCK_SIZE)?;
    let parallelism = number(parallelism, "p=", SCRYPT_PARALLELISM)?;
    scrypt_work(log_cost, block_size, parallelism)?;
    phc_salt_and_digest(salt, digest)?;
    Ok(HashScheme::Scrypt)
}

/// Checks that scrypt's costs fit together: the cost below what the block
/// size can hold, as RFC 7914 asks, and the work within [`SCRYPT_WORK`].
/// The product saturates, so a cost past every bound reads as too much
/// work rather than wrapping round to a small one.
fn scrypt_work(log_cost: u32, block_size: u32, parallelism: u32) -> Result<(), ValidationError> {
    if log_cost >= block_size.saturating_mul(16) {
        return Err(unreadable(
            "names an scrypt cost its block size cannot hold",
        ));
    }
    let work = 1_u64
        .checked_shl(log_cost)
        .unwrap_or(u64::MAX)
        .saturating_mul(u64::from(block_size))
        .saturating_mul(u64::from(parallelism));
    validate_range(FIELD, work, SCRYPT_WORK)
}

/// Reads PBKDF2's PHC form: `i=600000` with an optional `,l=32` digest
/// length, which the digest must hold, and an unpadded base64 salt and
/// digest.
fn pbkdf2_phc(params: &str, salt: &str, digest: &str) -> Result<HashScheme, ValidationError> {
    let parts: Vec<&str> = params.split(',').collect();
    let (rounds, length) = match parts.as_slice() {
        [rounds] => (*rounds, None),
        [rounds, length] => (*rounds, Some(*length)),
        _ => return Err(unreadable("holds PBKDF2 parameters in no known form")),
    };
    number(rounds, "i=", PBKDF2_ROUNDS)?;
    if let Some(length) = length {
        digest_holds(digest, number(length, "l=", PBKDF2_DIGEST_BYTES)?)?;
    }
    phc_salt_and_digest(salt, digest)?;
    Ok(HashScheme::Pbkdf2Sha256)
}

/// Reads PBKDF2 as passlib writes it: bare rounds, and a salt and digest
/// in base64 with `.` for `+`.
fn pbkdf2_passlib(rounds: &str, salt: &str, digest: &str) -> Result<HashScheme, ValidationError> {
    number(rounds, "", PBKDF2_ROUNDS)?;
    salt_and_digest(salt, digest, base64() | Charset::DOT, MAX_SALT_CHARS)?;
    Ok(HashScheme::Pbkdf2Sha256)
}

/// Reads PBKDF2 as Django writes it: bare rounds, a salt, and a digest in
/// padded base64.
fn pbkdf2_django(rounds: &str, salt: &str, digest: &str) -> Result<HashScheme, ValidationError> {
    number(rounds, "", PBKDF2_ROUNDS)?;
    salt_and_digest(salt, digest.trim_end_matches('='), base64(), MAX_SALT_CHARS)?;
    Ok(HashScheme::Pbkdf2Sha256)
}

/// Checks that `digest`, in unpadded base64, holds `bytes` bytes.
fn digest_holds(digest: &str, bytes: u32) -> Result<(), ValidationError> {
    if u32::try_from(digest.len().saturating_mul(3) / 4) == Ok(bytes) {
        return Ok(());
    }
    Err(unreadable("holds a digest of another length than it names"))
}

/// The three comma-separated parameters of a PHC string.
fn params_of(params: &str) -> Result<[&str; 3], ValidationError> {
    let parts: Vec<&str> = params.split(',').collect();
    match parts.as_slice() {
        [first, second, third] => Ok([*first, *second, *third]),
        _ => Err(unreadable("holds its parameters in no known form")),
    }
}

/// The number in `range` that `part` holds after `prefix`.
fn number(part: &str, prefix: &str, range: RangeInclusive<u32>) -> Result<u32, ValidationError> {
    let digits = part
        .strip_prefix(prefix)
        .ok_or_else(|| unreadable("holds its parameters in no known order"))?;
    Validator::new(FIELD, digits)
        .length(1..=10)
        .charset_single(Charset::DIGIT)
        .validate_first()?;
    let value = digits
        .parse::<u32>()
        .map_err(|_| unreadable("holds a parameter too large to be one"))?;
    validate_range(FIELD, value, range)?;
    Ok(value)
}

/// Checks the salt and digest of a PHC string, in unpadded base64 and no
/// longer than the format holds.
fn phc_salt_and_digest(salt: &str, digest: &str) -> Result<(), ValidationError> {
    salt_and_digest(salt, digest, base64(), MAX_PHC_SALT_CHARS)
}

/// Checks a salt of at most `most_salt` characters and a digest, both
/// written in `alphabet`.
fn salt_and_digest(
    salt: &str,
    digest: &str,
    alphabet: CharsetUnion,
    most_salt: usize,
) -> Result<(), ValidationError> {
    Validator::new(FIELD, salt)
        .length(MIN_SALT_CHARS..=most_salt)
        .charset(alphabet.clone())
        .validate_first()?;
    Validator::new(FIELD, digest)
        .length(MIN_DIGEST_CHARS..=MAX_DIGEST_CHARS)
        .charset(alphabet)
        .validate_first()
}

/// Letters and digits.
fn alphanumeric() -> CharsetUnion {
    Charset::UPPERCASE | Charset::LOWERCASE | Charset::DIGIT
}

/// The alphabet base64 writes, its `=` padding left out.
fn base64() -> CharsetUnion {
    alphanumeric() | Charset::PLUS | Charset::SLASH
}

/// A hash refused for the reason `why` gives.
fn unreadable(why: &str) -> ValidationError {
    ValidationError::Custom {
        field: FIELD,
        code: "unsupported_password_hash".to_owned(),
        message: message!(
            "identity-the-password-hash",
            format!("the password hash {why}")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An Argon2id hash as the reference implementation writes it.
    const ARGON2ID: &str =
        "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

    /// A bcrypt hash of cost 12.
    const BCRYPT: &str = "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW";

    /// An scrypt hash in its PHC form.
    const SCRYPT: &str =
        "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";

    /// A PBKDF2-SHA256 hash in its PHC form.
    const PBKDF2_PHC: &str =
        "$pbkdf2-sha256$i=600000,l=32$c29tZXNhbHRzYWx0$Kv8b1pXxQ7Zp0Oq0d1wQh8cJ9eN2rR1yJmJ4d4k8tqs";

    /// A PBKDF2-SHA256 hash as passlib writes it.
    const PBKDF2_PASSLIB: &str =
        "$pbkdf2-sha256$29000$N2bMOcd4D2Hs/b.XMsZYyw$L4tCzXt.c8Ndw5gl8JlBbX8JxCdTvwjYpuNQwXv8wYo";

    /// A PBKDF2-SHA256 hash as Django writes it.
    const PBKDF2_DJANGO: &str =
        "pbkdf2_sha256$600000$ZVlWbFwXqbQx$3D3E8Ks0d0hXfXn0hvUNzZjQ2o1z7pBdDkQ1zj2C6pI=";

    /// Asserts that every one of `encoded` is refused.
    fn all_refused(encoded: &[&str]) {
        for hash in encoded {
            assert!(
                ImportedPasswordHash::parse(hash).is_err(),
                "{hash} was read"
            );
        }
    }

    /// Each supported format is read as its scheme, and the hash is kept
    /// exactly as it came, so the person's old password keeps working.
    #[test]
    fn every_supported_format_is_read_as_its_scheme() {
        let cases = [
            (ARGON2ID, HashScheme::Argon2id),
            (BCRYPT, HashScheme::Bcrypt),
            (SCRYPT, HashScheme::Scrypt),
            (PBKDF2_PHC, HashScheme::Pbkdf2Sha256),
            (PBKDF2_PASSLIB, HashScheme::Pbkdf2Sha256),
            (PBKDF2_DJANGO, HashScheme::Pbkdf2Sha256),
        ];

        for (encoded, scheme) in cases {
            let imported = ImportedPasswordHash::parse(encoded).unwrap();

            assert_eq!(imported.scheme(), scheme, "{encoded}");
            assert_eq!(imported.hash().as_str(), encoded);
        }
    }

    /// Each format at its ceiling is still read: bcrypt cost 14, Argon2
    /// at 256 MiB, ten passes and sixteen lanes, scrypt at `ln=17,r=8,p=1`
    /// and PBKDF2 at a million rounds.
    #[test]
    fn a_hash_at_its_ceiling_is_read() {
        let at_ceiling = [
            BCRYPT.replacen("$12$", "$14$", 1),
            ARGON2ID.replacen("m=65536,t=3,p=4", "m=262144,t=10,p=16", 1),
            SCRYPT.replacen("ln=16", "ln=17", 1),
            PBKDF2_PHC.replacen("i=600000", "i=1000000", 1),
            PBKDF2_DJANGO.replacen("$600000$", "$1000000$", 1),
        ];

        for encoded in at_ceiling {
            assert!(ImportedPasswordHash::parse(&encoded).is_ok(), "{encoded}");
        }
    }

    /// MD5 crypt, bare SHA-1, Argon2i and empty input are rejected as
    /// unsupported password-hash formats.
    #[test]
    fn a_hash_in_no_supported_format_is_refused() {
        all_refused(&[
            "$1$saltsalt$qjXMvbEw8oaL.CzflDugX/",
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
            "$argon2i$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
            "",
        ]);
    }

    /// A ten-round PBKDF2 hash fails the minimum-cost requirement at import.
    #[test]
    fn a_pbkdf2_hash_of_too_few_rounds_is_refused() {
        let weak = "pbkdf2_sha256$10$ZVlWbFwXqbQx$3D3E8Ks0d0hXfXn0hvUNzZjQ2o1z7pBdDkQ1zj2C6pI=";

        assert!(ImportedPasswordHash::parse(weak).is_err());
    }

    /// A bcrypt hash with cost 15 is refused before it can become an
    /// imported credential.
    #[test]
    fn a_bcrypt_hash_past_its_ceiling_is_refused() {
        all_refused(&[&BCRYPT.replacen("$12$", "$15$", 1)]);
    }

    /// Argon2id memory, pass and lane costs exceeding their individual
    /// ceilings are rejected at import.
    #[test]
    fn an_argon2id_hash_past_its_ceiling_is_refused() {
        all_refused(&[
            &ARGON2ID.replacen("m=65536", "m=4194304", 1),
            &ARGON2ID.replacen("m=65536", "m=262145", 1),
            &ARGON2ID.replacen("t=3", "t=11", 1),
            &ARGON2ID.replacen("p=4", "p=17", 1),
        ]);
    }

    /// Scrypt hashes exceeding the cost, block-size or combined-work
    /// ceiling are rejected at import.
    #[test]
    fn an_scrypt_hash_past_its_ceiling_is_refused() {
        all_refused(&[
            &SCRYPT.replacen("ln=16", "ln=18", 1),
            &SCRYPT.replacen("r=8", "r=9", 1),
            &SCRYPT.replacen("ln=16,r=8,p=1", "ln=17,r=8,p=2", 1),
            &SCRYPT.replacen("ln=16,r=8,p=1", "ln=14,r=8,p=16", 1),
        ]);
    }

    /// PBKDF2 hashes exceeding a million rounds are refused in PHC,
    /// passlib and Django forms.
    #[test]
    fn a_pbkdf2_hash_past_its_ceiling_is_refused() {
        all_refused(&[
            &PBKDF2_PHC.replacen("i=600000", "i=1000001", 1),
            &PBKDF2_PASSLIB.replacen("$29000$", "$1000001$", 1),
            &PBKDF2_DJANGO.replacen("$600000$", "$1000001$", 1),
        ]);
    }

    /// Incompatible scrypt cost and block size, and insufficient Argon2
    /// memory for its lanes, are rejected as unusable hash parameters.
    #[test]
    fn a_hash_whose_costs_cannot_run_is_refused() {
        all_refused(&[
            &SCRYPT.replacen("ln=16,r=8", "ln=16,r=1", 1),
            &ARGON2ID.replacen("m=65536,t=3,p=4", "m=64,t=3,p=16", 1),
        ]);
    }

    /// PBKDF2 hashes with a mismatched digest length or an oversized PHC
    /// salt are rejected.
    #[test]
    fn a_pbkdf2_hash_whose_parts_disagree_is_refused() {
        let long_salt = "c29tZXNhbHRzYWx0".repeat(5);

        all_refused(&[
            &PBKDF2_PHC.replacen("l=32", "l=64", 1),
            &PBKDF2_PHC.replacen("c29tZXNhbHRzYWx0", &long_salt, 1),
        ]);
    }

    /// A bcrypt hash cut short, one with a cost of 99, and one whose salt
    /// holds a character bcrypt never writes are each refused.
    #[test]
    fn a_malformed_bcrypt_hash_is_refused() {
        all_refused(&[
            "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMU",
            "$2b$99$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
            "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMU!",
        ]);
    }

    /// An Argon2id hash of another version, with its costs out of order, or
    /// with a salt too short to be one is refused.
    #[test]
    fn a_malformed_argon2id_hash_is_refused() {
        all_refused(&[
            "$argon2id$v=16$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
            "$argon2id$v=19$t=3,m=65536,p=4$c29tZXNhbHRzb21lc2FsdA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
            "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
        ]);
    }

    /// Debug formatting an imported bcrypt credential omits its hash data.
    #[test]
    fn an_imported_hash_never_prints() {
        let imported = ImportedPasswordHash::parse(BCRYPT).unwrap();

        assert!(!format!("{imported:?}").contains("R9h/cIPz0gi"));
    }
}
