//! Chance drawn from the operating system's secure generator, which keeps
//! no state of its own, so a draw needs no lock, and the encodings the
//! platform writes random secrets in.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_app::ports::crypto::SecureTokenGenerator;
use ianua_app::ports::runtime::SecureRandom;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::random::RandomSource;
use ianua_domain::shared::security::secret::Secret;
use rand::rngs::OsRng;
use rand::{Rng as _, RngCore as _};

/// `N` bytes from the operating system's secure generator.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the generator cannot be read.
pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], DomainError> {
    let mut bytes = [0_u8; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(DomainError::infra)?;
    Ok(bytes)
}

/// `bytes` as lowercase base32 with no padding: letters and digits only,
/// so a token written in it is never split by the `_` between the parts
/// of a key, and reads aloud without case.
pub(crate) fn base32(bytes: &[u8]) -> String {
    data_encoding::BASE32_DNSSEC.encode(bytes)
}

/// The secure generator's uniform choices, for the app's port.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsSecureRandom;

impl SecureRandom for OsSecureRandom {
    fn index_below(&self, upper: usize) -> usize {
        OsRng.gen_range(0..upper.max(1))
    }
}

/// The secure generator's uniform choices, for the domain's rules.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct OsRandomSource;

impl RandomSource for OsRandomSource {
    fn index_below(&mut self, upper: usize) -> usize {
        OsRng.gen_range(0..upper.max(1))
    }
}

/// Random tokens of a requested length, as URL-safe base64.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsSecureTokenGenerator;

impl SecureTokenGenerator for OsSecureTokenGenerator {
    fn generate(&self, byte_len: usize) -> Secret {
        let mut bytes = vec![0_u8; byte_len];
        OsRng.fill_bytes(&mut bytes);
        Secret::new(URL_SAFE_NO_PAD.encode(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every index drawn is below the bound, and over many draws each one
    /// below it comes up.
    #[test]
    fn indexes_fall_below_the_bound_and_cover_it() {
        let random = OsSecureRandom;

        let drawn: std::collections::HashSet<usize> =
            (0..500).map(|_| random.index_below(5)).collect();

        assert_eq!(drawn, (0..5).collect());
    }

    /// Two tokens of 32 bytes are 43 characters of URL-safe base64, and
    /// never the same.
    #[test]
    fn tokens_are_url_safe_and_fresh() {
        let tokens = OsSecureTokenGenerator;

        let first = tokens.generate(32);
        let second = tokens.generate(32);

        assert_eq!(first.expose().len(), 43);
        assert!(
            first
                .expose()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert_ne!(first.expose(), second.expose());
    }

    /// Base32 is letters and digits only, lowercase.
    #[test]
    fn base32_holds_lowercase_letters_and_digits() {
        let written = base32(&random_bytes::<20>().unwrap());

        assert_eq!(written.len(), 32);
        assert!(
            written
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }
}
