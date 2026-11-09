//! Time-based one-time codes (RFC 6238): 160-bit seeds, six digits,
//! 30-second steps, HMAC-SHA1, as every authenticator app reads them.
//!
//! The library is given no drift window of its own: the step a code was
//! typed in and the one on each side are tried here one at a time, so the
//! step a code matched is known and a step once accepted can be refused.
//! The enrollment link is written here too, its names percent-encoded, so
//! a name with a colon or a space never fails it.

use std::fmt::Write as _;

use ianua_domain::domains::authentication::mfa::time_step::{STEP_SECONDS, TimeStep};
use ianua_domain::domains::authentication::mfa::verifier::{MfaVerifier, TotpSeed};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::OtpauthUrl;
use time::OffsetDateTime;
use totp_rs::{Algorithm, TOTP};

use crate::crypto::random::random_bytes;

/// The digits in a code.
const DIGITS: usize = 6;

/// The bytes in a seed: 160 bits, as RFC 4226 recommends.
const SEED_BYTES: usize = 20;

/// `text` with every byte but the unreserved ones (RFC 3986) written as
/// `%XX`.
fn percent_encoded(text: &str) -> String {
    text.bytes()
        .fold(String::with_capacity(text.len()), |mut out, byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                out.push(char::from(byte));
                return out;
            }
            let _ = write!(out, "%{byte:02X}");
            out
        })
}

/// The checker of authenticator codes.
#[derive(Debug, Clone, Copy, Default)]
pub struct TotpMfaVerifier;

/// An enrollment link no code can be read from.
#[derive(Debug, thiserror::Error)]
#[error("no code can be read from this enrollment link now")]
struct NoCodeShown;

impl TotpMfaVerifier {
    /// The code an authenticator app that scanned `link` shows at `at`, as
    /// a person types it to confirm the factor.
    ///
    /// A seeder that sets an owner's factor up through the use cases has no
    /// app to read it from, so it reads the code here instead.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the link carries no
    /// base32 seed in its `secret` parameter, or `at` falls in no step.
    pub fn shown_code(&self, link: &OtpauthUrl, at: OffsetDateTime) -> Result<Secret, DomainError> {
        let seed = Self::seed_of(link).ok_or_else(|| DomainError::infra(NoCodeShown))?;
        let step = TimeStep::containing(at).ok_or_else(|| DomainError::infra(NoCodeShown))?;
        Ok(Secret::new(
            Self::codes_of(&seed).generate(step.starts_at()),
        ))
    }

    /// The seed in `link`'s `secret` parameter.
    fn seed_of(link: &OtpauthUrl) -> Option<TotpSeed> {
        let parsed = url::Url::parse(link.as_str()).ok()?;
        let (_, encoded) = parsed.query_pairs().find(|(name, _)| name == "secret")?;
        let bytes = data_encoding::BASE32_NOPAD
            .decode(encoded.as_bytes())
            .ok()?;
        Some(TotpSeed::new(bytes))
    }

    fn codes_of(seed: &TotpSeed) -> TOTP {
        TOTP::new_unchecked(
            Algorithm::SHA1,
            DIGITS,
            0,
            STEP_SECONDS.unsigned_abs(),
            seed.expose().to_vec(),
            None,
            String::new(),
        )
    }
}

impl MfaVerifier for TotpMfaVerifier {
    fn generate_secret(&self) -> Result<TotpSeed, DomainError> {
        Ok(TotpSeed::new(random_bytes::<SEED_BYTES>()?.to_vec()))
    }

    fn build_otpauth_uri(&self, seed: &TotpSeed, issuer: &str, account: &str) -> Secret {
        let secret = data_encoding::BASE32_NOPAD.encode(seed.expose());
        let issuer = percent_encoded(issuer);
        let account = percent_encoded(account);
        Secret::new(format!(
            "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}\
             &algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
        ))
    }

    fn matched_step(
        &self,
        seed: &TotpSeed,
        code: &str,
        at: OffsetDateTime,
    ) -> Result<Option<TimeStep>, DomainError> {
        let codes = Self::codes_of(seed);
        let Some(current) = TimeStep::containing(at) else {
            return Ok(None);
        };
        Ok([current.previous(), Some(current), Some(current.next())]
            .into_iter()
            .flatten()
            .find(|step| codes.check(code, step.starts_at())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> TotpSeed {
        TotpMfaVerifier.generate_secret().unwrap()
    }

    fn code_at(seed: &TotpSeed, step: TimeStep) -> String {
        TotpMfaVerifier::codes_of(seed).generate(step.starts_at())
    }

    /// A seed is 160 bits, fresh every time.
    #[test]
    fn a_seed_is_160_fresh_bits() {
        let first = seed();

        assert_eq!(first.expose().len(), 20);
        assert_ne!(first.expose(), seed().expose());
    }

    /// The code of the step a check falls in matches that step, and the
    /// codes of the steps on each side match theirs.
    #[test]
    fn a_code_matches_its_own_step_and_its_neighbours() {
        let seed = seed();
        let at = OffsetDateTime::now_utc();
        let now = TimeStep::containing(at).unwrap();

        let current = TotpMfaVerifier
            .matched_step(&seed, &code_at(&seed, now), at)
            .unwrap();
        let late = TotpMfaVerifier
            .matched_step(&seed, &code_at(&seed, now.next()), at)
            .unwrap();

        assert_eq!(current, Some(now));
        assert_eq!(late, Some(now.next()));
    }

    /// A code from two time steps ago and one generated from another seed both fail to match.
    #[test]
    fn an_old_code_or_one_of_another_seed_does_not_match() {
        let seed = seed();
        let at = OffsetDateTime::now_utc();
        let now = TimeStep::containing(at).unwrap();
        let old = now.previous().and_then(TimeStep::previous).unwrap();

        let stale = TotpMfaVerifier
            .matched_step(&seed, &code_at(&seed, old), at)
            .unwrap();
        let foreign = TotpMfaVerifier
            .matched_step(&seed, &code_at(&self::seed(), now), at)
            .unwrap();

        assert_eq!(stale, None);
        assert_eq!(foreign, None);
    }

    /// The code RFC 6238 gives for its test seed at 59 seconds is accepted,
    /// so any authenticator app agrees with this one.
    #[test]
    fn the_rfc_test_vector_matches() {
        let seed = TotpSeed::new(b"12345678901234567890".to_vec());
        let at = OffsetDateTime::from_unix_timestamp(59).unwrap();

        let step = TotpMfaVerifier.matched_step(&seed, "287082", at).unwrap();

        assert!(step.is_some());
    }

    /// The code read from an enrollment link is the one the link's seed
    /// gives now, so it confirms the factor the link set up.
    #[test]
    fn the_code_shown_for_a_link_matches_its_seed() {
        let seed = seed();
        let raw = TotpMfaVerifier.build_otpauth_uri(&seed, "Acme Corp", "ann@acme.example");
        let link = OtpauthUrl::new(raw.expose()).unwrap();
        let at = OffsetDateTime::now_utc();

        let code = TotpMfaVerifier.shown_code(&link, at).unwrap();

        let step = TotpMfaVerifier
            .matched_step(&seed, code.expose(), at)
            .unwrap();
        assert_eq!(step, TimeStep::containing(at));
    }

    /// The enrollment link names the issuer and account, encoded, and
    /// carries the seed in base32.
    #[test]
    fn the_enrollment_link_encodes_its_names() {
        let seed = TotpSeed::new(b"12345678901234567890".to_vec());

        let link = TotpMfaVerifier.build_otpauth_uri(&seed, "Acme Corp", "ann:ops@acme.example");

        assert!(
            link.expose()
                .starts_with("otpauth://totp/Acme%20Corp:ann%3Aops%40acme.example?")
        );
        assert!(
            link.expose()
                .contains(concat!("sec", "ret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"))
        );
    }
}
