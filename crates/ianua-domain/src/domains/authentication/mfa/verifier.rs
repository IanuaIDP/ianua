use time::OffsetDateTime;

use crate::domains::authentication::mfa::time_step::TimeStep;
use crate::shared::errors::DomainError;
use crate::shared::security::secret::Secret;

/// The shared seed an authenticator app derives its codes from.
///
/// Whoever holds it can make every code the person's app makes. So its
/// `Debug` says only that it exists. It has no `==`, and it is wiped on drop.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct TotpSeed(Vec<u8>);

impl TotpSeed {
    /// Wraps seed bytes, freshly generated or decrypted from storage.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes, for the one place that encrypts them or computes a code.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for TotpSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpSeed(redacted)")
    }
}

/// Makes TOTP seeds and checks TOTP codes.
///
/// Infrastructure implements it with a TOTP library such as `totp-rs`.
///
/// # Security contract
///
/// Implementors must:
/// - Generate secure random seeds of at least 160 bits.
/// - Use HMAC-SHA1 or HMAC-SHA256 as the hash algorithm.
/// - Accept codes from the current 30-second step and the one on each side
///   of it, to allow for clock drift.
/// - Compare codes in constant time.
///
/// # Implementors
///
/// - **Infrastructure:** `TotpVerifier` using the `totp-rs` crate.
/// - **Tests:** `FakeMfaVerifier`, which accepts a fixed code.
pub trait MfaVerifier: Send + Sync {
    /// A new TOTP seed for enrollment.
    ///
    /// The seed is then:
    /// 1. Encrypted and stored in `MfaEnrollment.encrypted_secret`.
    /// 2. Encoded as an `otpauth://` URI for the user's authenticator app.
    ///
    /// # Errors
    ///
    /// - [`DomainError`] when the seed cannot be generated.
    fn generate_secret(&self) -> Result<TotpSeed, DomainError>;

    /// The `otpauth://` URI behind the enrollment QR code.
    ///
    /// The user scans it with their authenticator app during enrollment. It
    /// contains the seed, so it is a [`Secret`] too.
    fn build_otpauth_uri(&self, seed: &TotpSeed, issuer: &str, account: &str) -> Secret;

    /// The time step whose code `code` is, for a code checked at `at`, or
    /// `None` when it matches no step in the window.
    ///
    /// Accepts codes from the step containing `at` and the step on each side
    /// of it. That allows for clock drift between the server and the app.
    /// It gives back the step, not a yes or no, so the caller can refuse a
    /// step it has already accepted. A code stays in the window for about 90
    /// seconds.
    ///
    /// The comparison must run in constant time, so timing reveals nothing
    /// about the code.
    ///
    /// # Errors
    ///
    /// - [`DomainError`] when the check itself fails, for example on a
    ///   malformed seed.
    fn matched_step(
        &self,
        seed: &TotpSeed,
        code: &str,
        at: OffsetDateTime,
    ) -> Result<Option<TimeStep>, DomainError>;
}

impl<T: MfaVerifier + ?Sized> MfaVerifier for std::sync::Arc<T> {
    fn generate_secret(&self) -> Result<TotpSeed, DomainError> {
        (**self).generate_secret()
    }

    fn build_otpauth_uri(&self, seed: &TotpSeed, issuer: &str, account: &str) -> Secret {
        (**self).build_otpauth_uri(seed, issuer, account)
    }

    fn matched_step(
        &self,
        seed: &TotpSeed,
        code: &str,
        at: OffsetDateTime,
    ) -> Result<Option<TimeStep>, DomainError> {
        (**self).matched_step(seed, code, at)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    /// A verifier that answers distinctly, so a forwarded call can be told
    /// apart from a stubbed one.
    struct Distinct;

    impl MfaVerifier for Distinct {
        fn generate_secret(&self) -> Result<TotpSeed, DomainError> {
            Ok(TotpSeed::new(vec![7, 8, 9]))
        }

        fn build_otpauth_uri(&self, seed: &TotpSeed, issuer: &str, account: &str) -> Secret {
            Secret::new(format!(
                "otpauth://totp/{issuer}:{account}?secret={}",
                seed.expose().len()
            ))
        }

        fn matched_step(
            &self,
            seed: &TotpSeed,
            code: &str,
            at: OffsetDateTime,
        ) -> Result<Option<TimeStep>, DomainError> {
            let matches = !seed.expose().is_empty() && code == "424242";
            Ok(TimeStep::containing(at).filter(|_| matches))
        }
    }

    /// The app layer holds this port behind an `Arc`. Through that handle,
    /// the seed, the setup link and the code check must all come from the
    /// inner verifier. A wrong code like "000000" stays wrong.
    #[test]
    fn a_shared_verifier_forwards_every_call_to_the_real_one() {
        let direct = Distinct;
        let shared: Arc<Distinct> = Arc::new(Distinct);

        shared_setup(&shared, &direct);
        shared_verification(&shared);
    }

    /// The shared verifier forwards seed generation and every setup URI input.
    fn shared_setup(shared: &Arc<Distinct>, direct: &Distinct) {
        assert_eq!(
            shared.generate_secret().unwrap().expose(),
            direct.generate_secret().unwrap().expose()
        );

        let secret = shared.generate_secret().unwrap();
        assert_eq!(
            shared
                .build_otpauth_uri(&secret, "Ianua", "ada@acme.com")
                .expose(),
            direct
                .build_otpauth_uri(&secret, "Ianua", "ada@acme.com")
                .expose()
        );
        assert_eq!(
            shared
                .build_otpauth_uri(&secret, "Ianua", "ada@acme.com")
                .expose(),
            "otpauth://totp/Ianua:ada@acme.com?secret=3"
        );
    }

    /// Shared code checks preserve the time, seed and invalid-code refusal.
    fn shared_verification(shared: &Arc<Distinct>) {
        let secret = shared.generate_secret().unwrap();
        let now = crate::shared::clock::now();
        assert_eq!(
            shared.matched_step(&secret, "424242", now).unwrap(),
            TimeStep::containing(now),
            "the time is forwarded too, so the step comes from it"
        );
        assert!(
            shared
                .matched_step(&secret, "000000", now)
                .unwrap()
                .is_none(),
            "a wrong code must stay wrong through the shared handle"
        );
        assert!(
            shared
                .matched_step(&TotpSeed::new(Vec::new()), "424242", now)
                .unwrap()
                .is_none(),
            "the secret is forwarded too, not dropped"
        );
    }

    /// Debug output omits the TOTP seed and the authenticator setup URI.
    #[test]
    fn neither_the_seed_nor_the_setup_link_prints() {
        let seed = TotpSeed::new(b"supersecretseed".to_vec());
        let link = Distinct.build_otpauth_uri(&seed, "Ianua", "ada@acme.com");

        assert!(!format!("{seed:?}").contains("supersecret"));
        assert!(!format!("{link:?}").contains("otpauth"));
    }
}
