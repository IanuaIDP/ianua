//! An authenticator app: the secret scanned from the `otpauth://` link a
//! setup answered with, and the code it shows now.
//!
//! A phone shows one code per time step, and the platform takes each step
//! once, so the app never hands out a second code in a step it already
//! showed one in: it waits for the clock to reach the next. Scenarios
//! opting into a controlled clock advance the shared application clock
//! to that step instead, without changing the verifier or its replay rules.

use std::fmt;
use std::time::Duration;

use totp_rs::{Algorithm, Secret, TOTP};
use url::Url;

use crate::clock;
use crate::expect::eventually_within;

/// The longest a code is waited for: a step and a little more.
const STEP_WAIT: Duration = Duration::from_secs(40);

/// The step length a link that names none means, as RFC 6238 sets it.
const DEFAULT_PERIOD: u64 = 30;

/// The digits a link that names none means.
const DEFAULT_DIGITS: usize = 6;

/// An authenticator app holding one secret. `Debug` shows no secret.
pub struct TotpApp {
    codes: TOTP,
    encoded_secret: String,
    period: u64,
    last_step: Option<u64>,
}

impl fmt::Debug for TotpApp {
    /// Describes timing state without exposing the seed or a usable code.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpApp")
            .field("period", &self.period)
            .field("last_step", &self.last_step)
            .finish_non_exhaustive()
    }
}

impl TotpApp {
    /// The app after scanning `otpauth_uri`, the link a setup answered
    /// with.
    ///
    /// # Panics
    ///
    /// When the link is not an `otpauth://totp/` link carrying a base32
    /// `secret`, or names an algorithm, digits or period no app reads,
    /// which means the platform answered a link no phone could scan.
    #[must_use]
    pub fn scanning(otpauth_uri: &str) -> Self {
        let link = totp_link(otpauth_uri);
        let parameter = |name: &str| {
            link.query_pairs()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned())
        };
        let Some(encoded_secret) = parameter("secret") else {
            panic!("the setup's link carries no secret");
        };
        let Ok(seed) = Secret::Encoded(encoded_secret.clone()).to_bytes() else {
            panic!("the setup's secret is not base32");
        };
        let algorithm = algorithm_named(parameter("algorithm").as_deref());
        let digits = parameter("digits").map_or(DEFAULT_DIGITS, |digits| {
            digits
                .parse()
                .unwrap_or_else(|_| panic!("the setup's digits are not a number"))
        });
        let period = parameter("period").map_or(DEFAULT_PERIOD, |period| {
            period
                .parse()
                .unwrap_or_else(|_| panic!("the setup's period is not a number"))
        });
        assert!(period > 0, "the setup's period is zero");
        Self {
            codes: TOTP::new_unchecked(algorithm, digits, 0, period, seed, None, String::new()),
            encoded_secret,
            period,
            last_step: None,
        }
    }

    /// The code the app shows now, in a step it has shown no code in yet,
    /// waiting for the next step when it already showed one in this. An
    /// opted-in scenario advances its application clock to that step;
    /// ordinary scenarios wait for the real clock.
    ///
    /// # Panics
    ///
    /// When no fresh step comes within forty seconds, which a running
    /// clock never allows.
    /// The scenario must fail if its last time step has no successor.
    #[allow(clippy::expect_used)]
    pub async fn code(&mut self) -> String {
        let period = self.period;
        let last_step = self.last_step;
        if let Some(last) = last_step {
            clock::reach_step(last.checked_add(1).expect("a next time step"), period);
        }
        let step = eventually_within(
            "a time step this app has shown no code in",
            STEP_WAIT,
            || {
                let now = step_now(period);
                async move { last_step.is_none_or(|last| now > last).then_some(now) }
            },
        )
        .await;
        self.last_step = Some(step);
        self.codes.generate(step * period)
    }

    /// The code of a step it already showed, as someone who copied an old
    /// code would type it again; or, before any, the current one.
    #[must_use]
    pub fn last_code_again(&self) -> String {
        let step = self.last_step.unwrap_or_else(|| step_now(self.period));
        self.codes.generate(step * self.period)
    }

    /// The secret as the link carried it, in base32, to make sure it never
    /// appears where it should not.
    #[must_use]
    pub fn secret(&self) -> &str {
        &self.encoded_secret
    }
}

/// Checks that the setup response names a TOTP authenticator link.
fn totp_link(otpauth_uri: &str) -> Url {
    let Ok(link) = Url::parse(otpauth_uri) else {
        panic!("the setup's link does not read as a URL");
    };
    assert_eq!(
        link.scheme(),
        "otpauth",
        "the setup's link is not an otpauth link"
    );
    assert_eq!(
        link.host_str(),
        Some("totp"),
        "the setup's link is not for TOTP"
    );
    link
}

/// The algorithm a link names, SHA-1 when it names none.
///
/// # Panics
///
/// When it names one no app reads.
fn algorithm_named(name: Option<&str>) -> Algorithm {
    match name.map(str::to_ascii_uppercase).as_deref() {
        None | Some("SHA1") => Algorithm::SHA1,
        Some("SHA256") => Algorithm::SHA256,
        Some("SHA512") => Algorithm::SHA512,
        Some(other) => panic!("the setup's link names the algorithm {other}, which no app reads"),
    }
}

/// The time step of `period` seconds the clock is in.
fn step_now(period: u64) -> u64 {
    clock::seconds() / period
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seed of RFC 6238's SHA-1 test vectors in base32, encoded here so
    /// no key-shaped text sits in the source.
    fn rfc_seed() -> String {
        let Secret::Encoded(text) = Secret::Raw(b"12345678901234567890".to_vec()).to_encoded()
        else {
            unreachable!("a raw secret encodes as text");
        };
        text
    }

    /// The app reads the link the platform writes and shows six digits.
    #[test]
    fn the_app_reads_the_platforms_link() {
        let seed = rfc_seed();
        let app = TotpApp::scanning(&format!(
            "otpauth://totp/Acme:ann%40acme.test?secret={seed}&issuer=Acme&algorithm=SHA1&digits=6&period=30"
        ));

        let code = app.last_code_again();

        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
        assert_eq!(app.secret(), seed);
    }

    /// The codes are RFC 6238's: at 59 seconds the eight-digit SHA-1 code
    /// is 94287082.
    #[test]
    fn the_codes_are_rfc_6238s() {
        let app = TotpApp::scanning(&format!(
            "otpauth://totp/x?secret={}&digits=8&period=30",
            rfc_seed()
        ));

        assert_eq!(app.codes.generate(59), "94287082");
    }

    /// A link with no secret is no link an app can scan.
    #[test]
    #[should_panic(expected = "the setup's link carries no secret")]
    fn a_link_without_a_secret_is_refused() {
        let _ = TotpApp::scanning("otpauth://totp/Acme:ann?issuer=Acme");
    }

    /// Two codes asked for at once come from two different steps.
    #[tokio::test]
    async fn two_codes_never_share_a_step() {
        let mut app =
            TotpApp::scanning(&format!("otpauth://totp/x?secret={}&period=1", rfc_seed()));

        app.code().await;
        let first = app.last_step;
        app.code().await;

        assert!(app.last_step > first);
    }

    /// A controlled scenario reaches a fresh production-length step at
    /// once. Its phone and application see the same instant, and asking
    /// for a replay still returns the code already shown in that step.
    #[tokio::test]
    async fn a_controlled_clock_advances_the_phone_and_application_together() {
        let _clock = clock::Clock::controlled();
        let mut app =
            TotpApp::scanning(&format!("otpauth://totp/x?secret={}&period=30", rfc_seed()));
        app.code().await;
        let first = app.last_step.expect("a code was shown");
        let fresh = app.code().await;
        assert!(app.last_step.expect("a second code was shown") > first);
        assert_eq!(fresh, app.codes.generate(clock::seconds()));
        assert_eq!(app.last_code_again(), fresh);
    }

    /// The phone explicitly advances a fixed application clock to a new
    /// production-length step, preserving fixed time after issuing the code.
    #[tokio::test]
    async fn a_fixed_clock_reaches_the_next_phone_step_without_a_real_wait() {
        let _clock = clock::Clock::fixed();
        let mut app =
            TotpApp::scanning(&format!("otpauth://totp/x?secret={}&period=30", rfc_seed()));
        app.code().await;
        let first = app.last_step.expect("the first step");
        let fresh = app.code().await;
        let instant = clock::seconds();
        assert!(app.last_step.expect("the second step") > first);
        assert_eq!(fresh, app.codes.generate(instant));
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(clock::seconds(), instant);
    }
}
