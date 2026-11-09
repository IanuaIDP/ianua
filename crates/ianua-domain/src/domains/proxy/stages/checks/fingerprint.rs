//! Telling automation from a person's browser, by what the client says it
//! is and by the TLS hello it opened the connection with.
//!
//! Two signs, both narrow on purpose. A user agent carrying a well-known
//! automation signature, such as `GPTBot`, `curl/` or `HeadlessChrome`, is
//! automation by its own account. A user agent claiming to be a browser
//! over a TLS hello that offered no application protocol is automation
//! dressed as one: every browser offers ALPN, and HTTP libraries often do
//! not. Nothing here guesses from behaviour; a noisy guess that refuses
//! real people is worse than none.

use crate::domains::proxy::stages::decision::{AnswerAt, ChallengeType, StageDecision};
use crate::domains::proxy::stages::stage::{FingerprintAction, FingerprintConfig};
use crate::types::{DenialStatus, Fact};

/// User-agent substrings naming well-known automation, matched as sent.
const AUTOMATION_SIGNATURES: &[&str] = &[
    "GPTBot",
    "ChatGPT-User",
    "ClaudeBot",
    "Claude-Web",
    "anthropic-ai",
    "python-requests",
    "python-urllib",
    "curl/",
    "Wget/",
    "Go-http-client",
    "okhttp",
    "axios/",
    "node-fetch",
    "HeadlessChrome",
    "PhantomJS",
    "Scrapy",
];

/// What every browser's user agent starts with.
const BROWSER_PREFIX: &str = "Mozilla/";

/// Where the first ALPN protocol's first and last character sit in a JA4
/// fingerprint: `t13d1516h2_…` offered `h2`.
const JA4_ALPN: std::ops::Range<usize> = 8..10;

/// What that place reads when the hello offered no ALPN.
const JA4_NO_ALPN: &str = "00";

/// What kind of automation a client was recognised as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Automation {
    /// Its user agent carries this signature.
    Signature(&'static str),
    /// Its user agent claims a browser; its TLS hello is not one.
    BrowserClaimWithoutAlpn,
}

impl Automation {
    fn describe(self) -> String {
        match self {
            Self::Signature(signature) => format!("signature '{signature}'"),
            Self::BrowserClaimWithoutAlpn => "a browser claim over a hello without ALPN".to_owned(),
        }
    }
}

/// What a client's user agent and TLS hello say it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientReading {
    /// Recognised as this kind of automation.
    Automation(Automation),
    /// Nothing marks it as automation.
    NoAutomation,
}

impl ClientReading {
    /// What the client is, by the `user_agent` it sent and the JA4
    /// fingerprint `ja4` of its TLS hello.
    ///
    /// A client that sent no user agent is not marked by either sign. The
    /// fingerprint is unknown on plain HTTP, where there was no hello to
    /// read; a browser claim is then taken at its word.
    #[must_use]
    pub fn of(user_agent: Fact<&str>, ja4: Fact<&str>) -> Self {
        let Fact::Known(user_agent) = user_agent else {
            return Self::NoAutomation;
        };
        if let Some(signature) = AUTOMATION_SIGNATURES
            .iter()
            .copied()
            .find(|signature| user_agent.contains(signature))
        {
            return Self::Automation(Automation::Signature(signature));
        }
        let claims_browser = user_agent.starts_with(BROWSER_PREFIX);
        if claims_browser && offered_no_alpn(ja4) {
            return Self::Automation(Automation::BrowserClaimWithoutAlpn);
        }
        Self::NoAutomation
    }
}

/// Whether the hello `ja4` describes offered no application protocol.
fn offered_no_alpn(ja4: Fact<&str>) -> bool {
    let Fact::Known(fingerprint) = ja4 else {
        return false;
    };
    fingerprint.get(JA4_ALPN) == Some(JA4_NO_ALPN)
}

impl FingerprintConfig {
    /// The decision this stage takes on a client read as `client`: a pass
    /// when no automation was recognised, otherwise the configured action,
    /// a challenge to enroll as an agent among them.
    #[must_use]
    pub fn verdict(&self, client: ClientReading) -> StageDecision {
        let ClientReading::Automation(automation) = client else {
            return StageDecision::Pass {
                reason: "fingerprint: no automation recognised".to_owned(),
            };
        };
        let what = automation.describe();
        match self.action {
            FingerprintAction::Allow => StageDecision::Pass {
                reason: format!("fingerprint: {what} allowed by the stage"),
            },
            FingerprintAction::Deny => StageDecision::Deny {
                status: DenialStatus::FORBIDDEN,
                reason: format!("fingerprint: {what} refused"),
            },
            FingerprintAction::Challenge => StageDecision::Challenge {
                challenge_type: ChallengeType::DeviceEnroll,
                answer_at: AnswerAt::Retry,
                reason: format!("fingerprint: {what} must enroll as an agent"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BROWSER: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15";
    const BROWSER_HELLO: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";
    const LIBRARY_HELLO: &str = "t13d171500_5b57614c22b0_3d5424432f57";

    fn acting(action: FingerprintAction) -> FingerprintConfig {
        FingerprintConfig { action }
    }

    #[test]
    fn a_known_signature_is_recognised() {
        assert_eq!(
            ClientReading::of(Fact::Known("curl/8.4.0"), Fact::Unknown),
            ClientReading::Automation(Automation::Signature("curl/"))
        );
        assert_eq!(
            ClientReading::of(Fact::Known("GPTBot/1.0"), Fact::Known(BROWSER_HELLO)),
            ClientReading::Automation(Automation::Signature("GPTBot"))
        );
    }

    #[test]
    fn a_browser_over_a_browser_hello_is_not_automation() {
        assert_eq!(
            ClientReading::of(Fact::Known(BROWSER), Fact::Known(BROWSER_HELLO)),
            ClientReading::NoAutomation
        );
        assert_eq!(
            ClientReading::of(Fact::Known(BROWSER), Fact::Unknown),
            ClientReading::NoAutomation
        );
        assert_eq!(
            ClientReading::of(Fact::Unknown, Fact::Known(LIBRARY_HELLO)),
            ClientReading::NoAutomation
        );
    }

    /// A browser user agent paired with a TLS fingerprint lacking ALPN is
    /// classified as automation claiming to be a browser.
    #[test]
    fn a_browser_claim_over_a_hello_without_alpn_is_automation() {
        assert_eq!(
            ClientReading::of(Fact::Known(BROWSER), Fact::Known(LIBRARY_HELLO)),
            ClientReading::Automation(Automation::BrowserClaimWithoutAlpn)
        );
    }

    /// A fingerprint too short to read its ALPN place proves nothing.
    #[test]
    fn a_fingerprint_too_short_to_read_proves_nothing() {
        assert_eq!(
            ClientReading::of(Fact::Known(BROWSER), Fact::Known("t13")),
            ClientReading::NoAutomation
        );
    }

    #[test]
    fn each_action_is_applied_to_recognised_automation() {
        let bot = ClientReading::Automation(Automation::Signature("curl/"));

        assert!(!acting(FingerprintAction::Allow).verdict(bot).is_terminal());
        assert!(matches!(
            acting(FingerprintAction::Deny).verdict(bot),
            StageDecision::Deny { status, .. } if status == DenialStatus::FORBIDDEN
        ));
        assert!(matches!(
            acting(FingerprintAction::Challenge).verdict(bot),
            StageDecision::Challenge {
                challenge_type: ChallengeType::DeviceEnroll,
                ..
            }
        ));
    }

    #[test]
    fn a_client_not_recognised_passes_whatever_the_action() {
        assert!(
            !acting(FingerprintAction::Deny)
                .verdict(ClientReading::NoAutomation)
                .is_terminal()
        );
    }
}
