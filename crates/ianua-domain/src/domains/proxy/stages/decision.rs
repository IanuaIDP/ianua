//! What one pipeline stage decided about a request.

use crate::domains::proxy::request::transform::RequestMutation;
use crate::types::{ApprovalId, DenialStatus, HeaderName, HeaderValue, HttpsUrl};

/// What one pipeline stage decided about a request.
///
/// Each stage returns exactly one decision, and the executor acts on it
/// before the next stage runs. Every variant carries a `reason`, so the audit
/// log can say why.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum StageDecision {
    /// The request passes this check and goes on to the next stage.
    Pass {
        /// Why this stage passed, such as "valid session".
        reason: String,
    },

    /// Refuse the request now. No later stage runs.
    ///
    /// Headers the refusal needs, such as `Retry-After` on a 429, go on
    /// the context's
    /// [`response_headers`](crate::domains::proxy::request::context::PipelineContext::response_headers),
    /// which every answer the pipeline ends in carries.
    Deny {
        /// The HTTP status to return, such as 403 or 429. Always an error
        /// status, so a denial never reads as success.
        status: DenialStatus,
        /// A reason code a program can read.
        reason: String,
    },

    /// Stop and ask the caller to answer a challenge.
    ///
    /// No later stage runs. The request is refused, and the caller retries
    /// once the challenge is answered.
    Challenge {
        /// The kind of challenge, such as MFA or a consent prompt.
        challenge_type: ChallengeType,
        /// Where the caller answers it.
        answer_at: AnswerAt,
        /// Why the challenge was asked.
        reason: String,
    },

    /// Change the request before it reaches the upstream.
    ///
    /// Headers and query parameters are added, overwritten or dropped. The
    /// pipeline goes on to the next stage.
    Transform {
        /// What this stage changes about the forwarded request.
        mutation: RequestMutation,
        /// Why the request was changed.
        reason: String,
    },
}

/// Where a caller answers a challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AnswerAt {
    /// Wherever the caller already knows to go. It answers, then retries the
    /// same request.
    Retry,
    /// A page the caller is sent to.
    Page(HttpsUrl),
}

/// A single header a stage adds to a request or response.
///
/// Both halves are checked types, so no header reaches the wire with a name
/// that is not a token or a value that could start another header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HeaderEntry {
    name: HeaderName,
    value: HeaderValue,
}

impl HeaderEntry {
    /// A header named `name` carrying `value`.
    #[must_use]
    pub fn new(name: HeaderName, value: HeaderValue) -> Self {
        Self { name, value }
    }

    /// The header's name, in lower case.
    #[must_use]
    pub fn name(&self) -> &HeaderName {
        &self.name
    }

    /// The header's value.
    #[must_use]
    pub fn value(&self) -> &HeaderValue {
        &self.value
    }
}

/// The kind of challenge the caller is asked to answer.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ChallengeType {
    /// A second factor, such as TOTP or WebAuthn.
    Mfa,
    /// Requires an interactive human-verification challenge before proceeding.
    Captcha,
    /// A consent prompt, such as agreeing to share data.
    Consent,
    /// Enrolling the device so it becomes trusted.
    DeviceEnroll,
    /// A proof of possession of the key the credential is bound to, asked
    /// with `WWW-Authenticate: DPoP`. The client retries with a `DPoP`
    /// proof.
    KeyProof,
    /// A person's approval of an agent's action, held open under this id.
    /// The agent is told the id, and retries the same action once the
    /// person decided; the retry spends the approval.
    Approval(ApprovalId),
}

impl ChallengeType {
    /// The authentication scheme the challenge is asked with in a
    /// `WWW-Authenticate` header, when it is asked with one: `DPoP` for a
    /// key proof. The other kinds are answered elsewhere than in the
    /// request's credentials.
    #[must_use]
    pub fn authenticate_scheme(&self) -> Option<&'static str> {
        match self {
            Self::KeyProof => Some("DPoP"),
            Self::Mfa | Self::Captcha | Self::Consent | Self::DeviceEnroll | Self::Approval(_) => {
                None
            }
        }
    }
}

impl StageDecision {
    /// The reason the decision carries, whatever its kind.
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::Pass { reason }
            | Self::Deny { reason, .. }
            | Self::Challenge { reason, .. }
            | Self::Transform { reason, .. } => reason,
        }
    }

    /// Whether the pipeline should stop after this decision.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Deny { .. } | Self::Challenge { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stage adds `x-api-key: sk-live-s3cret`. The entry's `Debug` shows
    /// the name but not the key.
    #[test]
    fn a_header_entry_never_prints_its_value() {
        let entry = HeaderEntry::new(
            HeaderName::new("x-api-key").unwrap(),
            HeaderValue::new("sk-live-s3cret").unwrap(),
        );

        let printed = format!("{entry:?}");

        assert!(printed.contains("x-api-key"));
        assert!(!printed.contains("s3cret"));
    }

    /// A key proof is asked with `WWW-Authenticate: DPoP`; a second factor
    /// and an approval are answered elsewhere, so they name no scheme.
    #[test]
    fn only_a_key_proof_is_asked_in_www_authenticate() {
        assert_eq!(ChallengeType::KeyProof.authenticate_scheme(), Some("DPoP"));
        assert_eq!(ChallengeType::Mfa.authenticate_scheme(), None);
        assert_eq!(
            ChallengeType::Approval(ApprovalId::new()).authenticate_scheme(),
            None
        );
    }

    /// A denial and a challenge stop the pipeline. A pass and a transform go
    /// on to the next stage, so a denied request is never forwarded.
    #[test]
    fn only_a_denial_or_a_challenge_stops_the_pipeline() {
        assert!(
            StageDecision::Deny {
                status: DenialStatus::FORBIDDEN,
                reason: "policy denied".to_owned(),
            }
            .is_terminal()
        );
        assert!(
            StageDecision::Challenge {
                challenge_type: ChallengeType::Mfa,
                answer_at: AnswerAt::Retry,
                reason: "step up required".to_owned(),
            }
            .is_terminal()
        );

        assert!(
            !StageDecision::Pass {
                reason: "valid session".to_owned(),
            }
            .is_terminal()
        );
        assert!(
            !StageDecision::Transform {
                mutation: RequestMutation::asserting(Vec::new()),
                reason: "identity forwarded".to_owned(),
            }
            .is_terminal()
        );
    }

    /// Each of the four kinds of decision gives back the exact reason it was
    /// built with, so the audit log records what the stage said.
    #[test]
    fn every_decision_hands_back_the_reason_it_carries() {
        let decisions = [
            StageDecision::Pass {
                reason: "valid session".to_owned(),
            },
            StageDecision::Deny {
                status: DenialStatus::FORBIDDEN,
                reason: "policy denied".to_owned(),
            },
            StageDecision::Challenge {
                challenge_type: ChallengeType::Mfa,
                answer_at: AnswerAt::Retry,
                reason: "step up required".to_owned(),
            },
            StageDecision::Transform {
                mutation: RequestMutation::asserting(Vec::new()),
                reason: "identity forwarded".to_owned(),
            },
        ];
        let expected = [
            "valid session",
            "policy denied",
            "step up required",
            "identity forwarded",
        ];

        for (decision, reason) in decisions.iter().zip(expected) {
            assert_eq!(decision.reason(), reason);
        }
    }
}
