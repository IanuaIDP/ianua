//! The guest ABI, version 1: what a module is given and what it answers.
//!
//! The module is given the bytes the stage built, a JSON snapshot of
//! request facts already checked, never a credential. It answers with a
//! JSON decision at a `(pointer << 32) | length` it returns from
//! `evaluate`: `pass`, `deny` with an optional error status, `challenge`,
//! or `enrich` with headers to add. Any other decision, `fork` included,
//! does not parse, so a module can never pick where a request goes.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use ianua_domain::shared::validation::ValidationError;
use ianua_domain::types::{DenialStatus, HeaderName, HeaderValue};

use super::failure::Failure;

/// The most bytes a module is given.
pub(crate) const MAX_INPUT_BYTES: usize = 16 * 1024;

/// The most bytes of answer read back from a module. Enough for the most
/// headers an answer may carry at their longest.
pub(super) const MAX_ANSWER_BYTES: usize = 96 * 1024;

/// The most headers an `enrich` answer may add.
const MAX_ENRICH_HEADERS: usize = 16;

/// The longest reason kept from an answer, in bytes.
const MAX_REASON_BYTES: usize = 256;

/// The reason given when a module gives none.
const NO_REASON: &str = "no reason given";

/// What a module is given: the stage's snapshot of the request, bounded.
#[derive(Clone)]
pub(crate) struct GuestInput(Arc<[u8]>);

/// The input the stage built is larger than a module may be given.
#[derive(Debug, thiserror::Error)]
#[error("a module's input is {size} bytes, over the {MAX_INPUT_BYTES}-byte limit")]
pub(crate) struct InputTooLarge {
    size: usize,
}

impl GuestInput {
    /// `bytes` as a module's input.
    ///
    /// # Errors
    ///
    /// - [`InputTooLarge`] past [`MAX_INPUT_BYTES`].
    pub(crate) fn new(bytes: Vec<u8>) -> Result<Self, InputTooLarge> {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(InputTooLarge { size: bytes.len() });
        }
        Ok(Self(bytes.into()))
    }

    /// The bytes, shared with the call's store.
    pub(super) fn shared(&self) -> Arc<[u8]> {
        Arc::clone(&self.0)
    }
}

impl fmt::Debug for GuestInput {
    /// The length only: the snapshot describes a caller.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuestInput")
            .field("len", &self.0.len())
            .finish()
    }
}

/// What a call to a module comes to.
#[derive(Debug)]
pub(crate) enum Verdict {
    /// The module lets the request go on.
    Pass {
        /// Why, as the module put it, bounded.
        reason: String,
    },
    /// The module refuses the request.
    Deny {
        /// The status it asked for, or 403 when it asked for none or for
        /// one that is not an error.
        status: DenialStatus,
        /// Why, as the module put it, bounded.
        reason: String,
    },
    /// The module asks the caller to answer a challenge.
    Challenge {
        /// Why, as the module put it, bounded.
        reason: String,
    },
    /// The module adds headers and lets the request go on. Whether a
    /// header is one the gateway asserts, which a tenant may not write, is
    /// the stage's check.
    Enrich {
        /// The headers to add.
        headers: Vec<(HeaderName, HeaderValue)>,
        /// Why, as the module put it, bounded.
        reason: String,
    },
    /// The call reached no verdict of its own. A denial.
    Refused(Failure),
}

/// Why a module's answer does not fit the ABI.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MalformedAnswer {
    /// It is not one of the decisions, as JSON.
    #[error("the answer is not a decision")]
    NotADecision(#[source] serde_json::Error),
    /// It is longer than an answer may be.
    #[error("the answer is {len} bytes, over the limit")]
    TooLong {
        /// Its length.
        len: usize,
    },
    /// It points outside the module's memory.
    #[error("the answer lies outside the module's memory")]
    OutOfBounds,
    /// It adds more headers than an answer may.
    #[error("the answer adds {count} headers, over the {MAX_ENRICH_HEADERS} allowed")]
    TooManyHeaders {
        /// How many it adds.
        count: usize,
    },
    /// A header it adds is not a valid name or value.
    #[error("the answer adds a header that is not valid")]
    Header(#[source] ValidationError),
}

/// The decision as the module writes it, before it is checked.
#[derive(serde::Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
enum WireDecision {
    Pass {
        #[serde(default)]
        reason: Option<String>,
    },
    Deny {
        #[serde(default)]
        status: Option<u16>,
        #[serde(default)]
        reason: Option<String>,
    },
    Challenge {
        #[serde(default)]
        reason: Option<String>,
    },
    Enrich {
        #[serde(default)]
        headers: BTreeMap<String, String>,
        #[serde(default)]
        reason: Option<String>,
    },
}

/// The pointer and length an `evaluate` result packs.
pub(super) fn unpack(packed: i64) -> (usize, usize) {
    let bits = u64::from_ne_bytes(packed.to_ne_bytes());
    let pointer = usize::try_from(bits >> 32).unwrap_or(usize::MAX);
    let len = usize::try_from(bits & u64::from(u32::MAX)).unwrap_or(usize::MAX);
    (pointer, len)
}

/// The verdict a module's answer comes to.
///
/// # Errors
///
/// - [`MalformedAnswer`] when it is not a decision, or adds too many
///   headers or one that is not valid.
pub(super) fn verdict_from(answer: &[u8]) -> Result<Verdict, MalformedAnswer> {
    let wire: WireDecision =
        serde_json::from_slice(answer).map_err(MalformedAnswer::NotADecision)?;
    match wire {
        WireDecision::Pass { reason } => Ok(Verdict::Pass {
            reason: bounded(reason),
        }),
        WireDecision::Deny { status, reason } => Ok(Verdict::Deny {
            status: denial_status(status),
            reason: bounded(reason),
        }),
        WireDecision::Challenge { reason } => Ok(Verdict::Challenge {
            reason: bounded(reason),
        }),
        WireDecision::Enrich { headers, reason } => Ok(Verdict::Enrich {
            headers: checked_headers(headers)?,
            reason: bounded(reason),
        }),
    }
}

/// The status a module asked for, or 403 for none or one that is not an
/// error.
fn denial_status(asked: Option<u16>) -> DenialStatus {
    asked
        .and_then(|code| DenialStatus::new(code).ok())
        .unwrap_or(DenialStatus::FORBIDDEN)
}

/// The headers an `enrich` answer adds, each checked.
fn checked_headers(
    headers: BTreeMap<String, String>,
) -> Result<Vec<(HeaderName, HeaderValue)>, MalformedAnswer> {
    if headers.len() > MAX_ENRICH_HEADERS {
        return Err(MalformedAnswer::TooManyHeaders {
            count: headers.len(),
        });
    }
    headers
        .into_iter()
        .map(checked_header)
        .collect::<Result<_, _>>()
        .map_err(MalformedAnswer::Header)
}

/// One header an `enrich` answer adds, checked.
fn checked_header(
    (name, value): (String, String),
) -> Result<(HeaderName, HeaderValue), ValidationError> {
    Ok((HeaderName::new(name)?, HeaderValue::new(value)?))
}

/// A module's reason without control characters, cut at
/// [`MAX_REASON_BYTES`] on a character boundary.
fn bounded(reason: Option<String>) -> String {
    let reason = reason.unwrap_or_else(|| NO_REASON.to_owned());
    let mut kept = String::with_capacity(reason.len().min(MAX_REASON_BYTES));
    for c in reason.chars().filter(|c| !c.is_control()) {
        if kept.len() + c.len_utf8() > MAX_REASON_BYTES {
            break;
        }
        kept.push(c);
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pass_is_read() {
        let verdict = verdict_from(br#"{"decision":"pass","reason":"ok"}"#).expect("a decision");

        assert!(matches!(verdict, Verdict::Pass { reason } if reason == "ok"));
    }

    #[test]
    fn a_deny_keeps_an_error_status() {
        let verdict = verdict_from(br#"{"decision":"deny","status":451}"#).expect("a decision");

        assert!(matches!(verdict, Verdict::Deny { status, .. } if status.code() == 451));
    }

    #[test]
    fn a_deny_asking_for_a_success_status_is_a_403() {
        let verdict = verdict_from(br#"{"decision":"deny","status":200}"#).expect("a decision");

        assert!(
            matches!(verdict, Verdict::Deny { status, .. } if status == DenialStatus::FORBIDDEN)
        );
    }

    #[test]
    fn a_fork_is_not_a_decision() {
        let answer = verdict_from(br#"{"decision":"fork","target":"https://evil.example"}"#);

        assert!(matches!(answer, Err(MalformedAnswer::NotADecision(_))));
    }

    #[test]
    fn garbage_is_not_a_decision() {
        assert!(matches!(
            verdict_from(b"not json"),
            Err(MalformedAnswer::NotADecision(_))
        ));
    }

    #[test]
    fn an_enrich_past_the_header_limit_is_malformed() {
        let headers: Vec<String> = (0..=MAX_ENRICH_HEADERS)
            .map(|i| format!(r#""x-tag-{i}":"v""#))
            .collect();
        let answer = format!(
            r#"{{"decision":"enrich","headers":{{{}}}}}"#,
            headers.join(",")
        );

        assert!(matches!(
            verdict_from(answer.as_bytes()),
            Err(MalformedAnswer::TooManyHeaders { .. })
        ));
    }

    #[test]
    fn an_enrich_with_an_invalid_header_name_is_malformed() {
        let answer = br#"{"decision":"enrich","headers":{"bad name":"v"}}"#;

        assert!(matches!(
            verdict_from(answer),
            Err(MalformedAnswer::Header(_))
        ));
    }

    #[test]
    fn a_long_reason_is_cut_on_a_character_boundary() {
        let reason = bounded(Some("é".repeat(MAX_REASON_BYTES)));

        assert!(reason.len() <= MAX_REASON_BYTES);
        assert!(reason.chars().all(|c| c == 'é'));
    }

    #[test]
    fn an_input_past_the_limit_is_refused() {
        assert!(GuestInput::new(vec![0; MAX_INPUT_BYTES + 1]).is_err());
        assert!(GuestInput::new(vec![0; MAX_INPUT_BYTES]).is_ok());
    }

    #[test]
    fn a_packed_answer_unpacks_to_its_pointer_and_length() {
        assert_eq!(unpack((16_i64 << 32) | 19), (16, 19));
    }
}
