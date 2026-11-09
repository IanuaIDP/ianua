//! A tenant's own WASM module as a stage: the snapshot it is given, and
//! what its verdict comes to.
//!
//! The module is given what the pipeline has verified so far, never a
//! credential: no token, cookie, session, key or certificate fingerprint,
//! the same line drawn for an upstream. Each text is cut to a bounded
//! length, and when the whole would still pass the input limit a minimal
//! snapshot is sent instead.
//!
//! Its verdict is enforced as the module put it, within what a tenant may
//! do: the headers it adds pass the same check as a tenant's transform, so
//! it cannot write one the gateway asserts. A module that reaches no
//! verdict of its own is a refusal, its cause kept for the audit record.

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::proxy::request::context::{Caller, PipelineContext};
use ianua_domain::domains::proxy::request::transform::{RequestMutation, RequestMutationRules};
use ianua_domain::domains::proxy::stages::decision::{AnswerAt, ChallengeType, StageDecision};
use ianua_domain::types::{
    CountryCode, DenialStatus, HeaderName, HeaderValue, IpAddress, PermissionName, Scope,
};
use serde::Serialize;

use super::{deny, pass};
use crate::pipeline::facts::RequestFacts;
use crate::wasm::{GuestInput, MAX_INPUT_BYTES, Verdict};

/// The longest a single text in the snapshot may be, in bytes.
const MAX_FIELD_BYTES: usize = 2048;

/// What the module is given about the request.
#[derive(Serialize)]
struct Snapshot<'a> {
    tenant_id: String,
    method: &'static str,
    path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    query: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_address: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country_code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    caller: Option<SnapshotCaller>,
    scopes: Vec<&'a str>,
    permissions: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    assurance: Option<String>,
    classification: Vec<&'static str>,
}

/// The snapshot when the full one is too large: who asked for what.
#[derive(Serialize)]
struct MinimalSnapshot<'a> {
    tenant_id: String,
    method: &'static str,
    path: &'a str,
    authenticated: bool,
}

/// Who the caller is, by kind and id.
#[derive(Serialize)]
struct SnapshotCaller {
    kind: &'static str,
    id: String,
}

impl SnapshotCaller {
    /// Names the verified principal without copying any credential into the guest input.
    fn of(caller: &Caller) -> Self {
        let (kind, id) = match caller {
            Caller::User { user_id, .. } => ("user", user_id.to_string()),
            Caller::Agent { agent_id, .. } => ("agent", agent_id.to_string()),
            Caller::Consumer { consumer_id, .. } => ("consumer", consumer_id.to_string()),
        };
        Self { kind, id }
    }
}

/// The module's input for `request` as `ctx` stands, or `None` when even
/// the minimal snapshot cannot be written within the limit.
pub(super) fn input(request: &RequestFacts, ctx: &PipelineContext) -> Option<GuestInput> {
    let full = serde_json::to_vec(&snapshot(request, ctx)).ok()?;
    if full.len() <= MAX_INPUT_BYTES {
        return GuestInput::new(full).ok();
    }
    let minimal = MinimalSnapshot {
        tenant_id: ctx.tenant_id.to_string(),
        method: request.admitted.method().as_str(),
        path: bounded(request.admitted.path().as_str()),
        authenticated: ctx.authentication().caller().is_some(),
    };
    GuestInput::new(serde_json::to_vec(&minimal).ok()?).ok()
}

/// Copies only the bounded request facts and verified claims visible to a guest.
fn snapshot<'a>(request: &'a RequestFacts, ctx: &'a PipelineContext) -> Snapshot<'a> {
    Snapshot {
        tenant_id: ctx.tenant_id.to_string(),
        method: request.admitted.method().as_str(),
        path: bounded(request.admitted.path().as_str()),
        query: request.query().map(bounded),
        ip_address: ctx.ip_address.known().map(IpAddress::as_str),
        user_agent: ctx.user_agent.known().map(|agent| bounded(agent.as_str())),
        country_code: ctx.country_code.known().map(CountryCode::as_str),
        caller: ctx.authentication().caller().map(SnapshotCaller::of),
        scopes: ctx.claims.scopes.iter().map(Scope::as_str).collect(),
        permissions: ctx
            .claims
            .permissions
            .iter()
            .map(PermissionName::as_str)
            .collect(),
        assurance: ctx.claims.current_aal.known().map(ToString::to_string),
        classification: ctx
            .classification_levels
            .iter()
            .copied()
            .map(DataClassLevel::as_str)
            .collect(),
    }
}

/// `text` cut to at most [`MAX_FIELD_BYTES`], on a character boundary.
fn bounded(text: &str) -> &str {
    let end = (0..=text.len().min(MAX_FIELD_BYTES))
        .rev()
        .find(|index| text.is_char_boundary(*index))
        .unwrap_or(0);
    &text[..end]
}

/// What the module's `verdict` comes to.
pub(super) fn decision(verdict: Verdict) -> StageDecision {
    match verdict {
        Verdict::Pass { reason } => pass(&format!("custom: {reason}")),
        Verdict::Deny { status, reason } => deny(status, &format!("custom: {reason}")),
        Verdict::Challenge { reason } => StageDecision::Challenge {
            challenge_type: ChallengeType::Consent,
            answer_at: AnswerAt::Retry,
            reason: format!("custom: {reason}"),
        },
        Verdict::Enrich { headers, reason } => enriched(headers, &reason),
        Verdict::Refused(failure) => deny(
            DenialStatus::FORBIDDEN,
            &format!(
                "custom: the module reached no verdict ({})",
                failure.as_str()
            ),
        ),
    }
}

/// The headers a module adds, held to what a tenant may set. One the
/// gateway asserts refuses the request: the module asked to run it under a
/// configuration it does not get.
fn enriched(headers: Vec<(HeaderName, HeaderValue)>, reason: &str) -> StageDecision {
    let rules = RequestMutationRules {
        set_headers: headers,
        ..RequestMutationRules::default()
    };
    let Ok(mutation) = RequestMutation::configured(rules) else {
        return deny(
            DenialStatus::FORBIDDEN,
            "custom: the module set a header the gateway asserts",
        );
    };
    StageDecision::Transform {
        mutation,
        reason: format!("custom: {reason}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm::Failure;

    fn header(name: &str, value: &str) -> (HeaderName, HeaderValue) {
        (
            HeaderName::new(name).unwrap(),
            HeaderValue::new(value).unwrap(),
        )
    }

    #[test]
    fn a_pass_and_a_deny_are_enforced_as_the_module_put_them() {
        let passed = decision(Verdict::Pass {
            reason: "fine".to_owned(),
        });
        let denied = decision(Verdict::Deny {
            status: DenialStatus::TOO_MANY_REQUESTS,
            reason: "slow down".to_owned(),
        });

        assert!(!passed.is_terminal());
        assert!(matches!(
            denied,
            StageDecision::Deny { status, .. } if status == DenialStatus::TOO_MANY_REQUESTS
        ));
    }

    #[test]
    fn a_challenge_stops_the_request() {
        let challenged = decision(Verdict::Challenge {
            reason: "consent".to_owned(),
        });

        assert!(challenged.is_terminal());
    }

    /// A missing-module result yields 403 with its failure code in the reason.
    #[test]
    fn a_module_that_reached_no_verdict_is_a_refusal() {
        let refused = decision(Verdict::Refused(Failure::NotFound));

        let StageDecision::Deny { status, reason } = refused else {
            panic!("a module with no verdict refuses");
        };
        assert_eq!(status, DenialStatus::FORBIDDEN);
        assert!(reason.contains("module_not_found"));
    }

    #[test]
    fn headers_a_module_adds_are_forwarded() {
        let enriched = decision(Verdict::Enrich {
            headers: vec![header("x-region", "eu")],
            reason: "tagged".to_owned(),
        });

        let StageDecision::Transform { mutation, .. } = enriched else {
            panic!("an enrich adds headers");
        };
        assert_eq!(mutation.headers_to_set()[0].name().as_str(), "x-region");
    }

    /// A custom module attempting to set the trusted user header receives a terminal refusal.
    #[test]
    fn a_module_writing_an_asserted_header_is_refused() {
        let forged = decision(Verdict::Enrich {
            headers: vec![header("x-forwarded-user", "admin")],
            reason: "forged".to_owned(),
        });

        assert!(forged.is_terminal());
    }

    #[test]
    fn a_long_text_is_cut_on_a_character_boundary() {
        let long = "é".repeat(MAX_FIELD_BYTES);

        let cut = bounded(&long);

        assert!(cut.len() <= MAX_FIELD_BYTES);
        assert!(cut.chars().all(|c| c == 'é'));
    }
}
