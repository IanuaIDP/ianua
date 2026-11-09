// Failed fixture construction or assertions must stop this test target immediately.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Properties every parser keeps, checked over generated input.
//!
//! - Nothing a caller can send makes a parser panic.
//! - Whatever a parser accepts reads back as itself when parsed again, so a
//!   stored or forwarded value never changes meaning on the next read.
//! - The rule each parser exists for holds for every value it accepts.

use ianua_domain::domains::agents::authority::capability::TopicPattern;
use ianua_domain::domains::authentication::risk_engine::assessment::RiskLevel;
use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
use ianua_domain::domains::authentication::risk_engine::step_up::{
    AuthenticationContext, Familiarity, Sensitivity, SignInSignals, StepUpDecision, StepUpPolicy,
};
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::proxy::request::trace::{Sampling, SpanId, TraceContext, TraceId};
use ianua_domain::domains::routing::matching::path_rewrite::PathTemplate;
use ianua_domain::domains::tenant::custom_domains::dns_zone::{
    RecordKind, RecordName, RecordValue,
};
use ianua_domain::types::{CidrRange, DomainName, Email, HeaderName, IpAddress, Scope};
use proptest::prelude::*;

/// Text shaped like what each parser is fed: mostly near-valid, sometimes not.
fn hostish() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z0-9-]{1,20}(\\.[a-z0-9-]{1,20}){0,3}",
        "[A-Za-z0-9.*_-]{0,40}",
        ".{0,80}",
    ]
}

/// How far a step-up decision goes, from letting the sign-in through to
/// refusing it.
fn strictness(decision: StepUpDecision) -> u8 {
    match decision {
        StepUpDecision::Sufficient => 0,
        StepUpDecision::MfaRequired => 1,
        StepUpDecision::HardwareKeyRequired => 2,
        StepUpDecision::Denied => 3,
    }
}

fn risk() -> impl Strategy<Value = RiskLevel> {
    prop_oneof![
        Just(RiskLevel::Low),
        Just(RiskLevel::Medium),
        Just(RiskLevel::High),
        Just(RiskLevel::Critical),
    ]
}

fn assurance() -> impl Strategy<Value = AssuranceLevel> {
    prop_oneof![
        Just(AssuranceLevel::Aal1),
        Just(AssuranceLevel::Aal2),
        Just(AssuranceLevel::Aal3),
    ]
}

fn familiarity() -> impl Strategy<Value = Familiarity> {
    prop_oneof![Just(Familiarity::Known), Just(Familiarity::New)]
}

fn signals() -> impl Strategy<Value = SignInSignals> {
    (
        familiarity(),
        familiarity(),
        prop_oneof![Just(Sensitivity::Ordinary), Just(Sensitivity::Sensitive)],
    )
        .prop_map(|(device, country, operation)| SignInSignals {
            device,
            country,
            operation,
        })
}

fn policy() -> impl Strategy<Value = StepUpPolicy> {
    prop_oneof![Just(StepUpPolicy::relaxed()), Just(StepUpPolicy::strict())]
}

fn record_kind() -> impl Strategy<Value = RecordKind> {
    prop::sample::select(RecordKind::ALL.to_vec())
}

fn topic() -> impl Strategy<Value = Option<TopicPattern>> {
    "(tasks|orders|\\*)(\\.(eu|us|\\*)){0,2}(\\.>)?".prop_map(|p| TopicPattern::new(p).ok())
}

proptest! {
    #[test]
    fn an_email_reads_back_as_itself(raw in "[a-zA-Z0-9._%+-]{1,20}@[a-z0-9-]{1,20}\\.[a-z]{2,6}|.{0,60}") {
        if let Ok(email) = Email::new(raw) {
            prop_assert_eq!(Email::new(email.as_str()).unwrap(), email);
        }
    }

    #[test]
    fn a_domain_name_reads_back_as_itself(raw in hostish()) {
        if let Ok(name) = DomainName::new(raw) {
            prop_assert_eq!(DomainName::new(name.as_str()).unwrap(), name);
        }
    }

    #[test]
    fn a_record_name_reads_back_as_itself(raw in hostish()) {
        if let Ok(name) = RecordName::new(raw) {
            prop_assert_eq!(RecordName::new(name.as_str()).unwrap(), name);
        }
    }

    #[test]
    fn a_scope_reads_back_as_itself(raw in "[a-z:_*.-]{0,30}|.{0,40}") {
        if let Ok(scope) = Scope::new(raw) {
            prop_assert_eq!(Scope::new(scope.as_str()).unwrap(), scope);
        }
    }

    /// A header name is a token: anything else could split the header block.
    #[test]
    fn an_accepted_header_name_holds_only_token_characters(raw in "[A-Za-z0-9!#$%&'*+.^_`|~-]{1,20}|.{0,30}") {
        if let Ok(name) = HeaderName::new(raw) {
            prop_assert!(name.as_str().chars().all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)));
        }
    }

    /// A range contains its own network address; one that did not would match
    /// nothing it names.
    #[test]
    fn a_cidr_range_contains_its_own_network(a in 0u8..=255, b in 0u8..=255, c in 0u8..=255, prefix in 8u8..=32) {
        let raw = format!("{a}.{b}.{c}.0/{prefix}");
        if let Ok(range) = CidrRange::new(raw) {
            let network = IpAddress::new(range.network()).unwrap();
            prop_assert!(range.contains(&network));
        }
    }

    #[test]
    fn a_cidr_range_never_panics(raw in ".{0,60}") {
        let _ = CidrRange::new(raw);
    }

    #[test]
    fn a_system_permission_reads_back_through_its_text(raw in "(idp:)?[a-z_]{1,15}:[a-z_]{1,15}|.{0,40}") {
        if let Some(permission) = SystemPermission::parse(&raw) {
            prop_assert_eq!(SystemPermission::parse(&permission.to_string()), Some(permission));
        }
    }

    /// A trace context forwarded to the upstream must read back as the same
    /// trace, or the hop is lost from it.
    #[test]
    fn a_trace_context_survives_its_own_header(trace in any::<[u8; 16]>(), span in any::<[u8; 8]>(), sampled in any::<bool>()) {
        let (Some(trace_id), Some(span_id)) = (TraceId::new(trace), SpanId::new(span)) else {
            return Ok(());
        };
        let sampling = if sampled { Sampling::Sampled } else { Sampling::NotSampled };
        let context = TraceContext::new(trace_id, span_id, sampling);

        let read = TraceContext::parse(&context.to_header()).unwrap();

        prop_assert_eq!(read.trace_id(), trace_id);
        prop_assert_eq!(read.span_id(), span_id);
        prop_assert_eq!(read.is_sampled(), sampled);
    }

    #[test]
    fn a_traceparent_never_panics(raw in ".{0,80}") {
        let _ = TraceContext::parse(&raw);
    }

    /// More risk never makes a sign-in easier.
    #[test]
    fn more_risk_never_relaxes_a_step_up(policy in policy(), aal in assurance(), signals in signals(), lower in risk(), higher in risk()) {
        prop_assume!(lower <= higher);
        let at = |risk| policy.evaluate(&AuthenticationContext::new(aal, risk, signals));

        prop_assert!(strictness(at(lower)) <= strictness(at(higher)));
    }

    /// A stronger sign-in never asks for more; a refusal stands whatever the
    /// caller has proved.
    #[test]
    fn more_assurance_never_tightens_a_step_up(policy in policy(), risk in risk(), signals in signals(), weaker in assurance(), stronger in assurance()) {
        prop_assume!(weaker <= stronger);
        let at = |aal| policy.evaluate(&AuthenticationContext::new(aal, risk, signals));
        let (before, after) = (at(weaker), at(stronger));

        if before == StepUpDecision::Denied {
            prop_assert_eq!(after, StepUpDecision::Denied);
        } else {
            prop_assert!(strictness(after) <= strictness(before));
        }
    }

    #[test]
    fn a_topic_pattern_covers_itself(pattern in topic()) {
        if let Some(pattern) = pattern {
            prop_assert!(pattern.covers(&pattern));
        }
    }

    /// Covering chains: a delegation narrowed twice stays within the first.
    #[test]
    fn topic_coverage_is_transitive(a in topic(), b in topic(), c in topic()) {
        let (Some(a), Some(b), Some(c)) = (a, b, c) else {
            return Ok(());
        };
        if a.covers(&b) && b.covers(&c) {
            prop_assert!(a.covers(&c));
        }
    }

    #[test]
    fn a_record_value_never_panics(kind in record_kind(), raw in ".{0,120}") {
        let _ = RecordValue::parse(kind, &raw);
    }

    /// A rewrite whose every placeholder has a value renders to a path with
    /// no brace left in it; one left over would reach the upstream literally.
    #[test]
    fn a_fully_answered_template_leaves_no_placeholder(raw in "(/[a-z]{1,8}|/\\{[a-z]{1,6}\\}){1,5}") {
        let Ok(template) = PathTemplate::new(raw) else {
            return Ok(());
        };

        let rendered = template.render(|name| Some(format!("v-{name}"))).unwrap();

        let braces_left = rendered.contains(['{', '}']);
        prop_assert!(!braces_left);
        for name in template.parameters() {
            let value = format!("v-{name}");
            prop_assert!(rendered.contains(&value));
        }
    }
}
