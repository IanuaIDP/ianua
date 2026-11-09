//! One pass of arbitrary bytes across every place the proxy reads something
//! an unauthenticated client controls.
//!
//! A sweep rather than one target per parser, deliberately. The proxy's own
//! entry points are small and mostly total, and the interesting question is
//! not "does this one parser survive" but "is there anywhere in the front
//! door that does not". Feeding the same bytes to all of them in one
//! iteration answers that for the price of one, at the cost of muddier
//! coverage feedback — a crash says which by its stack, which is enough.
//!
//! What each part asserts, past the panic-freedom libFuzzer gives for free:
//!
//! - **`ClientHello`**: a name the client chose must not open a route
//!   restricted to another. `StreamSni::Only` is the whole of what keeps one
//!   tenant's port from answering another's handshake.
//! - **WAF**: the same request must draw the same verdict twice. A firewall
//!   that sometimes passes what it sometimes denies is not one, and an
//!   attacker who can find the difference only has to retry.
//! - **Canary tokens**: a decoy that is literally present in a response body
//!   must be reported as leaked. The whole feature is that appearance proves
//!   the upstream is leaking, so a miss here is a leak that is never noticed.

#![no_main]

use std::sync::LazyLock;

use ianua_domain::domains::proxy::decision::StageDecision;
use ianua_domain::domains::proxy::stage::{WafConfig, WafRuleSet};
use ianua_domain::domains::routing::stream::StreamSni;
use ianua_domain::types::DomainName;
use ianua_zero::stages::{canary_token, waf};
use ianua_zero::stream::sni::{MAX_CLIENT_HELLO, server_name};
use libfuzzer_sys::fuzz_target;

/// Built once: a validator chain per iteration would cost more than every
/// parser under test put together.
static RESTRICTED: LazyLock<StreamSni> = LazyLock::new(|| {
    StreamSni::only(vec![DomainName::new("admin.acme.com").expect("a domain")])
        .expect("a restriction")
});

/// Every rule set on, so the firewall has the most to say about the input.
static WAF_CONFIG: LazyLock<WafConfig> = LazyLock::new(|| WafConfig {
    rule_sets: vec![
        WafRuleSet::Sqli,
        WafRuleSet::Xss,
        WafRuleSet::Traversal,
        WafRuleSet::CommandInjection,
        WafRuleSet::PromptInjection,
    ],
    anomaly_threshold: 5,
    max_body_bytes: 1 << 20,
});

/// A decoy of the shape a tenant would configure.
static CANARIES: LazyLock<Vec<String>> = LazyLock::new(|| vec!["sk-decoy-abc123".to_owned()]);

/// Splits the input so each parser gets something of its own to chew on, while
/// still sharing a lineage the mutator can work with.
fn split(data: &[u8]) -> (&[u8], &[u8]) {
    let at = data.len() / 2;
    (&data[..at], &data[at..])
}

fuzz_target!(|data: &[u8]| {
    let (head, tail) = split(data);

    // ── The TLS front door ────────────────────────────────
    if let Some(name) = server_name(data) {
        assert!(!name.is_empty(), "an empty name is not 'no name'");
        assert!(name.len() <= MAX_CLIENT_HELLO, "a name longer than its record");
        assert!(
            !name.contains('\0') && !name.chars().any(char::is_control),
            "a control character reaches the logs and the router: {name:?}"
        );

        if RESTRICTED.accepts(&name) {
            assert!(
                name.eq_ignore_ascii_case("admin.acme.com"),
                "a client-chosen name opened a route restricted to another: {name:?}"
            );
        }
    }

    // ── The firewall, over the whole request surface ──────
    let path = String::from_utf8_lossy(head);
    let query = std::str::from_utf8(tail).ok();
    let headers = hyper::HeaderMap::new();

    let first = waf::evaluate(&path, query, tail, &headers, &WAF_CONFIG);
    let second = waf::evaluate(&path, query, tail, &headers, &WAF_CONFIG);

    assert_eq!(
        matches!(first, StageDecision::Deny { .. }),
        matches!(second, StageDecision::Deny { .. }),
        "the firewall gave one request two verdicts, so retrying defeats it"
    );

    // ── The response-side leak check ──────────────────────
    let decoy = CANARIES[0].as_bytes();
    let planted: Vec<u8> = head
        .iter()
        .copied()
        .chain(decoy.iter().copied())
        .chain(tail.iter().copied())
        .collect();

    assert!(
        canary_token::leaked_in_response(&planted, &CANARIES),
        "a decoy sitting in the body was not reported as leaked"
    );

    // And a body the fuzzer built is only a leak if it genuinely carries one.
    if canary_token::leaked_in_response(data, &CANARIES) {
        assert!(
            data.windows(decoy.len()).any(|w| w == decoy),
            "a leak was reported for a body that does not contain the decoy"
        );
    }
});
