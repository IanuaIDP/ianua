//! Response sources distinguished from diagnostics and serialized protocol data.

use crate::catalog::{Evidence, Message, Occurrence};

/// Keeps locations that supply public text, retaining translations whenever
/// any occurrence of the same source is response related.
pub(crate) fn retain(message: &mut Message) -> bool {
    let english = &message.english;
    message.occurrences.retain_mut(|occurrence| {
        if internal_literal(english, occurrence) || !response(occurrence) {
            return false;
        }
        if matches!(
            occurrence.evidence,
            Evidence::Review | Evidence::ErrorDisplay
        ) {
            occurrence.evidence = Evidence::Presentation;
        }
        true
    });
    !message.occurrences.is_empty()
}

/// Rendering helpers also build protocol values, field labels and sample
/// identities. Their source context distinguishes them from public copy.
fn internal_literal(english: &str, occurrence: &Occurrence) -> bool {
    match (occurrence.path.as_str(), occurrence.context.as_str()) {
        ("crates/ianua-api/src/error/oauth.rs", "CLIENT_CHALLENGE" | "challenged")
        | ("crates/ianua-domain/src/shared/validation/rules/pem.rs", "holds_block")
        | ("crates/ianua-infra/src/pages/sign_in.rs", "note_of")
        | ("crates/ianua-app/src/use_cases/notifications/delivery/render.rs", "title_word") => true,
        ("crates/ianua-app/src/use_cases/notifications/delivery/render.rs", "body_for_event") => {
            english == "body"
        }
        ("crates/ianua-infra/src/mail/compose/samples.rs", "sample_of") => {
            matches!(english, "Alex Sample" | "Sam Admin")
        }
        _ => false,
    }
}

/// Constructors and renderers establish visibility; otherwise the owning
/// helper or error type needs a traced public caller.
fn response(occurrence: &Occurrence) -> bool {
    let Occurrence {
        path,
        context,
        evidence,
        ..
    } = occurrence;
    if let Some(shown) = shared_error_shows(path, context) {
        return shown;
    }
    match evidence {
        Evidence::CustomerError
        | Evidence::Presentation
        | Evidence::Template
        | Evidence::Subject
        | Evidence::Event => true,
        Evidence::ErrorDisplay => public_error(path, context),
        Evidence::Review => public_renderer(path, context),
    }
}

/// Whether a shared error type shows the message written under `context`,
/// when `path` is one of the two files that hold them.
fn shared_error_shows(path: &str, context: &str) -> Option<bool> {
    match path {
        "crates/ianua-app/src/error.rs" => Some(matches!(
            context,
            "Unauthenticated"
                | "StepUpRequired"
                | "AccountLocked"
                | "EmailNotVerified"
                | "from_domain"
        )),
        "crates/ianua-domain/src/shared/errors.rs" => {
            Some(matches!(context, "NotFound" | "TenantSuspended"))
        }
        _ => None,
    }
}

/// Business errors and cursors are rendered by their adapters. Startup and
/// infrastructure error displays are not themselves public messages.
fn public_error(path: &str, context: &str) -> bool {
    if path == "crates/ianua-domain/src/domains/authentication/mfa/enrollment.rs" {
        return !matches!(context, "NotPending" | "NotActive");
    }
    if path == "crates/ianua-domain/src/domains/authentication/mfa/answered_code.rs" {
        return context != "Unchecked";
    }
    path.starts_with("crates/ianua-domain/src/")
        || matches!(
            path,
            "crates/ianua-app/src/listing/cursor.rs" | "crates/ianua-app/src/listing/sorting.rs"
        )
}

/// Helpers returned in response bodies or interpolated into public messages,
/// deliberately scoped more narrowly than an entire application crate.
fn public_renderer(path: &str, context: &str) -> bool {
    if let Some(path) = path.strip_prefix("crates/ianua-app/src/") {
        return application(path, context);
    }
    if let Some(path) = path.strip_prefix("crates/ianua-domain/src/") {
        return domain(path, context);
    }
    if let Some(path) = path.strip_prefix("crates/ianua-api/src/") {
        return api(path, context);
    }
    matches!(
        (path, context),
        ("crates/ianua-ldap/src/ops/errors.rs", "refusal")
            | ("crates/ianua-ldap/src/ops/bind.rs", "refusal")
            | ("crates/ianua-ldap/src/ops/password_modify.rs", "own")
            | ("crates/ianua-runner/src/handler.rs", "answer")
    )
}

/// Application helpers publish OAuth descriptions, document refusals,
/// admission decisions and mail content independently of error constructors.
fn application(path: &str, context: &str) -> bool {
    if let Some(case) = path.strip_prefix("use_cases/") {
        return application_use_case(case, context);
    }
    match path {
        "acting/agent.rs" => context == "reason",
        "services/authentication/channels.rs" => context.starts_with("NO_"),
        "services/authentication/sign_in_steps.rs" => {
            matches!(context, "recovery_refused" | "refusal_error")
        }
        "services/authorization/catalogue_check.rs" => context == "undeclared_message",
        _ => changed_meanwhile(context),
    }
}

/// The use cases among the application helpers: token, gateway and agent
/// access answers whole, and named refusals and mail content elsewhere.
fn application_use_case(path: &str, context: &str) -> bool {
    if path.starts_with("oauth/token/")
        || path.starts_with("gateway/apply/")
        || path.starts_with("agents/access/")
    {
        return true;
    }
    match path {
        "branding/mail/test_provider.rs" => matches!(context, "TEST_SUBJECT" | "TEST_BODY"),
        "gateway/import_config.rs" => context == "ensure_named_once",
        "routing/services/sign_in_checks.rs" => context.starts_with("ensure_"),
        "identity/email/changes/links.rs" => context == "warning_variables",
        "authentication/app_sign_in/password/complete_mfa.rs" => context == "device_name",
        "authentication/password/sign_in/due.rs" => context == "NO_PROOF_OF_THE_PERSON",
        "domain/registration/add.rs" => matches!(
            context,
            "ensure_outside_platform" | "ensure_wildcard_parent"
        ),
        "agents/enforcement/admit_action.rs" => context == "reason",
        "agents/approvals/deny_action.rs" => context == "DENIED_REASON",
        "onboarding/founding.rs" => matches!(context, "COMPANY_NAME_TAKEN" | "TENANT_NAME_TAKEN"),
        "tenant/lifecycle/provision.rs" => context == "SLUG_TAKEN",
        _ => changed_meanwhile(context),
    }
}

/// The refusals for a record another request changed meanwhile, which any
/// application helper may give.
fn changed_meanwhile(context: &str) -> bool {
    matches!(context, "ANSWERED_MEANWHILE" | "CHANGED_MEANWHILE")
}

/// API response bodies, setup instructions and request parsers expose prose;
/// headers, OpenAPI metadata and serialized protocol constants do not.
fn api(path: &str, context: &str) -> bool {
    if path.starts_with("extractors/")
        || path == "patch.rs"
        || path.starts_with("dto/") && context == "deserialize"
    {
        return true;
    }
    match path {
        "dto/scim.rs" => matches!(
            context,
            "schemas" | "service_provider_config" | "me_unsupported"
        ),
        "dto/organization/cloud_accounts.rs" => context == "steps",
        "middleware/auth.rs" => context == "auth_unavailable",
        "middleware/ip_rate_limit.rs" => matches!(context, "ip_rate_limit" | "too_many_requests"),
        "middleware/user_rate_limit.rs" => context == "user_rate_limit",
        "middleware/rate_limit.rs" => context == "call",
        "ws.rs" => context == "close_refused",
        _ => false,
    }
}

/// Domain helper text used by response data and validation details, rather
/// than row reconstruction, wire serialization or model prompts.
fn domain(path: &str, context: &str) -> bool {
    if path.starts_with("types/") {
        return value_text(path, context);
    }
    if let Some(agents) = path.strip_prefix("domains/agents/") {
        return agent_text(agents, context);
    }
    match path {
        simulator if simulator.starts_with("domains/authorization/policy/simulator/") => true,
        "domains/organization/billing/catalog.rs" => context.ends_with("_tier"),
        "domains/organization/billing/usage.rs" => context.ends_with("_counts"),
        "domains/identity/attribute/kind.rs" => context == "text_format",
        "domains/identity/attribute/value_type.rs" => context == "describe",
        "domains/identity/attribute/definition/value_check.rs" => context != "strip_prefix",
        "domains/identity/attribute/schema.rs" => {
            matches!(context, "resolve_filter" | "resolve_sort")
        }
        "domains/identity/account/import/password_hash.rs" => context != "ensure_consistent",
        "domains/federation/admission.rs" => context == "fmt",
        "domains/routing/matching/path_rewrite.rs" => {
            matches!(context, "check" | "placeholder_problem")
        }
        "domains/tenant/custom_domains/dns_zone/name.rs" => {
            matches!(context, "check" | "label_problem")
        }
        "domains/tenant/access/sign_in_gate.rs" => context == "shut_out",
        "shared/security/ssrf.rs" => matches!(context, "internal_refused" | "reject_internal_host"),
        "shared/security/secret.rs" => matches!(context, "parse" | "check_segments"),
        _ => false,
    }
}

/// The agents' domain text that refusals and run pauses show.
fn agent_text(path: &str, context: &str) -> bool {
    match path {
        "identity/standing.rs" => context == "denial_reason",
        "execution/run/gate.rs" => context == "reason",
        "execution/run/pause.rs" => context == "APPROVAL_LIMIT_REACHED",
        "execution/tool/path.rs" => matches!(context, "check" | "segment_problem"),
        "authority/capability/topic.rs" => context == "check",
        _ => false,
    }
}

/// Text-value constructors return these descriptions and custom rule
/// messages. PEM markers and serialization text stay literal.
fn value_text(path: &str, context: &str) -> bool {
    match path {
        "types/password_policy.rs" => matches!(context, "check_common" | "check_personal_data"),
        "types/locale/code.rs" | "types/locale/country_code.rs" | "types/locale/timezone.rs" => {
            context == "rules"
        }
        "types/branding/hex_color.rs" => context == "invalid_color",
        "types/branding/sanitized_css.rs" => context == "check" || context.ends_with("_problem"),
        "types/certificate/fingerprint.rs" => context == "invalid",
        "types/naming/tenant_slug.rs" => context == "reserved_error",
        "types/naming/field_path.rs" => {
            matches!(context, "ensure_segment_valid" | "ensure_segments_valid")
        }
        "types/network/canonical_path.rs" => matches!(context, "check" | "segment_problem"),
        "types/network/ip.rs" => matches!(context, "new" | "parse_cidr" | "ensure_prefix_fits"),
        "types/network/public_host.rs" | "types/network/redirect_uri.rs" => true,
        "types/network/public_https_url.rs" => context == "ensure_public",
        "types/network/host_origin.rs"
        | "types/network/otpauth_url.rs"
        | "types/naming/saml_name_id_format.rs" => context == "check",
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::Syntax;

    /// Builds a renderer literal with the source context the scan records.
    fn rendered(english: &str, path: &str, context: &str) -> Message {
        Message::new(
            english.to_owned(),
            Syntax::RustFormat,
            Occurrence {
                path: path.to_owned(),
                line: 1,
                column: 1,
                context: context.to_owned(),
                evidence: Evidence::Presentation,
                keyed: None,
            },
        )
    }

    /// Protocol headers, PEM markers and page codes are excluded even
    /// when their source is classified as presentation code.
    #[test]
    fn renderer_protocol_literals_are_not_translatable_prose() {
        let oauth = "crates/ianua-api/src/error/oauth.rs";
        let pem = "crates/ianua-domain/src/shared/validation/rules/pem.rs";
        let page = "crates/ianua-infra/src/pages/sign_in.rs";
        let notice = "crates/ianua-app/src/use_cases/notifications/delivery/render.rs";
        for (text, path, context) in [
            ("Basic realm=\"ianua\"", oauth, "CLIENT_CHALLENGE"),
            (
                "Bearer realm=\"ianua\", error=\"{code}\"",
                oauth,
                "challenged",
            ),
            ("Bearer realm=\"ianua\"", oauth, "challenged"),
            ("-----BEGIN {label}-----", pem, "holds_block"),
            ("-----END {label}-----", pem, "holds_block"),
            ("verified", page, "note_of"),
            ("refused", page, "note_of"),
            ("info", page, "note_of"),
            ("oauth", notice, "title_word"),
            ("OAuth", notice, "title_word"),
        ] {
            assert!(!retain(&mut rendered(text, path, context)), "{text}");
        }
    }

    /// Sample names and the notification body field label are excluded,
    /// while preview prose and notification bindings remain translatable.
    #[test]
    fn rendering_data_is_excluded_without_losing_public_copy() {
        let samples = "crates/ianua-infra/src/mail/compose/samples.rs";
        let notifications = "crates/ianua-app/src/use_cases/notifications/delivery/render.rs";
        for name in ["Alex Sample", "Sam Admin"] {
            assert!(!retain(&mut rendered(name, samples, "sample_of")));
        }
        assert!(!retain(&mut rendered(
            "body",
            notifications,
            "body_for_event"
        )));
        assert!(retain(&mut rendered(
            "A sample notice",
            samples,
            "sample_of"
        )));
        assert!(retain(&mut rendered(
            "{actor} {verb}",
            notifications,
            "body_for_event"
        )));
    }

    /// A literal used both as a page code and actual public copy keeps
    /// the public occurrence instead of being discarded by its spelling.
    #[test]
    fn a_shared_literal_keeps_its_public_occurrence() {
        let mut message = rendered(
            "verified",
            "crates/ianua-infra/src/pages/sign_in.rs",
            "note_of",
        );
        let public = rendered(
            "verified",
            "crates/ianua-api/src/error.rs",
            "public_message",
        );
        message.occurrences.extend(public.occurrences);

        assert!(retain(&mut message));
        assert_eq!(message.occurrences.len(), 1);
        assert_eq!(message.occurrences[0].context, "public_message");
    }
}
