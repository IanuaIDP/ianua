//! `SecurityHeaders`: the hardening headers a tenant wants the gateway to
//! own, set on the answer the client gets.
//!
//! The stage runs before forwarding and writes into the context's response
//! headers, which the gateway sets on whatever answer goes back, the
//! upstream's or one a stage produced. Each header the tenant left unset
//! stays the upstream's to send; each one set replaces any value an earlier
//! stage queued for it.

use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::stages::decision::{HeaderEntry, StageDecision};
use ianua_domain::domains::proxy::stages::stage::SecurityHeadersConfig;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{HeaderName, HeaderValue};

use super::ResponseStages;

impl ResponseStages {
    /// Queues the configured security headers for the answer.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when a header cannot be written, which
    ///   the fixed names and values never cause.
    pub(crate) fn security_headers(
        &self,
        config: &SecurityHeadersConfig,
        ctx: &mut PipelineContext,
    ) -> Result<StageDecision, DomainError> {
        let headers = wanted(config)?;
        ctx.response_headers
            .retain(|queued| !headers.iter().any(|set| set.name() == queued.name()));
        ctx.response_headers.extend(headers);
        Ok(StageDecision::Pass {
            reason: "security headers queued".to_owned(),
        })
    }
}

/// The headers `config` asks for.
fn wanted(config: &SecurityHeadersConfig) -> Result<Vec<HeaderEntry>, DomainError> {
    let hsts = config.hsts_max_age_seconds.value().map(|max_age| {
        let mut value = format!("max-age={}", max_age.get());
        if bool::from(config.hsts_include_subdomains) {
            value.push_str("; includeSubDomains");
        }
        ("strict-transport-security", value)
    });
    let nosniff = bool::from(config.content_type_options_nosniff)
        .then(|| ("x-content-type-options", "nosniff".to_owned()));
    let frame = config
        .frame_options
        .value()
        .map(|frame| ("x-frame-options", frame.as_header_value().to_owned()));
    let referrer = config
        .referrer_policy
        .value()
        .map(|policy| ("referrer-policy", policy.as_header_value().to_owned()));
    [hsts, nosniff, frame, referrer]
        .into_iter()
        .flatten()
        .map(|(name, value)| entry(name, value))
        .collect()
}

/// The header `name: value`.
fn entry(name: &str, value: String) -> Result<HeaderEntry, DomainError> {
    Ok(HeaderEntry::new(
        HeaderName::new(name)?,
        HeaderValue::new(value)?,
    ))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::proxy::stages::stage::{
        FrameOptions, HstsSubdomains, NoSniff, ReferrerPolicy,
    };
    use ianua_domain::types::{Seconds, Setting};

    use super::*;
    use crate::pipeline::stages::response::fixtures::{Fakes, context, header};

    fn queued<'a>(ctx: &'a PipelineContext, name: &str) -> Vec<&'a str> {
        ctx.response_headers
            .iter()
            .filter(|entry| entry.name().as_str() == name)
            .map(|entry| entry.value().as_str())
            .collect()
    }

    fn everything() -> SecurityHeadersConfig {
        SecurityHeadersConfig {
            hsts_max_age_seconds: Setting::Set(Seconds::new(31_536_000)),
            hsts_include_subdomains: HstsSubdomains::Included,
            content_type_options_nosniff: NoSniff::Send,
            frame_options: Setting::Set(FrameOptions::Deny),
            referrer_policy: Setting::Set(ReferrerPolicy::NoReferrer),
        }
    }

    /// Every header the tenant set is queued for the answer, with its value.
    #[test]
    fn the_configured_headers_are_queued() {
        let mut ctx = context();

        let decision = Fakes::default()
            .stages()
            .security_headers(&everything(), &mut ctx)
            .unwrap();

        assert!(matches!(decision, StageDecision::Pass { .. }));
        assert_eq!(
            queued(&ctx, "strict-transport-security"),
            ["max-age=31536000; includeSubDomains"]
        );
        assert_eq!(queued(&ctx, "x-content-type-options"), ["nosniff"]);
        assert_eq!(queued(&ctx, "x-frame-options"), ["DENY"]);
        assert_eq!(queued(&ctx, "referrer-policy"), ["no-referrer"]);
    }

    /// A tenant that set nothing leaves every header to the upstream.
    #[test]
    fn an_unset_header_is_left_to_the_upstream() {
        let mut ctx = context();
        let nothing = SecurityHeadersConfig {
            hsts_max_age_seconds: Setting::Unset,
            hsts_include_subdomains: HstsSubdomains::Excluded,
            content_type_options_nosniff: NoSniff::Omit,
            frame_options: Setting::Unset,
            referrer_policy: Setting::Unset,
        };

        Fakes::default()
            .stages()
            .security_headers(&nothing, &mut ctx)
            .unwrap();

        assert!(ctx.response_headers.is_empty());
    }

    /// A header queued earlier is replaced, not sent twice, and other
    /// queued headers stay.
    #[test]
    fn a_header_is_sent_once() {
        let mut ctx = context();
        ctx.response_headers
            .push(header("x-frame-options", "SAMEORIGIN"));
        ctx.response_headers.push(header("vary", "origin"));

        Fakes::default()
            .stages()
            .security_headers(&everything(), &mut ctx)
            .unwrap();

        assert_eq!(queued(&ctx, "x-frame-options"), ["DENY"]);
        assert_eq!(queued(&ctx, "vary"), ["origin"]);
    }
}
