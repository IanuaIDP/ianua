//! What each kind of stage must be configured with to do anything at all.
//!
//! A stage's settings come from a tenant's dashboard or a stored pipeline. A
//! zero window, a threshold that is not a number or an empty list would be
//! saved and listed, but would do nothing or block everyone.
//! [`StageKind::validate`] is the one place every kind's rules are asked
//! for; the kinds whose checks also run on a request (WAF, geofence, CORS,
//! decoys and recon) keep their rules beside those checks. A
//! [`StageConfig`](crate::domains::proxy::stages::stage::StageConfig) cannot
//! be made without it.

use crate::domains::proxy::exchange::EXCHANGED_TOKEN_LIFETIME;
use crate::domains::proxy::request::transform::{validate_configurable, validate_message_header};
use crate::domains::proxy::stages::stage::{
    CacheConfig, CanaryTokenConfig, FlaggedClients, HstsSubdomains, IpReputationConfig, NoSniff,
    RateLimitConfig, RequestSignConfig, ResponseSignConfig, SecurityHeadersConfig, StageKind,
    TokenExchangeConfig, WasmStageRef,
};
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::{validate_count, validate_range};
use crate::types::Seconds;

/// One day, the longest a rate-limit window or a signature may last.
const DAY_SECS: u32 = 86_400;

/// A week, the longest a cached response or a block may last.
const WEEK_SECS: u32 = 7 * DAY_SECS;

/// The longest a custom stage may run, in milliseconds.
///
/// It is the whole pipeline's default time budget, so one stage cannot claim
/// more than all of them get.
const MAX_CUSTOM_STAGE_MS: u32 = 10_000;
/// The least memory a custom stage can run in: one WebAssembly page.
const MIN_CUSTOM_STAGE_MEMORY: u64 = 64 * 1024;
/// The most memory a custom stage may claim per request.
const MAX_CUSTOM_STAGE_MEMORY: u64 = 256 * 1024 * 1024;

impl StageKind {
    /// Checks that the settings this kind carries can do their job.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] naming the first value that is out of
    ///   range, missing, or contradicts another.
    pub fn validate(&self) -> Result<(), DomainError> {
        match self {
            Self::Waf(c) => c.validate(),
            Self::GeoFence(c) => c.validate(),
            Self::TokenExchange(c) => c.validate(),
            Self::RateLimit(c) => c.validate(),
            Self::RequestSign(c) => c.validate(),
            Self::ResponseSign(c) => c.validate(),
            Self::Cache(c) => c.validate(),
            Self::Cors(c) => c.validate(),
            Self::HoneypotRoutes(c) => c.validate(),
            Self::ReconDetection(c) => c.validate(),
            Self::SecurityHeaders(c) => c.validate(),
            Self::IpReputation(c) => c.validate(),
            Self::CanaryToken(c) => c.validate(),
            Self::Custom(c) => c.validate(),
            Self::Identity
            | Self::DevicePosture(_)
            | Self::DataClassify(_)
            | Self::Policy
            | Self::TokenRateLimit(_)
            | Self::StepUp(_)
            | Self::Redact(_)
            | Self::Fingerprint(_)
            | Self::Terminate(_)
            | Self::GraphQl(_)
            | Self::RequestTransform(_)
            | Self::ResponseTransform(_)
            | Self::Mcp => Ok(()),
        }
    }
}

/// Checks how long a signature stays valid: at least a second, at most a
/// day.
fn sign_ttl(ttl_seconds: Seconds) -> Result<(), DomainError> {
    validate_range("ttl_seconds", ttl_seconds.get(), 1..=DAY_SECS)?;
    Ok(())
}

fn refuse(reason: &str) -> DomainError {
    DomainError::invalid(reason.to_owned())
}

impl RequestSignConfig {
    fn validate(&self) -> Result<(), DomainError> {
        validate_configurable(&self.header_name)?;
        sign_ttl(self.ttl_seconds)
    }
}

impl ResponseSignConfig {
    fn validate(&self) -> Result<(), DomainError> {
        validate_message_header(&self.header_name)?;
        sign_ttl(self.ttl_seconds)
    }
}

impl TokenExchangeConfig {
    /// Refuses a token lasting longer than an exchanged token may, or one
    /// carrying no scope at all.
    fn validate(&self) -> Result<(), DomainError> {
        validate_range(
            "ttl_seconds",
            self.ttl_seconds.get(),
            1..=EXCHANGED_TOKEN_LIFETIME.get(),
        )?;
        validate_count("scopes", self.scopes.len(), 1..=usize::MAX)?;
        Ok(())
    }
}

impl RateLimitConfig {
    fn validate(&self) -> Result<(), DomainError> {
        validate_range("max_requests", self.max_requests, 1..=u32::MAX)?;
        validate_range("window_seconds", self.window_seconds.get(), 1..=DAY_SECS)?;
        Ok(())
    }
}

impl CacheConfig {
    fn validate(&self) -> Result<(), DomainError> {
        validate_range("ttl_seconds", self.ttl_seconds.get(), 1..=WEEK_SECS)?;
        Ok(())
    }
}

impl SecurityHeadersConfig {
    fn validate(&self) -> Result<(), DomainError> {
        let sets_something = !self.hsts_max_age_seconds.is_unset()
            || self.content_type_options_nosniff == NoSniff::Send
            || !self.frame_options.is_unset()
            || !self.referrer_policy.is_unset();
        if !sets_something {
            return Err(refuse(
                "a security headers stage needs at least one header to set",
            ));
        }
        if self.hsts_include_subdomains == HstsSubdomains::Included
            && self.hsts_max_age_seconds.is_unset()
        {
            return Err(refuse(
                "includeSubDomains needs a Strict-Transport-Security max-age to go with",
            ));
        }
        Ok(())
    }
}

impl IpReputationConfig {
    fn validate(&self) -> Result<(), DomainError> {
        if self.denylist.is_empty() && self.deny_platform_flagged == FlaggedClients::Ignore {
            return Err(refuse(
                "an IP reputation stage needs a range to deny or platform flags to honour",
            ));
        }
        Ok(())
    }
}

impl WasmStageRef {
    /// Refuses a module with no time or memory, which cannot run, and one
    /// with more than the limits, which would hold up every request on the
    /// route.
    fn validate(&self) -> Result<(), DomainError> {
        validate_range("timeout_ms", self.timeout_ms, 1..=MAX_CUSTOM_STAGE_MS)?;
        validate_range(
            "max_memory_bytes",
            self.max_memory_bytes,
            MIN_CUSTOM_STAGE_MEMORY..=MAX_CUSTOM_STAGE_MEMORY,
        )?;
        Ok(())
    }
}

impl CanaryTokenConfig {
    fn validate(&self) -> Result<(), DomainError> {
        validate_count("tokens", self.tokens.len(), 1..=usize::MAX)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::proxy::stages::stage::{
        CorsConfig, CorsCredentials, GeoFenceConfig, RateLimitKey, ReconDetectionConfig, WafConfig,
        WafRuleSet,
    };
    use crate::types::{CountryCode, Origin, Seconds, Setting};

    fn request_signed_into(header: &str) -> StageKind {
        StageKind::RequestSign(crate::domains::proxy::stages::stage::RequestSignConfig {
            header_name: crate::types::HeaderName::new(header).unwrap(),
            ttl_seconds: Seconds::new(60),
        })
    }

    fn response_signed_into(header: &str) -> StageKind {
        StageKind::ResponseSign(crate::domains::proxy::stages::stage::ResponseSignConfig {
            header_name: crate::types::HeaderName::new(header).unwrap(),
            ttl_seconds: Seconds::new(60),
        })
    }

    /// Request signing rejects proxy-owned identity headers, their tested
    /// underscore spelling, and Content-Length. Response signing rejects
    /// Transfer-Encoding, while both accept `x-signature`.
    #[test]
    fn a_signature_is_never_written_over_an_owned_or_framing_header() {
        for header in [
            "x-forwarded-user",
            "X_Forwarded_User",
            "x-ianua-assertion",
            "content-length",
        ] {
            assert!(request_signed_into(header).validate().is_err(), "{header}");
        }
        assert!(
            response_signed_into("transfer-encoding")
                .validate()
                .is_err()
        );
        assert!(request_signed_into("x-signature").validate().is_ok());
        assert!(response_signed_into("x-signature").validate().is_ok());
    }

    fn exchange(scopes: &[&str], ttl_seconds: u32) -> StageKind {
        StageKind::TokenExchange(TokenExchangeConfig {
            target_audience: crate::types::Audience::new("billing-service").unwrap(),
            scopes: scopes
                .iter()
                .map(|name| crate::types::Scope::new(*name).unwrap())
                .collect(),
            ttl_seconds: Seconds::new(ttl_seconds),
        })
    }

    /// Token-exchange settings reject a day-long or zero lifetime and an
    /// empty scope list, while accepting five minutes with a scope.
    #[test]
    fn an_exchanged_token_lives_minutes_and_asks_for_something() {
        assert!(exchange(&["invoices:read"], 86_400).validate().is_err());
        assert!(exchange(&["invoices:read"], 0).validate().is_err());
        assert!(exchange(&[], 60).validate().is_err());
        assert!(exchange(&["invoices:read"], 300).validate().is_ok());
    }

    fn rate_limit(max_requests: u32, window_seconds: u32) -> StageKind {
        StageKind::RateLimit(RateLimitConfig {
            max_requests,
            window_seconds: Seconds::new(window_seconds),
            key_by: RateLimitKey::IpAddress,
        })
    }

    fn recon() -> ReconDetectionConfig {
        ReconDetectionConfig {
            window_seconds: Seconds::new(60),
            min_requests: 10,
            error_ratio_threshold: 0.5,
            distinct_path_threshold: 50,
            auth_failure_threshold: 10,
            tarpit_signal_count: 1,
            block_signal_count: 3,
            tarpit_delay_ms: 2000,
        }
    }

    fn cors(origin: &str, allow_credentials: CorsCredentials) -> StageKind {
        StageKind::Cors(CorsConfig {
            allowed_origins: vec![Origin::new(origin).unwrap()],
            allowed_methods: Vec::new(),
            allowed_headers: Vec::new(),
            exposed_headers: Vec::new(),
            max_age_secs: Seconds::new(600),
            allow_credentials,
        })
    }

    /// 100 requests per 60 seconds is valid. A limit of zero requests or a
    /// window of zero seconds is refused.
    #[test]
    fn a_rate_limit_needs_a_limit_and_a_window() {
        assert!(rate_limit(100, 60).validate().is_ok());
        assert!(rate_limit(0, 60).validate().is_err());
        assert!(rate_limit(100, 0).validate().is_err());
    }

    /// A WAF with the SQL injection rules is valid. One with no rule sets
    /// would check nothing, so it is refused.
    #[test]
    fn a_waf_with_no_rule_set_is_refused() {
        let waf = |rule_sets| {
            StageKind::Waf(WafConfig {
                rule_sets,
                anomaly_threshold: 5,
                max_body_bytes: 1024,
            })
        };

        assert!(waf(vec![WafRuleSet::Sqli]).validate().is_ok());
        assert!(waf(Vec::new()).validate().is_err());
    }

    /// A geofence that lists Germany as both allowed and blocked is refused.
    #[test]
    fn a_country_cannot_be_both_allowed_and_blocked() {
        let de = || CountryCode::new("DE").unwrap();
        let fence = StageKind::GeoFence(GeoFenceConfig {
            allowed_countries: vec![de()],
            blocked_countries: vec![de()],
        });

        assert!(fence.validate().is_err());
    }

    /// A wildcard origin with credentials is refused. A wildcard without
    /// credentials, or a named origin with them, is accepted.
    #[test]
    fn credentials_are_refused_for_a_wildcard_origin() {
        assert!(cors("*", CorsCredentials::Allowed).validate().is_err());
        assert!(cors("*", CorsCredentials::Withheld).validate().is_ok());
        assert!(
            cors("https://app.acme.com", CorsCredentials::Allowed)
                .validate()
                .is_ok()
        );
    }

    /// An error ratio that is not a number or is above 1 is refused. So is
    /// blocking at fewer signals than slowing, or asking for four signals
    /// when there are three.
    #[test]
    fn recon_needs_a_sensible_ratio_and_escalation() {
        assert!(StageKind::ReconDetection(recon()).validate().is_ok());

        for bad in [
            ReconDetectionConfig {
                error_ratio_threshold: f32::NAN,
                ..recon()
            },
            ReconDetectionConfig {
                error_ratio_threshold: 1.5,
                ..recon()
            },
            ReconDetectionConfig {
                tarpit_signal_count: 3,
                block_signal_count: 2,
                ..recon()
            },
            ReconDetectionConfig {
                block_signal_count: 4,
                ..recon()
            },
        ] {
            assert!(StageKind::ReconDetection(bad).validate().is_err());
        }
    }

    /// A security headers stage with every header unset or omitted would do
    /// nothing, so it is refused.
    #[test]
    fn a_security_headers_stage_must_set_something() {
        let nothing = SecurityHeadersConfig {
            hsts_max_age_seconds: Setting::Unset,
            hsts_include_subdomains: HstsSubdomains::Excluded,
            content_type_options_nosniff: NoSniff::Omit,
            frame_options: Setting::Unset,
            referrer_policy: Setting::Unset,
        };

        assert!(StageKind::SecurityHeaders(nothing).validate().is_err());
    }

    /// A canary stage with no decoy tokens would catch nothing, so it is
    /// refused.
    #[test]
    fn a_canary_stage_needs_a_token() {
        assert!(
            StageKind::CanaryToken(CanaryTokenConfig { tokens: Vec::new() })
                .validate()
                .is_err()
        );
    }

    fn custom(timeout_ms: u32, max_memory_bytes: u64) -> StageKind {
        StageKind::Custom(WasmStageRef {
            module_ref: crate::domains::proxy::stages::stage::ModuleRef::new(
                "tenant/modules/geo-check.wasm",
            )
            .unwrap(),
            timeout_ms,
            max_memory_bytes,
        })
    }

    /// A module with 50 ms and 16 MiB is valid. Zero time, zero memory, or
    /// one more than the time or memory limit is refused.
    #[test]
    fn a_custom_stage_runs_within_bounded_time_and_memory() {
        assert!(custom(50, 16 * 1024 * 1024).validate().is_ok());
        assert!(custom(0, 16 * 1024 * 1024).validate().is_err());
        assert!(
            custom(MAX_CUSTOM_STAGE_MS + 1, 16 * 1024 * 1024)
                .validate()
                .is_err()
        );
        assert!(custom(50, 0).validate().is_err());
        assert!(custom(50, MAX_CUSTOM_STAGE_MEMORY + 1).validate().is_err());
    }

    /// Identity, Policy and Mcp have no settings, so there is nothing to
    /// refuse.
    #[test]
    fn stages_without_settings_are_always_valid() {
        assert!(StageKind::Identity.validate().is_ok());
        assert!(StageKind::Policy.validate().is_ok());
        assert!(StageKind::Mcp.validate().is_ok());
    }
}
