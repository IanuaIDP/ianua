//! The settings each kind of stage carries.

use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::domains::data_classification::level::DataClassLevel;
use crate::shared::model::two_cases::two_cases;
use crate::shared::validation::numeric::validate_range;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{
    Audience, CanonicalPath, CidrRange, ClassificationRuleSetId, CountryCode, HeaderName,
    HeaderValue, HttpMethod, Origin, Scope, Seconds, Setting,
};

/// Settings for the WAF stage.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WafConfig {
    /// Which rule categories are on.
    pub rule_sets: Vec<WafRuleSet>,
    /// The anomaly score at which a request is blocked.
    ///
    /// Scoring works as in the OWASP Core Rule Set. Each matched rule adds to
    /// a running score instead of blocking on the first hit. One weak signal
    /// passes, while several, or one strong one, block. So a tenant can tune
    /// how strict the WAF is.
    pub anomaly_threshold: u32,
    /// The largest request body allowed, in bytes.
    ///
    /// WAF rules decide on the path, query, headers and a capped prefix of
    /// the body; the rest of the body streams. This cap is the size of the
    /// whole body, applied while it streams, and
    /// [`Pipeline::body_limit`](crate::domains::proxy::pipeline::Pipeline::body_limit)
    /// gives it for the pipeline.
    pub max_body_bytes: u64,
}

/// A category of WAF rules that can be turned on by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum WafRuleSet {
    /// SQL injection.
    Sqli,
    /// Cross-site scripting.
    Xss,
    /// Path traversal and null-byte injection.
    Traversal,
    /// OS command injection.
    CommandInjection,
    /// Known prompt-injection and jailbreak phrasing, for tenants in front
    /// of LLM-backed upstreams.
    ///
    /// It is one layer among several. Pattern matching stops known phrasing,
    /// not an attacker who rewords it.
    PromptInjection,
}

/// Settings for the GeoFence stage.
///
/// At least one list names a country, and no country is on both.
/// [`admits`](Self::admits) says who comes in.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GeoFenceConfig {
    /// Allowed countries. Empty allows every country the block list does
    /// not name; a list refuses every other country, and a client nobody
    /// could place.
    pub allowed_countries: Vec<CountryCode>,
    /// Requests located in these countries are refused even when otherwise allowed.
    pub blocked_countries: Vec<CountryCode>,
}

/// Settings for the DataClassify stage.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ClassificationConfig {
    /// The classification rule set to apply.
    pub rule_set_id: ClassificationRuleSetId,
}

/// Settings for the TokenExchange stage.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TokenExchangeConfig {
    /// The audience of the minted JWT.
    pub target_audience: Audience,
    /// The scopes the minted JWT carries.
    pub scopes: Vec<Scope>,
    /// How long the minted JWT lives, in seconds.
    pub ttl_seconds: Seconds,
}

/// Settings for the RateLimit stage.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RateLimitConfig {
    /// The most requests allowed per window.
    pub max_requests: u32,
    /// How long one window is, in seconds.
    pub window_seconds: Seconds,
    /// Whose requests are counted together.
    pub key_by: RateLimitKey,
}

/// Whose requests a rate limit counts together.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RateLimitKey {
    /// Per authenticated caller: each user, and each agent, on its own.
    UserId,
    /// Per source IP address.
    IpAddress,
    /// Per API key.
    ApiKey,
    /// Per tenant, as one limit for the whole tenant.
    Tenant,
    /// Per authenticated service identity.
    ConsumerId,
}

/// Settings for the StepUp stage.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StepUpConfig {
    /// The lowest assurance level the route accepts.
    pub required_aal: AssuranceLevel,
}

/// Settings for the RequestSign stage.
///
/// The signature covers the method, the path, a capped prefix of the body
/// and a timestamp. It vouches for what the proxy saw, not for the whole
/// body. A body longer than the cap is only partly covered. The signed
/// `body_complete` claim says so, so a verifier never takes a prefix hash for
/// a whole-body one.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RequestSignConfig {
    /// The header the compact JWS is written to before forwarding.
    pub header_name: HeaderName,
    /// How long the signature is valid, as its `exp` claim. It bounds how
    /// long a copied signature can be replayed.
    pub ttl_seconds: Seconds,
}

/// Settings for the ResponseSign stage.
///
/// It works like [`RequestSignConfig`], with the same capped prefix, but on
/// the response.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResponseSignConfig {
    /// The header the compact JWS is written to on the response.
    pub header_name: HeaderName,
    /// How long the signature is valid, as its `exp` claim.
    pub ttl_seconds: Seconds,
}

/// Settings for the Redact stage.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RedactConfig {
    /// The classification rule set that says how sensitive each field is.
    pub rule_set_id: ClassificationRuleSetId,
    /// The lowest data class that is redacted. Fields at or above it are
    /// redacted.
    pub min_class: DataClassLevel,
}

/// Settings for the Cache stage.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CacheConfig {
    /// How long an entry is kept, in seconds.
    pub ttl_seconds: Seconds,
    /// Whether the cache is kept per authenticated user or shared.
    pub vary_by_user: CacheScope,
}

two_cases! {
    /// Whether a cached response is kept per authenticated user.
    pub enum CacheScope {
        /// One cache entry per user, so nobody is served another's response.
        PerUser => true,
        /// One entry for everyone.
        ///
        /// Only a pipeline whose routes all let anyone in may hold it. On a
        /// signed-in route, Sam would be served the answer cached for Ann.
        Shared => false,
    }
}

two_cases! {
    /// Whether browsers may send credentials on a cross-origin request.
    pub enum CorsCredentials {
        /// They may.
        Allowed => true,
        /// They may not.
        Withheld => false,
    }
}

/// Settings for the Cors stage on a route.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CorsConfig {
    /// Allowed origin patterns.
    pub allowed_origins: Vec<Origin>,
    /// Allowed HTTP methods.
    pub allowed_methods: Vec<HttpMethod>,
    /// Allowed request headers.
    pub allowed_headers: Vec<HeaderName>,
    /// Response headers the browser may read.
    pub exposed_headers: Vec<HeaderName>,
    /// How long a browser may cache a preflight answer, in seconds.
    pub max_age_secs: Seconds,
    /// Whether browsers may send credentials.
    pub allow_credentials: CorsCredentials,
}

two_cases! {
    /// Whether `Strict-Transport-Security` also covers subdomains.
    pub enum HstsSubdomains {
        /// `includeSubDomains` is sent.
        Included => true,
        /// It is not.
        Excluded => false,
    }
}

two_cases! {
    /// Whether `X-Content-Type-Options: nosniff` is sent.
    pub enum NoSniff {
        /// It is sent.
        Send => true,
        /// It is not.
        Omit => false,
    }
}

two_cases! {
    /// Whether clients flagged on any tenant are denied here too.
    pub enum FlaggedClients {
        /// Denied.
        Deny => true,
        /// Only this tenant's own list applies.
        Ignore => false,
    }
}

/// Settings for the CanaryToken stage.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CanaryTokenConfig {
    /// Decoy bearer tokens and API keys planted for this tenant.
    ///
    /// None is ever issued to a real user or service. So one presented to
    /// the proxy proves a credential was stolen.
    pub tokens: Vec<CanaryToken>,
}

/// Settings for the HoneypotRoutes stage.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HoneypotConfig {
    /// Decoy paths no real client ever requests, such as `/.env`,
    /// `/.git/config` or `/wp-login.php`.
    ///
    /// They are kept in canonical spelling, so a probe for `/.env/` or
    /// `/%2eenv` is caught too.
    pub paths: Vec<CanonicalPath>,
    /// How long a client that hits a decoy path is blocked, in seconds.
    ///
    /// Each later hit starts the block again from that moment. Blocks do not
    /// add up.
    pub block_ttl_seconds: Seconds,
}

/// Settings for the ReconDetection stage.
///
/// A signal trips once it crosses its own threshold within the current
/// window. `tarpit_signal_count` and `block_signal_count` say how many tripped
/// signals lead to each action. For example, one signal slows the client and
/// all three block it.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReconDetectionConfig {
    /// How long the scoring window is, in seconds.
    ///
    /// When it ends, the scores start again from zero. They do not fade
    /// gradually.
    pub window_seconds: Seconds,
    /// How many requests the window needs before the error-ratio signal
    /// counts, so one 404 does not flag a client.
    pub min_requests: u32,
    /// The share of responses in the window, from 0.0 to 1.0, that were 404
    /// or 403, above which the error-ratio signal trips.
    pub error_ratio_threshold: f32,
    /// The number of distinct paths in the window above which the
    /// path-velocity signal trips.
    pub distinct_path_threshold: u32,
    /// The number of 401 responses in the window above which the
    /// auth-failure signal trips.
    pub auth_failure_threshold: u32,
    /// How many tripped signals slow the client down.
    pub tarpit_signal_count: u8,
    /// How many tripped signals block the client.
    pub block_signal_count: u8,
    /// How long a slowed request is held, in milliseconds.
    pub tarpit_delay_ms: u32,
}

/// Settings for the Fingerprint stage.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FingerprintConfig {
    /// What to do with a request bearing a known automation signature.
    pub action: FingerprintAction,
}

/// What to do with unenrolled automation the fingerprint stage detects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FingerprintAction {
    /// Let it through. The stage only detects.
    Allow,
    /// Require agent enrollment before continuing.
    Challenge,
    /// Refuse outright.
    Deny,
}

/// Settings for the SecurityHeaders stage.
///
/// Each header is a [`Setting`]. `Setting::Unset` means the proxy does not set
/// that header, and leaves it to the upstream. A tenant opts in to only the
/// headers it wants the proxy to own.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SecurityHeadersConfig {
    /// `Strict-Transport-Security` max-age in seconds, if set.
    pub hsts_max_age_seconds: Setting<Seconds>,
    /// Whether `Strict-Transport-Security` includes `includeSubDomains`.
    pub hsts_include_subdomains: HstsSubdomains,
    /// Whether to set `X-Content-Type-Options: nosniff`.
    pub content_type_options_nosniff: NoSniff,
    /// `X-Frame-Options` value, if set.
    pub frame_options: Setting<FrameOptions>,
    /// `Referrer-Policy` value, if set.
    pub referrer_policy: Setting<ReferrerPolicy>,
}

/// The values `X-Frame-Options` may take, from RFC 7034.
///
/// Stored and sent as the header value itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FrameOptions {
    /// The page may not be framed at all.
    #[cfg_attr(feature = "serde", serde(rename = "DENY"))]
    Deny,
    /// Only pages on the same origin may frame it.
    #[cfg_attr(feature = "serde", serde(rename = "SAMEORIGIN"))]
    SameOrigin,
}

impl FrameOptions {
    /// The exact X-Frame-Options directive emitted on the response.
    #[must_use]
    pub fn as_header_value(self) -> &'static str {
        match self {
            Self::Deny => "DENY",
            Self::SameOrigin => "SAMEORIGIN",
        }
    }
}

/// The values `Referrer-Policy` may take, from the W3C Referrer Policy.
///
/// Stored and sent as the header value itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum ReferrerPolicy {
    /// Never send a referrer.
    NoReferrer,
    /// Send none when going from HTTPS to HTTP.
    NoReferrerWhenDowngrade,
    /// Send only the origin.
    Origin,
    /// The full URL within the origin, only the origin across origins.
    OriginWhenCrossOrigin,
    /// The full URL within the origin, nothing across origins.
    SameOrigin,
    /// Only the origin, and none when going from HTTPS to HTTP.
    StrictOrigin,
    /// The full URL within the origin, only the origin across origins, none
    /// on a downgrade.
    StrictOriginWhenCrossOrigin,
    /// Always the full URL.
    UnsafeUrl,
}

impl ReferrerPolicy {
    /// The exact Referrer-Policy directive emitted on the response.
    #[must_use]
    pub fn as_header_value(self) -> &'static str {
        match self {
            Self::NoReferrer => "no-referrer",
            Self::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
            Self::Origin => "origin",
            Self::OriginWhenCrossOrigin => "origin-when-cross-origin",
            Self::SameOrigin => "same-origin",
            Self::StrictOrigin => "strict-origin",
            Self::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
            Self::UnsafeUrl => "unsafe-url",
        }
    }
}

/// Settings for the IpReputation stage.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IpReputationConfig {
    /// CIDR ranges this tenant always denies.
    pub denylist: Vec<CidrRange>,
    /// Whether to also deny a client recently flagged by the honeypot or
    /// recon-detection stage on any tenant, not just this one.
    pub deny_platform_flagged: FlaggedClients,
}

/// What a `Terminate` stage answers with.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "TerminateConfigWire"))]
pub struct TerminateConfig {
    /// The status to return.
    ///
    /// Any valid HTTP status is accepted, including `503` for a maintenance
    /// window and `410` for a retired route.
    ///
    status: u16,
    /// The `Content-Type` of `body`.
    content_type: HeaderValue,
    /// The body, as written.
    ///
    /// It is at most `MAX_TERMINATE_BODY` bytes. It is a stub or a notice,
    /// not a document.
    body: String,
}

/// The largest body a `Terminate` stage may carry.
///
/// Every request on the route pays for it in the pipeline it is loaded with,
/// so it is a notice, not a payload.
pub(crate) const MAX_TERMINATE_BODY: usize = 64 * 1024;

/// A fixed answer as it arrives, before [`TerminateConfig::new`] has checked it.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct TerminateConfigWire {
    status: u16,
    content_type: String,
    body: String,
}

#[cfg(feature = "serde")]
impl TryFrom<TerminateConfigWire> for TerminateConfig {
    type Error = crate::shared::errors::DomainError;

    /// A fixed answer read from a stored pipeline or an API body is held to
    /// the same rules as one built in code.
    fn try_from(wire: TerminateConfigWire) -> Result<Self, Self::Error> {
        Self::new(wire.status, wire.content_type, wire.body)
    }
}

impl TerminateConfig {
    /// The status to answer with.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The `Content-Type` of the body.
    #[must_use]
    pub fn content_type(&self) -> &HeaderValue {
        &self.content_type
    }

    /// The body to answer with.
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }

    /// A fixed answer for a `Terminate` stage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`](crate::shared::errors::DomainError::Validation)
    ///   if the status is outside `200` to `599`. A `1xx` is only ever an
    ///   interim answer, so it cannot be the final one.
    /// - [`DomainError::Validation`](crate::shared::errors::DomainError::Validation)
    ///   if the body is longer than `MAX_TERMINATE_BODY` bytes.
    /// - [`DomainError::Validation`](crate::shared::errors::DomainError::Validation)
    ///   if the content type is blank or not a [`HeaderValue`].
    pub fn new(
        status: u16,
        content_type: impl Into<String>,
        body: impl Into<String>,
    ) -> Result<Self, crate::shared::errors::DomainError> {
        let content_type = content_type.into();
        let body = body.into();

        validate_range("status", status, 200..=599)?;
        Validator::new("body", &body)
            .max_bytes(MAX_TERMINATE_BODY)
            .validate_first()?;
        Validator::new("content_type", &content_type)
            .not_blank()
            .validate_first()?;
        let content_type = HeaderValue::new(content_type)?;

        Ok(Self {
            status,
            content_type,
            body,
        })
    }
}

/// Which uploaded WASM module a `Custom` stage runs, and its limits.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WasmStageRef {
    /// Where the module is stored, such as its hash or path.
    pub module_ref: ModuleRef,
    /// The longest the module may run, in milliseconds.
    pub timeout_ms: u32,
    /// The most memory the module may use, in bytes.
    pub max_memory_bytes: u64,
}

text_value! {
    redacted
    /// A decoy value a canary stage watches for.
    ///
    /// It is 16 to 512 characters, so nobody guesses it by chance, with no
    /// whitespace or control characters. It is redacted like any credential.
    /// A decoy printed in a log could be replayed by anyone reading the log
    /// to raise false alarms, or learned and avoided.
    pub struct CanaryToken;
}

impl TextValue for CanaryToken {
    const FIELD: &'static str = "token";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .char_length(16..=512)
            .no_whitespace()
            .no_control_chars()
    }
}

text_value! {
    /// Which uploaded WASM module a stage runs.
    pub struct ModuleRef;
}

impl TextValue for ModuleRef {
    const FIELD: &'static str = "module_ref";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(1..=512)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A body of exactly 64 KiB is accepted and one byte more is refused.
    /// The body is loaded with every request on the route, so it stays small.
    #[test]
    fn a_termination_body_may_be_as_large_as_the_ceiling_and_no_larger() {
        assert_eq!(MAX_TERMINATE_BODY, 65_536);

        assert!(TerminateConfig::new(503, "text/plain", "a".repeat(MAX_TERMINATE_BODY)).is_ok());
        assert!(
            TerminateConfig::new(503, "text/plain", "a".repeat(MAX_TERMINATE_BODY + 1)).is_err()
        );
    }

    /// Statuses 99, 101 and 600 are refused, and so is a blank content type.
    /// A `410` with `text/plain` is accepted.
    #[test]
    fn a_termination_needs_an_http_status_and_a_content_type() {
        assert!(TerminateConfig::new(99, "text/plain", "gone").is_err());
        assert!(TerminateConfig::new(101, "text/plain", "gone").is_err());
        assert!(TerminateConfig::new(600, "text/plain", "gone").is_err());
        assert!(TerminateConfig::new(410, "  ", "gone").is_err());
        assert!(TerminateConfig::new(410, "text/plain", "gone").is_ok());
    }

    /// Every frame option and referrer policy is written to JSON as its exact
    /// header value, such as `"SAMEORIGIN"`, and read back to the same value.
    #[cfg(feature = "serde")]
    #[test]
    fn frame_and_referrer_settings_are_written_as_their_header_value() {
        let frames = [FrameOptions::Deny, FrameOptions::SameOrigin];
        let referrers = [
            ReferrerPolicy::NoReferrer,
            ReferrerPolicy::NoReferrerWhenDowngrade,
            ReferrerPolicy::Origin,
            ReferrerPolicy::OriginWhenCrossOrigin,
            ReferrerPolicy::SameOrigin,
            ReferrerPolicy::StrictOrigin,
            ReferrerPolicy::StrictOriginWhenCrossOrigin,
            ReferrerPolicy::UnsafeUrl,
        ];

        for frame in frames {
            let json = serde_json::to_string(&frame).unwrap();
            assert_eq!(json, format!("\"{}\"", frame.as_header_value()));
            assert_eq!(serde_json::from_str::<FrameOptions>(&json).unwrap(), frame);
        }
        for referrer in referrers {
            let json = serde_json::to_string(&referrer).unwrap();
            assert_eq!(json, format!("\"{}\"", referrer.as_header_value()));
            assert_eq!(
                serde_json::from_str::<ReferrerPolicy>(&json).unwrap(),
                referrer
            );
        }
    }

    /// Formatting a canary token with `Debug` omits its decoy value.
    #[test]
    fn a_canary_token_does_not_show_in_debug_output() {
        let token = CanaryToken::new("decoy-token-0123456789").unwrap();

        assert!(!format!("{token:?}").contains("decoy-token"));
    }

    /// A 22-character decoy with no spaces is a valid canary token.
    #[test]
    fn a_well_formed_canary_token_is_accepted() {
        assert!(CanaryToken::new("decoy-token-0123456789").is_ok());
    }

    /// An empty decoy, one under 16 characters and one with spaces are
    /// refused.
    #[test]
    fn a_malformed_canary_token_is_refused() {
        for value in ["", "short", "decoy token 0123456789"] {
            assert!(CanaryToken::new(value).is_err(), "{value:?} was accepted");
        }
    }

    /// A path such as `tenant/modules/geo-check.wasm` is a valid module
    /// reference.
    #[test]
    fn a_well_formed_module_ref_is_accepted() {
        assert!(ModuleRef::new("tenant/modules/geo-check.wasm").is_ok());
    }

    /// An empty module reference and one with a space are refused.
    #[test]
    fn a_malformed_module_ref_is_refused() {
        for value in ["", "a b"] {
            assert!(ModuleRef::new(value).is_err(), "{value:?} was accepted");
        }
    }
}
