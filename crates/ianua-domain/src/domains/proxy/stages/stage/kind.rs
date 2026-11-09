//! What a stage does, and which chain of a request's life it acts in.

use crate::domains::proxy::request::graphql::GraphQlLimits;
use crate::domains::proxy::request::transform::{RequestMutation, ResponseMutation};
use crate::domains::proxy::stages::posture::PostureRule;
use crate::domains::proxy::stages::stage::{
    CacheConfig, CacheScope, CanaryTokenConfig, ClassificationConfig, CorsConfig,
    FingerprintConfig, GeoFenceConfig, HoneypotConfig, IpReputationConfig, RateLimitConfig,
    ReconDetectionConfig, RedactConfig, RequestSignConfig, ResponseSignConfig,
    SecurityHeadersConfig, StageKindName, StepUpConfig, TerminateConfig, TokenExchangeConfig,
    WafConfig, WasmStageRef,
};
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::ClassificationRuleSetId;

/// The classification rules a tenant has, which a stage reading rules must
/// name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantRules<'a> {
    /// The tenant has classified fields, in this rule set.
    Classified(&'a ClassificationRuleSetId),
    /// The tenant has classified nothing yet, so it has no rule set.
    Unclassified,
}

/// What a pipeline stage does.
///
/// Each variant carries its own typed settings. The proxy's `StageExecutor`
/// adapter runs each kind.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum StageKind {
    /// A web application firewall. It blocks known attack patterns.
    Waf(WafConfig),

    /// Allows or refuses a request by the client's country.
    GeoFence(GeoFenceConfig),

    /// Allows a request only from a device whose reported posture meets the
    /// rule: trusted, on a recent enough system, with the protections asked
    /// for. A device nothing reported on is refused.
    DevicePosture(PostureRule),

    /// Verifies the caller's session or token, through the authentication
    /// context's ports.
    Identity,

    /// Tags request and response fields with how sensitive they are, so a
    /// later stage can redact them.
    DataClassify(ClassificationConfig),

    /// Checks the route's authorization policy against the caller.
    Policy,

    /// Mints a JWT for the upstream service, with narrowed claims.
    TokenExchange(TokenExchangeConfig),

    /// Limits how many requests a caller makes per window.
    RateLimit(RateLimitConfig),

    /// Limits what a caller spends on a language model, not how often it
    /// asks.
    ///
    /// A request count says little about cost here. One request can cost a
    /// thousand times another. Unlike every other limit, this one is checked
    /// before the request and charged after it, because the price is only
    /// known once the provider has answered.
    TokenRateLimit(crate::domains::proxy::stages::token_budget::TokenRateLimitConfig),

    /// Asks for MFA when the route needs a higher assurance level than the
    /// caller has.
    StepUp(StepUpConfig),

    /// Signs the request, so the upstream can check where it came from.
    RequestSign(RequestSignConfig),

    /// Strips classified fields from the response before the caller gets
    /// it.
    Redact(RedactConfig),

    /// Signs the response body, so the caller can check it was not changed.
    ResponseSign(ResponseSignConfig),

    /// Caches responses, per tenant.
    Cache(CacheConfig),

    /// A tenant's own WASM module, run in a sandboxed Wasmtime runtime.
    Custom(WasmStageRef),

    /// Cross-origin resource sharing rules for the route.
    Cors(CorsConfig),

    /// Decoy paths no real client ever requests.
    ///
    /// A hit blocks the client and raises an audit event, before any route
    /// matching happens.
    HoneypotRoutes(HoneypotConfig),

    /// Scores clients on scanning behaviour and slows or blocks those past
    /// the threshold.
    ///
    /// The signals are the error ratio, how fast new paths are tried and how
    /// fast sign-ins fail.
    ReconDetection(ReconDetectionConfig),

    /// Matches the client against known bot and AI user agents, such as
    /// GPTBot, ClaudeBot, curl or a headless browser.
    ///
    /// It applies the configured action to automation that is not enrolled.
    Fingerprint(FingerprintConfig),

    /// Adds hardening headers to the response, for tenants that want the
    /// proxy to own them.
    ///
    /// These are `Strict-Transport-Security`, `X-Content-Type-Options`,
    /// `X-Frame-Options` and `Referrer-Policy`.
    SecurityHeaders(SecurityHeadersConfig),

    /// Refuses clients on a tenant's CIDR denylist.
    ///
    /// A tenant can also opt in to refuse clients that a honeypot or recon
    /// stage recently flagged on any tenant. A scanner caught at one tenant
    /// is then refused at every tenant that opted in.
    IpReputation(IpReputationConfig),

    /// Decoy credentials no real client is ever issued.
    ///
    /// A match proves the credential leaked and is being replayed. That is a
    /// stronger signal than an ordinary failed sign-in.
    CanaryToken(CanaryTokenConfig),

    /// Answers the request here, without asking an upstream.
    ///
    /// For a maintenance window, a route retired behind a `410`, or a backend
    /// that does not exist yet while a client team builds against it.
    Terminate(TerminateConfig),

    /// GraphQL depth and complexity limits, and a cache key that tells one
    /// query from another.
    ///
    /// It reads the body, because a GraphQL request says what it wants
    /// nowhere else.
    GraphQl(GraphQlLimits),

    /// Rewrites headers and query parameters on the way to the upstream.
    ///
    /// For a caller and a backend that disagree about the shape of a
    /// request. It changes only metadata, so the body still streams.
    RequestTransform(RequestMutation),

    /// Rewrites headers on the way back to the client, often to drop what an
    /// upstream says about itself.
    ResponseTransform(ResponseMutation),

    /// Authorizes MCP tool calls.
    ///
    /// It reads the JSON-RPC envelope and checks the tool it names against
    /// the caller's granted tools and declared purpose. Under MCP every tool
    /// call is the same method on the same path, so a policy on path and
    /// method cannot tell a read from a deletion.
    Mcp,
}

/// When in a request's life a stage acts.
///
/// The data plane runs two chains: one before forwarding, and one after the
/// upstream answers. A stage put in the wrong chain is saved and listed, but
/// never runs. A stage's settings do not say which chain it belongs in, so
/// this type does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagePhase {
    /// Decides before the request is forwarded.
    Request,
    /// Acts on the upstream's answer.
    Response,
    /// Decides on the way out and records something on the way back, like a
    /// cache that looks up and then stores.
    Both,
}

impl StagePhase {
    /// Whether this stage takes part in the pre-forward chain.
    #[must_use]
    pub fn runs_on_request(self) -> bool {
        matches!(self, Self::Request | Self::Both)
    }

    /// Whether this stage takes part in the post-response chain.
    #[must_use]
    pub fn runs_on_response(self) -> bool {
        matches!(self, Self::Response | Self::Both)
    }
}

impl StageKind {
    /// The stage's name, as an audit record carries it.
    ///
    /// It is the kind alone, never its settings, which may hold decoys and
    /// secret references.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.kind_name().as_str()
    }

    /// The stage's kind on its own, without its settings.
    ///
    /// One arm per kind, with no catch-all, so a new kind does not compile
    /// until it is given a name a record can keep.
    #[must_use]
    pub fn kind_name(&self) -> StageKindName {
        match self {
            Self::Waf(_) => StageKindName::Waf,
            Self::GeoFence(_) => StageKindName::GeoFence,
            Self::DevicePosture(_) => StageKindName::DevicePosture,
            Self::Identity => StageKindName::Identity,
            Self::DataClassify(_) => StageKindName::DataClassify,
            Self::Policy => StageKindName::Policy,
            Self::TokenExchange(_) => StageKindName::TokenExchange,
            Self::RateLimit(_) => StageKindName::RateLimit,
            Self::TokenRateLimit(_) => StageKindName::TokenRateLimit,
            Self::StepUp(_) => StageKindName::StepUp,
            Self::RequestSign(_) => StageKindName::RequestSign,
            Self::Redact(_) => StageKindName::Redact,
            Self::ResponseSign(_) => StageKindName::ResponseSign,
            Self::Cache(_) => StageKindName::Cache,
            Self::Custom(_) => StageKindName::Custom,
            Self::Cors(_) => StageKindName::Cors,
            Self::HoneypotRoutes(_) => StageKindName::HoneypotRoutes,
            Self::ReconDetection(_) => StageKindName::ReconDetection,
            Self::Fingerprint(_) => StageKindName::Fingerprint,
            Self::SecurityHeaders(_) => StageKindName::SecurityHeaders,
            Self::IpReputation(_) => StageKindName::IpReputation,
            Self::CanaryToken(_) => StageKindName::CanaryToken,
            Self::Terminate(_) => StageKindName::Terminate,
            Self::GraphQl(_) => StageKindName::GraphQl,
            Self::RequestTransform(_) => StageKindName::RequestTransform,
            Self::ResponseTransform(_) => StageKindName::ResponseTransform,
            Self::Mcp => StageKindName::Mcp,
        }
    }

    /// The classification rule set this stage reads, when it reads one.
    #[must_use]
    pub fn rule_set(&self) -> Option<&ClassificationRuleSetId> {
        match self {
            Self::DataClassify(config) => Some(&config.rule_set_id),
            Self::Redact(config) => Some(&config.rule_set_id),
            Self::Waf(_)
            | Self::GeoFence(_)
            | Self::DevicePosture(_)
            | Self::Identity
            | Self::Policy
            | Self::TokenExchange(_)
            | Self::RateLimit(_)
            | Self::TokenRateLimit(_)
            | Self::StepUp(_)
            | Self::RequestSign(_)
            | Self::ResponseSign(_)
            | Self::Cache(_)
            | Self::Custom(_)
            | Self::Cors(_)
            | Self::HoneypotRoutes(_)
            | Self::ReconDetection(_)
            | Self::Fingerprint(_)
            | Self::SecurityHeaders(_)
            | Self::IpReputation(_)
            | Self::CanaryToken(_)
            | Self::Terminate(_)
            | Self::GraphQl(_)
            | Self::RequestTransform(_)
            | Self::ResponseTransform(_)
            | Self::Mcp => None,
        }
    }

    /// Refuses this stage when it reads classification rules other than
    /// `own`, the tenant's, or when the tenant has classified nothing. A
    /// stage reading another tenant's rules would classify or redact
    /// nothing, since the gateway withholds them, so it is refused when
    /// saved rather than left to look as though it protects the data.
    ///
    /// # Errors
    ///
    /// [`DomainError::Validation`] when the stage reads rules that are not
    /// `own`, or reads rules and the tenant has none.
    pub fn ensure_reads_own_rules(&self, own: TenantRules<'_>) -> Result<(), DomainError> {
        let Some(read) = self.rule_set() else {
            return Ok(());
        };
        match own {
            TenantRules::Classified(own) if own == read => Ok(()),
            TenantRules::Classified(_) => Err(DomainError::invalid(message!(
                "proxy-stage-reads-another-tenants-rules",
                "the stage reads classification rules that are not this tenant's"
            ))),
            TenantRules::Unclassified => Err(DomainError::invalid(message!(
                "proxy-stage-reads-no-rules",
                "the tenant has classified no fields, so the stage has no rules to read"
            ))),
        }
    }

    /// This stage reading `rule_set` in place of the one it reads now, as a
    /// stage copied into another tenant reads that tenant's rule set. A
    /// stage that reads none is returned as it is.
    #[must_use]
    pub fn reading(&self, rule_set: ClassificationRuleSetId) -> Self {
        let mut read = self.clone();
        if let Some(slot) = read.rule_set_slot() {
            *slot = rule_set;
        }
        read
    }

    /// Where this stage keeps the rule set it reads, when it reads one.
    fn rule_set_slot(&mut self) -> Option<&mut ClassificationRuleSetId> {
        match self {
            Self::DataClassify(config) => Some(&mut config.rule_set_id),
            Self::Redact(config) => Some(&mut config.rule_set_id),
            Self::Waf(_)
            | Self::GeoFence(_)
            | Self::DevicePosture(_)
            | Self::Identity
            | Self::Policy
            | Self::TokenExchange(_)
            | Self::RateLimit(_)
            | Self::TokenRateLimit(_)
            | Self::StepUp(_)
            | Self::RequestSign(_)
            | Self::ResponseSign(_)
            | Self::Cache(_)
            | Self::Custom(_)
            | Self::Cors(_)
            | Self::HoneypotRoutes(_)
            | Self::ReconDetection(_)
            | Self::Fingerprint(_)
            | Self::SecurityHeaders(_)
            | Self::IpReputation(_)
            | Self::CanaryToken(_)
            | Self::Terminate(_)
            | Self::GraphQl(_)
            | Self::RequestTransform(_)
            | Self::ResponseTransform(_)
            | Self::Mcp => None,
        }
    }

    /// Which chains this stage runs in.
    ///
    /// This is the one place that answers it. The match names every kind, so
    /// a new kind does not compile until it is placed here. The data plane
    /// decides what it runs from this, not from a list of its own.
    ///
    /// Three stages run both ways. The cache looks up on the way out and
    /// stores on the way back. The canary token checks the request for a
    /// planted credential, then the response for one leaking back. The token
    /// rate limit checks what has been spent, then charges what the request
    /// cost.
    #[must_use]
    pub fn phase(&self) -> StagePhase {
        match self {
            Self::Redact(_) | Self::ResponseSign(_) | Self::ResponseTransform(_) => {
                StagePhase::Response
            }

            Self::Cache(_) | Self::CanaryToken(_) | Self::TokenRateLimit(_) => StagePhase::Both,

            Self::Waf(_)
            | Self::GeoFence(_)
            | Self::DevicePosture(_)
            | Self::Identity
            | Self::DataClassify(_)
            | Self::Policy
            | Self::TokenExchange(_)
            | Self::RateLimit(_)
            | Self::StepUp(_)
            | Self::RequestSign(_)
            | Self::Custom(_)
            | Self::Cors(_)
            | Self::HoneypotRoutes(_)
            | Self::ReconDetection(_)
            | Self::Fingerprint(_)
            | Self::SecurityHeaders(_)
            | Self::IpReputation(_)
            | Self::Terminate(_)
            | Self::GraphQl(_)
            | Self::RequestTransform(_)
            | Self::Mcp => StagePhase::Request,
        }
    }

    /// Whether this stage keeps one cached response for every caller.
    ///
    /// Such a stage hands Ann's answer to Sam. So it may only run on routes
    /// nobody signs in to.
    #[must_use]
    pub fn shares_cached_responses(&self) -> bool {
        matches!(self, Self::Cache(cache) if cache.vary_by_user == CacheScope::Shared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::domains::proxy::stages::stage::RateLimitKey;
    use crate::domains::proxy::stages::token_budget::{
        LlmDialect, TokenRateLimitConfig, TokenRateLimitParams, UnknownUsage,
    };

    /// A request-phase stage runs only before forwarding, a response-phase
    /// stage only after, and a both-phase stage in each chain.
    #[test]
    fn each_phase_names_the_chains_it_runs_in() {
        assert!(StagePhase::Request.runs_on_request());
        assert!(!StagePhase::Request.runs_on_response());

        assert!(!StagePhase::Response.runs_on_request());
        assert!(StagePhase::Response.runs_on_response());

        assert!(StagePhase::Both.runs_on_request());
        assert!(StagePhase::Both.runs_on_response());
    }

    /// A Redact stage over `rule_set`, hiding confidential fields.
    fn redacting(rule_set: ClassificationRuleSetId) -> StageKind {
        StageKind::Redact(RedactConfig {
            rule_set_id: rule_set,
            min_class: DataClassLevel::Confidential,
        })
    }

    /// Ann's Redact stage reads her tenant's own rules and is taken; a
    /// stage that reads no rules is taken whatever the tenant has.
    #[test]
    fn a_stage_reading_its_tenants_own_rules_is_taken() {
        let own = ClassificationRuleSetId::new();

        assert!(
            redacting(own)
                .ensure_reads_own_rules(TenantRules::Classified(&own))
                .is_ok()
        );
        assert!(
            StageKind::Identity
                .ensure_reads_own_rules(TenantRules::Unclassified)
                .is_ok()
        );
    }

    /// A Redact stage fails validation when it names another tenant's rules
    /// or the tenant has no classification rules.
    #[test]
    fn a_stage_reading_another_tenants_rules_or_none_is_refused() {
        let own = ClassificationRuleSetId::new();
        let bobs = ClassificationRuleSetId::new();

        let anothers = redacting(bobs).ensure_reads_own_rules(TenantRules::Classified(&own));
        let unclassified = redacting(own).ensure_reads_own_rules(TenantRules::Unclassified);

        assert!(matches!(anothers, Err(DomainError::Validation(_))));
        assert!(matches!(unclassified, Err(DomainError::Validation(_))));
    }

    /// A Redact stage read into another tenant reads that tenant's rule set
    /// and keeps the class it redacts from; a stage reading no rule set is
    /// left as it is.
    #[test]
    fn a_stage_reads_the_rule_set_it_is_given() {
        let theirs = ClassificationRuleSetId::new();
        let redact = StageKind::Redact(RedactConfig {
            rule_set_id: ClassificationRuleSetId::new(),
            min_class: crate::domains::data_classification::level::DataClassLevel::Confidential,
        });

        let read = redact.reading(theirs);

        assert_eq!(read.rule_set(), Some(&theirs));
        assert!(matches!(
            read,
            StageKind::Redact(RedactConfig {
                min_class: crate::domains::data_classification::level::DataClassLevel::Confidential,
                ..
            })
        ));
        assert_eq!(StageKind::Identity.reading(theirs), StageKind::Identity);
    }

    /// Every stage that acts on the upstream's answer has a place in the
    /// response order, and a request-only stage has none. A response stage
    /// without a place would never run while it looks configured.
    #[test]
    fn every_response_stage_has_a_place_in_the_response_order() {
        let requests = [
            StageKind::Identity,
            StageKind::Policy,
            StageKind::Mcp,
            StageKind::GraphQl(GraphQlLimits::default()),
            StageKind::RequestTransform(RequestMutation::default()),
        ];
        for kind in response_stages().into_iter().chain(requests) {
            assert_eq!(
                kind.phase().runs_on_response(),
                kind.kind_name().response_slot().is_some(),
                "{}",
                kind.name()
            );
        }
    }

    /// The six response-participating stage kinds with valid, minimal settings.
    fn response_stages() -> [StageKind; 6] {
        let seconds = crate::types::Seconds::new(60);
        [
            redacting(ClassificationRuleSetId::new()),
            StageKind::ResponseTransform(ResponseMutation::default()),
            StageKind::ResponseSign(ResponseSignConfig {
                header_name: crate::types::HeaderName::new("x-signature").unwrap(),
                ttl_seconds: seconds,
            }),
            StageKind::Cache(CacheConfig {
                ttl_seconds: seconds,
                vary_by_user: CacheScope::PerUser,
            }),
            StageKind::CanaryToken(CanaryTokenConfig { tokens: Vec::new() }),
            StageKind::TokenRateLimit(
                TokenRateLimitConfig::new(TokenRateLimitParams {
                    max_tokens: 1000,
                    window_seconds: seconds,
                    key_by: RateLimitKey::UserId,
                    dialect: LlmDialect::OpenAi,
                    on_unknown: UnknownUsage::default(),
                })
                .unwrap(),
            ),
        ]
    }
}
