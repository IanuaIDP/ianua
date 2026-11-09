//! The kind of a pipeline stage on its own, without its settings: what a
//! request record names as the stage that refused, and what a search of
//! the records filters by.

use crate::domains::proxy::request::body::BodyReader;

/// The kind of a pipeline stage, without the settings it runs with.
///
/// A record keeps the kind alone, never the settings, which may hold decoys
/// and secret references. Typed rather than written as text, so a search for
/// refusals by the geofence stage cannot ask for a kind that does not exist,
/// and a stored name that reads back as none of these is a broken row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StageKindName {
    /// A web application firewall.
    Waf,
    /// A country fence.
    GeoFence,
    /// A check of the device's reported posture.
    DevicePosture,
    /// The caller's session or token check.
    Identity,
    /// Data classification.
    DataClassify,
    /// The route's authorization policy.
    Policy,
    /// A token minted for the upstream.
    TokenExchange,
    /// A request rate limit.
    RateLimit,
    /// A language model spend limit.
    TokenRateLimit,
    /// A step-up to a higher assurance level.
    StepUp,
    /// Signing the request for the upstream.
    RequestSign,
    /// Redacting classified fields.
    Redact,
    /// Signing the response.
    ResponseSign,
    /// A response cache.
    Cache,
    /// A tenant's own WASM stage.
    Custom,
    /// Cross-origin rules.
    Cors,
    /// Decoy routes.
    HoneypotRoutes,
    /// Reconnaissance detection.
    ReconDetection,
    /// Client fingerprinting.
    Fingerprint,
    /// Security headers on the response.
    SecurityHeaders,
    /// Checks the client's network address against known risk information.
    IpReputation,
    /// Planted canary credentials.
    CanaryToken,
    /// Ending the request with an answer of the gateway's own.
    Terminate,
    /// GraphQL limits.
    GraphQl,
    /// Rewriting the request.
    RequestTransform,
    /// Rewriting the response.
    ResponseTransform,
    /// Model Context Protocol traffic.
    Mcp,
}

impl StageKindName {
    /// Every kind, in the order a pipeline editor lists them.
    pub const ALL: [Self; 27] = [
        Self::Waf,
        Self::GeoFence,
        Self::DevicePosture,
        Self::Identity,
        Self::DataClassify,
        Self::Policy,
        Self::TokenExchange,
        Self::RateLimit,
        Self::TokenRateLimit,
        Self::StepUp,
        Self::RequestSign,
        Self::Redact,
        Self::ResponseSign,
        Self::Cache,
        Self::Custom,
        Self::Cors,
        Self::HoneypotRoutes,
        Self::ReconDetection,
        Self::Fingerprint,
        Self::SecurityHeaders,
        Self::IpReputation,
        Self::CanaryToken,
        Self::Terminate,
        Self::GraphQl,
        Self::RequestTransform,
        Self::ResponseTransform,
        Self::Mcp,
    ];

    /// The stable name a record keeps, such as `geo_fence`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Waf => "waf",
            Self::GeoFence => "geo_fence",
            Self::DevicePosture => "device_posture",
            Self::Identity => "identity",
            Self::DataClassify => "data_classify",
            Self::Policy => "policy",
            Self::TokenExchange => "token_exchange",
            Self::RateLimit => "rate_limit",
            Self::TokenRateLimit => "token_rate_limit",
            Self::StepUp => "step_up",
            Self::RequestSign => "request_sign",
            Self::Redact => "redact",
            Self::ResponseSign => "response_sign",
            Self::Cache => "cache",
            Self::Custom => "custom",
            Self::Cors => "cors",
            Self::HoneypotRoutes => "honeypot_routes",
            Self::ReconDetection => "recon_detection",
            Self::Fingerprint => "fingerprint",
            Self::SecurityHeaders => "security_headers",
            Self::IpReputation => "ip_reputation",
            Self::CanaryToken => "canary_token",
            Self::Terminate => "terminate",
            Self::GraphQl => "graphql",
            Self::RequestTransform => "request_transform",
            Self::ResponseTransform => "response_transform",
            Self::Mcp => "mcp",
        }
    }

    /// The kind whose stable name is `name`, or `None` when no kind has it.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == name)
    }

    /// What this kind reads of a request body before the proxy decides, or
    /// `None` when it decides on the request line and headers alone.
    ///
    /// One arm per kind, so a new kind does not compile until somebody says
    /// whether it reads the body.
    #[must_use]
    pub fn body_reader(self) -> Option<BodyReader> {
        match self {
            Self::Waf => Some(BodyReader::Waf),
            Self::RequestSign => Some(BodyReader::RequestSign),
            Self::Mcp => Some(BodyReader::Mcp),
            Self::GraphQl => Some(BodyReader::GraphQl),
            Self::GeoFence
            | Self::DevicePosture
            | Self::Identity
            | Self::DataClassify
            | Self::Policy
            | Self::TokenExchange
            | Self::RateLimit
            | Self::TokenRateLimit
            | Self::StepUp
            | Self::Redact
            | Self::ResponseSign
            | Self::Cache
            | Self::Custom
            | Self::Cors
            | Self::HoneypotRoutes
            | Self::ReconDetection
            | Self::Fingerprint
            | Self::SecurityHeaders
            | Self::IpReputation
            | Self::CanaryToken
            | Self::Terminate
            | Self::RequestTransform
            | Self::ResponseTransform => None,
        }
    }

    /// Where this kind acts on the upstream's answer, or `None` when it acts
    /// on the request alone.
    ///
    /// One arm per kind, so a new kind does not compile until it is placed.
    /// A response stage left out of the order would run nowhere while it
    /// looks configured.
    #[must_use]
    pub fn response_slot(self) -> Option<ResponseSlot> {
        match self {
            Self::Redact => Some(ResponseSlot::Redact),
            Self::TokenRateLimit => Some(ResponseSlot::ChargeTokens),
            Self::ResponseTransform => Some(ResponseSlot::Transform),
            Self::CanaryToken => Some(ResponseSlot::CanaryScan),
            Self::ResponseSign => Some(ResponseSlot::Sign),
            Self::Cache => Some(ResponseSlot::CacheStore),
            Self::Waf
            | Self::GeoFence
            | Self::DevicePosture
            | Self::Identity
            | Self::DataClassify
            | Self::Policy
            | Self::TokenExchange
            | Self::RateLimit
            | Self::StepUp
            | Self::RequestSign
            | Self::Custom
            | Self::Cors
            | Self::HoneypotRoutes
            | Self::ReconDetection
            | Self::Fingerprint
            | Self::SecurityHeaders
            | Self::IpReputation
            | Self::Terminate
            | Self::GraphQl
            | Self::RequestTransform
            | Self::Mcp => None,
        }
    }
}

/// Where a stage acts on the upstream's answer, earliest first.
///
/// The order is fixed by what each one must see, not by where the tenant
/// placed the stage. Classified fields are removed first, so nothing after
/// sees them. The spend is charged next, before a tenant's own transform
/// could strip the usage it is read from. The transform comes before the
/// canary scan, so a transform cannot hide a leaked credential from it. The
/// signature covers the bytes the client receives, and the cache keeps them
/// last, so a hit needs nothing redone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResponseSlot {
    /// Redacting classified fields.
    Redact,
    /// Charging what a language model call cost.
    ChargeTokens,
    /// The tenant's rewrite of the response.
    Transform,
    /// Scanning for a planted canary credential leaking back.
    CanaryScan,
    /// Signing the response.
    Sign,
    /// Storing the response in the cache.
    CacheStore,
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    /// Every kind reads back from its own name, and no two share one, so a
    /// stored name always means the same kind.
    #[test]
    fn every_kind_reads_back_from_its_own_name() {
        let names: HashSet<&str> = StageKindName::ALL.iter().map(|k| k.as_str()).collect();

        assert_eq!(names.len(), StageKindName::ALL.len());
        for kind in StageKindName::ALL {
            assert_eq!(StageKindName::parse(kind.as_str()), Some(kind));
        }
    }

    /// The unrecognized stage name `firewall` parses as no stage kind.
    #[test]
    fn a_name_no_kind_has_reads_as_none() {
        assert_eq!(StageKindName::parse("firewall"), None);
    }

    /// Only the WAF, request signing, MCP and GraphQL stages read a request
    /// body. Every other kind leaves it to stream.
    #[test]
    fn four_kinds_read_the_request_body() {
        let readers: Vec<StageKindName> = StageKindName::ALL
            .into_iter()
            .filter(|kind| kind.body_reader().is_some())
            .collect();

        assert_eq!(
            readers,
            [
                StageKindName::Waf,
                StageKindName::RequestSign,
                StageKindName::GraphQl,
                StageKindName::Mcp,
            ]
        );
    }

    /// The response stages run redact, charge, transform, canary scan, sign,
    /// then cache store. No request-only kind has a place among them.
    #[test]
    fn response_stages_run_in_a_fixed_order() {
        let mut placed: Vec<(ResponseSlot, StageKindName)> = StageKindName::ALL
            .into_iter()
            .filter_map(|kind| kind.response_slot().map(|slot| (slot, kind)))
            .collect();
        placed.sort_by_key(|(slot, _)| *slot);

        let order: Vec<StageKindName> = placed.into_iter().map(|(_, kind)| kind).collect();

        assert_eq!(
            order,
            [
                StageKindName::Redact,
                StageKindName::TokenRateLimit,
                StageKindName::ResponseTransform,
                StageKindName::CanaryToken,
                StageKindName::ResponseSign,
                StageKindName::Cache,
            ]
        );
    }
}
