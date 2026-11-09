//! How large a request body a pipeline takes, and how much of it the proxy
//! reads before deciding.
//!
//! Most stages decide on the request line and headers, and the body streams
//! to the upstream unread. A few must see it. They share one read of the
//! same prefix, sized to the largest of their caps, so the body is never
//! read twice and never read at all when nothing asks for it.

use crate::domains::proxy::pipeline::Pipeline;
use crate::domains::proxy::request::body::{BodyNeed, BodyReadSettings, BodyReader, ByteCap};
use crate::domains::proxy::stages::stage::StageKind;
use crate::domains::routing::matching::parameter::ParameterRule;
use crate::isolation::scope::TenantScope;

impl<T: TenantScope> Pipeline<T> {
    /// The largest request body this pipeline takes.
    ///
    /// An enabled WAF stage sets it, whatever else it does. Without one,
    /// `default` applies. Two WAF stages answer with the smaller limit. A
    /// stage is checked when it is made, so its limit always reads; if it
    /// did not, it would count as the smallest limit, not as none.
    #[must_use]
    pub fn body_limit(&self, default: ByteCap) -> ByteCap {
        self.active_stages()
            .into_iter()
            .filter_map(|stage| {
                let StageKind::Waf(config) = stage.kind() else {
                    return None;
                };
                Some(ByteCap::new(config.max_body_bytes).unwrap_or(ByteCap::SMALLEST))
            })
            .min()
            .unwrap_or(default)
    }

    /// How much of a request body to read before deciding, on a route with
    /// `parameter_rules`.
    ///
    /// Nothing, when no enabled stage reads the body and the route has no
    /// parameter rules. Otherwise the largest cap among the readers, held to
    /// [`body_limit`](Self::body_limit), so the read never runs past the
    /// largest body the pipeline takes.
    #[must_use]
    pub fn body_need(
        &self,
        parameter_rules: &[ParameterRule],
        settings: &BodyReadSettings,
    ) -> BodyNeed {
        let parameters = (!parameter_rules.is_empty()).then_some(BodyReader::ParameterRules);
        let Some(widest) = self
            .active_stages()
            .into_iter()
            .filter_map(|stage| stage.kind().kind_name().body_reader())
            .chain(parameters)
            .map(|reader| settings.cap_for(reader))
            .max()
        else {
            return BodyNeed::Nothing;
        };
        BodyNeed::Prefix(widest.min(self.body_limit(settings.default_limit)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::proxy::fixtures::{running, stage, switched_off};
    use crate::domains::proxy::request::graphql::GraphQlLimits;
    use crate::domains::proxy::stages::stage::{
        GeoFenceConfig, RequestSignConfig, WafConfig, WafRuleSet,
    };
    use crate::domains::routing::matching::parameter::ParameterLocation;
    use crate::isolation::scope::ResolvedTenant;
    use crate::types::{CountryCode, DomainName, HeaderName, Seconds};

    fn cap(bytes: u64) -> ByteCap {
        ByteCap::new(bytes).unwrap()
    }

    fn settings() -> BodyReadSettings {
        BodyReadSettings {
            default_limit: cap(10_000),
            waf: cap(100),
            request_sign: cap(200),
            mcp: cap(400),
            graphql: cap(300),
            parameter_rules: cap(500),
        }
    }

    fn waf(max_body_bytes: u64) -> StageKind {
        StageKind::Waf(WafConfig {
            rule_sets: vec![WafRuleSet::Sqli],
            anomaly_threshold: 5,
            max_body_bytes,
        })
    }

    fn signing() -> StageKind {
        StageKind::RequestSign(RequestSignConfig {
            header_name: HeaderName::new("x-signature").unwrap(),
            ttl_seconds: Seconds::new(60),
        })
    }

    fn geofence() -> StageKind {
        StageKind::GeoFence(GeoFenceConfig {
            allowed_countries: Vec::new(),
            blocked_countries: vec![CountryCode::new("KP").unwrap()],
        })
    }

    fn no_rules() -> Vec<ParameterRule> {
        Vec::new()
    }

    /// Without a WAF stage, a pipeline takes the default body size.
    #[test]
    fn without_a_waf_the_default_limit_applies() {
        let pipeline: Pipeline<ResolvedTenant> = running(vec![stage(geofence())]);

        assert_eq!(pipeline.body_limit(cap(10_000)), cap(10_000));
    }

    /// A WAF stage's limit replaces the default, smaller or larger.
    #[test]
    fn a_waf_sets_the_body_limit() {
        let tighter: Pipeline<ResolvedTenant> = running(vec![stage(waf(1024))]);
        let looser: Pipeline<ResolvedTenant> = running(vec![stage(waf(50_000))]);

        assert_eq!(tighter.body_limit(cap(10_000)), cap(1024));
        assert_eq!(looser.body_limit(cap(10_000)), cap(50_000));
    }

    /// Two WAF stages, 1 KiB and 1 MiB. The smaller limit holds.
    #[test]
    fn two_wafs_answer_with_the_smaller_limit() {
        let pipeline: Pipeline<ResolvedTenant> =
            running(vec![stage(waf(1_048_576)), stage(waf(1024))]);

        assert_eq!(pipeline.body_limit(cap(10_000)), cap(1024));
    }

    /// A switched-off WAF sets no limit.
    #[test]
    fn a_switched_off_waf_sets_no_limit() {
        let pipeline: Pipeline<ResolvedTenant> = running(vec![switched_off(waf(1024))]);

        assert_eq!(pipeline.body_limit(cap(10_000)), cap(10_000));
    }

    /// A pipeline of Identity, Policy and a geofence on a route without
    /// parameter rules reads no body. It streams.
    #[test]
    fn nothing_reads_the_body_unless_asked() {
        let pipeline: Pipeline<ResolvedTenant> = running(vec![stage(geofence())]);

        assert_eq!(
            pipeline.body_need(&no_rules(), &settings()),
            BodyNeed::Nothing
        );
    }

    /// A WAF and a signing stage share one read, sized to the larger cap.
    #[test]
    fn readers_share_one_read_of_the_largest_cap() {
        let pipeline: Pipeline<ResolvedTenant> =
            running(vec![stage(waf(10_000)), stage(signing())]);

        assert_eq!(
            pipeline.body_need(&no_rules(), &settings()),
            BodyNeed::Prefix(cap(200))
        );
    }

    /// MCP and GraphQL stages read their own caps.
    #[test]
    fn mcp_and_graphql_read_the_body() {
        let mcp: Pipeline<ResolvedTenant> = running(vec![stage(StageKind::Mcp)]);
        let graphql: Pipeline<ResolvedTenant> =
            running(vec![stage(StageKind::GraphQl(GraphQlLimits::default()))]);

        assert_eq!(
            mcp.body_need(&no_rules(), &settings()),
            BodyNeed::Prefix(cap(400))
        );
        assert_eq!(
            graphql.body_need(&no_rules(), &settings()),
            BodyNeed::Prefix(cap(300))
        );
    }

    /// A query-parameter rule makes the pipeline request a body prefix using
    /// the configured parameter-rule cap, even without a body-reading stage.
    #[test]
    fn parameter_rules_read_the_body() {
        let pipeline: Pipeline<ResolvedTenant> = running(Vec::new());
        let rules = vec![
            ParameterRule::new(
                "callback",
                ParameterLocation::Query,
                vec![DomainName::new("hooks.acme.com").unwrap()],
            )
            .unwrap(),
        ];

        assert_eq!(
            pipeline.body_need(&rules, &settings()),
            BodyNeed::Prefix(cap(500))
        );
    }

    /// A read never runs past the body limit: with a 150 byte WAF limit, a
    /// 200 byte signing cap reads 150 bytes.
    #[test]
    fn a_read_never_passes_the_body_limit() {
        let pipeline: Pipeline<ResolvedTenant> = running(vec![stage(waf(150)), stage(signing())]);

        assert_eq!(
            pipeline.body_need(&no_rules(), &settings()),
            BodyNeed::Prefix(cap(150))
        );
    }

    /// A switched-off reader reads nothing.
    #[test]
    fn a_switched_off_reader_reads_nothing() {
        let pipeline: Pipeline<ResolvedTenant> = running(vec![switched_off(signing())]);

        assert_eq!(
            pipeline.body_need(&no_rules(), &settings()),
            BodyNeed::Nothing
        );
    }
}
