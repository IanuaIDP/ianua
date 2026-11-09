//! The check group: the stages that look at a request and pass, refuse or
//! answer it before it is forwarded. The web application firewall, CORS,
//! the client fingerprint, the country fence, GraphQL costing, MCP tool
//! calls, a tenant's request transform, its own WASM module and a fixed
//! answer.
//!
//! Each stage reads what the gateway already took off the request, from
//! the one [`RequestFacts`] the handler built: the admitted request line,
//! the headers left after the owned ones were stripped, the bounded body
//! prefix the pipeline asked for, and the facts of the connection. What it needs from outside the gateway it asks
//! through a port: the country through the app's `Geolocator`, a GraphQL
//! body's cost through its `GraphQlAnalyzer`, a tenant's module through the
//! [`WasmRuntime`].
//!
//! Deny by default. A lookup that fails or does not answer in time, a body
//! the stage needed and was not given, a body it cannot read, a setting
//! that leaves the stage nothing to check and a module that reaches no
//! verdict are each a refusal. A deny carries a reason for the audit
//! record; the client is told only the status.

mod cors;
mod custom;
mod geo_fence;
mod graphql;
mod mcp;
mod terminate;
mod waf;

use std::sync::Arc;
use std::time::Duration;

use ianua_app::ports::authentication::Geolocator;
use ianua_app::ports::proxy::GraphQlAnalyzer;
use ianua_domain::domains::proxy::request::context::{PipelineContext, ResponseSource};
use ianua_domain::domains::proxy::request::graphql::GraphQlLimits;
use ianua_domain::domains::proxy::request::transform::RequestMutation;
use ianua_domain::domains::proxy::stages::checks::fingerprint::ClientReading;
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::domains::proxy::stages::stage::{
    CorsConfig, FingerprintConfig, GeoFenceConfig, TerminateConfig, WafConfig, WasmStageRef,
};
use ianua_domain::types::{CountryCode, DenialStatus, Fact};

use crate::listen::Ja4;
use crate::pipeline::facts::RequestFacts;
use crate::wasm::WasmRuntime;

/// What [`CheckStages`] is built from.
pub(crate) struct CheckStagesParts {
    /// Places a client address in a country, for the `GeoFence` stage.
    pub geolocator: Arc<dyn Geolocator>,
    /// Reads a GraphQL body into its depth and cost, for the `GraphQl`
    /// stage.
    pub graphql: Arc<dyn GraphQlAnalyzer>,
    /// Runs a tenant's module, for the `Custom` stage.
    pub wasm: Arc<WasmRuntime>,
    /// The longest a country lookup may take before it counts as failed.
    pub lookup_timeout: Duration,
}

/// The check stages, holding what they need.
pub(crate) struct CheckStages {
    geolocator: Arc<dyn Geolocator>,
    graphql: Arc<dyn GraphQlAnalyzer>,
    wasm: Arc<WasmRuntime>,
    lookup_timeout: Duration,
}

impl CheckStages {
    /// The group, built from `parts`.
    #[must_use]
    pub(crate) fn new(parts: CheckStagesParts) -> Self {
        Self {
            geolocator: parts.geolocator,
            graphql: parts.graphql,
            wasm: parts.wasm,
            lookup_timeout: parts.lookup_timeout,
        }
    }

    /// The `Waf` stage: scores the path, the query, every header value and
    /// the body prefix against the configured rule sets, and refuses a
    /// request whose score reaches the threshold.
    ///
    /// A request whose body was not read for the scan is refused: the
    /// pipeline asks for the body whenever a WAF runs, so an unread body
    /// is a scan that did not happen.
    pub(crate) async fn waf(&self, config: &WafConfig, request: &RequestFacts) -> StageDecision {
        let Some(body) = request.captured_body() else {
            return deny(
                DenialStatus::FORBIDDEN,
                "waf: the body was not read for the scan",
            );
        };
        waf::verdict(
            config,
            &waf::Scanned {
                path: request.admitted.path().as_str(),
                query: request.query(),
                headers: &request.headers,
                body: body.bytes,
            },
        )
    }

    /// The `Cors` stage: refuses an origin the route does not allow,
    /// answers a preflight from the configuration without asking the
    /// upstream, and leaves the headers the response carries on the
    /// context for the response side to write.
    pub(crate) async fn cors(
        &self,
        config: &CorsConfig,
        request: &RequestFacts,
        ctx: &mut PipelineContext,
    ) -> StageDecision {
        match config.answer(&cors::read(request.admitted.method(), &request.headers)) {
            Ok(answer) => answer.applied_to(ctx),
            Err(refusal) => refusal.decision(),
        }
    }

    /// The `Fingerprint` stage: names known automation by its user agent,
    /// and a client claiming to be a browser over a TLS hello no browser
    /// sends, then applies the configured action.
    pub(crate) async fn fingerprint(
        &self,
        config: &FingerprintConfig,
        request: &RequestFacts,
    ) -> StageDecision {
        let user_agent = request
            .headers
            .get(http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok());
        let ja4 = request.connection.ja4().map(Ja4::as_str);
        config.verdict(ClientReading::of(Fact::from_option(user_agent), ja4))
    }

    /// The `GeoFence` stage: places the client in a country and holds it to
    /// the fence. The country found is kept on the context for later
    /// stages.
    ///
    /// Fails closed. Every fence names a country to allow or block, so a
    /// client whose country cannot be told, for want of an address, an
    /// address the lookup does not know, or a lookup that fails or does not
    /// answer in time, is refused, on a block list as on an allow list.
    pub(crate) async fn geo_fence(
        &self,
        config: &GeoFenceConfig,
        ctx: &mut PipelineContext,
    ) -> StageDecision {
        let country = self.country_of(ctx).await;
        if let Fact::Known(found) = &country {
            ctx.country_code = Fact::Known(found.clone());
        }
        geo_fence::verdict(config, country.as_ref())
    }

    /// The `GraphQl` stage: costs the query in the body and refuses one
    /// past the tenant's depth or cost, one it cannot read, a batch, and a
    /// body longer than the gateway reads.
    pub(crate) async fn graphql(
        &self,
        limits: &GraphQlLimits,
        request: &RequestFacts,
    ) -> StageDecision {
        graphql::verdict(limits, request.captured_body(), self.graphql.as_ref())
    }

    /// The `Mcp` stage: reads the JSON-RPC calls in the body and lets
    /// through only those the caller's delegation grants and its declared
    /// purpose allows.
    pub(crate) async fn mcp(&self, request: &RequestFacts, ctx: &PipelineContext) -> StageDecision {
        mcp::verdict(ctx.authentication(), request.captured_body())
    }

    /// The `RequestTransform` stage: the tenant's changes to the forwarded
    /// request's headers and query. The pipeline folds them into the
    /// context's request mutation, which the forwarded request is built
    /// from.
    pub(crate) async fn request_transform(&self, mutation: &RequestMutation) -> StageDecision {
        StageDecision::Transform {
            mutation: mutation.clone(),
            reason: "request_transform: applied".to_owned(),
        }
    }

    /// The `Custom` stage: runs the tenant's module on a snapshot of what
    /// the pipeline has verified so far and enforces its verdict. A module
    /// that reaches none is a refusal.
    pub(crate) async fn custom(
        &self,
        stage: &WasmStageRef,
        request: &RequestFacts,
        ctx: &PipelineContext,
    ) -> StageDecision {
        let Some(input) = custom::input(request, ctx) else {
            return deny(
                DenialStatus::FORBIDDEN,
                "custom: the module's input could not be built",
            );
        };
        let verdict = self.wasm.run(&request.tenant, stage, &input).await;
        custom::decision(verdict)
    }

    /// The `Terminate` stage: answers the request with the configured
    /// response instead of forwarding it. Later stages still run, and the
    /// response headers they leave apply to this answer too.
    pub(crate) async fn terminate(
        &self,
        config: &TerminateConfig,
        ctx: &mut PipelineContext,
    ) -> StageDecision {
        let Ok(ready) = terminate::ready(config) else {
            return deny(
                DenialStatus::FORBIDDEN,
                "terminate: the configured answer is not valid",
            );
        };
        ctx.response = ResponseSource::Ready(ready);
        pass(&format!("terminate: answered with {}", config.status()))
    }

    /// The country the client is in: one an earlier stage found, or the
    /// lookup's answer for the client's address. Unknown whenever neither
    /// can tell.
    async fn country_of(&self, ctx: &PipelineContext) -> Fact<CountryCode> {
        if let Fact::Known(found) = &ctx.country_code {
            return Fact::Known(found.clone());
        }
        let Fact::Known(address) = &ctx.ip_address else {
            return Fact::Unknown;
        };
        let lookup = tokio::time::timeout(self.lookup_timeout, self.geolocator.locate(address));
        match lookup.await {
            Ok(Ok(found)) => Fact::from_option(found.map(|place| place.country_code().clone())),
            Ok(Err(error)) => {
                tracing::warn!(error = %error, "country lookup failed; the geofence refuses");
                Fact::Unknown
            }
            Err(_) => {
                tracing::warn!("country lookup timed out; the geofence refuses");
                Fact::Unknown
            }
        }
    }
}

/// A refusal answered with `status`, recorded as `reason`.
fn deny(status: DenialStatus, reason: &str) -> StageDecision {
    StageDecision::Deny {
        status,
        reason: reason.to_owned(),
    }
}

/// A pass, recorded as `reason`.
fn pass(reason: &str) -> StageDecision {
    StageDecision::Pass {
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests;
