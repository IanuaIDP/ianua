//! Running a pipeline's stages on requests and responses.

use async_trait::async_trait;
use ianua_domain::domains::proxy::request::body::CapturedBody;
use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::request::transform::ResponseMutation;
use ianua_domain::domains::proxy::stages::decision::{HeaderEntry, StageDecision};
use ianua_domain::domains::proxy::stages::stage::StageConfig;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::DenialStatus;

/// Dyn-safe port for executing a single pipeline stage.
///
/// The `ianua-zero` adapter implements this, dispatching on `StageKind`.
/// The use case calls it for each active stage in order.
#[async_trait]
pub trait StageExecutor: Send + Sync {
    /// Evaluates a stage against the current pipeline context.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the stage cannot be evaluated.
    async fn execute(
        &self,
        stage: &StageConfig,
        ctx: &mut PipelineContext,
    ) -> Result<StageDecision, DomainError>;
}

/// Transport-agnostic view of the upstream response's status and headers,
/// handed to a post-response stage. Deliberately carries no body: the
/// bounded body prefix a stage may act on is a separate argument to
/// [`ResponseStageExecutor::execute_response`], keeping this port free of
/// any streaming or body-type concern. [`StageExecutor`] keeps the same
/// discipline: a transport type like `hyper::HeaderMap` lives only in the
/// `ianua-zero` adapter and never crosses this boundary.
#[derive(Debug, Clone)]
pub struct ResponseMeta {
    /// The upstream's HTTP status code.
    pub status: u16,
    /// The response headers.
    pub headers: Vec<HeaderEntry>,
}

/// What a post-response stage decided to do with the response it saw.
#[derive(Debug, Clone)]
pub enum ResponseStageOutcome {
    /// No change. `reason` mirrors `StageDecision::Pass` for audit parity.
    Pass {
        /// Why nothing changed.
        reason: String,
    },
    /// Change the response before it reaches the client.
    ///
    /// Headers and body in one variant because a stage may legitimately do
    /// both: a transform that strips a debugging header and the field behind
    /// it is one rule set, and splitting it across two outcomes would make
    /// the executor run it twice to get both halves.
    ///
    /// A replacement body is only ever legal when the stage was handed the
    /// *complete* one (`execute_response`'s body is `BodyExtent::Whole`).
    /// Rewriting over a prefix truncated by the peek cap would silently
    /// corrupt the response.
    Change {
        /// What this stage changes about the response headers.
        headers: ResponseMutation,
        /// The replacement body, when the stage rewrote one.
        body: Option<Vec<u8>>,
        /// Why the response was changed.
        reason: String,
    },
    /// Withhold the response entirely. Mirrors `StageDecision::Deny`.
    Block {
        /// HTTP status to return to the client instead, always an error
        /// status so a withheld response never reads as success.
        status: DenialStatus,
        /// Why the response was withheld.
        reason: String,
    },
}

/// Dyn-safe port for executing a single stage against the upstream
/// response, after the pre-request pipeline already ran and the upstream
/// has replied.
///
/// Mirrors [`StageExecutor`] in shape and intent, for the stage kinds
/// that need to see the *response* rather than (or in addition to) the
/// request: `CanaryToken`, `Redact`, `ResponseSign`, `ResponseTransform`,
/// `TokenRateLimit`, and `Cache`'s store step.
#[async_trait]
pub trait ResponseStageExecutor: Send + Sync {
    /// Evaluates one stage against a bounded prefix of the response body.
    ///
    /// `body` holds exactly what was physically read off the response
    /// stream, up to the caller's configured cap, and whether that is the
    /// entire body (the stream ended before the cap was reached). See
    /// [`ResponseStageOutcome::Change`].
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the stage cannot be evaluated.
    async fn execute_response(
        &self,
        stage: &StageConfig,
        ctx: &PipelineContext,
        response: &ResponseMeta,
        body: CapturedBody<'_>,
    ) -> Result<ResponseStageOutcome, DomainError>;
}
