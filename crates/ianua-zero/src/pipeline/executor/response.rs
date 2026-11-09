//! The chain on the upstream's answer: each stage kind that acts on it
//! handed to the response group, the token limit settling what its request
//! side set aside.

use ianua_app::ports::proxy::{ResponseMeta, ResponseStageOutcome};
use ianua_domain::domains::proxy::request::body::CapturedBody;
use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::stages::stage::{StageConfig, StageKind};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::DenialStatus;

use super::run::RequestRun;
use crate::pipeline::stages::response::{Exchange, ResponseRead, TokenLimit};

/// What one stage on the answer is handed.
pub(super) struct Answered<'a> {
    /// The upstream's status and headers.
    pub(super) response: &'a ResponseMeta,
    /// The bounded prefix of its body that was read, and whether it is all
    /// of it.
    pub(super) body: CapturedBody<'a>,
}

impl RequestRun {
    /// What `stage` does with the upstream's answer, from the response
    /// group.
    ///
    /// One arm per kind, with no catch-all. A kind that only decides before
    /// forwarding withholds the answer here: the response chain never holds
    /// one, and one that arrives is a fault, not a pass.
    ///
    /// # Errors
    ///
    /// The [`DomainError`] of a stage that could not run, which the run
    /// turns into a withheld answer.
    /// The exhaustive kind dispatch stays together so new stages require an explicit phase decision.
    #[allow(clippy::too_many_lines)]
    pub(super) async fn answered(
        &self,
        stage: &StageConfig,
        ctx: &PipelineContext,
        answered: Answered<'_>,
    ) -> Result<ResponseStageOutcome, DomainError> {
        let response = &self.groups().response;
        let Answered {
            response: meta,
            body,
        } = answered;
        let read = ResponseRead {
            context: ctx,
            meta,
            body,
        };
        match stage.kind() {
            StageKind::CanaryToken(config) => response.canary_leak(config, read).await,
            StageKind::Redact(config) => response.redact(config, read).await,
            StageKind::ResponseSign(config) => {
                response.response_sign(config, self.facts(), read).await
            }
            StageKind::ResponseTransform(mutation) => {
                Ok(response.response_transform(mutation, meta, body))
            }
            StageKind::TokenRateLimit(config) => {
                self.token_charge(
                    TokenLimit {
                        stage: stage.id(),
                        config,
                    },
                    read,
                )
                .await
            }
            StageKind::Cache(config) => {
                let exchange = Exchange::from(self.facts());
                response.cache_store(config, exchange, read).await
            }
            StageKind::Waf(_)
            | StageKind::GeoFence(_)
            | StageKind::DevicePosture(_)
            | StageKind::Identity
            | StageKind::DataClassify(_)
            | StageKind::Policy
            | StageKind::TokenExchange(_)
            | StageKind::RateLimit(_)
            | StageKind::StepUp(_)
            | StageKind::RequestSign(_)
            | StageKind::Custom(_)
            | StageKind::Cors(_)
            | StageKind::HoneypotRoutes(_)
            | StageKind::ReconDetection(_)
            | StageKind::Fingerprint(_)
            | StageKind::SecurityHeaders(_)
            | StageKind::IpReputation(_)
            | StageKind::Terminate(_)
            | StageKind::GraphQl(_)
            | StageKind::RequestTransform(_)
            | StageKind::Mcp => Ok(out_of_phase(stage, ctx)),
        }
    }

    /// The response side of a token limit: what the exchange cost settled
    /// against the tokens its request side set aside. Tokens nobody set
    /// aside mean the request side never admitted this exchange, so the
    /// answer is withheld rather than handed on uncounted.
    async fn token_charge(
        &self,
        limit: TokenLimit<'_>,
        answer: ResponseRead<'_>,
    ) -> Result<ResponseStageOutcome, DomainError> {
        let Some(reservation) = self.carried().reservation_of(limit.stage) else {
            tracing::error!(
                correlation_id = %answer.context.correlation_id,
                "an answer reached a token limit that set nothing aside for it; withholding"
            );
            return Ok(withheld(
                DenialStatus::BAD_GATEWAY,
                "token_reservation_missing",
            ));
        };
        self.groups()
            .response
            .token_charge(limit, reservation, answer)
            .await
    }
}

/// The answer withheld with `status`, recorded as `reason`.
pub(super) fn withheld(status: DenialStatus, reason: &str) -> ResponseStageOutcome {
    ResponseStageOutcome::Block {
        status,
        reason: reason.to_owned(),
    }
}

/// The answer withheld because a stage that decides before forwarding was
/// handed it.
fn out_of_phase(stage: &StageConfig, ctx: &PipelineContext) -> ResponseStageOutcome {
    tracing::error!(
        stage = stage.kind().name(),
        correlation_id = %ctx.correlation_id,
        "a stage deciding before forwarding reached the answer's chain; withholding"
    );
    withheld(DenialStatus::SERVICE_UNAVAILABLE, "stage_out_of_phase")
}
