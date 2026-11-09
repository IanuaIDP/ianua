//! The `TokenExchange` stage: a narrowed token minted for the upstream, in
//! place of trusting it with the caller's own.
//!
//! What the token may say is the domain's, from the request's proven,
//! authorized caller; `ExchangeTokenUseCase` mints it with the tenant's
//! assertion key, the key the gateway owns. The stage only asks and hands
//! the token on as the request's `Authorization`, the caller's own already
//! stripped. Deny by default: an anonymous request is a 401, one the
//! policy did not let through or whose token the use case refuses a 403,
//! and a token that cannot be minted a 503, never a forward without it.
//! The token is never logged.

use ianua_app::error::AppError;
use ianua_app::tenancy::ScopedTenant;
use ianua_app::use_case::Query as _;
use ianua_app::use_cases::proxy::TokenExchangeRequest;
use ianua_domain::domains::proxy::exchange::{ExchangeGrounds, ExchangeRefused};
use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::request::transform::RequestMutation;
use ianua_domain::domains::proxy::stages::decision::{HeaderEntry, StageDecision};
use ianua_domain::domains::proxy::stages::stage::TokenExchangeConfig;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{DenialStatus, HeaderName, HeaderValue};

use super::{IdentityStages, deny};

impl IdentityStages {
    /// The `TokenExchange` stage: the narrowed token `config` describes,
    /// minted for the request's caller and set as its `Authorization`.
    ///
    /// # Errors
    ///
    /// None: every failure is a refusal.
    pub(crate) async fn token_exchange(
        &self,
        tenant: &ScopedTenant,
        config: &TokenExchangeConfig,
        ctx: &PipelineContext,
    ) -> Result<StageDecision, DomainError> {
        let grounds = match ExchangeGrounds::of_request(ctx) {
            Ok(grounds) => grounds,
            Err(ExchangeRefused::Anonymous) => {
                return Ok(deny(DenialStatus::UNAUTHORIZED, "token_exchange_anonymous"));
            }
            Err(_) => return Ok(deny(DenialStatus::FORBIDDEN, "token_exchange_refused")),
        };
        let asked = TokenExchangeRequest {
            grounds,
            config: config.clone(),
        };
        match self.exchange.execute(tenant, asked).await {
            Ok(exchanged) => Ok(bearing(&exchanged.token)),
            Err(AppError::Forbidden(_)) => {
                Ok(deny(DenialStatus::FORBIDDEN, "token_exchange_forbidden"))
            }
            Err(error) => {
                tracing::warn!(%error, "an exchanged token could not be minted; refusing");
                Ok(deny(
                    DenialStatus::SERVICE_UNAVAILABLE,
                    "token_exchange_unavailable",
                ))
            }
        }
    }
}

/// The change setting `token` as the forwarded request's bearer, or a 503
/// when it cannot be written in a header.
fn bearing(token: &Secret) -> StageDecision {
    let header = HeaderName::new("authorization").and_then(|name| {
        Ok((
            name,
            HeaderValue::new(format!("Bearer {}", token.expose()))?,
        ))
    });
    let Ok((name, value)) = header else {
        return deny(
            DenialStatus::SERVICE_UNAVAILABLE,
            "token_exchange_unwritable",
        );
    };
    StageDecision::Transform {
        mutation: RequestMutation::asserting(vec![HeaderEntry::new(name, value)]),
        reason: "token_exchanged".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{Audience, CorrelationId, PipelineId, Scope, Seconds, TenantId};

    use super::*;
    use crate::pipeline::stages::identity::fixtures;

    fn stages() -> IdentityStages {
        IdentityStages::new(fixtures::parts())
    }

    fn billing() -> TokenExchangeConfig {
        TokenExchangeConfig {
            target_audience: Audience::new("billing-service").unwrap(),
            scopes: vec![Scope::new("invoices:read").unwrap()],
            ttl_seconds: Seconds::new(60),
        }
    }

    /// Token exchange for an anonymous request returns a 401 denial.
    #[tokio::test]
    async fn an_anonymous_request_gets_no_exchanged_token() {
        let tenant = TenantId::new();
        let ctx = PipelineContext::new(tenant, PipelineId::new(), CorrelationId::new());

        let decision = stages()
            .token_exchange(&ScopedTenant::for_background(tenant), &billing(), &ctx)
            .await
            .unwrap();

        assert!(matches!(
            decision,
            StageDecision::Deny { status, .. } if status == DenialStatus::UNAUTHORIZED
        ));
    }

    /// The token set on the forwarded request is the one minted, as a
    /// bearer.
    #[test]
    fn the_minted_token_is_the_forwarded_bearer() {
        let decision = bearing(&Secret::new("minted.token.value"));

        let StageDecision::Transform { mutation, .. } = decision else {
            panic!("expected a transform");
        };
        let set = mutation.headers_to_set();
        assert_eq!(set[0].name().as_str(), "authorization");
        assert_eq!(set[0].value().as_str(), "Bearer minted.token.value");
    }
}
