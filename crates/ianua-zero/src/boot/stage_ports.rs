//! The response stages' ports the composition root fills itself, each a
//! thin adapter over an app use case, or a stand-in for what is not built.
//!
//! - [`InboxCanaryAlarm`] records a canary token presented or leaking
//!   through the gateway's inbox, by the app's use cases.
//! - [`FleetTokenLedger`] settles what an exchange with a language model
//!   cost, or gives back what a refused request set aside, on the counter
//!   every gateway shares.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::auditor::RequestAuditor;
use ianua_app::ports::runtime::FleetCounters;
use ianua_app::ports::shared::EventDispatcher;
use ianua_app::tenancy::ScopedTenant;
use ianua_app::use_case::Command as _;
use ianua_app::use_cases::proxy::threats::{
    RecordCanaryLeakRequest, RecordCanaryLeakUseCase, RecordCanaryTriggeredRequest,
    RecordCanaryTriggeredUseCase,
};
use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::stages::token_budget::TokenCharge;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CorrelationId, IpAddress, TenantId};

use crate::pipeline::stages::counters::token_counter_key;
use crate::pipeline::stages::response::{CanaryAlarm, TokenLedger, TokenLimit};

/// Canary tokens recorded through the gateway's inbox.
pub(crate) struct InboxCanaryAlarm {
    events: Arc<dyn EventDispatcher>,
}

impl InboxCanaryAlarm {
    /// An alarm recording through `events`, the gateway's inbox.
    #[must_use]
    pub(crate) fn new(events: Arc<dyn EventDispatcher>) -> Self {
        Self { events }
    }
}

#[async_trait]
impl CanaryAlarm for InboxCanaryAlarm {
    async fn record_leak(
        &self,
        tenant_id: TenantId,
        correlation_id: CorrelationId,
    ) -> Result<(), DomainError> {
        let tenant = ScopedTenant::from_request_host(tenant_id);
        let auditor = RequestAuditor::system(Arc::clone(&self.events)).with_tenant(tenant_id);
        RecordCanaryLeakUseCase
            .execute(
                &tenant,
                &auditor,
                RecordCanaryLeakRequest { correlation_id },
            )
            .await
            .map_err(DomainError::infra)
    }

    async fn record_presentation(
        &self,
        tenant_id: TenantId,
        ip_address: IpAddress,
        correlation_id: CorrelationId,
    ) -> Result<(), DomainError> {
        let tenant = ScopedTenant::from_request_host(tenant_id);
        let auditor = RequestAuditor::system(Arc::clone(&self.events)).with_tenant(tenant_id);
        let presented = RecordCanaryTriggeredRequest {
            ip_address,
            correlation_id,
        };
        RecordCanaryTriggeredUseCase
            .execute(&tenant, &auditor, presented)
            .await
            .map_err(DomainError::infra)
    }
}

/// The token ledger on the counters every gateway shares: a charge lands
/// on the counter its reservation was taken from, in the window it was
/// taken in.
pub(crate) struct FleetTokenLedger {
    fleet: Arc<dyn FleetCounters>,
}

impl FleetTokenLedger {
    /// A ledger on `fleet`.
    #[must_use]
    pub(crate) fn new(fleet: Arc<dyn FleetCounters>) -> Self {
        Self { fleet }
    }
}

#[async_trait]
impl TokenLedger for FleetTokenLedger {
    async fn settle(
        &self,
        ctx: &PipelineContext,
        limit: TokenLimit<'_>,
        charge: TokenCharge,
    ) -> Result<(), DomainError> {
        let Some(key) = token_counter_key(ctx, limit.stage, limit.config, charge.window()) else {
            return Err(DomainError::infra_msg(
                "the request names nothing its token limit is kept by",
            ));
        };
        self.fleet
            .adjust(&key, charge.adjustment(), limit.config.window_seconds())
            .await
            .map(|_| ())
            .ok_or_else(|| DomainError::infra_msg("the shared token counter did not answer"))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::proxy::stages::stage::RateLimitKey;
    use ianua_domain::domains::proxy::stages::token_budget::{
        LlmDialect, TokenRateLimitConfig, TokenRateLimitParams, UnknownUsage,
    };
    use ianua_domain::shared::clock;
    use ianua_domain::types::{PipelineId, Seconds, StageId};
    use ianua_infra::cache::{CacheFleetCounters, MemoryState};

    use super::*;

    fn config() -> TokenRateLimitConfig {
        TokenRateLimitConfig::new(TokenRateLimitParams {
            max_tokens: 10_000,
            window_seconds: Seconds::new(3600),
            key_by: RateLimitKey::Tenant,
            dialect: LlmDialect::OpenAi,
            on_unknown: UnknownUsage::default(),
        })
        .unwrap()
    }

    /// Releasing a reservation returns its shared token counter to zero.
    #[tokio::test]
    async fn a_reservation_given_back_lands_on_its_counter() {
        let fleet: Arc<dyn FleetCounters> =
            Arc::new(CacheFleetCounters::new(Arc::new(MemoryState::new(100))));
        let ledger = FleetTokenLedger::new(Arc::clone(&fleet));
        let ctx = PipelineContext::new(TenantId::new(), PipelineId::new(), CorrelationId::new());
        let (stage, config) = (StageId::new(), config());
        let now = clock::now();
        let key = token_counter_key(&ctx, &stage, &config, config.window_at(now)).unwrap();
        let reservation = config.admit(0, now).unwrap();
        fleet
            .add(&key, reservation.tokens(), config.window_seconds())
            .await
            .unwrap();

        ledger
            .settle(
                &ctx,
                TokenLimit {
                    stage: &stage,
                    config: &config,
                },
                config.release(reservation, now),
            )
            .await
            .unwrap();

        assert_eq!(fleet.read(&key).await, Some(0));
    }
}
