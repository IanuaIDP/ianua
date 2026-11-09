//! A route in attack mode, checked before its pipeline: an address any
//! tenant's decoys or recon scoring caught is refused, and each address is
//! held to the attack mode's limit, counted across the fleet. Both are the
//! IpReputation and RateLimit stages' own checks, with attack mode's
//! settings.

use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::domains::proxy::stages::stage::{
    FlaggedClients, IpReputationConfig, RateLimitConfig, RateLimitKey,
};
use ianua_domain::domains::routing::route::{ATTACK_REQUESTS_PER_WINDOW, ATTACK_WINDOW_SECONDS};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{RouteId, Seconds, StageId};

use super::CounterStages;

impl CounterStages {
    /// Checks a request to `route`, in attack mode: refused when its
    /// address was flagged anywhere, unknown, or over attack mode's limit,
    /// or when a shared counter does not answer.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when a refusal's headers cannot be written.
    pub(crate) async fn under_attack(
        &self,
        route: &RouteId,
        ctx: &mut PipelineContext,
    ) -> Result<StageDecision, DomainError> {
        let flagged = IpReputationConfig {
            denylist: Vec::new(),
            deny_platform_flagged: FlaggedClients::Deny,
        };
        let reputation = self.ip_reputation(&flagged, ctx).await?;
        if !matches!(reputation, StageDecision::Pass { .. }) {
            return Ok(reputation);
        }
        let limit = RateLimitConfig {
            max_requests: ATTACK_REQUESTS_PER_WINDOW,
            window_seconds: Seconds::new(ATTACK_WINDOW_SECONDS),
            key_by: RateLimitKey::IpAddress,
        };
        self.rate_limit(&StageId::from_uuid(*route.as_uuid()), &limit, ctx)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::super::fakes::{Rig, context, denial_status};
    use super::*;

    /// An address sends a route in attack mode as many requests as attack
    /// mode lets it, and each goes on; the next is refused as too many.
    #[tokio::test]
    async fn an_address_is_held_to_attack_modes_limit() {
        let rig = Rig::counting();
        let route = RouteId::new();
        let mut ctx = context();

        for _ in 0..ATTACK_REQUESTS_PER_WINDOW {
            let decision = rig.stages().under_attack(&route, &mut ctx).await.unwrap();
            assert!(
                matches!(decision, StageDecision::Pass { .. }),
                "{decision:?}"
            );
        }
        let over = rig.stages().under_attack(&route, &mut ctx).await.unwrap();

        assert_eq!(denial_status(&over), Some(429));
    }
}
