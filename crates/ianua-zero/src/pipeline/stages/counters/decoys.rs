//! The HoneypotRoutes stage: decoy paths no real client asks for.
//!
//! It runs before route matching, since a decoy matches no real route. A
//! client that asks for one is refused, recorded for the tenant's threat
//! dashboard, blocked from the tenant for the decoy's lifetime and flagged
//! for every tenant that refuses what another tenant's defences caught. A
//! blocked client is refused whatever it asks for next.

use std::sync::Arc;

use ianua_app::auditor::RequestAuditor;
use ianua_app::tenancy::ScopedTenant;
use ianua_app::use_case::Command;
use ianua_app::use_cases::proxy::threats::{RecordHoneypotHitRequest, RecordHoneypotHitUseCase};
use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::domains::proxy::stages::stage::DecoyLifetime;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DenialStatus, IpAddress, UntrustedText};

use super::keys::client_address;
use super::{CounterStages, refused, unknown_client};

/// What the honeypot needs to know about a request.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DecoyProbe<'a> {
    /// The path as the client sent it, for the record.
    pub path: &'a str,
    /// How long a client asking for this path is blocked, from the
    /// domain's `Pipeline::decoy_lifetime_across` over the tenant's
    /// pipelines. `None` when the path is no decoy.
    pub lifetime: Option<DecoyLifetime>,
}

impl CounterStages {
    /// Refuses a request for a decoy path, blocking and recording its
    /// client, and any request from a client already blocked.
    ///
    /// # Errors
    ///
    /// Never; the `Result` keeps the shape every stage has.
    pub(crate) async fn honeypot(
        &self,
        ctx: &PipelineContext,
        probe: DecoyProbe<'_>,
    ) -> Result<StageDecision, DomainError> {
        let (Some(address), Some(client)) = (ctx.ip_address.known(), client_address(ctx)) else {
            return Ok(unknown_client());
        };
        let Some(lifetime) = probe.lifetime else {
            return Ok(self.unless_blocked(ctx.tenant_id, client).await);
        };
        self.block(ctx.tenant_id, client, lifetime.seconds()).await;
        self.flag(client, lifetime.seconds()).await;
        self.record_hit(ctx, address, probe.path).await;
        Ok(refused(DenialStatus::FORBIDDEN, "decoy path requested"))
    }

    /// Records the hit in the gateway's inbox. The client is refused
    /// whether or not the record is written.
    async fn record_hit(&self, ctx: &PipelineContext, address: &IpAddress, path: &str) {
        let auditor = RequestAuditor::system(Arc::clone(&self.events))
            .with_tenant(ctx.tenant_id)
            .with_request(Some(address.clone()), ctx.user_agent.known().cloned());
        let hit = RecordHoneypotHitRequest {
            ip_address: address.clone(),
            path: UntrustedText::record(path),
            correlation_id: ctx.correlation_id,
        };
        let tenant = ScopedTenant::from_request_host(ctx.tenant_id);
        let recorded = RecordHoneypotHitUseCase.execute(&tenant, &auditor, hit);
        match tokio::time::timeout(self.record_timeout, recorded).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(%error, "a decoy hit was not recorded"),
            Err(_) => tracing::warn!("recording a decoy hit timed out"),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{Fact, Seconds};

    use super::super::fakes::{Rig, context, denial_status};
    use super::*;

    fn decoy(path: &str) -> DecoyProbe<'_> {
        DecoyProbe {
            path,
            lifetime: Some(DecoyLifetime::new(Seconds::new(3_600)).unwrap()),
        }
    }

    fn real(path: &str) -> DecoyProbe<'_> {
        DecoyProbe {
            path,
            lifetime: None,
        }
    }

    /// Mallory's scanner asks the shop for `/.env`. It is refused and the
    /// hit is recorded in the shop's tenant.
    #[tokio::test]
    async fn a_decoy_hit_is_refused_and_recorded() {
        let rig = Rig::counting();
        let ctx = context();

        let decision = rig.stages().honeypot(&ctx, decoy("/.env")).await.unwrap();

        assert_eq!(denial_status(&decision), Some(403));
        assert_eq!(
            rig.events.records.lock().unwrap().as_slice(),
            ["proxy.honeypot_hit"]
        );
        assert_eq!(
            rig.events.tenant_of("proxy.honeypot_hit"),
            Some(ctx.tenant_id)
        );
    }

    /// After asking for `/.env`, the scanner's next request for a real page
    /// is refused too.
    #[tokio::test]
    async fn a_client_that_hit_a_decoy_is_blocked() {
        let rig = Rig::counting();
        let stages = rig.stages();
        let ctx = context();
        stages.honeypot(&ctx, decoy("/.env")).await.unwrap();

        let decision = stages.honeypot(&ctx, real("/products")).await.unwrap();

        assert_eq!(denial_status(&decision), Some(403));
    }

    /// After a decoy hit, a fresh stage instance using the shared counters
    /// refuses the same tenant and client on a real path with 403.
    #[tokio::test]
    async fn a_block_holds_on_every_instance() {
        let rig = Rig::counting();
        let ctx = context();
        rig.stages().honeypot(&ctx, decoy("/.env")).await.unwrap();

        let elsewhere = rig.stages();
        let decision = elsewhere.honeypot(&ctx, real("/products")).await.unwrap();

        assert_eq!(denial_status(&decision), Some(403));
    }

    /// The block is for the tenant whose decoy was hit; another tenant's
    /// pages still answer the same address.
    #[tokio::test]
    async fn a_block_is_for_one_tenant() {
        let rig = Rig::counting();
        let stages = rig.stages();
        stages.honeypot(&context(), decoy("/.env")).await.unwrap();

        let decision = stages
            .honeypot(&context(), real("/products"))
            .await
            .unwrap();

        assert!(!decision.is_terminal());
    }

    /// A decoy hit whose record cannot be written is still refused.
    #[tokio::test]
    async fn an_unrecorded_hit_is_still_refused() {
        let rig = Rig::with_failing_inbox();

        let decision = rig
            .stages()
            .honeypot(&context(), decoy("/.env"))
            .await
            .unwrap();

        assert_eq!(denial_status(&decision), Some(403));
    }

    /// An unavailable block counter yields 503 even for a real path.
    #[tokio::test]
    async fn an_unreachable_block_counter_refuses() {
        let rig = Rig::unreachable();

        let decision = rig
            .stages()
            .honeypot(&context(), real("/products"))
            .await
            .unwrap();

        assert_eq!(denial_status(&decision), Some(503));
    }

    /// A request whose address is unknown cannot be checked against any
    /// block, and is refused.
    #[tokio::test]
    async fn an_unknown_address_is_refused() {
        let rig = Rig::counting();
        let mut ctx = context();
        ctx.ip_address = Fact::Unknown;

        let decision = rig
            .stages()
            .honeypot(&ctx, real("/products"))
            .await
            .unwrap();

        assert_eq!(denial_status(&decision), Some(403));
    }
}
