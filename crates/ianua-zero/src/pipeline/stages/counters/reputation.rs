//! The IpReputation stage: the tenant's own denylist, and, when the tenant
//! asks for it, the addresses any tenant's decoys or recon scoring caught.

use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::domains::proxy::stages::stage::{FlaggedClients, IpReputationConfig};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::DenialStatus;

use super::keys::client_address;
use super::{CounterStages, passed, refused, unknown_client};

impl CounterStages {
    /// Refuses an address on the tenant's denylist, and one flagged on any
    /// tenant when the tenant refuses those.
    ///
    /// # Errors
    ///
    /// Never; the `Result` keeps the shape every stage has.
    pub(crate) async fn ip_reputation(
        &self,
        config: &IpReputationConfig,
        ctx: &PipelineContext,
    ) -> Result<StageDecision, DomainError> {
        let Some(client) = client_address(ctx) else {
            return Ok(unknown_client());
        };
        if config
            .denylist
            .iter()
            .any(|range| range.contains_addr(client))
        {
            return Ok(denylisted());
        }
        match config.deny_platform_flagged {
            FlaggedClients::Deny => Ok(self.unless_flagged(client).await),
            FlaggedClients::Ignore => Ok(passed("the address is not on the denylist")),
        }
    }
}

fn denylisted() -> StageDecision {
    refused(
        DenialStatus::FORBIDDEN,
        "the address is on the tenant's denylist",
    )
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::proxy::stages::stage::DecoyLifetime;
    use ianua_domain::types::{CidrRange, Seconds};

    use super::super::DecoyProbe;
    use super::super::fakes::{Rig, context, denial_status};
    use super::*;

    fn config(denylist: &[&str], flagged: FlaggedClients) -> IpReputationConfig {
        IpReputationConfig {
            denylist: denylist
                .iter()
                .map(|range| CidrRange::new(*range).unwrap())
                .collect(),
            deny_platform_flagged: flagged,
        }
    }

    /// An address inside a denied range is refused.
    #[tokio::test]
    async fn a_denylisted_address_is_refused() {
        let rig = Rig::counting();
        let denied = config(&["203.0.113.0/24"], FlaggedClients::Ignore);

        let decision = rig
            .stages()
            .ip_reputation(&denied, &context())
            .await
            .unwrap();

        assert_eq!(denial_status(&decision), Some(403));
    }

    /// An address outside every denied range passes.
    #[tokio::test]
    async fn an_address_outside_the_denylist_passes() {
        let rig = Rig::counting();
        let denied = config(&["10.0.0.0/8"], FlaggedClients::Ignore);

        let decision = rig
            .stages()
            .ip_reputation(&denied, &context())
            .await
            .unwrap();

        assert!(!decision.is_terminal());
    }

    async fn caught_by_another_tenant(rig: &Rig) {
        let probe = DecoyProbe {
            path: "/.env",
            lifetime: Some(DecoyLifetime::new(Seconds::new(3_600)).unwrap()),
        };
        rig.stages().honeypot(&context(), probe).await.unwrap();
    }

    /// A scanner caught by another tenant's decoy is refused on its first
    /// request to a tenant that refuses flagged addresses, on any instance.
    #[tokio::test]
    async fn a_flagged_address_is_refused_when_the_tenant_asks() {
        let rig = Rig::counting();
        caught_by_another_tenant(&rig).await;

        let decision = rig
            .stages()
            .ip_reputation(&config(&[], FlaggedClients::Deny), &context())
            .await
            .unwrap();

        assert_eq!(denial_status(&decision), Some(403));
    }

    /// A tenant that does not take the cross-tenant signal still serves a
    /// flagged address.
    #[tokio::test]
    async fn a_flagged_address_passes_when_the_tenant_does_not_ask() {
        let rig = Rig::counting();
        caught_by_another_tenant(&rig).await;

        let decision = rig
            .stages()
            .ip_reputation(&config(&[], FlaggedClients::Ignore), &context())
            .await
            .unwrap();

        assert!(!decision.is_terminal());
    }

    /// A flag that cannot be read refuses the request.
    #[tokio::test]
    async fn an_unreachable_flag_counter_refuses() {
        let rig = Rig::unreachable();

        let decision = rig
            .stages()
            .ip_reputation(&config(&[], FlaggedClients::Deny), &context())
            .await
            .unwrap();

        assert_eq!(denial_status(&decision), Some(503));
    }
}
