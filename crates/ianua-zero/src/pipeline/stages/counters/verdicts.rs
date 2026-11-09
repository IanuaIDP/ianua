//! Blocks and flags: raised here, held on this instance, written to the
//! shared counters and broadcast to the other instances; and read back,
//! from this instance's copy first and the shared counters second.
//!
//! A block keeps a client from one tenant; a flag marks it for the tenants
//! that refuse what any tenant's defences caught.

use std::net::IpAddr;

use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::types::{DenialStatus, Seconds, TenantId};

use super::{CounterStages, passed, refused, unavailable};
use crate::fleet::{ThreatVerdict, VerdictLifetime};

/// The shared counter holding whether `client` is blocked from `tenant`.
fn block_key(tenant: TenantId, client: IpAddr) -> String {
    format!("block:{tenant}:{client}")
}

/// The shared counter holding whether `client` is flagged. It names no
/// tenant on purpose: a flag follows a client across tenants.
fn flag_key(client: IpAddr) -> String {
    format!("flag:{client}")
}

impl CounterStages {
    /// Blocks `client` from `tenant` for `lasts`, here, on the shared
    /// counters and on the other instances.
    pub(super) async fn block(&self, tenant: TenantId, client: IpAddr, lasts: Seconds) {
        self.held.block(tenant, client, lasts.std_duration());
        self.publish(ThreatVerdict::ClientBlocked {
            tenant,
            client,
            lasts: VerdictLifetime::capped(lasts.std_duration()),
        });
        self.share(&block_key(tenant, client), lasts).await;
    }

    /// Flags `client` for `lasts`, here, on the shared counters and on the
    /// other instances.
    pub(super) async fn flag(&self, client: IpAddr, lasts: Seconds) {
        self.held.flag(client, lasts.std_duration());
        self.publish(ThreatVerdict::ClientFlagged {
            client,
            lasts: VerdictLifetime::capped(lasts.std_duration()),
        });
        self.share(&flag_key(client), lasts).await;
    }

    /// Refuses `client` when it is blocked from `tenant`.
    pub(super) async fn unless_blocked(&self, tenant: TenantId, client: IpAddr) -> StageDecision {
        if self.held.is_blocked(tenant, client) {
            return blocked();
        }
        self.unless_shared(&block_key(tenant, client), blocked())
            .await
    }

    /// Refuses `client` when it is flagged.
    pub(super) async fn unless_flagged(&self, client: IpAddr) -> StageDecision {
        if self.held.is_flagged(client) {
            return flagged();
        }
        self.unless_shared(&flag_key(client), flagged()).await
    }

    /// Answers `refusal` when the shared counter `key` holds anything,
    /// and refuses when it cannot be read.
    async fn unless_shared(&self, key: &str, refusal: StageDecision) -> StageDecision {
        let Some(held) = self.within(self.fleet.read(key)).await else {
            return unavailable();
        };
        if held > 0 {
            return refusal;
        }
        passed("the address is neither blocked nor flagged")
    }

    /// Holds a verdict on the shared counters for `lasts` from now, so each
    /// new hit restarts the wait. The request that raised it is refused
    /// either way, and this instance holds it, so a write that fails is
    /// logged.
    async fn share(&self, key: &str, lasts: Seconds) {
        if self.within(self.fleet.hold(key, lasts)).await.is_none() {
            tracing::warn!("a block or flag did not reach the shared counters");
        }
    }

    fn publish(&self, verdict: ThreatVerdict) {
        let Some(publisher) = &self.publisher else {
            return;
        };
        publisher.publish(verdict);
    }
}

fn blocked() -> StageDecision {
    refused(
        DenialStatus::FORBIDDEN,
        "the address is blocked after a decoy hit",
    )
}

fn flagged() -> StageDecision {
    refused(
        DenialStatus::FORBIDDEN,
        "the address is flagged by another tenant's defences",
    )
}
