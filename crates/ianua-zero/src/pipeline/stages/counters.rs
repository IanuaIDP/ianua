//! The stages that count: rate limits, agent request budgets, the request
//! side of token limits, decoy paths, address reputation and recon scoring,
//! and the check a route in attack mode makes before its pipeline.
//!
//! Every count lives on the cache server every instance shares, so a limit
//! of a hundred means a hundred across the fleet rather than a hundred per
//! instance. A count that cannot be read in time refuses the request: a
//! limit that lapses whenever the cache is slow is no limit, and falling
//! back to one instance's own count would hand a caller one allowance per
//! instance exactly when the fleet is busiest.
//!
//! A refusal for being over a limit is a 429 that says when to come back:
//! `Retry-After` and the `RateLimit-*` headers go onto the context's
//! response headers, which the gateway sends with the refusal.

mod attack;
mod budget;
mod decoys;
mod held;
mod keys;
mod limits;
mod recon;
mod reputation;
mod verdicts;

#[cfg(test)]
pub(crate) mod fakes;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

pub(crate) use decoys::DecoyProbe;
pub(crate) use held::HeldVerdicts;
use ianua_app::ports::agents::BudgetCounter;
use ianua_app::ports::runtime::FleetCounters;
use ianua_app::ports::shared::EventDispatcher;
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::types::DenialStatus;
pub(crate) use limits::token_counter_key;
pub(crate) use recon::{ReconOutcome, ReconProbe};
use tokio::sync::Semaphore;

use crate::fleet::FleetPublisher;

/// What the counting stages reach outside the gateway.
pub(crate) struct CounterPorts {
    /// The counters and claims every instance shares.
    pub fleet: Arc<dyn FleetCounters>,
    /// The shared count of each agent's and delegation's request budget.
    pub budgets: Arc<dyn BudgetCounter>,
    /// The gateway's event inbox, where a decoy hit is recorded.
    pub events: Arc<dyn EventDispatcher>,
    /// This instance's copy of the fleet's blocks and flags, also handed
    /// to the fleet as the sink for the other instances' verdicts.
    pub held: Arc<HeldVerdicts>,
    /// Where blocks and flags raised here go to the other instances, when
    /// the gateway runs as part of a fleet.
    pub publisher: Option<FleetPublisher>,
}

/// How long the counting stages may wait, and how many requests they may
/// hold at once.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CounterLimits {
    /// The longest one request waits on a shared counter
    /// (`GATEWAY_COUNTER_TIMEOUT_MS`).
    pub counter_timeout: Duration,
    /// The longest a decoy hit's record may take to reach the inbox.
    pub record_timeout: Duration,
    /// How many requests the recon stage may slow down at once.
    pub tarpits: usize,
}

/// The counting stages, one method per stage kind.
pub(crate) struct CounterStages {
    fleet: Arc<dyn FleetCounters>,
    budgets: Arc<dyn BudgetCounter>,
    events: Arc<dyn EventDispatcher>,
    held: Arc<HeldVerdicts>,
    publisher: Option<FleetPublisher>,
    tarpits: Semaphore,
    counter_timeout: Duration,
    record_timeout: Duration,
}

impl CounterStages {
    /// The counting stages on `ports`, waiting no longer than `limits` say.
    #[must_use]
    pub(crate) fn new(ports: CounterPorts, limits: CounterLimits) -> Self {
        Self {
            fleet: ports.fleet,
            budgets: ports.budgets,
            events: ports.events,
            held: ports.held,
            publisher: ports.publisher,
            tarpits: Semaphore::new(limits.tarpits),
            counter_timeout: limits.counter_timeout,
            record_timeout: limits.record_timeout,
        }
    }

    /// What a shared counter answered, or `None` when it answered nothing
    /// or not in time.
    async fn within<T>(&self, answer: impl Future<Output = Option<T>>) -> Option<T> {
        tokio::time::timeout(self.counter_timeout, answer)
            .await
            .ok()
            .flatten()
    }
}

/// The request goes on to the next stage.
fn passed(reason: &str) -> StageDecision {
    StageDecision::Pass {
        reason: reason.to_owned(),
    }
}

/// The request is refused with `status`.
fn refused(status: DenialStatus, reason: &str) -> StageDecision {
    StageDecision::Deny {
        status,
        reason: reason.to_owned(),
    }
}

/// A shared counter did not answer in time, so the request is refused
/// rather than let through uncounted.
fn unavailable() -> StageDecision {
    refused(
        DenialStatus::SERVICE_UNAVAILABLE,
        "a shared counter did not answer",
    )
}

/// The request's address is unknown, so nothing keyed on it can be
/// checked, and the request is refused rather than let through unchecked.
fn unknown_client() -> StageDecision {
    refused(DenialStatus::FORBIDDEN, "the client's address is not known")
}
