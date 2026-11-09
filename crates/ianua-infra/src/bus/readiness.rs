//! Whether the message bus answers, for the process's readiness check.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::runtime::{Readiness, ReadinessProbe, UnreadyReason};

use crate::bus::stream::{Bus, BusError};

/// The longest the bus is waited on before it counts as not ready.
const WAIT: Duration = Duration::from_secs(2);

/// Asks the message bus whether it answers.
pub struct BusReadinessProbe {
    bus: Arc<dyn Bus>,
}

impl BusReadinessProbe {
    /// A probe of `bus`.
    #[must_use]
    pub fn new(bus: Arc<dyn Bus>) -> Self {
        Self { bus }
    }
}

#[async_trait]
impl ReadinessProbe for BusReadinessProbe {
    async fn check(&self) -> Readiness {
        match tokio::time::timeout(WAIT, self.bus.ping()).await {
            Ok(Ok(())) => Readiness::Ready,
            Ok(Err(error)) => Readiness::NotReady(UnreadyReason::new(reason(&error))),
            Err(_) => Readiness::NotReady(UnreadyReason::new("the bus did not answer in time")),
        }
    }
}

/// What went wrong, without the server's address.
fn reason(error: &BusError) -> &'static str {
    match error {
        BusError::TimedOut => "the bus did not answer in time",
        BusError::Unreachable(_) => "the bus cannot be reached",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::{MemoryBus, RefusingBus};

    /// A successful ping from the in-memory bus satisfies the readiness probe.
    #[tokio::test]
    async fn a_bus_that_answers_is_ready() {
        let probe = BusReadinessProbe::new(Arc::new(MemoryBus::new(16)));

        assert_eq!(probe.check().await, Readiness::Ready);
    }

    /// A failed bus ping makes the readiness probe report not ready.
    #[tokio::test]
    async fn a_bus_that_does_not_answer_is_not_ready() {
        let probe = BusReadinessProbe::new(Arc::new(RefusingBus));

        assert!(matches!(probe.check().await, Readiness::NotReady(_)));
    }
}
