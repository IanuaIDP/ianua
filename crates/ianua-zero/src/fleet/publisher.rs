//! Raising a verdict, and sending it to the other instances.
//!
//! The stage that raises a verdict has already enforced it and must not
//! wait on the bus to say so, so raising one only queues it. The queue is
//! bounded: when it is full the newest verdict is dropped and counted,
//! since a queue that deep already means the bus is gone, and a queue that
//! grows behind an enforcement path is an outage. One sender drains it,
//! each broadcast given a timeout, so a bus that hangs holds up the
//! verdicts and nothing else.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use time::OffsetDateTime;
use tokio::sync::mpsc;
use uuid::Uuid;

use super::FleetChannel;
use super::verdict::ThreatVerdict;
use super::wire::Stamped;

/// How many verdicts may wait to go out.
const OUTBOUND_ROOM: usize = 1024;

/// How long one broadcast may take.
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(2);

/// Raises verdicts for the other instances. Cheap to clone; every clone
/// feeds the one queue.
#[derive(Debug, Clone)]
pub(crate) struct FleetPublisher {
    outbound: mpsc::Sender<ThreatVerdict>,
    dropped: Arc<AtomicU64>,
}

impl FleetPublisher {
    /// Queues `verdict` for the other instances, or drops and counts it
    /// when the queue is full or the sender has stopped.
    pub(crate) fn publish(&self, verdict: ThreatVerdict) {
        if self.outbound.try_send(verdict).is_ok() {
            return;
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
        tracing::warn!("a threat verdict was dropped; the fleet's queue is full or closed");
    }

    /// Reads the count used to verify that a full queue drops verdicts.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Sends the queued verdicts.
pub(super) struct FleetSender {
    channel: FleetChannel,
    instance: Uuid,
    queued: mpsc::Receiver<ThreatVerdict>,
}

/// A publisher and the sender draining its queue onto `channel`, for
/// `instance`.
pub(super) fn outbound(channel: FleetChannel, instance: Uuid) -> (FleetPublisher, FleetSender) {
    with_room(channel, instance, OUTBOUND_ROOM)
}

fn with_room(channel: FleetChannel, instance: Uuid, room: usize) -> (FleetPublisher, FleetSender) {
    let (outbound, queued) = mpsc::channel(room.max(1));
    let publisher = FleetPublisher {
        outbound,
        dropped: Arc::new(AtomicU64::new(0)),
    };
    let sender = FleetSender {
        channel,
        instance,
        queued,
    };
    (publisher, sender)
}

impl FleetSender {
    /// Sends every verdict queued, until every publisher is gone.
    pub(super) async fn run(mut self) {
        while let Some(verdict) = self.queued.recv().await {
            self.send(verdict).await;
        }
    }

    async fn send(&self, verdict: ThreatVerdict) {
        let stamped = Stamped {
            origin: self.instance,
            nonce: Uuid::now_v7(),
            sent_at: OffsetDateTime::now_utc(),
            verdict,
        };
        let frame = match self.channel.framed(&stamped) {
            Ok(frame) => frame,
            Err(error) => {
                tracing::error!(%error, "a threat verdict could not be written for the fleet");
                return;
            }
        };
        let broadcast = self.channel.bus.broadcast(&self.channel.subject, &frame);
        match tokio::time::timeout(PUBLISH_TIMEOUT, broadcast).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(%error, "a threat verdict was not shared with the fleet");
            }
            Err(_) => tracing::warn!("sharing a threat verdict with the fleet timed out"),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_infra::bus::MemoryBus;

    use super::*;
    use crate::fleet::wire::tests::{KeyedSeal, flagged, test_fleet};

    /// Five verdicts sent to an undrained queue with two slots count three drops.
    #[test]
    fn a_full_queue_drops_and_counts() {
        let channel = FleetChannel::of(
            Arc::new(MemoryBus::new(10)),
            Arc::new(KeyedSeal(7)),
            &test_fleet(),
        );
        let (publisher, _sender) = with_room(channel, Uuid::now_v7(), 2);

        for _ in 0..5 {
            publisher.publish(flagged("1.2.3.4"));
        }

        assert_eq!(publisher.dropped(), 3);
    }
}
