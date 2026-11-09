//! Hearing the other instances' verdicts, and applying the ones that hold.

use std::sync::Arc;
use std::time::Duration;

use ianua_infra::bus::Listener;
use time::OffsetDateTime;
use uuid::Uuid;

use super::FleetChannel;
use super::ledger::NonceLedger;
use super::verdict::ThreatVerdict;
use super::wire::{Refusal, Stamped};

/// How old a verdict may be when it arrives.
const OLDEST: time::Duration = time::Duration::seconds(60);

/// How far ahead of this instance's clock a sender's may run.
const SKEW: time::Duration = time::Duration::seconds(5);

/// How many nonces the ledger remembers at once.
const LEDGER_ROOM: usize = 65_536;

/// How long the listener waits before listening again once the bus closed
/// or refused it.
const LISTEN_AGAIN: Duration = Duration::from_secs(1);

/// Where the other instances' verdicts are applied: the honeypot's blocks
/// and the reputation flags this instance holds.
pub(crate) trait VerdictSink: Send + Sync {
    /// Holds `verdict` from now on, for as long as it lasts. Applying a
    /// verdict never raises it again, or two instances would hand one
    /// block to each other forever.
    fn apply(&self, verdict: ThreatVerdict);
}

/// Hears the fleet's verdicts and applies those that hold.
pub(super) struct FleetListener {
    channel: FleetChannel,
    sink: Arc<dyn VerdictSink>,
    instance: Uuid,
    ledger: NonceLedger,
}

impl FleetListener {
    /// A listener on `channel` for `instance`, which skips its own
    /// verdicts.
    pub(super) fn new(channel: FleetChannel, sink: Arc<dyn VerdictSink>, instance: Uuid) -> Self {
        Self {
            channel,
            sink,
            instance,
            ledger: NonceLedger::new(LEDGER_ROOM, OLDEST + SKEW),
        }
    }

    /// Listens for as long as the gateway runs, listening again whenever
    /// the bus ends it.
    pub(super) async fn run(self) {
        loop {
            self.listen_once().await;
            tokio::time::sleep(LISTEN_AGAIN).await;
        }
    }

    async fn listen_once(&self) {
        let mut listener: Box<dyn Listener> =
            match self.channel.bus.listen(&self.channel.subject).await {
                Ok(listener) => listener,
                Err(error) => {
                    tracing::warn!(%error, "the fleet's verdicts cannot be listened for; retrying");
                    return;
                }
            };
        while let Some(frame) = listener.next().await {
            self.receive(&frame, OffsetDateTime::now_utc());
        }
        tracing::warn!("the bus ended the fleet's verdicts; listening again");
    }

    fn receive(&self, frame: &[u8], now: OffsetDateTime) {
        let stamped = match self.channel.opened(frame) {
            Ok(stamped) => stamped,
            Err(refusal) => {
                tracing::warn!(%refusal, "a fleet verdict was refused");
                return;
            }
        };
        if stamped.origin == self.instance {
            return;
        }
        match self.admit(&stamped, now) {
            Ok(()) => self.sink.apply(stamped.verdict),
            Err(refusal) => tracing::warn!(%refusal, "a fleet verdict was refused"),
        }
    }

    /// Whether `stamped` is fresh at `now` and its nonce unspent, spending
    /// it.
    fn admit(&self, stamped: &Stamped, now: OffsetDateTime) -> Result<(), Refusal> {
        fresh(stamped.sent_at, now)?;
        self.ledger.spend(stamped.nonce, now)
    }
}

/// Whether a verdict sent at `sent_at` may still be applied at `now`.
fn fresh(sent_at: OffsetDateTime, now: OffsetDateTime) -> Result<(), Refusal> {
    if sent_at > now + SKEW {
        return Err(Refusal::Early);
    }
    if now - sent_at > OLDEST {
        return Err(Refusal::Stale);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use ianua_infra::bus::MemoryBus;

    use super::*;
    use crate::config::deployment::FleetName;
    use crate::fleet::FleetMember;
    use crate::fleet::wire::sealed;
    use crate::fleet::wire::tests::{KeyedSeal, flagged, stamped, test_fleet};

    #[derive(Debug, Default)]
    struct Applied(Mutex<Vec<ThreatVerdict>>);

    impl Applied {
        fn verdicts(&self) -> Vec<ThreatVerdict> {
            self.0.lock().map(|held| held.clone()).unwrap_or_default()
        }
    }

    impl VerdictSink for Applied {
        fn apply(&self, verdict: ThreatVerdict) {
            if let Ok(mut held) = self.0.lock() {
                held.push(verdict);
            }
        }
    }

    fn listener(seal: KeyedSeal) -> (FleetListener, Arc<Applied>) {
        let applied = Arc::new(Applied::default());
        let channel = FleetChannel::of(Arc::new(MemoryBus::new(10)), Arc::new(seal), &test_fleet());
        let listener = FleetListener::new(channel, applied.clone(), Uuid::now_v7());
        (listener, applied)
    }

    fn frame_of(sent: &Stamped) -> Vec<u8> {
        frame_on(&test_fleet(), sent)
    }

    fn frame_on(fleet: &FleetName, sent: &Stamped) -> Vec<u8> {
        sealed(&KeyedSeal(7), &format!("fleet.threats.{fleet}"), sent).unwrap()
    }

    #[test]
    fn a_fresh_sealed_verdict_is_applied() {
        let (listener, applied) = listener(KeyedSeal(7));
        let sent = stamped(flagged("1.2.3.4"));

        listener.receive(&frame_of(&sent), sent.sent_at);

        assert_eq!(applied.verdicts(), vec![sent.verdict]);
    }

    /// Delivering the same sealed verdict twice applies it only once.
    #[test]
    fn a_replayed_verdict_is_refused() {
        let (listener, applied) = listener(KeyedSeal(7));
        let sent = stamped(flagged("1.2.3.4"));
        let frame = frame_of(&sent);

        listener.receive(&frame, sent.sent_at);
        listener.receive(&frame, sent.sent_at + time::Duration::seconds(1));

        assert_eq!(applied.verdicts().len(), 1);
    }

    #[test]
    fn a_verdict_sealed_with_another_key_is_refused() {
        let (listener, applied) = listener(KeyedSeal(8));
        let sent = stamped(flagged("1.2.3.4"));

        listener.receive(&frame_of(&sent), sent.sent_at);

        assert!(applied.verdicts().is_empty());
    }

    /// A verdict arriving five minutes after its timestamp is not applied.
    #[test]
    fn a_stale_verdict_is_refused() {
        let (listener, applied) = listener(KeyedSeal(7));
        let sent = stamped(flagged("1.2.3.4"));

        listener.receive(&frame_of(&sent), sent.sent_at + time::Duration::minutes(5));

        assert!(applied.verdicts().is_empty());
    }

    /// A verdict stamped five minutes ahead of the receiving clock is not applied.
    #[test]
    fn a_verdict_from_the_future_is_refused() {
        let (listener, applied) = listener(KeyedSeal(7));
        let sent = stamped(flagged("1.2.3.4"));

        listener.receive(&frame_of(&sent), sent.sent_at - time::Duration::minutes(5));

        assert!(applied.verdicts().is_empty());
    }

    /// A verdict sealed for the staging fleet is not applied by the default fleet.
    #[test]
    fn another_fleets_verdict_is_refused() {
        let (listener, applied) = listener(KeyedSeal(7));
        let sent = stamped(flagged("1.2.3.4"));
        let staging = FleetName::new("staging").unwrap();

        listener.receive(&frame_on(&staging, &sent), sent.sent_at);

        assert!(applied.verdicts().is_empty());
    }

    #[test]
    fn this_instances_own_verdict_is_skipped() {
        let (listener, applied) = listener(KeyedSeal(7));
        let mut sent = stamped(flagged("1.2.3.4"));
        sent.origin = listener.instance;

        listener.receive(&frame_of(&sent), sent.sent_at);

        assert!(applied.verdicts().is_empty());
    }

    /// The point of it all: a client caught on one instance is refused by
    /// another without ever having reached it.
    #[tokio::test]
    async fn a_verdict_raised_on_one_instance_reaches_another() {
        let bus = Arc::new(MemoryBus::new(10));
        let applied = Arc::new(Applied::default());
        let (raising, first) = FleetMember::join(
            bus.clone(),
            Arc::new(KeyedSeal(7)),
            Arc::new(Applied::default()),
            &test_fleet(),
        );
        let (_, second) =
            FleetMember::join(bus, Arc::new(KeyedSeal(7)), applied.clone(), &test_fleet());
        tokio::spawn(first.run());
        tokio::spawn(second.run());

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while applied.verdicts().is_empty() && tokio::time::Instant::now() < deadline {
            raising.publish(flagged("1.2.3.4"));
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        assert_eq!(applied.verdicts().first(), Some(&flagged("1.2.3.4")));
    }
}
