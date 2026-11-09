//! Threat verdicts shared between the gateway's instances.
//!
//! Two defences hold a verdict about a client rather than a count: the
//! honeypot's block and the cross-tenant reputation flag. Both are raised
//! rarely and read on every request, so each instance keeps its own copy
//! and a verdict reached on one is broadcast to the others on the bus,
//! costing a message when something trips and nothing otherwise. Delivery
//! is best effort: a lost verdict leaves the other instances enforcing on
//! what they saw themselves.
//!
//! Reaching the bus is no authority to block a tenant's clients. Every
//! verdict is sealed under a key derived from the platform's root for this
//! use alone, and carries the time it was sent and a nonce: a verdict whose
//! seal does not hold, one too old or from the future, and one whose nonce
//! was already spent are refused. However long a verdict asks to last, it
//! lasts a day at most, so even a forged one buys little. Verdicts wait to
//! go out in a bounded queue; when it is full the newest is dropped and
//! counted, and every broadcast has a timeout.

mod ledger;
mod listener;
mod publisher;
mod seal;
mod verdict;
mod wire;

use std::sync::Arc;

use ianua_infra::bus::Bus;
pub(crate) use listener::VerdictSink;
pub(crate) use publisher::FleetPublisher;
pub(crate) use seal::VerdictSeal;
use uuid::Uuid;
pub(crate) use verdict::{ThreatVerdict, VerdictLifetime};

use self::listener::FleetListener;
use self::publisher::{FleetSender, outbound};
use self::wire::{Refusal, Stamped, opened, sealed};
use crate::config::deployment::FleetName;

/// The subject the instances broadcast verdicts on, before the fleet's
/// name: outside the events stream, which no follower of it should act on,
/// and put under the deployment's namespace by the bus, so one
/// deployment's verdicts never reach another's gateways on a shared bus
/// server.
const SUBJECT: &str = "fleet.threats";

/// The bus one fleet's verdicts travel on, the seal they carry, and the
/// subject they travel on and are sealed under. The fleet's name is in the
/// subject, so a staging fleet's verdicts neither reach production's
/// gateways nor hold there should they arrive.
#[derive(Clone)]
struct FleetChannel {
    bus: Arc<dyn Bus>,
    seal: Arc<dyn VerdictSeal>,
    subject: Arc<str>,
}

impl FleetChannel {
    /// `fleet`'s channel on `bus`, sealed with `seal`.
    fn of(bus: Arc<dyn Bus>, seal: Arc<dyn VerdictSeal>, fleet: &FleetName) -> Self {
        Self {
            bus,
            seal,
            subject: Arc::from(format!("{SUBJECT}.{fleet}")),
        }
    }

    /// `stamped`, sealed under this channel's subject and framed.
    fn framed(&self, stamped: &Stamped) -> Result<Vec<u8>, serde_json::Error> {
        sealed(self.seal.as_ref(), &self.subject, stamped)
    }

    /// The verdict `frame` carries, when its seal holds on this channel.
    fn opened(&self, frame: &[u8]) -> Result<Stamped, Refusal> {
        opened(self.seal.as_ref(), &self.subject, frame)
    }
}

/// One instance's part in the fleet: the handle that raises verdicts, and
/// the work that sends them and applies the others'.
pub(crate) struct FleetMember {
    sender: FleetSender,
    listener: FleetListener,
}

impl std::fmt::Debug for FleetMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetMember").finish_non_exhaustive()
    }
}

impl FleetMember {
    /// This instance joining `fleet` on `bus`: verdicts sealed and checked
    /// with `seal`, and the other instances' verdicts handed to `sink`.
    /// Returns the publisher every enforcing stage raises verdicts through,
    /// and the member to [`run`](Self::run).
    #[must_use]
    pub(crate) fn join(
        bus: Arc<dyn Bus>,
        seal: Arc<dyn VerdictSeal>,
        sink: Arc<dyn VerdictSink>,
        fleet: &FleetName,
    ) -> (FleetPublisher, Self) {
        let instance = Uuid::now_v7();
        let channel = FleetChannel::of(bus, seal, fleet);
        let (publisher, sender) = outbound(channel.clone(), instance);
        let listener = FleetListener::new(channel, sink, instance);
        (publisher, Self { sender, listener })
    }

    /// Sends this instance's verdicts and applies the others', for as long
    /// as the gateway runs. Spawn it once, until the stop.
    pub(crate) async fn run(self) {
        tokio::join!(self.sender.run(), self.listener.run());
    }
}
