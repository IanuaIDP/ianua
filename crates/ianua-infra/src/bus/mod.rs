//! The message bus: events published durably for every consumer, and
//! broadcasts for whoever listens now.
//!
//! Every bus-shaped adapter is written once over [`Bus`], so where the bus
//! lives is the composition root's choice: [`MemoryBus`] in this process,
//! for a deployment of one node and for tests, or [`ServerBus`] on a bus
//! server every node reaches, every subject and stream there under the
//! deployment's [`Namespace`](crate::namespace::Namespace). Events travel as [`EventEnvelope`]s, the
//! audit records they were kept as. Live updates travel as broadcasts
//! through [`BusNotificationPublisher`] and [`BusNotificationSubscriber`],
//! a tenant's setup progress among them, through
//! [`BusSetupProgressObserver`].
//! The agent message plane, [`MessagePlane`] behind [`BusMessagePublisher`],
//! [`BusMessageConsumer`] and [`BusDeadLetters`], keeps durable consumers and
//! dead letters, so it runs on the bus server alone; a bus in process has
//! [`NoMessagePublisher`], [`NoMessageConsumer`] and [`NoDeadLetters`],
//! which refuse every message. Every node follows the
//! events through [`Bus::follow`], so its store caches drop what an event
//! changed. The worker's consumers each read a share of them through
//! [`Bus::share`], every event handed to one worker until it is done with,
//! and read each back through [`HeardEvents`] once its seal holds.

mod envelope;
mod heard;
mod memory;
mod no_plane;
mod progress;
mod readiness;
mod realtime;
mod server;
mod stream;

pub use envelope::{EventEnvelope, EventScope};
pub use heard::{HeardEvents, Unheard};
#[cfg(test)]
pub(crate) use memory::RefusingBus;
pub use memory::{MemoryBus, Published};
pub use no_plane::{NoDeadLetters, NoMessageConsumer, NoMessagePublisher};
pub use progress::BusSetupProgressObserver;
pub use readiness::BusReadinessProbe;
pub use realtime::{BusNotificationPublisher, BusNotificationSubscriber};
pub use server::{
    BusDeadLetters, BusMessageConsumer, BusMessagePublisher, BusSignIn, MessagePlane, ServerBus,
};
pub use stream::{
    Bus, BusError, EventFeed, EventShare, Handed, Heard, HeardEvent, Listener, SealedEvent,
    SharedFeed,
};
