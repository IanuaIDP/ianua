//! The gateway's inbox: the few events the data plane raises, kept apart
//! from the audit trail until the worker has checked them.
//!
//! The trail's chain head is sealed with the control plane's root, and the
//! outbox is relayed under the control plane's seal, so whatever the
//! gateway wrote to either would leave vouched for by a key the gateway
//! never holds. The gateway writes neither. Its use cases send their events
//! through [`InboxEventDispatcher`], which takes only the event types the
//! data plane's seal may vouch for (an agent's action allowed or denied,
//! egress denied, a honeypot hit, automation caught, a canary token
//! presented or leaking), seals each one under the data plane's
//! key and adds it to the tenant's `gateway_events`, in the request's unit
//! of work. The table holds those types and no other, and the gateway's
//! database role may only add to it.
//!
//! The worker runs [`InboxDrain`], as it runs the outbox relay: it takes the
//! oldest events, checks each one's seal and type again, appends those
//! that hold to the trail, where they get their chain link and their
//! outbox row, and removes every event it took, in one transaction. An
//! event whose seal or type does not hold is removed and logged, never
//! appended.

mod dispatcher;
mod drain;
mod record;

pub use dispatcher::InboxEventDispatcher;
pub use drain::{Drained, InboxDrain};
