//! Planning the signals an event means, sending one signal to one stream,
//! handing poll streams their events, and reading what was sent.

pub(crate) mod dispatch;
pub(crate) mod job;
pub(crate) mod list_stream_deliveries;
pub(crate) mod plan;
pub(crate) mod poll_events;
mod push;

pub use dispatch::{DispatchSignalPorts, DispatchSignalRequest, DispatchSignalUseCase, Dispatched};
pub use job::{DISPATCH_SIGNAL_JOB, DispatchSignalHandler, SignalJobs};
pub use list_stream_deliveries::{
    ListStreamDeliveriesPorts, ListStreamDeliveriesRequest, ListStreamDeliveriesUseCase,
};
pub use plan::{PlanPorts, PlanUseCase};
pub use poll_events::{PollEventsPorts, PollEventsRequest, PollEventsUseCase};
