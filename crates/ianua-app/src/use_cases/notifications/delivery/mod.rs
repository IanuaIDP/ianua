//! Who hears about an event, and how it is written to them.

pub(super) mod audience;
pub(crate) mod fan_out;
pub(crate) mod job;
pub(super) mod notice;
pub(super) mod people;
pub(crate) mod post;
pub(super) mod recipients;
pub(super) mod render;

pub use fan_out::{
    AudiencePorts, DeliveryPorts, FanOutPorts, FanOutUseCase, InboxPorts, PreferencePorts,
    RecordedEvent,
};
pub use job::{DESTINATION_POST_JOB, DestinationPost, PostHandler, PostedNotification};
pub use post::{PostPorts, PostUseCase, Posted};
