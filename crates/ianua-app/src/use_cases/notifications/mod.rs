//! Notification use cases: fan out, list, unread count, mark read,
//! preferences for tenant users, members and operators, and an
//! organization's destinations outside the app.

/// Who hears about an event, and how it is written to them.
pub(crate) mod delivery;
pub mod destinations;
/// A person's notifications: read, marked, streamed live.
pub(crate) mod inbox;
mod lookup;
pub mod notices;
pub mod personal;
/// What a person chose to hear about.
pub(crate) mod preferences;

pub use delivery::{
    AudiencePorts, DESTINATION_POST_JOB, DeliveryPorts, DestinationPost, FanOutPorts,
    FanOutUseCase, InboxPorts, PostHandler, PostPorts, PostUseCase, Posted, PostedNotification,
    PreferencePorts, RecordedEvent,
};
pub use inbox::{
    ListPorts, ListRequest, ListUseCase, MarkAllReadPorts, MarkAllReadUseCase, MarkReadPorts,
    MarkReadUseCase, NotificationReader, NotificationStream, OpenStreamPorts, OpenStreamUseCase,
    PurgeOldPorts, PurgeOldUseCase, ReaderPorts, StreamNarrowing, StreamStanding, UnreadCountPorts,
    UnreadCountUseCase,
};
pub use preferences::{
    GetPreferencesPorts, GetPreferencesUseCase, PreferenceUpdate, UpdatePreferencesPorts,
    UpdatePreferencesRequest, UpdatePreferencesUseCase,
};
