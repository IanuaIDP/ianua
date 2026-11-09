//! A person's notifications: read, marked, streamed live.

pub(crate) mod list;
pub(crate) mod mark_all_read;
pub(crate) mod mark_read;
pub(crate) mod open_stream;
pub(crate) mod purge_old;
pub(crate) mod reader;
pub(crate) mod unread_count;

pub use list::{ListPorts, ListRequest, ListUseCase};
pub use mark_all_read::{MarkAllReadPorts, MarkAllReadUseCase};
pub use mark_read::{MarkReadPorts, MarkReadUseCase};
pub use open_stream::{
    NotificationStream, OpenStreamPorts, OpenStreamUseCase, StreamNarrowing, StreamStanding,
};
pub use purge_old::{PurgeOldPorts, PurgeOldUseCase};
pub use reader::{NotificationReader, ReaderPorts};
pub use unread_count::{UnreadCountPorts, UnreadCountUseCase};
