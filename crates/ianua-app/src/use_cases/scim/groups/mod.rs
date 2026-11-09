//! The directory's groups: listing and reading the ones it keeps, making
//! them, renaming them and changing who is in them, and deleting them.

pub(crate) mod cap;
pub(crate) mod create;
pub mod fields;
pub(crate) mod get;
pub(crate) mod list;
pub(crate) mod remove;
pub(crate) mod replace;
mod roster;
pub(crate) mod update;

pub use cap::MemberCap;
pub use create::{CreateScimPorts, CreateScimUseCase};
pub use get::{GetScimPorts, GetScimUseCase};
pub use list::{ListScimPorts, ListScimRequest, ListScimUseCase};
pub use remove::{RemoveScimPorts, RemoveScimUseCase};
pub use replace::{ReplaceScimPorts, ReplaceScimRequest, ReplaceScimUseCase};
pub use update::{UpdateScimPorts, UpdateScimRequest, UpdateScimUseCase};
