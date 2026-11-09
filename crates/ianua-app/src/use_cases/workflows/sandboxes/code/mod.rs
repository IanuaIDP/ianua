//! A version's code beyond the platform: written for a person by the
//! tenant's model, read from a file of a company's repository at an exact
//! commit, and pushed to a repository as a copy.

mod files;
pub(crate) mod push;
mod through;
pub(crate) mod write;

pub use push::{PushVersionPorts, PushVersionRequest, PushVersionUseCase};
pub use write::{WritePorts, WriteRequest, WriteUseCase, Writing, WrittenCode};

pub(in crate::use_cases::workflows::sandboxes) use self::files::{no_code, refused};
pub(in crate::use_cases::workflows::sandboxes) use self::through::Through;
