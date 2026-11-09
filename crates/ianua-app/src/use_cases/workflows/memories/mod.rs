//! Memories: a tenant's named stores of texts and their vectors, which
//! workflow steps keep texts in and search for the most similar.
//!
//! A memory is made on the platform's own embedding server or one of the
//! tenant's model providers, deleted only by someone who types its name,
//! brought back within its waiting period, and deleted for good, texts and
//! all, by the sweep once that period is over.

pub(crate) mod create;
pub(crate) mod delete;
pub(crate) mod export;
pub(crate) mod list;
pub(crate) mod lookup;
pub(crate) mod purge;
pub(crate) mod restore;

pub use create::{CreatePorts, CreateRequest, CreateUseCase, MemorySourceChoice};
pub use delete::{DeletePorts, DeleteRequest, DeleteUseCase};
pub use export::{ExportPorts, ExportRequest, ExportUseCase};
pub use list::{ListPorts, ListUseCase};
pub use purge::{PurgePorts, PurgeUseCase};
pub use restore::{RestorePorts, RestoreUseCase};
