//! Sandboxes: a tenant's named recipes of code, pinned packages and limits,
//! saved as versions whose package bundles are built by a job, and tried on
//! sample input; their code written by the tenant's model, imported from a
//! repository, or pushed to one. A sandbox may instead run the company's
//! own image, pinned to its digest and scanned before it first runs.

pub(crate) mod archive;
pub(crate) mod build;
pub mod code;
pub(crate) mod create;
pub(crate) mod get;
pub mod images;
pub(crate) mod list;
mod lookup;
pub(crate) mod runtimes;
pub(crate) mod save_version;
pub mod trying;

pub use archive::{ArchiveSandboxPorts, ArchiveSandboxUseCase};
pub use build::{
    BUILD_SANDBOX_JOB, BuildHandler, BuildRequest, BuildTry, BuildTurn, BuildVersionPorts,
    BuildVersionUseCase, SandboxBuilds,
};
pub use create::{CreateSandboxPorts, CreateSandboxRequest, CreateSandboxUseCase};
pub use get::{GetSandboxPorts, GetSandboxRequest, GetSandboxUseCase, SandboxDetail};
pub use list::{ListPorts, ListRequest, ListUseCase};
pub use runtimes::{ListRuntimesPorts, ListRuntimesUseCase};
pub use save_version::{
    SaveVersionPorts, SaveVersionRequest, SaveVersionUseCase, VersionCode, WrittenPackage,
};
