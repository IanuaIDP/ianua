//! Streams of a tenant's audit records to the SIEM it runs: adding one,
//! changing, pausing, resuming and removing it, and listing them. The
//! worker that sends each record lives in
//! [`audit`](crate::use_cases::audit::stream_record).

pub(crate) mod create;
pub mod destination;
pub(crate) mod list;
mod lookup;
pub(crate) mod pause;
pub(crate) mod reconfigure;
pub(crate) mod remove;
pub(crate) mod resume;

pub use create::{CreatePorts, CreateRequest, CreateUseCase};
pub use list::{ListPorts, ListUseCase};
pub use pause::{PausePorts, PauseUseCase};
pub use reconfigure::{ReconfigurePorts, ReconfigureRequest, ReconfigureUseCase};
pub use remove::{RemovePorts, RemoveUseCase};
pub use resume::{ResumePorts, ResumeUseCase};
