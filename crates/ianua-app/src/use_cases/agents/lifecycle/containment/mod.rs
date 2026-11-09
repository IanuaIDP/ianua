//! Stopping an agent from acting, and letting it act again.

pub(crate) mod contain;
pub(crate) mod resume;
pub(crate) mod revoke;
pub(crate) mod suspend;
pub(crate) mod suspend_all;
pub(in crate::use_cases::agents) mod suspension;

pub use contain::{ContainAgentPorts, ContainAgentUseCase};
pub use resume::{ResumeAgentPorts, ResumeAgentUseCase};
pub use revoke::{RevokeAgentPorts, RevokeAgentUseCase};
pub use suspend::{SuspendAgentPorts, SuspendAgentUseCase};
pub use suspend_all::{SuspendAllAgentsPorts, SuspendAllAgentsUseCase};
