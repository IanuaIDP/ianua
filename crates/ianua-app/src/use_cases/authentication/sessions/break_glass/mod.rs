//! Break-glass access: granting a tenant user emergency rights for a short
//! window, and taking them back early.

pub(crate) mod grant;
pub(crate) mod revoke;

pub use grant::{BreakGlassGrantRequest, BreakGlassLimits, GrantPorts, GrantUseCase};
pub use revoke::{RevokePorts, RevokeUseCase};
