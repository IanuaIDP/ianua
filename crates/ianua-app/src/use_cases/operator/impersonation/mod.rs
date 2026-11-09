//! Letting an operator act in a tenant, acting through it, and taking it
//! back.

pub(crate) mod act;
pub(crate) mod grant;
pub(crate) mod revoke;

pub use act::{ActThroughGrantPorts, ActThroughGrantUseCase, GrantInUse};
pub use grant::{GrantPorts, GrantUseCase};
pub use revoke::{RevokePorts, RevokeUseCase};
