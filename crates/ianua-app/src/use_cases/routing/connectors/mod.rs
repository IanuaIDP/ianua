//! Private-network connectors: agents inside a tenant's network that the
//! gateway reaches upstreams with no public address through.

pub(crate) mod change_scope;
pub(crate) mod create;
pub(crate) mod delete;
pub(crate) mod enroll;
pub(crate) mod get;
pub(crate) mod list;
pub(crate) mod lookup;
pub(crate) mod renew;
pub(crate) mod revoke;

pub use change_scope::{ChangeScopePorts, ChangeScopeRequest, ChangeScopeUseCase};
pub use create::{CreatePorts, CreateRequest, CreateUseCase, CreatedConnector};
pub use delete::{DeletePorts, DeleteUseCase};
pub use enroll::{EnrollPorts, EnrollRequest, EnrollUseCase};
pub use get::{GetPorts, GetUseCase};
pub use list::{ListPorts, ListUseCase};
pub use renew::{RenewPorts, RenewRequest, RenewUseCase};
pub use revoke::{RevokePorts, RevokeUseCase};

pub use crate::services::routing::connector_certificates::IssuedConnector;
