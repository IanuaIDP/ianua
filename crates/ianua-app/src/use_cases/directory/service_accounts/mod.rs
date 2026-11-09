//! Service accounts: the accounts applications such as Jira, GitLab and
//! SSSD bind to the tenant's directory as, instead of borrowing a person's
//! password. Making, changing and deleting them, binding as one, and
//! reading the directory through the bind. No write goes through a service
//! account: a directory write is a person's, over their own certificate.

pub(crate) mod bind;
pub(crate) mod change_scope;
pub(crate) mod change_status;
pub(crate) mod create;
pub(crate) mod delete;
pub(crate) mod get;
pub(crate) mod list;
mod lookup;
pub(crate) mod rotate_secret;
pub(crate) mod search_as;
pub mod service_principal;

pub use bind::{BindPorts, BindRequest, BindUseCase};
pub use change_scope::{ChangeScopePorts, ChangeScopeRequest, ChangeScopeUseCase};
pub use change_status::{ChangeStatusPorts, ChangeStatusRequest, ChangeStatusUseCase};
pub use create::{CreatePorts, CreateRequest, CreateUseCase, CreatedServiceAccount};
pub use delete::{DeletePorts, DeleteRequest, DeleteUseCase};
pub use get::{GetPorts, GetUseCase};
pub use list::{ListPorts, ListUseCase};
pub use rotate_secret::{RotateSecretPorts, RotateSecretUseCase};
pub use search_as::{SearchAsPorts, SearchAsUseCase, ServiceSearchRequest};
