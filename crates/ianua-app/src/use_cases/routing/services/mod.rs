//! The backends routes forward to, and how people sign in on them.

pub(crate) mod change_tls;
pub(crate) mod client_key;
pub(crate) mod configure_app_sign_in;
pub(crate) mod create;
pub(crate) mod delete;
pub(crate) mod get;
pub(crate) mod health;
pub(crate) mod list;
/// The rules app sign-in is held to among the tenant's routes and domains.
pub mod sign_in_checks;
pub(crate) mod update;
/// How a service's upstream TLS arrives, its client key sealed.
pub mod upstream_tls;

pub use change_tls::{ChangeTlsPorts, ChangeTlsRequest, ChangeTlsUseCase};
pub use client_key::{OpenClientKeyPorts, OpenClientKeyRequest, OpenClientKeyUseCase};
pub use configure_app_sign_in::{
    ConfigureAppSignInPorts, ConfigureAppSignInRequest, ConfigureAppSignInUseCase,
};
pub use create::{CreatePorts, CreateRequest, CreateUseCase};
pub use delete::{DeletePorts, DeleteUseCase};
pub use get::{GetPorts, GetUseCase};
pub use health::{HealthPorts, HealthUseCase, LiveHealth, ServiceHealth};
pub use list::{ListPorts, ListRequest, ListUseCase};
pub use update::{UpdatePorts, UpdateRequest, UpdateUseCase};
