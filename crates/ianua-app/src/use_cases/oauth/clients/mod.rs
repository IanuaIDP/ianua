//! OAuth clients: registering, reading, changing, rotating the secret of
//! and revoking them, and a person seeing and withdrawing the consent they
//! gave one.

pub(crate) mod create;
pub mod credentials;
pub(crate) mod get;
pub(crate) mod list;
pub(crate) mod list_my_apps;
pub(crate) mod revoke;
pub(crate) mod revoke_consent;
pub(crate) mod rotate_secret;
pub(crate) mod update;

pub use create::{CreatePorts, CreateRequest, CreateResult, CreateUseCase};
pub use get::{GetPorts, GetUseCase};
pub use list::{ClientFilter, ListPorts, ListRequest, ListUseCase};
pub use list_my_apps::{AuthorizedApp, ListMyAppsPorts, ListMyAppsUseCase};
pub use revoke::{RevokePorts, RevokeUseCase};
pub use revoke_consent::{RevokeConsentPorts, RevokeConsentUseCase};
pub use rotate_secret::{RotateSecretPorts, RotateSecretRequest, RotateSecretUseCase};
pub use update::{UpdatePorts, UpdateRequest, UpdateUseCase};
