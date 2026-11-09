//! Consumer use cases: machine identity management for tenants.

pub(crate) mod change_clearance;
pub(crate) mod change_quota;
pub(crate) mod create;
/// A consumer's credential: rotated, its overlap ended, its expiry changed.
pub(crate) mod credentials;
pub(crate) mod delete;
pub(crate) mod describe;
pub(crate) mod disable;
pub(crate) mod enable;
pub(crate) mod get;
pub(crate) mod list;
mod lookup;
pub(crate) mod rename;

pub use change_clearance::{ChangeClearancePorts, ChangeClearanceRequest, ChangeClearanceUseCase};
pub use change_quota::{ChangeQuotaPorts, ChangeQuotaRequest, ChangeQuotaUseCase};
pub use create::{CreatePorts, CreateRequest, CreateResult, CreateUseCase};
pub use credentials::{
    ChangeCredentialExpiryPorts, ChangeCredentialExpiryRequest, ChangeCredentialExpiryUseCase,
    EndCredentialOverlapPorts, EndCredentialOverlapUseCase, RotateCredentialPorts,
    RotateCredentialRequest, RotateCredentialUseCase, RotatedCredential,
};
pub use delete::{DeletePorts, DeleteUseCase};
pub use describe::{DescribePorts, DescribeRequest, DescribeUseCase};
pub use disable::{DisablePorts, DisableUseCase};
pub use enable::{EnablePorts, EnableUseCase};
pub use get::{GetPorts, GetUseCase};
pub use list::{ListPorts, ListRequest, ListUseCase};
pub use rename::{RenamePorts, RenameRequest, RenameUseCase};

pub use crate::services::consumers::NewCredential;
