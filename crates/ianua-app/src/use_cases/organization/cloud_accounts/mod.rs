//! Connecting the organization's own cloud accounts.

pub(crate) mod attach_cloud_credential;
pub(crate) mod begin_cloud_connection;
pub(crate) mod disconnect;
pub(crate) mod get_cloud_external_id;
pub(crate) mod list;
pub(crate) mod list_cloud_networks;
pub(in crate::use_cases::organization) mod lookup;
pub(in crate::use_cases::organization) mod rights;
pub(crate) mod verify;

pub use attach_cloud_credential::{
    AttachCloudCredentialPorts, AttachCloudCredentialRequest, AttachCloudCredentialUseCase,
};
pub use begin_cloud_connection::{
    BeginCloudConnectionPorts, BeginCloudConnectionRequest, BeginCloudConnectionUseCase,
    ConnectionInstructions,
};
pub use disconnect::{DisconnectPorts, DisconnectUseCase};
pub use get_cloud_external_id::{GetCloudExternalIdPorts, GetCloudExternalIdUseCase};
pub use list::{ListPorts, ListUseCase};
pub use list_cloud_networks::{
    ListCloudNetworksPorts, ListCloudNetworksRequest, ListCloudNetworksUseCase,
};
pub use verify::{VerifyPorts, VerifyRequest, VerifyUseCase};
