//! A tenant's custom user attributes: their declarations and the values people
//! hold.

pub(crate) mod declare;
pub(in crate::use_cases::identity) mod declared_schema;
pub(crate) mod delete;
pub(crate) mod delete_user_metadata;
pub(crate) mod get_metadata;
pub(crate) mod get_schema;
pub(crate) mod get_users_metadata;
pub(crate) mod list;
pub(crate) mod set_status;
pub(crate) mod set_value;
pub(in crate::use_cases::identity) mod stranded;
pub(crate) mod update;

pub use declare::{DeclarePorts, DeclareUseCase};
pub use delete::{DeletePorts, DeleteRequest, DeleteUseCase};
pub use delete_user_metadata::{DeleteUserMetadataPorts, DeleteUserMetadataUseCase};
pub use get_metadata::{GetMetadataPorts, GetMetadataUseCase, ReadableValue};
pub use get_schema::{GetSchemaPorts, GetSchemaUseCase};
pub use get_users_metadata::{
    GetUsersMetadataPorts, GetUsersMetadataRequest, GetUsersMetadataUseCase,
};
pub use list::{AttributeListing, ListPorts, ListUseCase};
pub use set_status::{SetStatusPorts, SetStatusRequest, SetStatusUseCase, Status};
pub use set_value::{SetValuePorts, SetValueRequest, SetValueUseCase};
pub use update::{Changes, UpdatePorts, UpdateRequest, UpdateUseCase};
