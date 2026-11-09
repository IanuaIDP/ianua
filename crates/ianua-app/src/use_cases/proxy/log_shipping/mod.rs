//! Log shipping: the places a tenant sends its request records to, and
//! sending them there.

pub(crate) mod change_log_target;
pub(crate) mod create_log_target;
mod credential;
pub(crate) mod delete_log_target;
pub(crate) mod get_log_target;
pub(crate) mod list_log_targets;
mod lookup;
pub(crate) mod pause_log_target;
pub(crate) mod resume_log_target;
pub(crate) mod ship_request_records;
mod target_changes;
mod view;

pub use change_log_target::{ChangeLogTargetPorts, ChangeLogTargetRequest, ChangeLogTargetUseCase};
pub use create_log_target::{CreateLogTargetPorts, CreateLogTargetRequest, CreateLogTargetUseCase};
pub use credential::CredentialChange;
pub use delete_log_target::{DeleteLogTargetPorts, DeleteLogTargetUseCase};
pub use get_log_target::{GetLogTargetPorts, GetLogTargetUseCase};
pub use list_log_targets::{ListLogTargetsPorts, ListLogTargetsUseCase};
pub use pause_log_target::{PauseLogTargetPorts, PauseLogTargetUseCase};
pub use resume_log_target::{ResumeLogTargetPorts, ResumeLogTargetUseCase};
pub use ship_request_records::{
    ShipRequestRecordsPorts, ShipRequestRecordsUseCase, ShipmentResult, TargetShipment,
};
pub use view::{CredentialState, LogTargetView};
