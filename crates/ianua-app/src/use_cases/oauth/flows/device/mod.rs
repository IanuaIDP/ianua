//! The device flow: a code shown on one device, approved on another.

pub(super) mod answer;
pub(crate) mod approve;
pub(crate) mod deny;
pub(crate) mod expire_authorizations;
pub(crate) mod request_code;

pub use approve::{ApproveDevicePorts, ApproveDeviceUseCase};
pub use deny::{DenyDevicePorts, DenyDeviceUseCase};
pub use expire_authorizations::{
    ExpireDeviceAuthorizationsPorts, ExpireDeviceAuthorizationsUseCase,
};
pub use request_code::{
    DeviceCodeResult, DeviceCodeTiming, RequestDeviceCodePorts, RequestDeviceCodeRequest,
    RequestDeviceCodeUseCase,
};
