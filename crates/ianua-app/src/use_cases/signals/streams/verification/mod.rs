//! Proving a stream's endpoint belongs to its receiver.

pub(super) mod challenge;
pub(crate) mod confirm_endpoint;
pub(crate) mod receiver_header;
pub(crate) mod request;

pub use confirm_endpoint::{ConfirmEndpointPorts, ConfirmEndpointRequest, ConfirmEndpointUseCase};
pub use receiver_header::ReceiverHeader;
pub use request::{
    RequestVerificationPorts, RequestVerificationRequest, RequestVerificationUseCase,
};
