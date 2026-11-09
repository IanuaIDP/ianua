//! Signal streams: registering, confirming, changing, pausing and removing
//! them, the subjects they hear about, verification events, and what the
//! transmitter offers.

/// A stream registered, changed, paused and removed.
pub(crate) mod lifecycle;
/// Who a stream reports on.
pub(crate) mod subjects;
/// Proving a stream's endpoint belongs to its receiver.
pub(crate) mod verification;

pub use lifecycle::{
    DeletePorts, DeleteUseCase, DisablePorts, DisableUseCase, GetPorts, GetStatusPorts,
    GetStatusUseCase, GetUseCase, ListPorts, ListRequest, ListUseCase, PausePorts, PauseUseCase,
    RegisterPorts, RegisterRequest, RegisterUseCase, Registered, ResumePorts, ResumeUseCase,
    StreamFilter, TransmitterConfiguration, TransmitterConfigurationPorts,
    TransmitterConfigurationUseCase, UpdatePorts, UpdateRequest, UpdateUseCase,
};
pub use subjects::{
    AddSubjectPorts, AddSubjectRequest, AddSubjectUseCase, RemoveSubjectPorts,
    RemoveSubjectRequest, RemoveSubjectUseCase,
};
pub use verification::{
    ConfirmEndpointPorts, ConfirmEndpointRequest, ConfirmEndpointUseCase, ReceiverHeader,
    RequestVerificationPorts, RequestVerificationRequest, RequestVerificationUseCase,
};
