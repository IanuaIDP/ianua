//! A person's data erased: asked for, held, cancelled, carried out.

pub(crate) mod cancel;
pub(crate) mod cancel_by_link;
pub(crate) mod hold;
pub(super) mod legal_hold;
pub(crate) mod process_erasures;
pub(crate) mod release;
pub(crate) mod request;

pub use cancel::{CancelErasurePorts, CancelErasureUseCase};
pub use cancel_by_link::{CancelErasureByLinkPorts, CancelErasureByLinkUseCase};
pub use hold::{HoldErasurePorts, HoldErasureUseCase};
pub use process_erasures::{ErasureReport, ProcessErasuresPorts, ProcessErasuresUseCase};
pub use release::{ReleaseErasurePorts, ReleaseErasureUseCase};
pub use request::{
    ErasurePolicy, RequestErasurePorts, RequestErasureRequest, RequestErasureUseCase,
};
