//! Signals reported by hand, or by a workflow for a person: a risk level, a
//! compromised credential or device.

mod send;

pub use send::{SendPorts, SendRequest, SendUseCase};
