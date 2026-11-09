//! Notices one person sends another by name.

mod lookup;
mod send;

pub use lookup::Offering;
pub use send::{SendPorts, SendRequest, SendUseCase};
