//! Agents seen at work that nobody registered: recording them, listing
//! them, and registering or dismissing each.

pub(crate) mod dismiss;
pub(crate) mod list;
pub(crate) mod register;

pub use dismiss::{DismissPorts, DismissUseCase};
pub use list::{ListPorts, ListUseCase, Shown};
pub use register::{RegisterPorts, RegisterRequest, RegisterUseCase};
