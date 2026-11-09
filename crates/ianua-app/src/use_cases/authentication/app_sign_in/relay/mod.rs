//! The internal relay the gateway calls: the signed command, its target and the page it answers with.

pub(super) mod common;
pub(super) mod note;
pub(super) mod page;
pub(super) mod receive;
pub(super) mod show_page;
pub(super) mod target;
pub(super) mod wire_command;

pub use note::{Refusal, SignInNote};
pub use page::{SignInPage, SsoChoice};
pub use receive::{ReceivePorts, ReceiveRequest, ReceiveUseCase};
pub use show_page::{AppSignInPageRequest, PageUseCase};
pub use target::TargetPorts;
