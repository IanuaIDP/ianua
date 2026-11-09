//! Setting up an account's channel: seeing the address to give a service,
//! pasting in the service's key, reading the token it sent, and saying it
//! was pasted back.

pub(crate) mod confirm;
pub(crate) mod lookup;
pub(crate) mod set_key;
pub(crate) mod show;
pub(crate) mod show_token;

pub use confirm::{ConfirmPorts, ConfirmUseCase};
pub use set_key::{SetKeyPorts, SetKeyRequest, SetKeyUseCase};
pub use show::{ChannelView, ShowPorts, ShowUseCase};
pub use show_token::{ShowTokenPorts, ShowTokenUseCase};
