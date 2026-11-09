//! The provider the tenant's mail goes out through.

pub(crate) mod get_provider;
pub(crate) mod provider;
pub(crate) mod switch_provider;
pub(crate) mod test_provider;

pub use get_provider::{GetMailProviderPorts, GetMailProviderUseCase};
pub use provider::{NamedMailProvider, NamedSmtpServer};
pub use switch_provider::{
    SwitchMailProviderPorts, SwitchMailProviderRequest, SwitchMailProviderUseCase,
};
pub use test_provider::{TestMailProviderPorts, TestMailProviderUseCase};
