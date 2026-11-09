//! The welcome a new account is sent.

pub(crate) mod mail;
pub(crate) mod send;
pub(crate) mod send_activation;

pub use mail::WelcomePorts;
pub use send::{SendWelcomePorts, SendWelcomeRequest, SendWelcomeUseCase};
pub use send_activation::SendActivationWelcomeUseCase;
