//! Signing in by a link instead of a password.

pub(crate) mod request;
pub(crate) mod sign_in;

pub use request::{
    MagicLinkPolicy, RequestMagicLinkPorts, RequestMagicLinkRequest, RequestMagicLinkUseCase,
};
pub use sign_in::{
    ConsumeMagicLinkPorts, ConsumeMagicLinkRequest, ConsumeMagicLinkUseCase, MagicLinkLoginSuccess,
};
