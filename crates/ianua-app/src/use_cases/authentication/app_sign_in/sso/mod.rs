//! Signing in on the app's own domain through an identity provider.

pub(super) mod callback;
pub(super) mod start;

pub use callback::{AppSsoAnswer, AppSsoCallbackRequest, AppSsoCallbackUseCase, AppSsoFinishFlows};
pub use start::{AppSsoStartRequest, AppSsoStartUseCase};
