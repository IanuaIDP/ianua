//! Single sign-on through a federation connection's OIDC or SAML identity
//! provider.

pub(crate) mod begin_single_sign_on;
pub mod completion;
pub(crate) mod exchange_sign_in_code;
mod federated_user;
pub(in crate::use_cases) mod lookup;
mod mapped_roles;
pub(crate) mod oidc_login;
pub(crate) mod saml_login;
pub mod single_sign_on;

pub use begin_single_sign_on::{
    BeginSingleSignOnPorts, BeginSingleSignOnRequest, BeginSingleSignOnUseCase, SsoReturn,
};
pub use exchange_sign_in_code::{
    ExchangeSignInCodePorts, ExchangeSignInCodeRequest, ExchangeSignInCodeUseCase, ExchangedSession,
};
pub use oidc_login::{OidcLoginPorts, OidcLoginRequest, OidcLoginUseCase};
pub use saml_login::{SamlCallbackRequest, SamlLoginPorts, SamlLoginUseCase};
