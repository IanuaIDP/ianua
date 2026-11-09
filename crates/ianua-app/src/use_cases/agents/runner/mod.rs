//! The runner beside an agent's sandbox: what each of the agent's requests
//! carries on its way out, and dropping a token a destination refused.

pub(crate) mod credential;
pub(crate) mod forget;

pub use credential::{Credential, CredentialPorts, CredentialRequest, CredentialUseCase};
pub use forget::{ForgetPorts, ForgetUseCase};
