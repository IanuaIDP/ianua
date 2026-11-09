//! Authentication ports, by topic: signing in, holding up under a sign-in
//! flood, the credentials an account holds, passkeys, signing in on an
//! app's own domain, and reading what a request presents at the gateway.

mod app_sign_in;
mod app_sign_in_wire;
mod credentials;
mod flood;
mod passkeys;
mod presented;
mod sealing;
mod sent_codes;
mod sign_in;

pub use app_sign_in::*;
pub use app_sign_in_wire::*;
pub use credentials::*;
pub use flood::*;
pub use ianua_domain::domains::authentication::credentials::passkey::AuthenticatorType;
pub use passkeys::*;
pub use presented::*;
pub use sealing::*;
pub use sent_codes::*;
pub use sign_in::*;
