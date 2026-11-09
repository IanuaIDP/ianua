//! Fakes for the authentication ports, by topic: sessions, signing in,
//! holding up under a flood, trusted devices, second factors, passwords,
//! LDAP certificates, passkeys, app sign-in, proving who you are again and
//! reading what a request presents at the gateway.

mod app_sign_in;
mod devices;
mod flood;
mod fresh_proofs;
mod ldap;
mod mfa;
mod passkeys;
mod passwords;
mod planes;
mod presented;
mod sent_codes;
mod sessions;
mod sign_in;
mod sign_in_codes;

pub use app_sign_in::*;
pub use devices::*;
pub use flood::*;
pub use fresh_proofs::*;
pub use ldap::*;
pub use mfa::*;
pub use passkeys::*;
pub use passwords::*;
pub use planes::*;
pub use presented::*;
pub use sent_codes::*;
pub use sessions::*;
pub use sign_in::*;
pub use sign_in_codes::*;
