//! Connecting an account and keeping its credential usable: signing in at
//! a service to connect one, asking an integration whether a credential
//! works, and exchanging the grant an account holds ahead of a call.

mod grants;
mod sign_in;
mod verifier;

pub use grants::InstalledGrantExchanger;
pub use sign_in::InstalledServiceSignIn;
pub use verifier::InstalledAccountVerifier;
