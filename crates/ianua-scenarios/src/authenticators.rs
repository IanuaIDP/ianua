//! The person's own devices, as real as the platform checks them: an
//! authenticator app making time-based codes from the secret it scanned, a
//! software passkey making real WebAuthn answers with a P-256 key, and the
//! recovery codes printed at setup.
//!
//! None of them asks the platform anything. Each holds what a device would
//! hold and answers what a device would answer, so the platform's checks
//! run against the same bytes a phone or a security key sends.

mod cbor;
mod passkey;
mod recovery;
mod totp;

pub use passkey::{PasskeyAnswer, SoftPasskey};
pub use recovery::RecoveryCodes;
pub use totp::TotpApp;
