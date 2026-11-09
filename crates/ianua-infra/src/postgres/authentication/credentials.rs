//! Passwords and their resets, second factors and recovery codes: the
//! stores of `ports/authentication/credentials.rs`.
//!
//! Each row names the account it belongs to, and goes with it when the
//! account is deleted. Only what the domain hands over is kept: password
//! hashes, keyed hashes of codes and links, a sealed seed, never a secret.

mod history;
mod mfa_enrollments;
mod passwords;
mod recovery_codes;
mod resets;

pub use history::PgPasswordHistory;
pub use mfa_enrollments::{PgFactorStanding, PgMfaEnrollmentStore};
pub use passwords::PgCredentialStore;
pub use recovery_codes::PgRecoveryCodeStore;
pub use resets::PgResetRequestStore;
