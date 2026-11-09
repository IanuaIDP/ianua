//! Members' second factors, passkeys, recovery codes and mailed links: the
//! stores of `ports/organization/credentials.rs`.
//!
//! Each row names the member it belongs to, and goes with them when they
//! are removed. Only what the domain hands over is kept: digests of codes
//! and links, a sealed seed, a passkey's public key, never a secret.

mod mfa_enrollments;
mod passkey_ceremonies;
mod passkeys;
mod recovery_codes;
mod tokens;

pub use mfa_enrollments::PgOrgMfaEnrollmentStore;
pub use passkey_ceremonies::PgOrgPasskeyCeremonyStore;
pub use passkeys::PgOrgPasskeyStore;
pub use recovery_codes::PgOrgRecoveryCodeStore;
pub use tokens::PgOrgTokenStore;
